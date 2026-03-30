import subprocess
import re
import time
import os

def scan_enterprise_networks(iface, duration=15):
    """Scan for WPA2-Enterprise (MGT auth) networks"""

    print(f"\n[*] Scanning for WPA2-Enterprise networks on {iface} ({duration}s)...")
    print("[*] Look for AUTH = MGT in results\n")

    out_file = "/tmp/eapx_scan"

    # Run airodump-ng in background, write to file
    proc = subprocess.Popen([
        "airodump-ng", iface,
        "--output-format", "csv",
        "-w", out_file,
        "--write-interval", "1"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(duration)
    proc.terminate()
    time.sleep(1)

    csv_file = out_file + "-01.csv"
    networks = []

    if not os.path.exists(csv_file):
        print("[!] Scan file not found. Is your adapter in monitor mode?")
        return []

    with open(csv_file, "r", errors="ignore") as f:
        lines = f.readlines()

    # Parse CSV — enterprise APs have MGT auth type
    for line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        bssid   = parts[0]
        channel = parts[3].strip()
        auth    = parts[7].strip()
        essid   = parts[13].strip()

        if auth == "MGT" and essid:
            networks.append({
                "bssid":   bssid,
                "channel": channel,
                "essid":   essid,
                "auth":    auth
            })

    # Remove duplicates
    seen = set()
    unique = []
    for n in networks:
        key = n["essid"] + n["bssid"]
        if key not in seen:
            seen.add(key)
            unique.append(n)

    return unique


def interactive_target_select(iface, duration=15):
    """Scan and let user pick a target interactively"""

    networks = scan_enterprise_networks(iface, duration)

    if not networks:
        print("[!] No WPA2-Enterprise networks found.")
        print("[!] Make sure adapter is in monitor mode: sudo airmon-ng start wlan0")
        return None

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║          WPA2-Enterprise Networks Found                 ║")
    print("╠═══╦══════════════════════╦═══════════════════╦══════════╣")
    print("║ # ║ BSSID                ║ ESSID             ║ Channel  ║")
    print("╠═══╬══════════════════════╬═══════════════════╬══════════╣")

    for i, net in enumerate(networks):
        print(f"║ {i+1} ║ {net['bssid']:<20} ║ {net['essid']:<17} ║ ch {net['channel']:<5} ║")

    print("╚═══╩══════════════════════╩═══════════════════╩══════════╝")

    try:
        choice = int(input("\n[?] Select target number: ")) - 1
        if 0 <= choice < len(networks):
            selected = networks[choice]
            print(f"\n[+] Target selected: {selected['essid']} | {selected['bssid']} | ch{selected['channel']}")
            return selected
    except (ValueError, KeyboardInterrupt):
        pass

    print("[!] Invalid selection")
    return None

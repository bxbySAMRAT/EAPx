"""
reporter.py — Enhanced pentest report generator with cert fingerprint,
EAP methods, OUI device fingerprinting, and dual JSON+Markdown export.
"""

import datetime
import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_file(path):
    """Read a file and return lines, or empty list if missing."""
    if os.path.exists(path):
        with open(path) as f:
            return f.readlines()
    return []


def _read_json(path):
    """Read a JSON file and return dict, or empty dict if missing."""
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _extract_vendors(identities_lines):
    """Parse vendor info from identity log lines."""
    vendors = {}
    for line in identities_lines:
        parts = line.strip().split("|")
        for part in parts:
            part = part.strip()
            if part.startswith("vendor="):
                vendor = part.split("=", 1)[1].strip()
                if vendor and vendor != "N/A" and vendor != "Unknown":
                    vendors[vendor] = vendors.get(vendor, 0) + 1
    return vendors


def generate_report(target_essid, target_bssid, channel, attacks_run):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_dir = os.path.join(BASE_DIR, "report")
    os.makedirs(report_dir, exist_ok=True)

    safe_essid = target_essid.replace(" ", "_").replace("/", "")
    ts_short = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    fname_md   = os.path.join(report_dir, f"pentest_{safe_essid}_{ts_short}.md")
    fname_json = os.path.join(report_dir, f"pentest_{safe_essid}_{ts_short}.json")

    loot_dir = os.path.join(BASE_DIR, "loot")
    cert_dir = os.path.join(BASE_DIR, "certs")

    # ── Read all loot data ──
    identities = _read_file(os.path.join(loot_dir, "identities.txt"))
    hashes     = _read_file(os.path.join(loot_dir, "hashes.txt"))
    passwords  = _read_file(os.path.join(loot_dir, "cracked_passwords.txt"))
    ad_creds   = _read_file(os.path.join(loot_dir, "ad_creds.txt"))

    # ── Read enhanced data ──
    eap_methods_raw = _read_file(os.path.join(loot_dir, "eap_methods.txt"))
    cert_fp         = _read_json(os.path.join(cert_dir, "fingerprint.json"))
    radius_cert     = _read_json(os.path.join(loot_dir, "radius_cert_metadata.json"))
    identities_json = _read_json(os.path.join(loot_dir, "identities_summary.json"))

    # ── Extract vendors ──
    vendors = _extract_vendors(identities)

    # ── Risk rating ──
    if passwords or ad_creds:
        risk = "🔴 CRITICAL — Plaintext credentials obtained"
        risk_level = "CRITICAL"
    elif hashes:
        risk = "🟠 HIGH — Credential hashes captured for offline cracking"
        risk_level = "HIGH"
    elif identities:
        risk = "🟡 MEDIUM — User identities exposed"
        risk_level = "MEDIUM"
    else:
        risk = "🟢 LOW — No credentials obtained"
        risk_level = "LOW"

    # ── Build EAP methods section ──
    eap_section = ""
    if eap_methods_raw:
        eap_section = f"""## EAP Methods Detected
```
{''.join(eap_methods_raw)}
```
"""
    # ── Build cert fingerprint section ──
    cert_section = ""
    if cert_fp:
        cert_section = f"""## Certificate Deployed
| Field | Value |
|---|---|
| Fingerprint | {cert_fp.get('fingerprint', 'N/A')} |
| Subject | {cert_fp.get('subject', 'N/A')} |
| CA Subject | {cert_fp.get('ca_subject', 'N/A')} |
| SAN | {', '.join(cert_fp.get('san', [])) or 'N/A'} |
| Generated | {cert_fp.get('generated_at', 'N/A')} |
"""

    # ── Build cloned cert section ──
    cloned_section = ""
    if radius_cert:
        cloned_section = f"""## Real RADIUS Certificate (Cloned)
| Field | Value |
|---|---|
| CN | {radius_cert.get('cn', 'N/A')} |
| Organization | {radius_cert.get('org', 'N/A')} |
| OU | {radius_cert.get('ou', 'N/A')} |
| Country | {radius_cert.get('country', 'N/A')} |
| SAN | {', '.join(radius_cert.get('san', [])) or 'N/A'} |
| Issuer CN | {radius_cert.get('issuer_cn', 'N/A')} |
| Valid | {radius_cert.get('not_before', '?')} → {radius_cert.get('not_after', '?')} |
"""

    # ── Build device fingerprinting section ──
    device_section = ""
    if vendors:
        vendor_rows = "\n".join(f"| {v} | {c} |" for v, c in
                                sorted(vendors.items(), key=lambda x: -x[1]))
        device_section = f"""## Client Device Fingerprinting
| Vendor | Count |
|---|---|
{vendor_rows}
"""

    # ── Build full report ──
    report = f"""# WPA2-Enterprise Penetration Test Report

**Date:** {timestamp}
**Tool:** EAPx Framework — github.com/babySAMRAT/eapx

---

## Target
| Field | Value |
|---|---|
| SSID | {target_essid} |
| BSSID | {target_bssid} |
| Channel | {channel} |
| Auth | WPA2-Enterprise (802.1X/EAP) |

## Attacks Run
{chr(10).join(f'- {a}' for a in attacks_run)}

## Risk Rating
{risk}

{eap_section}
{cert_section}
{cloned_section}
## EAP Identities Harvested ({len(identities)})
```
{''.join(identities) if identities else 'None captured'}
```

## Credential Hashes ({len(hashes)})
```
{''.join(hashes) if hashes else 'None captured'}
```

## Cracked Passwords ({len(passwords)})
```
{''.join(passwords) if passwords else 'None cracked'}
```

## Portal Credentials ({len(ad_creds)})
```
{''.join(ad_creds) if ad_creds else 'None captured'}
```

{device_section}
## Recommendations
- Enforce server certificate validation on all EAP supplicants
- Use EAP-TLS with client certificates instead of password-based EAP methods
- Implement 802.11w (Management Frame Protection) to prevent deauthentication attacks
- Deploy WIDS/WIPS to detect rogue access points
- Train users to verify certificate prompts before connecting
- Implement network access control (NAC) for device posture checking
- Use certificate pinning on managed devices

---
*Generated by EAPx Framework*
"""

    # ── Write Markdown report ──
    with open(fname_md, "w") as f:
        f.write(report)

    # ── Build and write JSON report ──
    json_report = {
        "metadata": {
            "tool": "EAPx Framework",
            "version": "2.0",
            "generated_at": timestamp,
            "report_file": fname_md,
        },
        "target": {
            "essid": target_essid,
            "bssid": target_bssid,
            "channel": channel,
            "auth": "WPA2-Enterprise (802.1X/EAP)",
        },
        "risk": {
            "level": risk_level,
            "description": risk,
        },
        "attacks_run": attacks_run,
        "eap_methods": [l.strip() for l in eap_methods_raw] if eap_methods_raw else [],
        "certificate": {
            "deployed": cert_fp,
            "cloned_original": radius_cert,
        },
        "identities": {
            "count": len(identities),
            "entries": [l.strip() for l in identities],
            "details": identities_json,
        },
        "hashes": {
            "count": len(hashes),
            "entries": [l.strip() for l in hashes],
        },
        "cracked": {
            "count": len(passwords),
            "entries": [l.strip() for l in passwords],
        },
        "portal_creds": {
            "count": len(ad_creds),
            "entries": [l.strip() for l in ad_creds],
        },
        "device_fingerprints": vendors,
    }

    with open(fname_json, "w") as f:
        json.dump(json_report, f, indent=2)

    print(f"\n[+] Report saved → {fname_md}")
    print(f"[+] JSON export → {fname_json}")
    return fname_md

"""
autocrack.py — Multi-stage hash cracking pipeline with hashcat
and ASLEAP support. Watches for new hashes and cracks automatically.
"""

import subprocess
import os
import time
import threading
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")

WORDLIST = "/usr/share/wordlists/rockyou.txt"

# ── Multi-stage cracking chain ──
CRACK_STAGES = [
    {
        "name": "Stage 1 — rockyou + best64",
        "wordlist": WORDLIST,
        "rules": "/usr/share/hashcat/rules/best64.rule",
    },
    {
        "name": "Stage 2 — rockyou + d3adhob0",
        "wordlist": WORDLIST,
        "rules": "/usr/share/hashcat/rules/d3adhob0.rule",
    },
    {
        "name": "Stage 3 — rockyou direct",
        "wordlist": WORDLIST,
        "rules": None,
    },
]


def _decompress_wordlist(path):
    """Decompress a .gz wordlist if needed."""
    if not os.path.exists(path) and os.path.exists(path + ".gz"):
        print(f"[*] Decompressing {path}.gz ...")
        subprocess.run(["gunzip", "-k", path + ".gz"],
                       stderr=subprocess.DEVNULL)


def _try_asleap(hash_line):
    """Try ASLEAP for MS-CHAPv2 challenge-response cracking."""
    if shutil.which("asleap") is None:
        return None

    # asleap expects challenge:response format
    # Typical NetNTLMv1 hash: user::domain:challenge:response:challenge
    parts = hash_line.split(":")
    if len(parts) < 6:
        return None

    challenge = parts[3]
    response = parts[4]

    print(f"[ASLEAP] Trying ASLEAP on challenge-response...")

    _decompress_wordlist(WORDLIST)

    result = subprocess.run(
        [
            "asleap",
            "-C", challenge,
            "-R", response,
            "-W", WORDLIST,
        ],
        capture_output=True, text=True, timeout=120,
    )

    for line in result.stdout.split("\n"):
        if "password:" in line.lower():
            password = line.split(":")[-1].strip()
            if password:
                print(f"\n[!!!] ══════════════════════════════════")
                print(f"[!!!] ASLEAP CRACKED → {password}")
                print(f"[!!!] ══════════════════════════════════\n")
                return password

    return None


def crack_hash(hash_line, mode=5500, custom_wordlist=None):
    """
    Multi-stage cracking: tries each stage in order until
    the hash is cracked or all stages are exhausted.
    """
    hash_file = "/tmp/eapx_crack.txt"

    with open(hash_file, "w") as f:
        f.write(hash_line.strip() + "\n")

    os.makedirs(LOOT_DIR, exist_ok=True)

    # Try ASLEAP first for MS-CHAPv2
    if mode == 5500:
        result = _try_asleap(hash_line)
        if result:
            with open(os.path.join(LOOT_DIR, "cracked_passwords.txt"), "a") as f:
                f.write(f"{hash_line.strip()}:{result} [asleap]\n")
            return result

    # Build stage list
    stages = list(CRACK_STAGES)

    # Add custom wordlist as Stage 0 if provided
    if custom_wordlist and os.path.exists(custom_wordlist):
        stages.insert(0, {
            "name": "Stage 0 — custom wordlist",
            "wordlist": custom_wordlist,
            "rules": None,
        })

    for stage in stages:
        wl = stage["wordlist"]
        rules = stage["rules"]
        name = stage["name"]

        # Check wordlist exists
        _decompress_wordlist(wl)
        if not os.path.exists(wl):
            print(f"[*] Skipping {name} — wordlist not found: {wl}")
            continue

        # Check rules exist
        if rules and not os.path.exists(rules):
            print(f"[*] Skipping {name} — rules not found: {rules}")
            continue

        print(f"\n[AUTOCRACK] {name}...")

        cmd = [
            "hashcat", "-m", str(mode),
            hash_file, wl,
            "--quiet", "--potfile-disable",
        ]
        if rules:
            cmd += ["-r", rules]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
        except subprocess.TimeoutExpired:
            print(f"[*] {name} timed out — moving to next stage")
            continue

        for line in (result.stdout + result.stderr).split("\n"):
            if ":" in line and not line.startswith("[") and len(line) > 5:
                password = line.strip().split(":")[-1]
                print(f"\n[!!!] ══════════════════════════════════")
                print(f"[!!!] CRACKED → {password}")
                print(f"[!!!] Stage:  {name}")
                print(f"[!!!] ══════════════════════════════════\n")
                with open(os.path.join(LOOT_DIR, "cracked_passwords.txt"), "a") as f:
                    f.write(f"{line.strip()} [{name}]\n")
                return password

    print("[*] Hash not cracked across all stages")
    return None


def watch_and_crack(hash_file=None, interval=5, custom_wordlist=None):
    """Watch a hash file for new entries and auto-crack them."""
    if hash_file is None:
        hash_file = os.path.join(LOOT_DIR, "hashes.txt")
    print(f"\n[AUTOCRACK] Watching {hash_file} for new hashes...")
    print(f"[AUTOCRACK] {len(CRACK_STAGES)} crack stages configured")
    if custom_wordlist:
        print(f"[AUTOCRACK] Custom wordlist: {custom_wordlist}")
    seen = set()

    while True:
        try:
            if os.path.exists(hash_file):
                with open(hash_file, "r") as f:
                    lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        print(f"[AUTOCRACK] New hash: {line[:60]}...")
                        mode = 5600 if ":::" in line else 5500
                        t = threading.Thread(
                            target=crack_hash,
                            args=(line, mode, custom_wordlist),
                            daemon=True
                        )
                        t.start()
            time.sleep(interval)
        except KeyboardInterrupt:
            break

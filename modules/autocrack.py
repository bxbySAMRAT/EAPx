import subprocess
import os
import time
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")

WORDLIST = "/usr/share/wordlists/rockyou.txt"
RULES    = "/usr/share/hashcat/rules/best64.rule"


def crack_hash(hash_line, mode=5500):
    hash_file = "/tmp/eapx_crack.txt"

    with open(hash_file, "w") as f:
        f.write(hash_line.strip() + "\n")

    print(f"\n[AUTOCRACK] Cracking with mode {mode}...")

    # Decompress rockyou if needed
    if not os.path.exists(WORDLIST) and os.path.exists(WORDLIST + ".gz"):
        subprocess.run(["gunzip", WORDLIST + ".gz"])

    result = subprocess.run([
        "hashcat", "-m", str(mode),
        hash_file, WORDLIST,
        "-r", RULES,
        "--quiet", "--potfile-disable"
    ], capture_output=True, text=True)

    for line in (result.stdout + result.stderr).split("\n"):
        if ":" in line and not line.startswith("[") and len(line) > 5:
            password = line.strip().split(":")[-1]
            print(f"\n[!!!] ══════════════════════════════════")
            print(f"[!!!] CRACKED → {password}")
            print(f"[!!!] ══════════════════════════════════\n")
            os.makedirs(LOOT_DIR, exist_ok=True)
            with open(os.path.join(LOOT_DIR, "cracked_passwords.txt"), "a") as f:
                f.write(line.strip() + "\n")
            return password

    print("[*] Not cracked with current wordlist")
    return None


def watch_and_crack(hash_file=None, interval=5):
    if hash_file is None:
        hash_file = os.path.join(LOOT_DIR, "hashes.txt")
    print(f"\n[AUTOCRACK] Watching {hash_file} for new hashes...")
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
                            args=(line, mode),
                            daemon=True
                        )
                        t.start()
            time.sleep(interval)
        except KeyboardInterrupt:
            break

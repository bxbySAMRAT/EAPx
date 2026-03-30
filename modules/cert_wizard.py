import subprocess
import os

def generate_certs(cn="FakeRADIUS", org="Corp", country="IN"):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_dir = os.path.join(base_dir, "certs")
    os.makedirs(cert_dir, exist_ok=True)

    print("[*] Generating CA certificate...")
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-nodes",
        "-keyout", f"{cert_dir}/ca.key",
        "-out",    f"{cert_dir}/ca.pem",
        "-days",   "3650",
        "-subj",   f"/C={country}/O={org}/CN={cn}-CA"
    ], check=True)

    print("[*] Generating server key and CSR...")
    subprocess.run([
        "openssl", "req", "-new", "-nodes",
        "-keyout", f"{cert_dir}/server.key",
        "-out",    f"{cert_dir}/server.csr",
        "-subj",   f"/C={country}/O={org}/CN={cn}"
    ], check=True)

    print("[*] Signing server certificate with CA...")
    subprocess.run([
        "openssl", "x509", "-req",
        "-in",          f"{cert_dir}/server.csr",
        "-CA",          f"{cert_dir}/ca.pem",
        "-CAkey",       f"{cert_dir}/ca.key",
        "-CAcreateserial",
        "-out",         f"{cert_dir}/server.pem",
        "-days",        "3650"
    ], check=True)

    print(f"\n[+] Certificates generated in {cert_dir}/")
    print("    ca.pem | ca.key | server.pem | server.key | server.csr")

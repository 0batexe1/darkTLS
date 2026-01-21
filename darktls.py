#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket, ssl, argparse, requests, re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus, OCSPCertStatus, load_der_ocsp_response

# ================= CONFIG =================
TIMEOUT = 4
TLS_PORTS = [443, 8443, 9443, 10443, 4443, 7443]
OID_SCT = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
OID_MUST_STAPLE = ObjectIdentifier("1.3.6.1.5.5.7.1.24")

# ================= COLORS =================
class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"
    B="\033[94m"; M="\033[95m"; END="\033[0m"

def ok(m): print(f"{C.G}[+] {m}{C.END}")
def info(m): print(f"{C.B}[*] {m}{C.END}")
def warn(m): print(f"{C.Y}[!] {m}{C.END}")
def crit(m): print(f"{C.R}[-] {m}{C.END}")

# ================= BANNER =================
def banner():
    print(f"""{C.R}
    ____             __   _______ __   _____
   / __ \\____ ______/ /__/ /_  __/ /  / ___/
  / / / / __ `/ ___/ //_/   / / / /   \\__ \\ 
 / /_/ / /_/ / /  / ,<     / / / /___ ___/ / 
/_____/\\__,_/_/  /_/|_|   /_/ /_____//____/  
{C.END}
DarkTLS v2.8 — OFFENSIVE MODE
Attacker‑oriented TLS / HTTP Exposure Analyzer
""")

# ================= TLS DISCOVERY =================
def discover_tls(host):
    for p in TLS_PORTS:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, p), timeout=TIMEOUT) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert = x509.load_der_x509_certificate(
                        ss.getpeercert(binary_form=True),
                        default_backend()
                    )
                    stapled = getattr(ss, "ocsp_response", None)
                    ok(f"TLS bulundu → {host}:{p}")
                    return p, cert, stapled
        except:
            continue
    return None, None, None

# ================= HTTP ANALYSIS =================
def http_offensive(host):
    print("\n=== HTTP OFFENSIVE ANALYSIS ===")
    risks = []

    try:
        r = requests.get(f"http://{host}", timeout=TIMEOUT)
        body = r.text.lower()

        # Redirect check
        if not r.url.startswith("https://"):
            crit("HTTP → HTTPS redirect yok")
            risks.append("Downgrade kalıcı")

        # Cookie analysis
        for c in r.cookies:
            if not c.secure:
                crit(f"Cookie '{c.name}' Secure flag YOK")
                risks.append("Session hijack")

        # Login form detection
        if re.search(r'<input[^>]+type=["\']password', body):
            crit("HTTP üzerinden password field tespit edildi")
            risks.append("Credential theft")

        # Headers
        if "strict-transport-security" not in r.headers:
            warn("HSTS yok → SSL stripping mümkün")

    except Exception as e:
        warn(f"HTTP analiz başarısız ({e})")

    return risks

# ================= TLS OFFENSIVE =================
def tls_offensive(cert, stapled):
    print("\n=== TLS OFFENSIVE ANALYSIS ===")
    risks = []

    # CT
    try:
        cert.extensions.get_extension_for_oid(OID_SCT)
        ok("CT mevcut")
    except:
        crit("CT yok → Sahte CA senaryosu")
        risks.append("Fake cert possible")

    # Must-Staple
    try:
        cert.extensions.get_extension_for_oid(OID_MUST_STAPLE)
        warn("Must‑Staple VAR")
        if not stapled:
            crit("Stapled OCSP yok → Fail‑open riski")
            risks.append("OCSP soft‑fail")
    except:
        info("Must‑Staple yok")

    return risks

# ================= ATTACK SUMMARY =================
def attack_summary(mode, risks):
    print("\n=== ATTACK SUMMARY ===")
    print(f"Mod: {mode}")
    if not risks:
        ok("Belirgin saldırı yüzeyi tespit edilmedi")
        return
    for r in set(risks):
        crit(r)

    print("\n=== ATTACKER VIEW ===")
    for r in set(risks):
        print(f"- {r} neden kritik?")
        if r == "Credential theft":
            print("  HTTP üzerinden gönderilen kimlik bilgileri ağda okunabilir.")
        if r == "Session hijack":
            print("  Secure olmayan cookie ağ seviyesinde ele geçirilebilir.")
        if r == "Downgrade kalıcı":
            print("  Kullanıcı her zaman HTTP’de kalmaya zorlanabilir.")
        if r == "OCSP soft‑fail":
            print("  Revocation kontrolü atlatılabilir.")
        if r == "Fake cert possible":
            print("  CT enforcement yoksa sahte sertifika fark edilmez.")

# ================= MAIN =================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    args = parser.parse_args()

    banner()

    port, cert, stapled = discover_tls(args.host)

    if not cert:
        crit("HTTPS YOK → TLS kullanılmıyor")
        risks = http_offensive(args.host)
        attack_summary("HTTP / MITM", risks)
        return

    ok(f"TLS aktif → Port {port}")
    risks = tls_offensive(cert, stapled)
    attack_summary("TLS / PKI", risks)

if __name__ == "__main__":
    main()

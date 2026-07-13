#!/usr/bin/env python3
"""mint_delegation_certs.py — one-shot cert minting for run_delegation_upload.sh.

Uses x509forge (already used by the WLCG x509 conformance suite) to build,
off a shared test CA:
  - user A's EEC cert+key (the TLS client identity A authenticates with)
  - user A's valid RFC-3820 proxy chain (proxy cert+key, then A's EEC cert)
  - user A's EXPIRED RFC-3820 proxy chain (notAfter well in the past)
  - user B's EEC cert+key
  - user B's valid RFC-3820 proxy chain (used in the cross-identity negative
    test: A authenticates over TLS but uploads a proxy delegating B)

x509forge's _EPOCH is a fixed 2026-01-01 anchor, not "now" — not_after_days
is computed relative to that anchor so the expired proxy is unambiguously in
the past regardless of when the test runs.

Usage: mint_delegation_certs.py <ca_cert.pem> <ca_key.pem> <outdir>
Writes into <outdir>: a_eec_cert.pem a_eec_key.pem a_proxy_valid.pem
a_proxy_expired.pem b_eec_cert.pem b_eec_key.pem b_proxy_valid.pem
a_proxy_wrongca.pem a_eec_wrongca_cert.pem a_eec_wrongca_key.pem
"""
import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import x509forge as xf
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def load_ca(cert_path: Path, key_path: Path) -> xf.Cert:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    return xf.Cert(cert, key)


def write_chain(out: Path, proxy: xf.Cert, eec: xf.Cert) -> None:
    out.write_bytes(proxy.pem + proxy.key_pem + eec.pem)


def main() -> int:
    ca_cert_path, ca_key_path, outdir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    ca = load_ca(Path(ca_cert_path), Path(ca_key_path))

    now_days = (datetime.datetime.now(datetime.timezone.utc) - xf._EPOCH).days

    a_eec = xf.make_eec(ca, "/DC=test/DC=xrootd/CN=Delegation Test User A/CN=88881",
                        not_after_days=now_days + 5)
    b_eec = xf.make_eec(ca, "/DC=test/DC=xrootd/CN=Delegation Test User B/CN=99992",
                        not_after_days=now_days + 5)

    a_proxy_valid = xf.make_proxy(a_eec, kind="rfc3820",
                                  not_before_days=now_days - 1,
                                  not_after_days=now_days + 1, serial=101)
    a_proxy_expired = xf.make_proxy(a_eec, kind="rfc3820",
                                    not_before_days=now_days - 10,
                                    not_after_days=now_days - 5, serial=102)
    b_proxy_valid = xf.make_proxy(b_eec, kind="rfc3820",
                                  not_before_days=now_days - 1,
                                  not_after_days=now_days + 1, serial=201)

    # Untrusted (wrong-CA / self-signed) proxy whose EEC SUBJECT STRING is
    # spoofed to equal user A's DN — the credential-endpoint chain-verification
    # negative test.  This chain does NOT anchor to the shared trusted CA, so a
    # server that only string-compares the EEC DN against ctx->dn (the pre-fix
    # gap) would wrongly accept it; a server that verifies against ca_store must
    # reject it (403).  A_DN below is the SAME subject string as a_eec.
    rogue_ca = xf.make_ca("/DC=test/DC=xrootd/CN=Rogue Untrusted Delegation CA",
                          not_after_days=now_days + 3650)
    a_eec_forged = xf.make_eec(
        rogue_ca, "/DC=test/DC=xrootd/CN=Delegation Test User A/CN=88881",
        not_after_days=now_days + 5)
    a_proxy_wrongca = xf.make_proxy(a_eec_forged, kind="rfc3820",
                                    not_before_days=now_days - 1,
                                    not_after_days=now_days + 1, serial=301)

    (outdir / "a_eec_cert.pem").write_bytes(a_eec.pem)
    (outdir / "a_eec_key.pem").write_bytes(a_eec.key_pem)
    (outdir / "b_eec_cert.pem").write_bytes(b_eec.pem)
    (outdir / "b_eec_key.pem").write_bytes(b_eec.key_pem)
    write_chain(outdir / "a_proxy_valid.pem", a_proxy_valid, a_eec)
    write_chain(outdir / "a_proxy_expired.pem", a_proxy_expired, a_eec)
    write_chain(outdir / "b_proxy_valid.pem", b_proxy_valid, b_eec)
    write_chain(outdir / "a_proxy_wrongca.pem", a_proxy_wrongca, a_eec_forged)
    # The rogue EEC key/cert, for the two-step negative test which needs to sign
    # a server CSR with an untrusted EEC that still carries A's subject string.
    (outdir / "a_eec_wrongca_cert.pem").write_bytes(a_eec_forged.pem)
    (outdir / "a_eec_wrongca_key.pem").write_bytes(a_eec_forged.key_pem)

    # Print the DNs exactly as X509_NAME_oneline formats them (openssl -nameopt
    # oneline output matches the module's brix_x509_oneline / ctx->dn format),
    # so the shell script can derive the credential-store keys without a
    # second subprocess round-trip through openssl x509 -subject.
    print("A_DN=" + subject_oneline(a_eec.cert))
    print("B_DN=" + subject_oneline(b_eec.cert))
    return 0


def subject_oneline(cert: x509.Certificate) -> str:
    # RFC2253-reversed, slash-joined, matching OpenSSL's legacy oneline format
    # used by X509_NAME_oneline() (most-significant RDN first, "/OID=value").
    parts = []
    for attr in cert.subject:
        oid_name = attr.oid._name if hasattr(attr.oid, "_name") else attr.oid.dotted_string
        short = {
            "domainComponent": "DC",
            "commonName": "CN",
            "organizationName": "O",
            "organizationalUnitName": "OU",
            "countryName": "C",
        }.get(oid_name, oid_name)
        parts.append(f"/{short}={attr.value}")
    return "".join(parts)


if __name__ == "__main__":
    sys.exit(main())

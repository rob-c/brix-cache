"""The hostile-PKI scenario builders.

The tail of ``x509forge_part2.py`` plus ``_cad_expired_ca``, which the flat
split had stranded at the head of shard 3 purely because shard 2 had run out of
its line budget -- it belongs with the other four ``_cad_*`` builders and is
filed with them here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import (
    CertificateBuilder,
    Name,
    NameAttribute,
)
from cryptography.x509.oid import NameOID

from brix_suite.security.x509.constants import (
    OID_GLOBUS_LIMITED,
    OID_PPL_INHERIT_ALL,
    OID_PROXY_CERT_INFO,
    _DAY,
    _EPOCH,
)
from brix_suite.security.x509.cadir import (
    CA_DN,
    Scenario,
    _scenario,
    signing_policy_text,
    write_hashed_ca_dir,
)
from brix_suite.security.x509.primitives import (
    Cert,
    _key,
    make_ca,
    make_crl,
    make_eec,
    make_proxy,
    proxy_cert_info_der,
)

# --------------------------------------------------------------------------
# Scenario builders — signing_policy (SP)
# --------------------------------------------------------------------------

def _sp_in_namespace(root: Path) -> Scenario:
    sc = _scenario(root, "sp_in_namespace")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    write_hashed_ca_dir(sc.ca_dir, ca,
                        policy_text=signing_policy_text(CA_DN,
                            ["/DC=test/DC=xrootd/*"]))
    sc.write_credential("eec_in_ns", [eec, ca], eec)
    sc.add_manifest("eec_in_ns", "accept", reason="subject inside CA namespace",
                    spec_ref="signing_policy §3.1")
    return sc.finalize()


def _sp_out_of_namespace(root: Path) -> Scenario:
    sc = _scenario(root, "sp_out_of_namespace")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=evil/CN=Mallory")
    write_hashed_ca_dir(sc.ca_dir, ca,
                        policy_text=signing_policy_text(CA_DN,
                            ["/DC=test/DC=xrootd/*"]))
    sc.write_credential("eec_out_ns", [eec, ca], eec)
    sc.add_manifest("eec_out_ns", "reject",
                    reason="CA signed outside its signing_policy namespace",
                    spec_ref="signing_policy §3.1")
    return sc.finalize()


def _sp_wrong_ca_block(root: Path) -> Scenario:
    sc = _scenario(root, "sp_wrong_ca_block")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    # policy names a DIFFERENT CA — file present but does not cover this CA.
    write_hashed_ca_dir(sc.ca_dir, ca,
                        policy_text=signing_policy_text(
                            "/DC=other/CN=Some Other CA",
                            ["/DC=test/DC=xrootd/*"]))
    sc.write_credential("eec_wrongblock", [eec, ca], eec)
    sc.add_manifest("eec_wrongblock", "reject",
                    reason="policy file present but names the wrong CA (fail closed)",
                    spec_ref="signing_policy §3.1")
    return sc.finalize()


def _sp_no_policy(root: Path) -> Scenario:
    """CA with normal (both) hash links but NO signing_policy file."""
    sc = _scenario(root, "sp_no_policy")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    write_hashed_ca_dir(sc.ca_dir, ca)   # no policy_text
    sc.write_credential("eec", [eec, ca], eec)
    # ON: absent policy -> pass-through accept.  REQUIRE: absent -> reject.
    sc.add_manifest("eec", "accept", reason="no policy file present (ON pass-through)",
                    spec_ref="signing_policy §3.1")
    return sc.finalize()


def _sp_proxy_cn_exempt(root: Path) -> Scenario:
    sc = _scenario(root, "sp_proxy_cn_exempt")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    proxy = make_proxy(eec, kind="rfc3820")
    write_hashed_ca_dir(sc.ca_dir, ca,
                        policy_text=signing_policy_text(CA_DN,
                            ["/DC=test/DC=xrootd/*"]))
    # The proxy adds /CN=424242; policy must match the EEC, not the proxy CN.
    sc.write_credential("proxy_in_ns", [proxy, eec, ca], proxy)
    sc.add_manifest("proxy_in_ns", "accept", surface="root",
                    reason="proxy CN suffix is exempt; EEC is in namespace",
                    spec_ref="signing_policy §3.1")
    return sc.finalize()


# --------------------------------------------------------------------------
# Scenario builders — proxy (PX)
# --------------------------------------------------------------------------

def _px_rfc3820_ok(root: Path) -> Scenario:
    sc = _scenario(root, "px_rfc3820_ok")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    proxy = make_proxy(eec, kind="rfc3820")
    write_hashed_ca_dir(sc.ca_dir, ca)
    sc.write_credential("proxy_full", [proxy, eec, ca], proxy)
    sc.add_manifest("proxy_full", "accept", surface="root",
                    reason="valid RFC 3820 impersonation proxy",
                    spec_ref="RFC 3820")
    return sc.finalize()


def _px_limited_to_full(root: Path) -> Scenario:
    sc = _scenario(root, "px_limited_to_full")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    limited = make_proxy(eec, kind="limited", serial=1)
    full = make_proxy_from(limited, eec, kind="rfc3820", serial=2)
    write_hashed_ca_dir(sc.ca_dir, ca)
    sc.write_credential("escalated", [full.cert_obj, limited, eec, ca], full)
    sc.add_manifest("escalated", "reject", surface="root",
                    reason="full proxy issued beneath a limited proxy (RFC 3820 §3.8)",
                    spec_ref="RFC 3820 §3.8")
    return sc.finalize()


def _px_noncritical_pci(root: Path) -> Scenario:
    sc = _scenario(root, "px_noncritical_pci")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    proxy = make_proxy(eec, kind="rfc3820", pci_critical=False)
    write_hashed_ca_dir(sc.ca_dir, ca)
    sc.write_credential("proxy_noncrit", [proxy, eec, ca], proxy)
    # OpenSSL only treats a cert as a proxy when proxyCertInfo is CRITICAL;
    # a non-critical PCI is not recognised as a proxy → issuer mismatch → reject.
    sc.add_manifest("proxy_noncrit", "reject", surface="root",
                    reason="proxyCertInfo must be critical (RFC 3820 §3.1)",
                    spec_ref="RFC 3820 §3.1")
    return sc.finalize()


def make_proxy_from(parent_proxy: Cert, chain_parent: Cert, *, kind: str,
                    serial: int) -> "ProxyResult":
    """Issue a proxy whose signer is another proxy (for escalation tests)."""
    key = _key()
    parent_attrs = list(parent_proxy.cert.subject)
    subject = Name(parent_attrs
                   + [NameAttribute(NameOID.COMMON_NAME, str(serial))])
    oid = {"rfc3820": OID_PPL_INHERIT_ALL, "limited": OID_GLOBUS_LIMITED}[kind]
    pci = proxy_cert_info_der(oid, None)
    b = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent_proxy.cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(_EPOCH - _DAY)
        .not_valid_after(_EPOCH + _DAY)
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_PROXY_CERT_INFO), pci), critical=True)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
    )
    cert = b.sign(parent_proxy.key, hashes.SHA256())
    return ProxyResult(Cert(cert, key))


@dataclass
class ProxyResult:
    _c: Cert

    @property
    def cert_obj(self) -> Cert:
        return self._c

    @property
    def pem(self) -> bytes:
        return self._c.pem

    @property
    def key_pem(self) -> bytes:
        return self._c.key_pem


# --------------------------------------------------------------------------
# Scenario builders — CRL
# --------------------------------------------------------------------------

def _crl_revoked_eec(root: Path) -> Scenario:
    sc = _scenario(root, "crl_revoked_eec")
    ca = make_ca(CA_DN)
    good = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    bad = make_eec(ca, "/DC=test/DC=xrootd/CN=Revoked")
    crl = make_crl(ca, revoked=[bad])
    write_hashed_ca_dir(sc.ca_dir, ca, crls={"r0": crl})
    sc.write_credential("good", [good, ca], good)
    sc.write_credential("revoked", [bad, ca], bad)
    sc.objects.update(ca=ca, good=good, revoked=bad)
    sc.add_manifest("good", "accept", reason="not revoked", spec_ref="RFC 5280")
    sc.add_manifest("revoked", "reject", reason="serial on CRL", spec_ref="RFC 5280")
    return sc.finalize()


def rewrite_crl(sc: Scenario, *, revoked_names: list[str]) -> None:
    """Re-sign the scenario's .r0 CRL, revoking the named in-memory certs.

    Requires the builder to have stashed the CA (and any revoked certs) in
    sc.objects.  Used by hot-reload/un-revocation tests.
    """
    ca = sc.objects["ca"]
    revoked = [sc.objects[n] for n in revoked_names]
    pem = make_crl(ca, revoked=revoked)
    for r0 in sc.ca_dir.glob("*.r0"):
        r0.write_bytes(pem)


def _crl_expired(root: Path) -> Scenario:
    sc = _scenario(root, "crl_expired")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    # thisUpdate and nextUpdate both before "now" (2026-07-06), next after this.
    crl = make_crl(ca, this_update_days=-40, next_update_days=-10)
    write_hashed_ca_dir(sc.ca_dir, ca, crls={"r0": crl})
    sc.write_credential("eec", [eec, ca], eec)
    # In "try"/"require" an expired CRL is fatal (staleness is evidence).
    sc.add_manifest("eec", "reject", reason="CRL nextUpdate has passed",
                    spec_ref="brix_crl_mode §3.3")
    return sc.finalize()


# --------------------------------------------------------------------------
# Scenario builders — CA-dir mechanics (CAD)
# --------------------------------------------------------------------------

def _cad_md5_only(root: Path) -> Scenario:
    sc = _scenario(root, "cad_md5_only")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    write_hashed_ca_dir(sc.ca_dir, ca, links="old")
    sc.write_credential("eec", [eec, ca], eec)
    # FINDING: modern OpenSSL X509_STORE_load_path looks CAs up by the NEW
    # (SHA-1 canonical) subject hash.  A CA dir carrying ONLY the legacy MD5
    # hash link is therefore not found and the chain fails to build.  WLCG/IGTF
    # distributions always ship BOTH links, so this is a corner-case gap, not a
    # normal deployment — recorded rather than "fixed" (it is OpenSSL policy).
    sc.add_manifest("eec", "reject",
                    reason="MD5-only hash link: CA not found by OpenSSL new-hash lookup",
                    spec_ref="CA-dir / OpenSSL hash")
    return sc.finalize()


def _cad_sha1_only(root: Path) -> Scenario:
    sc = _scenario(root, "cad_sha1_only")
    ca = make_ca(CA_DN)
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    write_hashed_ca_dir(sc.ca_dir, ca, links="new")
    sc.write_credential("eec", [eec, ca], eec)
    sc.add_manifest("eec", "accept",
                    reason="CA reachable via canonical SHA-1 hash link",
                    spec_ref="CA-dir")
    return sc.finalize()


# --------------------------------------------------------------------------
# DER helpers (proxyCertInfo has no native cryptography builder)
# --------------------------------------------------------------------------

def _cad_expired_ca(root: Path) -> Scenario:
    sc = _scenario(root, "cad_expired_ca")
    ca = make_ca(CA_DN, not_after_days=-1)   # already expired
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    write_hashed_ca_dir(sc.ca_dir, ca)
    sc.write_credential("eec", [eec, ca], eec)
    sc.add_manifest("eec", "reject", reason="trust anchor expired", spec_ref="RFC 5280")
    return sc.finalize()

"""ARCHIVE -- the pre-TS-5 flat ``x509forge_part2.py``, byte-for-byte.

Kept as the rollback anchor and as the diffing baseline for
``tests/test_ci_ts5_x509_move.py``, which hashes every moved function body
against the copy here.  Nothing in the live suite imports this file; it is not
a shim and it is not composed.
"""

from __future__ import annotations

def _guard_write_hashed_ca_dir_1(policy_file, ca_dir, hh):
    if policy_file is not None:
        _symlink("signing-policy", ca_dir / f"{hh}.signing_policy")


"""x509forge — manufacture hostile PKI scenario trees for WLCG conformance.

Each scenario materialises a complete hashed CA directory (CA certs with both
SHA-1 and MD5 hash links, <hash>.signing_policy, .r0/.r1 CRLs) plus one or more
client credentials and a manifest.json.  The manifest is the single source of
truth consumed by every test layer (C unit, pytest e2e, differential), so a
verdict can never drift between layers.

The builders lean on the `cryptography` package, with a raw-DER escape hatch
(via x509.UnrecognizedExtension) for artifacts cryptography will not emit
directly — non-critical proxyCertInfo, bogus policy OIDs, and the like.

A scenario spec is a plain dict; forge_scenario(root, name, spec) turns it into
a Scenario.  See BASELINE_SPEC and the *_SPECS tables for the catalogue used by
the test suite.
"""

import functools
import datetime
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    CertificateBuilder,
    CertificateRevocationListBuilder,
    Name,
    NameAttribute,
    RevokedCertificateBuilder,
)
from cryptography.x509.oid import NameOID

# A fixed epoch keeps validity windows reproducible without Date.now(); tests
# that need "expired" pass explicit deltas relative to this.
_EPOCH = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_DAY = datetime.timedelta(days=1)

# Policy-language OIDs.
OID_PROXY_CERT_INFO = "1.3.6.1.5.5.7.1.14"
OID_PPL_INHERIT_ALL = "1.3.6.1.5.5.7.21.1"   # full / impersonation
OID_PPL_INDEPENDENT = "1.3.6.1.5.5.7.21.2"   # independent
OID_GLOBUS_LIMITED = "1.3.6.1.4.1.3536.1.1.1.9"


# --------------------------------------------------------------------------
# DER helpers (proxyCertInfo has no native cryptography builder)
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=8192)
def _openssl_hashes_cached(pem: bytes) -> tuple[str, str]:
    """Compute (subject_hash, subject_hash_old) for a CA cert, forking openssl.

    Keyed on the cert PEM bytes: the subject hash is a pure function of the
    certificate's subject DN, so identical content always yields identical
    hashes.  build_all(ALL_CLAUSES) places the same handful of CAs across
    hundreds of clause rows; without this memo each placement forked openssl
    twice, and the resulting fork-storm pushed the conformance corpus past the
    per-test timeout under load.  openssl reads the cert from stdin so no temp
    path is needed (and the cache key is content, not a per-run temp path).
    """
    def h(flag: str) -> str:
        r = subprocess.run(
            ["openssl", "x509", "-noout", flag],
            input=pem, capture_output=True, check=True)
        return r.stdout.decode().strip()
    return h("-subject_hash"), h("-subject_hash_old")


def _openssl_hashes(cert_path: Path) -> tuple[str, str]:
    return _openssl_hashes_cached(cert_path.read_bytes())


def write_hashed_ca_dir(ca_dir: Path, ca: Cert, *, policy_text: str | None = None,
                        crls: dict[str, bytes] | None = None,
                        links: str = "both") -> None:
    """Write ca.pem + hash links (+ optional signing_policy + CRLs) into ca_dir.

    links: "both" (new+old hash), "new", or "old" — for CAD hash-link tests.
    """
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_pem = ca_dir / "ca.pem"
    ca_pem.write_bytes(ca.pem)

    new_hash, old_hash = _openssl_hashes(ca_pem)
    chosen = {"both": {new_hash, old_hash}, "new": {new_hash},
              "old": {old_hash}}[links]

    policy_file = None
    if policy_text is not None:
        policy_file = ca_dir / "signing-policy"
        policy_file.write_text(policy_text, encoding="utf-8")

    for hh in chosen:
        _symlink("ca.pem", ca_dir / f"{hh}.0")
        _guard_write_hashed_ca_dir_1(policy_file, ca_dir, hh)

    if crls:
        for suffix, pem in crls.items():
            (ca_dir / f"{new_hash}.{suffix}").write_bytes(pem)


def _symlink(target: str, link: Path) -> None:
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target)


def signing_policy_text(ca_dn: str, globs: list[str], *, granted: bool = True) -> str:
    quoted = " ".join(f'"{g}"' for g in globs)
    rights = "pos_rights" if granted else "neg_rights"
    return (
        f"access_id_CA    X509    '{ca_dn}'\n"
        f"{rights}      globus  CA:sign\n"
        f"cond_subjects   globus  '{quoted}'\n"
    )


# --------------------------------------------------------------------------
# Scenario model
# --------------------------------------------------------------------------

@dataclass
class Scenario:
    name: str
    dir: Path
    ca_dir: Path
    credentials: dict[str, Path] = field(default_factory=dict)
    manifest: list[dict] = field(default_factory=list)
    objects: dict = field(default_factory=dict)   # in-memory Certs (CA, EECs)

    def write_credential(self, name: str, chain: list[Cert],
                         key_of: Cert) -> Path:
        """Write a cred file: leaf-first cert chain + private key."""
        p = self.dir / f"{name}.pem"
        blob = b"".join(c.pem for c in chain) + key_of.key_pem
        p.write_bytes(blob)
        p.chmod(0o600)
        self.credentials[name] = p
        return p

    def add_manifest(self, credential: str, expected: str, *,
                     surface: str = "both", reason: str = "",
                     spec_ref: str = "") -> None:
        self.manifest.append({
            "scenario": self.name, "credential": credential,
            "surface": surface, "expected": expected,
            "reason": reason, "spec_ref": spec_ref,
        })

    def finalize(self) -> "Scenario":
        (self.dir / "manifest.json").write_text(
            json.dumps(self.manifest, indent=2), encoding="utf-8")
        return self


CA_DN = "/DC=test/DC=xrootd/CN=Test XRootD CA"


def _scenario(root: Path, name: str) -> Scenario:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    return Scenario(name=name, dir=d, ca_dir=d / "ca")


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

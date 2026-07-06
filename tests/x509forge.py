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

from __future__ import annotations

import datetime
import json
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

def _encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split(".")]
    out = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        if part == 0:
            out.append(0)
            continue
        chunks = []
        while part > 0:
            chunks.append(part & 0x7F)
            part >>= 7
        chunks.reverse()
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        out.extend(chunks)
    return bytes(out)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_seq(value: bytes) -> bytes:
    return _der_tlv(0x30, value)


def _der_oid(oid_str: str) -> bytes:
    return _der_tlv(0x06, _encode_oid(oid_str))


def _der_int(n: int) -> bytes:
    if n == 0:
        return _der_tlv(0x02, b"\x00")
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return _der_tlv(0x02, raw)


def proxy_cert_info_der(policy_oid: str, path_len: int | None = None) -> bytes:
    """DER for ProxyCertInfo { [pCPathLenConstraint], ProxyPolicy{policyOID} }."""
    proxy_policy = _der_seq(_der_oid(policy_oid))
    body = b""
    if path_len is not None:
        body += _der_int(path_len)
    body += proxy_policy
    return _der_seq(body)


# --------------------------------------------------------------------------
# Primitive builders
# --------------------------------------------------------------------------

def _key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _make_key(key_type: str = "rsa", *, bits: int = 2048, curve: str = "P-256"):
    """RSA (any size) or EC (P-256/P-384/P-521) private key."""
    if key_type == "ec":
        from cryptography.hazmat.primitives.asymmetric import ec
        curves = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1,
                  "P-521": ec.SECP521R1}
        return ec.generate_private_key(curves[curve]())
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _digest(name: str = "sha256"):
    return {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(), "sha1": hashes.SHA1(),
            "md5": hashes.MD5()}[name]


def _name(dn_slash: str) -> Name:
    """Parse an OpenSSL slash DN (/DC=a/DC=b/CN=c) into an x509 Name."""
    attrs = []
    oid_map = {
        "DC": NameOID.DOMAIN_COMPONENT,
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": NameOID.COUNTRY_NAME,
    }
    for part in dn_slash.strip("/").split("/"):
        if not part:
            continue
        k, _, v = part.partition("=")
        attrs.append(NameAttribute(oid_map[k], v))
    return Name(attrs)


@dataclass
class Cert:
    cert: x509.Certificate
    key: rsa.RSAPrivateKey

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )


def make_ca(dn: str, *, key_bits: int = 2048, not_after_days: int = 3650,
            not_before_days: int = -1, keycert_sign: bool = True,
            path_length: int | None = None, digest=None,
            key_type: str = "rsa", curve: str = "P-256",
            digest_name: str = "sha256") -> Cert:
    key = _make_key(key_type, bits=key_bits, curve=curve)
    digest = digest or _digest(digest_name)
    b = (
        CertificateBuilder()
        .subject_name(_name(dn))
        .issuer_name(_name(dn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_EPOCH + not_before_days * _DAY)
        .not_valid_after(_EPOCH + not_after_days * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length),
                       critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=keycert_sign,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    )
    return Cert(b.sign(key, digest), key)


def make_eec(issuer: Cert, dn=None, *, subject_name=None, key_bits: int = 2048,
             not_after_days: int = 3650, not_before_days: int = -1,
             ca_true: bool = False, keycert_sign: bool = False,
             path_length: int | None = None,
             with_key_usage: bool = True, key_usage: dict | None = None,
             eku: list | None = None, name_constraints=None,
             extra_ext: list | None = None, skid: bool = True,
             digest=None, key_type: str = "rsa", curve: str = "P-256",
             digest_name: str = "sha256") -> Cert:
    """End-entity (or intermediate CA if ca_true) signed by issuer.

    subject_name overrides dn with a pre-built x509.Name (for raw-DER / custom
    encodings). extra_ext is a list of (x509.ExtensionType, critical) OR
    (ObjectIdentifier, der_bytes, critical) tuples.
    """
    key = _make_key(key_type, bits=key_bits, curve=curve)
    digest = digest or _digest(digest_name)
    subj = subject_name if subject_name is not None else _name(dn)
    b = (
        CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_EPOCH + not_before_days * _DAY)
        .not_valid_after(_EPOCH + not_after_days * _DAY)
        .add_extension(
            x509.BasicConstraints(ca=ca_true, path_length=path_length),
            critical=True)
    )
    if skid:
        b = b.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
    if with_key_usage:
        ku = dict(digital_signature=True, content_commitment=False,
                  key_encipherment=True, data_encipherment=False,
                  key_agreement=False, key_cert_sign=(ca_true and keycert_sign),
                  crl_sign=(ca_true and keycert_sign),
                  encipher_only=False, decipher_only=False)
        if key_usage:
            ku.update(key_usage)
        b = b.add_extension(x509.KeyUsage(**ku), critical=True)
    if eku is not None:
        b = b.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(o) for o in eku]),
            critical=False)
    if name_constraints is not None:
        b = b.add_extension(name_constraints, critical=True)
    for item in (extra_ext or []):
        if len(item) == 2:
            ext, crit = item
            b = b.add_extension(ext, critical=crit)
        else:
            oid, der, crit = item
            b = b.add_extension(
                x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der),
                critical=crit)
    return Cert(b.sign(issuer.key, digest), key)


def make_proxy(parent: Cert, *, kind: str = "rfc3820", path_len: int | None = None,
               pci_critical: bool = True, policy_oid: str | None = None,
               ca_true: bool = False, with_san: bool = False,
               not_after_days: int = 1, not_before_days: int = -1,
               serial: int = 424242) -> Cert:
    """Delegated proxy off parent.

    kind: "rfc3820" (full), "limited" (Globus limited policy OID),
          "independent", or "legacy" (no proxyCertInfo, CN=proxy) /
          "legacy-limited" (CN=limited proxy).
    """
    key = _key()
    parent_attrs = list(parent.cert.subject)

    if kind in ("legacy", "legacy-limited"):
        cn = "limited proxy" if kind == "legacy-limited" else "proxy"
        subject = Name(parent_attrs + [NameAttribute(NameOID.COMMON_NAME, cn)])
    else:
        subject = Name(parent_attrs
                       + [NameAttribute(NameOID.COMMON_NAME, str(serial))])

    b = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent.cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(_EPOCH + not_before_days * _DAY)
        .not_valid_after(_EPOCH + not_after_days * _DAY)
    )

    if kind not in ("legacy", "legacy-limited"):
        oid = policy_oid
        if oid is None:
            oid = {
                "rfc3820": OID_PPL_INHERIT_ALL,
                "limited": OID_GLOBUS_LIMITED,
                "independent": OID_PPL_INDEPENDENT,
            }[kind]
        pci = proxy_cert_info_der(oid, path_len)
        b = b.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_PROXY_CERT_INFO), pci),
            critical=pci_critical)

    b = b.add_extension(
        x509.BasicConstraints(ca=ca_true, path_length=None), critical=True)
    b = b.add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=ca_true, crl_sign=False,
            encipher_only=False, decipher_only=False),
        critical=True)
    if with_san:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("evil.example.org")]),
            critical=False)

    return Cert(b.sign(parent.key, hashes.SHA256()), key)


def make_crl(ca: Cert, *, revoked: list[Cert] | None = None,
             next_update_days: int = 3650, this_update_days: int = -1,
             signer: Cert | None = None, crl_number: int | None = None,
             delta_indicator: int | None = None, reason: str | None = None,
             digest_name: str = "sha256") -> bytes:
    """A CRL for ca.  signer overrides the issuer key (wrong-signer tests);
    crl_number sets the CRLNumber; delta_indicator sets DeltaCRLIndicator (base
    CRL number); reason is a CRLReason name (e.g. 'key_compromise',
    'remove_from_crl')."""
    revoked = revoked or []
    signer = signer or ca
    b = (
        CertificateRevocationListBuilder()
        .issuer_name(ca.cert.subject)
        .last_update(_EPOCH + this_update_days * _DAY)
        .next_update(_EPOCH + next_update_days * _DAY)
    )
    if crl_number is not None:
        b = b.add_extension(x509.CRLNumber(crl_number), critical=False)
    if delta_indicator is not None:
        b = b.add_extension(x509.DeltaCRLIndicator(delta_indicator),
                            critical=True)
    for c in revoked:
        rb = (RevokedCertificateBuilder()
              .serial_number(c.cert.serial_number)
              .revocation_date(_EPOCH))
        if reason is not None:
            rb = rb.add_extension(
                x509.CRLReason(getattr(x509.ReasonFlags, reason)), critical=False)
        b = b.add_revoked_certificate(rb.build())
    crl = b.sign(signer.key, _digest(digest_name))
    return crl.public_bytes(serialization.Encoding.PEM)


# --------------------------------------------------------------------------
# CA-directory materialisation
# --------------------------------------------------------------------------

def _openssl_hashes(cert_path: Path) -> tuple[str, str]:
    def h(flag: str) -> str:
        r = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", flag],
            capture_output=True, text=True, check=True)
        return r.stdout.strip()
    return h("-subject_hash"), h("-subject_hash_old")


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
        if policy_file is not None:
            _symlink("signing-policy", ca_dir / f"{hh}.signing_policy")

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


def _cad_expired_ca(root: Path) -> Scenario:
    sc = _scenario(root, "cad_expired_ca")
    ca = make_ca(CA_DN, not_after_days=-1)   # already expired
    eec = make_eec(ca, "/DC=test/DC=xrootd/CN=Alice")
    write_hashed_ca_dir(sc.ca_dir, ca)
    sc.write_credential("eec", [eec, ca], eec)
    sc.add_manifest("eec", "reject", reason="trust anchor expired", spec_ref="RFC 5280")
    return sc.finalize()


# --------------------------------------------------------------------------
# Catalogue + entry points
# --------------------------------------------------------------------------

_BUILDERS = {
    "sp_in_namespace": _sp_in_namespace,
    "sp_out_of_namespace": _sp_out_of_namespace,
    "sp_wrong_ca_block": _sp_wrong_ca_block,
    "sp_no_policy": _sp_no_policy,
    "sp_proxy_cn_exempt": _sp_proxy_cn_exempt,
    "px_rfc3820_ok": _px_rfc3820_ok,
    "px_limited_to_full": _px_limited_to_full,
    "px_noncritical_pci": _px_noncritical_pci,
    "crl_revoked_eec": _crl_revoked_eec,
    "crl_expired": _crl_expired,
    "cad_md5_only": _cad_md5_only,
    "cad_sha1_only": _cad_sha1_only,
    "cad_expired_ca": _cad_expired_ca,
}

BASELINE_SPEC = {"builder": "sp_in_namespace"}


def forge_scenario(root: Path, name: str, spec: dict | None = None) -> Scenario:
    """Materialise scenario `name` under root.  spec may override the builder."""
    builder_name = (spec or {}).get("builder", name)
    return _BUILDERS[builder_name](Path(root))


def forge_all(root: Path) -> dict[str, Scenario]:
    """Materialise every catalogued scenario; returns name→Scenario."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    return {name: builder(root) for name, builder in _BUILDERS.items()}


def rewrite_signing_policy(sc: Scenario, globs_quoted: str) -> None:
    """Rewrite the scenario's signing-policy cond_subjects (hot-reload test)."""
    pol = sc.ca_dir / "signing-policy"
    pol.write_text(
        f"access_id_CA    X509    '{CA_DN}'\n"
        f"pos_rights      globus  CA:sign\n"
        f"cond_subjects   globus  '{globs_quoted}'\n",
        encoding="utf-8")


# ==========================================================================
# Forge v2 — clause-indexed registry + the fixed-fleet materialiser
# ==========================================================================
#
# A Clause is one conformance test.  Its build(ctx) function uses the ForgeCtx
# to register CA material (into one big shared multi-CA dir, exactly like a real
# /etc/grid-security/certificates) and write the credential the test presents.
# build_all() materialises every clause and emits manifest.json + manifest.tsv,
# the single source of truth consumed by the conformance fleet and the C oracle.

# Server config-groups.  Every config-group server points at the SAME shared/ca
# directory; the credential's group selects which config evaluates it.  The
# bundle group uses a single concatenated CA file instead of a hashed dir.
GROUPS = {
    "sp_on_crl_off":     dict(signing_policy="on",      crl_mode="off"),
    "sp_off_crl_off":    dict(signing_policy="off",     crl_mode="off"),
    "sp_require_crl_off": dict(signing_policy="require", crl_mode="off"),
    "sp_on_crl_try":     dict(signing_policy="on",      crl_mode="try",     crl="ca"),
    "sp_on_crl_require": dict(signing_policy="on",      crl_mode="require", crl="ca"),
    "sp_off_crl_try":    dict(signing_policy="off",     crl_mode="try",     crl="ca"),
    "bundle":            dict(signing_policy="off",     crl_mode="off",     cafile="bundle.pem"),
}


@dataclass
class Clause:
    id: str
    clause: str
    title: str
    expected: str                       # "accept" | "reject"
    build: "callable"                   # (ctx: ForgeCtx) -> cred_name | None
    surface: str = "davs"               # davs | c-oracle | config
    group: str = "sp_on_crl_off"
    reason: str = ""


def _place_ca_in_dir(ca_dir: Path, ca: Cert, *, name: str,
                     policy_text: str | None = None,
                     crls: dict[str, bytes] | None = None,
                     links: str = "both") -> None:
    """Place one CA into a multi-CA hashed dir as <name>.pem + <hash>.N links,
    <hash>.signing_policy, <hash>.rN — without a shared ca.pem (so hundreds of
    CAs coexist).  Picks the next free .N slot for a hash collision."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    cert_file = ca_dir / f"{name}.pem"
    cert_file.write_bytes(ca.pem)
    new_hash, old_hash = _openssl_hashes(cert_file)
    chosen = {"both": [new_hash, old_hash], "new": [new_hash],
              "old": [old_hash]}[links]
    for hh in dict.fromkeys(chosen):     # preserve order, dedup if equal
        slot = 0
        while (ca_dir / f"{hh}.{slot}").exists():
            slot += 1
        _symlink(f"{name}.pem", ca_dir / f"{hh}.{slot}")
        if policy_text is not None:
            pf = ca_dir / f"{name}.signing_policy"
            pf.write_text(policy_text, encoding="utf-8")
            _symlink(f"{name}.signing_policy", ca_dir / f"{hh}.signing_policy")
        if crls:
            for suffix, pem in crls.items():
                (ca_dir / f"{hh}.{suffix}").write_bytes(pem)


class ForgeCtx:
    """Handed to each Clause.build(); registers CA material + writes creds."""

    def __init__(self, root: Path, clause: Clause):
        self.root = Path(root)
        self.clause = clause
        self.shared_ca = self.root / "shared" / "ca"
        self.creds = self.root / "creds"
        self.creds.mkdir(parents=True, exist_ok=True)
        self._n = 0

    def _uid(self, suffix: str = "") -> str:
        self._n += 1
        return f"{self.clause.id}-{self._n}{('-' + suffix) if suffix else ''}"

    def dn(self, suffix: str = "") -> str:
        """A unique CA DN for this clause (avoids cross-test hash collisions)."""
        return f"/DC=test/DC=x509conf/CN=CA {self._uid(suffix)}"

    def ca(self, *, suffix: str = "", policy_globs: list | None = None,
           revoke: list | None = None, empty_crl: bool = False,
           links: str = "both", place: bool = True, to_bundle: bool = False,
           extra_crls: dict | None = None, dn: str | None = None,
           **ca_kw) -> Cert:
        """Mint a uniquely-named CA and (by default) place it in the shared dir.

        policy_globs → writes a <hash>.signing_policy granting those globs.
        revoke/empty_crl → writes a <hash>.r0 CRL. place=False mints without
        placing (unknown-CA tests). to_bundle appends to the bundle file."""
        ca_dn = dn or self.dn(suffix)
        ca = make_ca(ca_dn, **ca_kw)
        name = self._uid(suffix)
        if not place:
            return ca
        if to_bundle:
            bundle = self.shared_ca.parent / "bundle.pem"
            bundle.parent.mkdir(parents=True, exist_ok=True)
            with open(bundle, "ab") as fh:
                fh.write(ca.pem)
            return ca
        policy = (signing_policy_text(ca_dn, policy_globs)
                  if policy_globs is not None else None)
        crls = dict(extra_crls or {})
        if empty_crl or revoke is not None:
            crls["r0"] = make_crl(ca, revoked=revoke or [])
        _place_ca_in_dir(self.shared_ca, ca, name=name, policy_text=policy,
                         crls=crls or None, links=links)
        return ca

    def cred(self, chain: list[Cert], key_of: Cert | None = None) -> str:
        """Write leaf-first chain + key; return the credential filename."""
        key_of = key_of or chain[0]
        name = f"{self.clause.id}.pem"
        blob = b"".join(c.pem for c in chain) + key_of.key_pem
        (self.creds / name).write_bytes(blob)
        return name

    def raw_cred(self, pem: bytes) -> str:
        name = f"{self.clause.id}.pem"
        (self.creds / name).write_bytes(pem)
        return name


def build_all(root: Path, clauses: list) -> Path:
    """Materialise every Clause and emit manifest.json + manifest.tsv."""
    root = Path(root)
    if root.exists():
        shutil.rmtree(root)
    (root / "shared" / "ca").mkdir(parents=True, exist_ok=True)
    (root / "creds").mkdir(parents=True, exist_ok=True)

    rows = []
    for c in clauses:
        ctx = ForgeCtx(root, c)
        cred = c.build(ctx)
        rows.append(dict(id=c.id, clause=c.clause, title=c.title, cred=cred or "",
                         expected=c.expected, surface=c.surface, group=c.group,
                         reason=c.reason))

    (root / "manifest.json").write_text(json.dumps(rows, indent=2),
                                        encoding="utf-8")
    tsv = "\n".join("\t".join([r["id"], r["cred"], r["expected"], r["surface"],
                               r["group"]]) for r in rows)
    (root / "manifest.tsv").write_text(tsv + "\n", encoding="utf-8")
    return root


if __name__ == "__main__":   # manual: python3 tests/x509forge.py /tmp/x509conf
    import sys
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/x509conf")
    forged = forge_all(out)
    for nm, sc in forged.items():
        print(f"{nm}: {len(sc.manifest)} manifest entries → {sc.dir}")

"""ARCHIVE -- the pre-TS-5 flat ``x509forge.py``, byte-for-byte.

Kept as the rollback anchor and as the diffing baseline for
``tests/test_ci_ts5_x509_move.py``, which hashes every moved function body
against the copy here.  Nothing in the live suite imports this file; it is not
a shim and it is not composed.  ``x509forge_flat`` additionally still ends in the
``split_continuation`` load, which resolves shard names relative to *this*
directory and so cannot succeed here -- reconstruct the trio in a scratch
directory under their original names to run the flat stack.
"""

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
    if digest_name in ("sha1", "md5") and key_type == "rsa":
        return _make_ca_openssl(dn, key_bits=key_bits, digest_name=digest_name,
                                not_after_days=not_after_days)
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


def _make_eec_openssl(issuer: Cert, dn: str, *, key_bits: int,
                      digest_name: str, not_after_days: int,
                      not_before_days: int, ca_true: bool = False) -> Cert:
    """Build a leaf (or intermediate CA if ca_true) via the openssl CLI for
    parameters the cryptography signer refuses (MD5/SHA-1 signatures, sub-1024-
    bit keys).  Loads the result back into a Cert for the normal cred path."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "ca.pem").write_bytes(issuer.pem)
        (td / "ca.key").write_bytes(issuer.key_pem)
        subprocess.run(["openssl", "genrsa", "-out", str(td / "leaf.key"),
                        str(key_bits)], check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-key", str(td / "leaf.key"),
                        "-subj", dn, "-out", str(td / "leaf.csr")],
                       check=True, capture_output=True)
        cmd = ["openssl", "x509", "-req", "-in", str(td / "leaf.csr"),
               "-CA", str(td / "ca.pem"), "-CAkey", str(td / "ca.key"),
               "-CAcreateserial", f"-{digest_name}", "-days", "3650",
               "-out", str(td / "leaf.pem")]
        if ca_true:
            ext = td / "ext.cnf"
            ext.write_text("basicConstraints=critical,CA:TRUE\n"
                           "keyUsage=critical,keyCertSign,cRLSign\n")
            cmd += ["-extfile", str(ext)]
        subprocess.run(cmd, check=True, capture_output=True)
        cert = x509.load_pem_x509_certificate((td / "leaf.pem").read_bytes())
        key = serialization.load_pem_private_key(
            (td / "leaf.key").read_bytes(), password=None)
    return Cert(cert, key)


def _make_ca_openssl(dn: str, *, key_bits: int, digest_name: str,
                     not_after_days: int) -> Cert:
    """Self-signed CA via openssl for a weak digest cryptography won't sign."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subprocess.run(["openssl", "genrsa", "-out", str(td / "ca.key"),
                        str(key_bits)], check=True, capture_output=True)
        subprocess.run(
            ["openssl", "req", "-x509", "-new", "-key", str(td / "ca.key"),
             "-subj", dn, f"-{digest_name}", "-days", str(max(not_after_days, 1)),
             "-out", str(td / "ca.pem"),
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash"],
            check=True, capture_output=True)
        cert = x509.load_pem_x509_certificate((td / "ca.pem").read_bytes())
        key = serialization.load_pem_private_key(
            (td / "ca.key").read_bytes(), password=None)
    return Cert(cert, key)


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
    # cryptography's signer rejects MD5/SHA-1 and sub-1024-bit RSA; for those
    # weak-crypto conformance cases fall back to the openssl CLI.
    if (digest_name in ("sha1", "md5") or (key_type == "rsa" and key_bits < 1024)) \
            and subject_name is None and eku is None and extra_ext is None \
            and name_constraints is None:
        return _make_eec_openssl(issuer, dn, key_bits=key_bits,
                                 digest_name=digest_name,
                                 not_after_days=not_after_days,
                                 not_before_days=not_before_days,
                                 ca_true=ca_true)

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
               serial: int = 424242, extra_ext: list | None = None) -> Cert:
    """Delegated proxy off parent.

    kind: "rfc3820" (full), "limited" (Globus limited policy OID),
          "independent", or "legacy" (no proxyCertInfo, CN=proxy) /
          "legacy-limited" (CN=limited proxy).

    extra_ext takes the same (ext, critical) / (oid, der, critical) tuples as
    make_eec.  A proxy is the LEAF a GSI login presents, so an extension whose
    consumer reads chain[0] — authorityInfoAccess, which is where an OCSP
    responder URL comes from — has to be settable HERE and not just on the EEC.
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
    for item in (extra_ext or []):
        if len(item) == 2:
            ext, crit = item
            b = b.add_extension(ext, critical=crit)
        else:
            oid, der, crit = item
            b = b.add_extension(
                x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der),
                critical=crit)

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


from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "x509forge_part2.py", "x509forge_part3.py")

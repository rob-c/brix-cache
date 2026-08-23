"""Certificate primitives: DER encoding, keys, names, and the four makers.

``x509forge.py``'s own body, moved verbatim.  Nothing here knows about
scenarios or CA directories -- it manufactures a single ``Cert`` at a time.
"""

from __future__ import annotations

import subprocess

from dataclasses import dataclass
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

from brix_suite.security.x509.constants import (
    OID_GLOBUS_LIMITED,
    OID_PPL_INDEPENDENT,
    OID_PPL_INHERIT_ALL,
    OID_PROXY_CERT_INFO,
    _DAY,
    _EPOCH,
)
from brix_suite.security.x509.primitive_operations import (
    encode_oid as _encode_oid_operation,
    make_crl as _make_crl_operation,
    make_eec as _make_eec_operation,
    make_proxy as _make_proxy_operation,
)

# --------------------------------------------------------------------------
# DER helpers (proxyCertInfo has no native cryptography builder)
# --------------------------------------------------------------------------

def _encode_oid(oid_str: str) -> bytes:
    return _encode_oid_operation(oid_str)


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
    return _make_eec_operation(
        issuer, dn, subject_name, key_bits, not_after_days, not_before_days,
        ca_true, keycert_sign, path_length, with_key_usage, key_usage, eku,
        name_constraints, extra_ext, skid, digest, key_type, curve, digest_name,
        globals(),
    )


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
    return _make_proxy_operation(
        parent, kind, path_len, pci_critical, policy_oid, ca_true, with_san,
        not_after_days, not_before_days, serial, extra_ext, globals(),
    )


def make_crl(ca: Cert, *, revoked: list[Cert] | None = None,
             next_update_days: int = 3650, this_update_days: int = -1,
             signer: Cert | None = None, crl_number: int | None = None,
             delta_indicator: int | None = None, reason: str | None = None,
             digest_name: str = "sha256") -> bytes:
    """A CRL for ca.  signer overrides the issuer key (wrong-signer tests);
    crl_number sets the CRLNumber; delta_indicator sets DeltaCRLIndicator (base
    CRL number); reason is a CRLReason name (e.g. 'key_compromise',
    'remove_from_crl')."""
    return _make_crl_operation(
        ca, revoked, next_update_days, this_update_days, signer, crl_number,
        delta_indicator, reason, digest_name, globals(),
    )

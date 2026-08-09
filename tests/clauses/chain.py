"""chain — RFC 5280 §4.1/§4.2/§6 path-validation & PKIX conformance family.

Every row isolates one PKIX chain property (basicConstraints, keyUsage, EKU,
AKI/SKI, validity, serial, signature algorithm, key strength, unknown critical
extensions, chain depth, and the structural failure modes) with matched
accept/reject variants.  All rows run in the `sp_off_crl_off` group so the
verdict reflects *chain* behaviour only — signing_policy and CRL processing are
switched off and can never colour the result.

`expected` is SPEC-FIRST: it is what RFC 5280 / IGTF require, even where our
current WebDAV x509 path (OpenSSL X509_verify_cert with nginx defaults) is
likely to disagree — those divergences are called out in `reason` and are the
work of a later code phase, never a reason to weaken the test.
"""

from __future__ import annotations

import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import CertificateBuilder

import x509forge
from x509forge import Cert, make_ca, make_eec
from x509forge import _DAY, _EPOCH, _der_oid, _der_seq, _der_tlv, _name
from clauses._helpers import clause, leaf_dn

# --------------------------------------------------------------------------
# EKU OIDs
# --------------------------------------------------------------------------
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
CODE_SIGN = "1.3.6.1.5.5.7.3.3"
EMAIL_PROT = "1.3.6.1.5.5.7.3.4"
TIME_STAMP = "1.3.6.1.5.5.7.3.8"
OCSP_SIGN = "1.3.6.1.5.5.7.3.9"
ANY_EKU = "2.5.29.37.0"
UNK_EKU = "1.3.6.1.4.1.99999.9.9"

UNK_EXT_1 = "1.3.6.1.4.1.99999.7.1"
UNK_EXT_2 = "1.3.6.1.4.1.99999.7.2"


# --------------------------------------------------------------------------
# Low-level helpers (things make_ca / make_eec cannot express directly)
# --------------------------------------------------------------------------

def _rsa(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _sign_ca(issuer: Cert, subject_dn: str, key, *, keycert_sign: bool = True,
             crl_sign: bool = True, with_bc: bool = True,
             bc_critical: bool = True, path_length=None, with_ku: bool = True,
             ku_critical: bool = True, digest_name: str = "sha256",
             not_after_days: int = 3650, not_before_days: int = -1) -> Cert:
    """Issue an intermediate CA for `key`, signed by `issuer`.

    Unlike make_eec(ca_true=True) this exposes basicConstraints presence /
    criticality and independent keyCertSign/cRLSign bits, which the structural
    tests need.  Returns a Cert (cert + key) that can itself sign further certs.
    """
    d = x509forge._digest(digest_name)
    b = (CertificateBuilder()
         .subject_name(_name(subject_dn))
         .issuer_name(issuer.cert.subject)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(_EPOCH + not_before_days * _DAY)
         .not_valid_after(_EPOCH + not_after_days * _DAY)
         .add_extension(
             x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
             critical=False))
    if with_bc:
        b = b.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=bc_critical)
    if with_ku:
        b = b.add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=keycert_sign,
                crl_sign=crl_sign, encipher_only=False, decipher_only=False),
            critical=ku_critical)
    return Cert(b.sign(issuer.key, d), key)


def _sig_algid() -> bytes:
    """AlgorithmIdentifier for sha256WithRSAEncryption { OID, NULL }."""
    return _der_seq(_der_oid("1.2.840.113549.1.1.11") + b"\x05\x00")


def _utctime(dt) -> bytes:
    return _der_tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())


def _der_to_pem(der: bytes) -> bytes:
    body = base64.encodebytes(der)
    return (b"-----BEGIN CERTIFICATE-----\n" + body
            + b"-----END CERTIFICATE-----\n")


def _raw_eec(issuer: Cert, subject_dn: str, *, serial_content: bytes = b"\x2a",
             nb_days: int = -1, na_days: int = 3650) -> tuple[bytes, object]:
    """Hand-build a validly-signed EEC with a caller-chosen serialNumber INTEGER
    and validity window.  Neither a non-positive/oversized serial nor an
    inverted (notBefore > notAfter) window can be minted through cryptography's
    builder, which validates both — so we assemble the DER directly.  Returns
    (leaf_pem, ee_key)."""
    ekey = _rsa()
    version = _der_tlv(0xA0, _der_tlv(0x02, b"\x02"))       # v3
    serial = _der_tlv(0x02, serial_content)
    sigalg = _sig_algid()
    issuer_der = issuer.cert.subject.public_bytes(serialization.Encoding.DER)
    validity = _der_seq(_utctime(_EPOCH + nb_days * _DAY)
                        + _utctime(_EPOCH + na_days * _DAY))
    subject_der = _name(subject_dn).public_bytes(serialization.Encoding.DER)
    spki = ekey.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    tbs = _der_seq(version + serial + sigalg + issuer_der + validity
                   + subject_der + spki)
    sig = issuer.key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    cert_der = _der_seq(tbs + _sig_algid() + _der_tlv(0x03, b"\x00" + sig))
    return _der_to_pem(cert_der), ekey


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


# --------------------------------------------------------------------------
# Generic build factories
# --------------------------------------------------------------------------

def _eec(**eec_kw):
    """One placed CA + a single EEC carrying eec_kw."""
    def build(ctx):
        ca = ctx.ca()
        eec = make_eec(ca, leaf_dn(ctx), **eec_kw)
        return ctx.cred([eec, ca], eec)
    return build


def _root(ca_kw, eec_kw=None):
    """CA minted with ca_kw + a normal EEC beneath it."""
    eec_kw = eec_kw or {}

    def build(ctx):
        ca = ctx.ca(**ca_kw)
        eec = make_eec(ca, leaf_dn(ctx), **eec_kw)
        return ctx.cred([eec, ca], eec)
    return build


def _inter(inter_kw=None, eec_kw=None):
    """root -> intermediate(make_eec ca_true) -> EEC."""
    inter_kw = inter_kw or {}
    eec_kw = eec_kw or {}

    def build(ctx):
        root = ctx.ca()
        inter = make_eec(root, ctx.dn("int"), ca_true=True, keycert_sign=True,
                         **inter_kw)
        eec = make_eec(inter, leaf_dn(ctx), **eec_kw)
        return ctx.cred([eec, inter, root], eec)
    return build


def _inter_eku(inter_eku, eec_eku):
    def build(ctx):
        root = ctx.ca()
        inter = make_eec(root, ctx.dn("int"), ca_true=True, keycert_sign=True,
                         eku=inter_eku)
        eec = make_eec(inter, leaf_dn(ctx), eku=eec_eku)
        return ctx.cred([eec, inter, root], eec)
    return build


def _crit_eku(oids):
    def build(ctx):
        ca = ctx.ca()
        ext = x509.ExtendedKeyUsage([x509.ObjectIdentifier(o) for o in oids])
        eec = make_eec(ca, leaf_dn(ctx), eku=None, extra_ext=[(ext, True)])
        return ctx.cred([eec, ca], eec)
    return build


def _unknown_ext_eec(critical):
    def build(ctx):
        ca = ctx.ca()
        eec = make_eec(ca, leaf_dn(ctx),
                       extra_ext=[(UNK_EXT_1, b"\x05\x00", critical)])
        return ctx.cred([eec, ca], eec)
    return build


def _unknown_ext_inter(critical):
    def build(ctx):
        root = ctx.ca()
        inter = make_eec(root, ctx.dn("int"), ca_true=True, keycert_sign=True,
                         extra_ext=[(UNK_EXT_1, b"\x05\x00", critical)])
        eec = make_eec(inter, leaf_dn(ctx))
        return ctx.cred([eec, inter, root], eec)
    return build


def _aki(kind):
    def build(ctx):
        ca = ctx.ca()
        ski = ca.cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value.digest
        if kind == "match":
            aki = x509.AuthorityKeyIdentifier(ski, None, None)
        elif kind == "mismatch":
            aki = x509.AuthorityKeyIdentifier(b"\x11" * 20, None, None)
        elif kind == "issuer_serial":
            aki = x509.AuthorityKeyIdentifier(
                None, [x509.DirectoryName(ca.cert.subject)],
                ca.cert.serial_number)
        elif kind == "issuer_serial_bad":
            aki = x509.AuthorityKeyIdentifier(
                None, [x509.DirectoryName(ca.cert.subject)], 999999999)
        eec = make_eec(ca, leaf_dn(ctx), extra_ext=[(aki, False)])
        return ctx.cred([eec, ca], eec)
    return build


def _serial(content):
    def build(ctx):
        ca = ctx.ca()
        leaf_pem, ekey = _raw_eec(ca, leaf_dn(ctx), serial_content=content)
        return ctx.raw_cred(leaf_pem + ca.pem + _key_pem(ekey))
    return build


def _inverted_validity(ctx):
    ca = ctx.ca()
    leaf_pem, ekey = _raw_eec(ca, leaf_dn(ctx), nb_days=400, na_days=390)
    return ctx.raw_cred(leaf_pem + ca.pem + _key_pem(ekey))


def _chain_depth(n):
    def build(ctx):
        root = ctx.ca()
        prev = root
        mids = []
        for i in range(n):
            inter = _sign_ca(prev, ctx.dn(f"d{i}"), _rsa())  # unlimited pathlen
            mids.append(inter)
            prev = inter
        eec = make_eec(prev, leaf_dn(ctx))
        return ctx.cred([eec, *reversed(mids), root], eec)
    return build


def _cross(which):
    def build(ctx):
        r1 = ctx.ca(suffix="r1")
        r2 = ctx.ca(suffix="r2")
        ik = _rsa()
        sdn = ctx.dn("xi")
        cross_a = _sign_ca(r1, sdn, ik)
        cross_b = _sign_ca(r2, sdn, ik)
        src = cross_a if which == "A" else cross_b
        anchor = r1 if which == "A" else r2
        eec = make_eec(src, leaf_dn(ctx))
        return ctx.cred([eec, src, anchor], eec)
    return build


# --------------------------------------------------------------------------
# Structural build functions (explicit — pathLen nesting, malformed, etc.)
# --------------------------------------------------------------------------

def _ca_false_issuer(ctx):
    root = ctx.ca()
    fake = make_eec(root, ctx.dn("fake"))            # basicConstraints CA:FALSE
    child = make_eec(fake, leaf_dn(ctx))
    return ctx.cred([child, fake, root], child)


def _no_bc_issuer(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("nobc"), _rsa(), with_bc=False)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _bc_noncrit_ca(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("nc"), _rsa(), bc_critical=False)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _ca_no_crlsign(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i"), _rsa(), keycert_sign=True,
                     crl_sign=False)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _ca_no_ku(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i"), _rsa(), with_ku=False)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _ca_ku_noncrit(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i"), _rsa(), ku_critical=False)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _ca_no_keycertsign(ctx):
    root = ctx.ca()
    inter = make_eec(root, ctx.dn("i"), ca_true=True, keycert_sign=False)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _pathlen0_direct(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i0"), _rsa(), path_length=0)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _pathlen0_subca(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i0"), _rsa(), path_length=0)
    sub = _sign_ca(inter, ctx.dn("sub"), _rsa())
    eec = make_eec(sub, leaf_dn(ctx))
    return ctx.cred([eec, sub, inter, root], eec)


def _pathlen1_one(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i1"), _rsa(), path_length=1)
    sub = _sign_ca(inter, ctx.dn("s"), _rsa(), path_length=0)
    eec = make_eec(sub, leaf_dn(ctx))
    return ctx.cred([eec, sub, inter, root], eec)


def _pathlen1_two(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i1"), _rsa(), path_length=1)
    s1 = _sign_ca(inter, ctx.dn("s1"), _rsa())
    s2 = _sign_ca(s1, ctx.dn("s2"), _rsa())
    eec = make_eec(s2, leaf_dn(ctx))
    return ctx.cred([eec, s2, s1, inter, root], eec)


def _pathlen2_two(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i2"), _rsa(), path_length=2)
    s1 = _sign_ca(inter, ctx.dn("s1"), _rsa(), path_length=1)
    s2 = _sign_ca(s1, ctx.dn("s2"), _rsa(), path_length=0)
    eec = make_eec(s2, leaf_dn(ctx))
    return ctx.cred([eec, s2, s1, inter, root], eec)


def _pathlen2_three(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i2"), _rsa(), path_length=2)
    s1 = _sign_ca(inter, ctx.dn("s1"), _rsa())
    s2 = _sign_ca(s1, ctx.dn("s2"), _rsa())
    s3 = _sign_ca(s2, ctx.dn("s3"), _rsa())
    eec = make_eec(s3, leaf_dn(ctx))
    return ctx.cred([eec, s3, s2, s1, inter, root], eec)


def _pathlen3_three(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i3"), _rsa(), path_length=3)
    s1 = _sign_ca(inter, ctx.dn("s1"), _rsa(), path_length=2)
    s2 = _sign_ca(s1, ctx.dn("s2"), _rsa(), path_length=1)
    s3 = _sign_ca(s2, ctx.dn("s3"), _rsa(), path_length=0)
    eec = make_eec(s3, leaf_dn(ctx))
    return ctx.cred([eec, s3, s2, s1, inter, root], eec)


def _root_pathlen0_inter(ctx):
    root = ctx.ca(path_length=0)
    inter = _sign_ca(root, ctx.dn("i"), _rsa())
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _root_pathlen0_direct(ctx):
    root = ctx.ca(path_length=0)
    eec = make_eec(root, leaf_dn(ctx))
    return ctx.cred([eec, root], eec)


def _root_pathlen1_inter(ctx):
    root = ctx.ca(path_length=1)
    inter = _sign_ca(root, ctx.dn("i"), _rsa(), path_length=0)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _root_pathlen1_two(ctx):
    root = ctx.ca(path_length=1)
    i1 = _sign_ca(root, ctx.dn("i1"), _rsa())
    i2 = _sign_ca(i1, ctx.dn("i2"), _rsa())
    eec = make_eec(i2, leaf_dn(ctx))
    return ctx.cred([eec, i2, i1, root], eec)


def _root_pathlen2_two(ctx):
    root = ctx.ca(path_length=2)
    i1 = _sign_ca(root, ctx.dn("i1"), _rsa(), path_length=1)
    i2 = _sign_ca(i1, ctx.dn("i2"), _rsa(), path_length=0)
    eec = make_eec(i2, leaf_dn(ctx))
    return ctx.cred([eec, i2, i1, root], eec)

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "chain_part2.py", "chain_part3.py")

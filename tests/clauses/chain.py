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


def _inter_key(inter_kw, eec_kw=None):
    eec_kw = eec_kw or {}

    def build(ctx):
        root = ctx.ca()
        inter = make_eec(root, ctx.dn("i"), ca_true=True, keycert_sign=True,
                         **inter_kw)
        eec = make_eec(inter, leaf_dn(ctx), **eec_kw)
        return ctx.cred([eec, inter, root], eec)
    return build


def _selfsigned_leaf(ctx):
    leaf = make_ca(ctx.dn("self"))          # self-signed, deliberately unplaced
    return ctx.cred([leaf], leaf)


def _wrong_issuer(ctx):
    rogue = ctx.ca(place=False)             # minted but not a trust anchor
    eec = make_eec(rogue, leaf_dn(ctx))
    return ctx.cred([eec, rogue], eec)


def _tampered(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx))
    der = bytearray(eec.cert.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF                          # corrupt the signatureValue tail
    return ctx.raw_cred(_der_to_pem(bytes(der)) + ca.pem + eec.key_pem)


def _truncated(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx))
    der = eec.cert.public_bytes(serialization.Encoding.DER)
    return ctx.raw_cred(_der_to_pem(der[:len(der) // 2]) + eec.key_pem)


def _issuer_dn_collision(ctx):
    """A rogue CA shares the trusted CA's subject DN but has a different key;
    the EEC it signs must fail signature verification against the real anchor."""
    dn = ctx.dn("shared")
    real = make_ca(dn)
    x509forge._place_ca_in_dir(ctx.shared_ca, real, name=f"{ctx.clause.id}-real")
    rogue = make_ca(dn)                      # same DN, different key, unplaced
    eec = make_eec(rogue, leaf_dn(ctx))
    return ctx.cred([eec, rogue], eec)


def _two_noncrit_ext(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx),
                   extra_ext=[(UNK_EXT_1, b"\x05\x00", False),
                              (UNK_EXT_2, b"\x05\x00", False)])
    return ctx.cred([eec, ca], eec)


def _unknown_ext_eec2(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx), extra_ext=[(UNK_EXT_2, b"\x30\x00", True)])
    return ctx.cred([eec, ca], eec)


def _bc_noncrit_pathlen0_direct(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i"), _rsa(), bc_critical=False, path_length=0)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _bc_noncrit_pathlen0_subca(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i"), _rsa(), bc_critical=False, path_length=0)
    sub = _sign_ca(inter, ctx.dn("s"), _rsa())
    eec = make_eec(sub, leaf_dn(ctx))
    return ctx.cred([eec, sub, inter, root], eec)


def _signca_no_keycertsign(ctx):
    root = ctx.ca()
    inter = _sign_ca(root, ctx.dn("i"), _rsa(), keycert_sign=False)
    eec = make_eec(inter, leaf_dn(ctx))
    return ctx.cred([eec, inter, root], eec)


def _root_pathlen2_three(ctx):
    root = ctx.ca(path_length=2)
    i1 = _sign_ca(root, ctx.dn("i1"), _rsa())
    i2 = _sign_ca(i1, ctx.dn("i2"), _rsa())
    i3 = _sign_ca(i2, ctx.dn("i3"), _rsa())
    eec = make_eec(i3, leaf_dn(ctx))
    return ctx.cred([eec, i3, i2, i1, root], eec)


def _aki_match_no_ski(ctx):
    ca = ctx.ca()
    ski = ca.cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value.digest
    aki = x509.AuthorityKeyIdentifier(ski, None, None)
    eec = make_eec(ca, leaf_dn(ctx), skid=False, extra_ext=[(aki, False)])
    return ctx.cred([eec, ca], eec)


# --------------------------------------------------------------------------
# CLAUSES
# --------------------------------------------------------------------------
G = "sp_off_crl_off"
KU_NO_DS = {"digital_signature": False, "key_encipherment": True}
KU_NONE = {"digital_signature": False, "key_encipherment": False}
KU_KA = {"digital_signature": False, "key_encipherment": False,
         "key_agreement": True}
KU_CC = {"content_commitment": True}

CLAUSES = [
    # ---- basicConstraints ------------------------------------------------
    clause("CHN-001", "RFC5280 §4.2.1.9", "CA:TRUE intermediate issues EEC",
           "accept", _inter(), group=G,
           reason="valid CA below the trust anchor"),
    clause("CHN-002", "RFC5280 §6.1.4(k)", "CA:FALSE cert used as issuer",
           "reject", _ca_false_issuer, group=G,
           reason="issuer lacks basicConstraints CA:TRUE"),
    clause("CHN-003", "RFC5280 §6.1.4(m)", "issuer with no basicConstraints",
           "reject", _no_bc_issuer, group=G,
           reason="a cert without CA:TRUE may not act as a CA"),
    clause("CHN-004", "RFC5280 §4.2.1.9", "non-critical basicConstraints on CA",
           "accept", _bc_noncrit_ca, group=G,
           reason="CA SHOULD mark BC critical, but §6.1.4 still validates it"),
    clause("CHN-005", "RFC5280 §4.2.1.9", "pathLen=0 CA issues EEC directly",
           "accept", _pathlen0_direct, group=G,
           reason="pathLen 0 permits end-entity certs, no subordinate CA"),
    clause("CHN-006", "RFC5280 §6.1.4(m)", "pathLen=0 CA issues a sub-CA",
           "reject", _pathlen0_subca, group=G,
           reason="a CA follows a pathLen-0 CA in the path"),
    clause("CHN-007", "RFC5280 §4.2.1.9", "pathLen=1 with one sub-CA",
           "accept", _pathlen1_one, group=G,
           reason="exactly one CA below a pathLen-1 CA"),
    clause("CHN-008", "RFC5280 §6.1.4(m)", "pathLen=1 with two sub-CAs",
           "reject", _pathlen1_two, group=G,
           reason="two CAs below a pathLen-1 CA exceeds the constraint"),
    clause("CHN-009", "RFC5280 §4.2.1.9", "pathLen=2 with two sub-CAs",
           "accept", _pathlen2_two, group=G,
           reason="two CAs below a pathLen-2 CA is within budget"),
    clause("CHN-010", "RFC5280 §6.1.4(m)", "pathLen=2 with three sub-CAs",
           "reject", _pathlen2_three, group=G,
           reason="three CAs below a pathLen-2 CA exceeds the constraint"),
    clause("CHN-011", "RFC5280 §4.2.1.9", "pathLen=3 chain fully within budget",
           "accept", _pathlen3_three, group=G,
           reason="descending pathLen 3/2/1/0 chain is legal"),
    clause("CHN-012", "RFC5280 §6.1.4(m)", "root pathLen=0 with an intermediate",
           "reject", _root_pathlen0_inter, group=G,
           reason="root permits zero intermediates"),
    clause("CHN-013", "RFC5280 §4.2.1.9", "root pathLen=0 issues EEC directly",
           "accept", _root_pathlen0_direct, group=G,
           reason="no intermediate present, constraint satisfied"),
    clause("CHN-014", "RFC5280 §4.2.1.9", "root pathLen=1 with one intermediate",
           "accept", _root_pathlen1_inter, group=G,
           reason="single intermediate within pathLen 1"),
    clause("CHN-015", "RFC5280 §6.1.4(m)", "root pathLen=1 with two intermediates",
           "reject", _root_pathlen1_two, group=G,
           reason="two intermediates exceed root pathLen 1"),
    clause("CHN-016", "RFC5280 §4.2.1.9", "root pathLen=2 with two intermediates",
           "accept", _root_pathlen2_two, group=G,
           reason="two intermediates within root pathLen 2"),
    clause("CHN-017", "RFC5280 §4.2.1.9", "leaf asserting CA:TRUE used as EE",
           "accept", _eec(ca_true=True, keycert_sign=False), group=G,
           reason="a CA cert may still be presented as an end entity"),

    # ---- keyUsage --------------------------------------------------------
    clause("CHN-018", "RFC5280 §4.2.1.3", "EEC keyUsage digitalSignature present",
           "accept", _eec(), group=G,
           reason="baseline TLS client cert"),
    clause("CHN-019", "RFC5280 §4.2.1.3", "EEC keyUsage without digitalSignature",
           "reject", _eec(key_usage=KU_NO_DS), group=G,
           reason="TLS client auth requires digitalSignature; likely divergence"
                  " — OpenSSL does not enforce client KU by default"),
    clause("CHN-020", "RFC5280 §4.2.1.3", "EEC keyUsage all-bits-clear",
           "reject", _eec(key_usage=KU_NONE), group=G,
           reason="no usage bit permits TLS authentication"),
    clause("CHN-021", "RFC5280 §4.2.1.3", "EEC keyUsage keyAgreement only (EC)",
           "accept", _eec(key_usage=KU_KA, key_type="ec"), group=G,
           reason="keyAgreement satisfies ECDHE client authentication"),
    clause("CHN-022", "RFC5280 §4.2.1.3", "EEC keyUsage extension absent",
           "accept", _eec(with_key_usage=False), group=G,
           reason="absent keyUsage imposes no restriction"),
    clause("CHN-023", "RFC5280 §4.2.1.3", "EEC digitalSignature + contentCommitment",
           "accept", _eec(key_usage=KU_CC), group=G,
           reason="extra nonRepudiation bit does not forbid client auth"),
    clause("CHN-024", "RFC5280 §4.2.1.3", "issuing CA lacks keyCertSign",
           "reject", _ca_no_keycertsign, group=G,
           reason="keyUsage present without keyCertSign forbids signing certs"),
    clause("CHN-025", "RFC5280 §4.2.1.3", "issuing CA lacks cRLSign only",
           "accept", _ca_no_crlsign, group=G,
           reason="cRLSign is irrelevant with CRL checking off"),
    clause("CHN-026", "RFC5280 §4.2.1.3", "issuing CA has no keyUsage extension",
           "accept", _ca_no_ku, group=G,
           reason="absent keyUsage leaves the CA unrestricted"),
    clause("CHN-027", "RFC5280 §4.2.1.3", "issuing CA keyUsage non-critical",
           "accept", _ca_ku_noncrit, group=G,
           reason="keyCertSign present; criticality does not block validation"),
    clause("CHN-028", "RFC5280 §4.2.1.3", "root lacks keyCertSign",
           "reject", _root({"keycert_sign": False}), group=G,
           reason="trust anchor keyUsage forbids signing certs"),

    # ---- extendedKeyUsage ------------------------------------------------
    clause("CHN-029", "RFC5280 §4.2.1.12", "EEC EKU clientAuth present",
           "accept", _eec(eku=[CLIENT_AUTH]), group=G,
           reason="clientAuth is the correct purpose"),
    clause("CHN-030", "RFC5280 §4.2.1.12", "EEC EKU serverAuth only",
           "reject", _eec(eku=[SERVER_AUTH]), group=G,
           reason="serverAuth alone does not permit client auth; divergence risk"),
    clause("CHN-031", "RFC5280 §4.2.1.12", "EEC EKU anyExtendedKeyUsage",
           "accept", _eec(eku=[ANY_EKU]), group=G,
           reason="anyEKU permits every purpose"),
    clause("CHN-032", "RFC5280 §4.2.1.12", "EEC EKU emailProtection only",
           "reject", _eec(eku=[EMAIL_PROT]), group=G,
           reason="emailProtection forbids TLS client auth"),
    clause("CHN-033", "RFC5280 §4.2.1.12", "EEC EKU clientAuth + serverAuth",
           "accept", _eec(eku=[CLIENT_AUTH, SERVER_AUTH]), group=G,
           reason="clientAuth present among the purposes"),
    clause("CHN-034", "RFC5280 §4.2.1.12", "EEC EKU codeSigning only",
           "reject", _eec(eku=[CODE_SIGN]), group=G,
           reason="codeSigning forbids TLS client auth"),
    clause("CHN-035", "RFC5280 §4.2.1.12", "EEC EKU clientAuth + anyEKU",
           "accept", _eec(eku=[CLIENT_AUTH, ANY_EKU]), group=G,
           reason="clientAuth explicitly present"),
    clause("CHN-036", "RFC5280 §4.2.1.12", "EEC no EKU extension",
           "accept", _eec(eku=None), group=G,
           reason="absent EKU imposes no purpose restriction"),
    clause("CHN-037", "RFC5280 §4.2.1.12", "EEC EKU OCSPSigning only",
           "reject", _eec(eku=[OCSP_SIGN]), group=G,
           reason="OCSPSigning forbids TLS client auth"),
    clause("CHN-038", "RFC5280 §4.2.1.12", "EEC EKU timeStamping only",
           "reject", _eec(eku=[TIME_STAMP]), group=G,
           reason="timeStamping forbids TLS client auth"),
    clause("CHN-039", "RFC5280 §4.2.1.12", "intermediate EKU clientAuth, EEC clientAuth",
           "accept", _inter_eku([CLIENT_AUTH], [CLIENT_AUTH]), group=G,
           reason="EKU nesting consistent along the path"),
    clause("CHN-040", "RFC5280 §4.2.1.12", "intermediate EKU serverAuth, EEC clientAuth",
           "reject", _inter_eku([SERVER_AUTH], [CLIENT_AUTH]), group=G,
           reason="issuing CA does not delegate clientAuth"),
    clause("CHN-041", "RFC5280 §4.2.1.12", "EEC critical EKU clientAuth",
           "accept", _crit_eku([CLIENT_AUTH]), group=G,
           reason="critical EKU naming the correct purpose"),
    clause("CHN-042", "RFC5280 §4.2.1.12", "EEC critical EKU unknown OID only",
           "reject", _crit_eku([UNK_EKU]), group=G,
           reason="critical EKU excludes clientAuth"),

    # ---- AKI / SKI -------------------------------------------------------
    clause("CHN-043", "RFC5280 §4.2.1.1", "EEC AKI keyid matches issuer SKI",
           "accept", _aki("match"), group=G,
           reason="authorityKeyIdentifier resolves the issuer"),
    clause("CHN-044", "RFC5280 §4.2.1.1", "EEC AKI keyid mismatched, issuer findable",
           "accept", _aki("mismatch"), group=G,
           reason="issuer still resolved by name + signature; AKI is a hint"),
    clause("CHN-045", "RFC5280 §4.2.1.1", "EEC AKI by issuer name + serial",
           "accept", _aki("issuer_serial"), group=G,
           reason="issuer identified by DirName + serial"),
    clause("CHN-046", "RFC5280 §4.2.1.1", "EEC AKI issuer name with wrong serial",
           "accept", _aki("issuer_serial_bad"), group=G,
           reason="name-based build still succeeds despite AKI serial mismatch"),
    clause("CHN-047", "RFC5280 §4.2.1.2", "EEC subjectKeyIdentifier present",
           "accept", _eec(skid=True), group=G,
           reason="SKI present, optional on end entities"),
    clause("CHN-048", "RFC5280 §4.2.1.2", "EEC subjectKeyIdentifier absent",
           "accept", _eec(skid=False), group=G,
           reason="SKI is optional on end-entity certs"),
    clause("CHN-049", "RFC5280 §6.1", "wrong-issuer EEC (issuer not in store)",
           "reject", _wrong_issuer, group=G,
           reason="no trust anchor matches the issuer DN"),
    clause("CHN-050", "RFC5280 §6.1", "self-signed leaf presented as EEC",
           "reject", _selfsigned_leaf, group=G,
           reason="self-signed leaf is not a configured trust anchor"),

    # ---- validity --------------------------------------------------------
    clause("CHN-051", "RFC5280 §4.1.2.5", "valid EEC within window",
           "accept", _eec(), group=G, reason="baseline valid window"),
    clause("CHN-052", "RFC5280 §4.1.2.5", "long-lived EEC",
           "accept", _eec(not_after_days=7300), group=G,
           reason="notAfter far in the future is still valid now"),
    clause("CHN-053", "RFC5280 §4.1.2.5", "notBefore in the recent past",
           "accept", _eec(not_before_days=-30), group=G,
           reason="active validity window"),
    clause("CHN-054", "RFC5280 §4.1.2.5", "expired EEC (notAfter < epoch)",
           "reject", _eec(not_after_days=-1), group=G,
           reason="notAfter has passed"),
    clause("CHN-055", "RFC5280 §4.1.2.5", "expired EEC (notAfter mid-January)",
           "reject", _eec(not_after_days=30), group=G,
           reason="notAfter precedes current date"),
    clause("CHN-056", "RFC5280 §4.1.2.5", "not-yet-valid EEC",
           "reject", _eec(not_before_days=300, not_after_days=3650), group=G,
           reason="notBefore is in the future"),
    clause("CHN-057", "RFC5280 §4.1.2.5", "far-future not-yet-valid EEC",
           "reject", _eec(not_before_days=1000, not_after_days=3650), group=G,
           reason="notBefore well beyond current date"),
    clause("CHN-058", "RFC5280 §4.1.2.5", "EEC notBefore > notAfter",
           "reject", _inverted_validity, group=G,
           reason="inverted validity interval is never valid"),
    clause("CHN-059", "RFC5280 §4.1.2.5", "expired intermediate CA",
           "reject", _inter(inter_kw={"not_after_days": -1}), group=G,
           reason="intermediate notAfter has passed"),
    clause("CHN-060", "RFC5280 §4.1.2.5", "not-yet-valid intermediate CA",
           "reject", _inter(inter_kw={"not_before_days": 300,
                                      "not_after_days": 3650}), group=G,
           reason="intermediate notBefore is in the future"),
    clause("CHN-061", "RFC5280 §4.1.2.5", "expired root CA",
           "reject", _root({"not_after_days": -1}), group=G,
           reason="trust anchor notAfter has passed"),
    clause("CHN-062", "RFC5280 §4.1.2.5", "not-yet-valid root CA",
           "reject", _root({"not_before_days": 300, "not_after_days": 3650}),
           group=G, reason="trust anchor notBefore is in the future"),

    # ---- serial number ---------------------------------------------------
    clause("CHN-063", "RFC5280 §4.1.2.2", "serial = 1 (minimal positive)",
           "accept", _serial(b"\x01"), group=G,
           reason="smallest legal positive serial"),
    clause("CHN-064", "RFC5280 §4.1.2.2", "serial 20 octets (maximal)",
           "accept", _serial(b"\x7f" + b"\xaa" * 19), group=G,
           reason="positive 20-octet serial is within the RFC ceiling"),
    clause("CHN-065", "RFC5280 §4.1.2.2", "serial = 0",
           "reject", _serial(b"\x00"), group=G,
           reason="serial MUST be positive; OpenSSL tolerates it — divergence"),
    clause("CHN-066", "RFC5280 §4.1.2.2", "serial negative (-1)",
           "reject", _serial(b"\xff"), group=G,
           reason="negative serial violates §4.1.2.2; likely accepted today"),
    clause("CHN-067", "RFC5280 §4.1.2.2", "serial 21 octets (over 20-octet ceiling)",
           "reject", _serial(b"\x7f" + b"\xaa" * 20), group=G,
           reason="serial exceeds 20 octets"),
    clause("CHN-068", "X.690 §8.3.2", "serial with non-minimal leading zeros",
           "reject", _serial(b"\x00\x00\x01"), surface="c-oracle", group=G,
           reason="DER INTEGER must use the minimum number of octets"),

    # ---- signature algorithm ---------------------------------------------
    clause("CHN-069", "RFC5280 §4.1.1.2", "EEC signed with SHA-256",
           "accept", _eec(digest_name="sha256"), group=G,
           reason="SHA-256 is a compliant signature hash"),
    clause("CHN-070", "RFC5280 §4.1.1.2", "EEC signed with SHA-384",
           "accept", _eec(digest_name="sha384"), group=G,
           reason="SHA-384 is a compliant signature hash"),
    clause("CHN-071", "RFC5280 §4.1.1.2", "EEC signed with SHA-512",
           "accept", _eec(digest_name="sha512"), group=G,
           reason="SHA-512 is a compliant signature hash"),
    clause("CHN-072", "IGTF weak-alg", "EEC signed with SHA-1",
           "reject", _eec(digest_name="sha1"), group=G,
           reason="SHA-1 signatures are deprecated / rejected by IGTF policy"),
    clause("CHN-073", "IGTF weak-alg", "EEC signed with MD5",
           "reject", _eec(digest_name="md5"), group=G,
           reason="MD5 signatures are broken and rejected"),
    clause("CHN-074", "RFC5280 §4.1.1.2", "intermediate signed with SHA-256",
           "accept", _inter(inter_kw={"digest_name": "sha256"}), group=G,
           reason="compliant intermediate signature"),
    clause("CHN-075", "IGTF weak-alg", "intermediate signed with SHA-1",
           "reject", _inter(inter_kw={"digest_name": "sha1"}), group=G,
           reason="SHA-1 intermediate signature is deprecated"),
    clause("CHN-076", "IGTF weak-alg", "intermediate signed with MD5",
           "reject", _inter(inter_kw={"digest_name": "md5"}), group=G,
           reason="MD5 intermediate signature is broken"),
    clause("CHN-077", "RFC5280 §4.1.1.2", "root self-signed with SHA-512",
           "accept", _root({"digest_name": "sha512"}), group=G,
           reason="strong self-signature on the trust anchor"),
    clause("CHN-078", "IGTF weak-alg", "root self-signed with SHA-1",
           "reject", _root({"digest_name": "sha1"}), group=G,
           reason="SHA-1 trust-anchor self-signature is deprecated"),
    clause("CHN-079", "RFC5280 §4.1.1.2", "root self-signed with SHA-384",
           "accept", _root({"digest_name": "sha384"}), group=G,
           reason="strong self-signature on the trust anchor"),

    # ---- key type / strength --------------------------------------------
    clause("CHN-080", "IGTF key-size", "EEC RSA-2048 key",
           "accept", _eec(key_bits=2048), group=G,
           reason="meets the 2048-bit RSA floor"),
    clause("CHN-081", "IGTF key-size", "EEC RSA-3072 key",
           "accept", _eec(key_bits=3072), group=G,
           reason="above the RSA floor"),
    clause("CHN-082", "IGTF key-size", "EEC RSA-4096 key",
           "accept", _eec(key_bits=4096), group=G,
           reason="above the RSA floor"),
    clause("CHN-083", "IGTF key-size", "EEC RSA-1024 key",
           "reject", _eec(key_bits=1024), group=G,
           reason="below the 2048-bit RSA floor"),
    clause("CHN-084", "IGTF key-size", "EEC RSA-512 key",
           "reject", _eec(key_bits=512), group=G,
           reason="far below the RSA floor; also below OpenSSL seclevel"),
    clause("CHN-085", "IGTF key-size", "EEC EC P-256 key",
           "accept", _eec(key_type="ec", curve="P-256"), group=G,
           reason="P-256 meets the EC floor"),
    clause("CHN-086", "IGTF key-size", "EEC EC P-384 key",
           "accept", _eec(key_type="ec", curve="P-384"), group=G,
           reason="P-384 above the EC floor"),
    clause("CHN-087", "IGTF key-size", "EEC EC P-521 key",
           "accept", _eec(key_type="ec", curve="P-521"), group=G,
           reason="P-521 above the EC floor"),
    clause("CHN-088", "IGTF key-size", "intermediate RSA-1024 key",
           "reject", _inter_key({"key_bits": 1024}), group=G,
           reason="weak intermediate key below the RSA floor"),
    clause("CHN-089", "IGTF key-size", "intermediate RSA-4096 key",
           "accept", _inter_key({"key_bits": 4096}), group=G,
           reason="strong intermediate key"),
    clause("CHN-090", "IGTF key-size", "intermediate EC P-256 key",
           "accept", _inter_key({"key_type": "ec", "curve": "P-256"}), group=G,
           reason="EC intermediate signing an RSA EEC"),
    clause("CHN-091", "IGTF key-size", "root EC P-256 key",
           "accept", _root({"key_type": "ec", "curve": "P-256"}), group=G,
           reason="EC trust anchor over the EC floor"),
    clause("CHN-092", "IGTF key-size", "root EC P-384 key",
           "accept", _root({"key_type": "ec", "curve": "P-384"}), group=G,
           reason="EC trust anchor over the EC floor"),
    clause("CHN-093", "IGTF key-size", "root RSA-4096 key",
           "accept", _root({"key_bits": 4096}), group=G,
           reason="strong RSA trust anchor"),
    clause("CHN-094", "IGTF key-size", "root RSA-1024 key",
           "reject", _root({"key_bits": 1024}), group=G,
           reason="trust anchor below the RSA floor"),

    # ---- unknown critical / non-critical extensions ----------------------
    clause("CHN-095", "RFC5280 §4.2", "EEC unknown critical extension",
           "reject", _unknown_ext_eec(True), group=G,
           reason="an unrecognized critical extension MUST be rejected"),
    clause("CHN-096", "RFC5280 §4.2", "EEC unknown non-critical extension",
           "accept", _unknown_ext_eec(False), group=G,
           reason="an unrecognized non-critical extension is ignored"),
    clause("CHN-097", "RFC5280 §4.2", "intermediate unknown critical extension",
           "reject", _unknown_ext_inter(True), group=G,
           reason="unrecognized critical extension on a CA in the path"),
    clause("CHN-098", "RFC5280 §4.2", "intermediate unknown non-critical extension",
           "accept", _unknown_ext_inter(False), group=G,
           reason="unrecognized non-critical extension is ignored"),

    # ---- chain depth -----------------------------------------------------
    clause("CHN-099", "RFC5280 §6.1", "two-intermediate chain within depth",
           "accept", _chain_depth(2), group=G,
           reason="short chain within the configured verify depth"),
    clause("CHN-100", "RFC5280 §6.1", "four-intermediate chain within depth",
           "accept", _chain_depth(4), group=G,
           reason="moderate chain within the configured verify depth"),
    clause("CHN-101", "RFC5280 §6.1", "fourteen-intermediate chain over depth",
           "reject", _chain_depth(14), group=G,
           reason="chain exceeds ssl_verify_depth; depends on fleet config"),

    # ---- structural failure & cross-signing ------------------------------
    clause("CHN-102", "RFC5280 §6.1.3", "tampered signature on EEC",
           "reject", _tampered, group=G,
           reason="signatureValue no longer verifies against the issuer key"),
    clause("CHN-103", "X.690", "truncated DER certificate",
           "reject", _truncated, surface="c-oracle", group=G,
           reason="half a certificate fails to parse before the wire"),
    clause("CHN-104", "RFC5280 §6.1", "cross-signed EEC via root A path",
           "accept", _cross("A"), group=G,
           reason="intermediate cross-certified by root A resolves the chain"),
    clause("CHN-105", "RFC5280 §6.1", "cross-signed EEC via root B path",
           "accept", _cross("B"), group=G,
           reason="same intermediate key cross-certified by root B also resolves"),
    clause("CHN-106", "RFC5280 §6.1.3", "issuer DN collision, wrong signing key",
           "reject", _issuer_dn_collision, group=G,
           reason="EEC issuer DN matches the anchor but signature is a rogue key's"),

    # ---- extra basicConstraints / pathLen coverage -----------------------
    clause("CHN-107", "RFC5280 §4.2.1.9", "non-critical BC pathLen=0 issues EEC",
           "accept", _bc_noncrit_pathlen0_direct, group=G,
           reason="pathLen enforced regardless of BC criticality; direct EEC ok"),
    clause("CHN-108", "RFC5280 §6.1.4(m)", "non-critical BC pathLen=0 issues sub-CA",
           "reject", _bc_noncrit_pathlen0_subca, group=G,
           reason="pathLen 0 still forbids a subordinate CA"),
    clause("CHN-109", "RFC5280 §4.2.1.3", "intermediate keyCertSign cleared (helper)",
           "reject", _signca_no_keycertsign, group=G,
           reason="keyUsage present without keyCertSign forbids issuing certs"),
    clause("CHN-110", "RFC5280 §6.1.4(m)", "root pathLen=2 with three intermediates",
           "reject", _root_pathlen2_three, group=G,
           reason="three intermediates exceed root pathLen 2"),
    clause("CHN-111", "RFC5280 §6.1", "five-intermediate chain within depth",
           "accept", _chain_depth(5), group=G,
           reason="chain within the configured verify depth"),
    clause("CHN-112", "RFC5280 §6.1", "eight-intermediate chain within depth",
           "accept", _chain_depth(8), group=G,
           reason="deep-but-legal chain within verify depth"),

    # ---- extra keyUsage / EKU coverage -----------------------------------
    clause("CHN-113", "RFC5280 §4.2.1.3", "EEC digitalSignature + dataEncipherment",
           "accept", _eec(key_usage={"data_encipherment": True}), group=G,
           reason="digitalSignature present alongside dataEncipherment"),
    clause("CHN-114", "RFC5280 §4.2.1.3", "EEC digitalSignature + keyAgreement (EC)",
           "accept", _eec(key_type="ec",
                          key_usage={"key_agreement": True}), group=G,
           reason="digitalSignature retained, keyAgreement added"),
    clause("CHN-115", "RFC5280 §4.2.1.12", "EEC critical EKU clientAuth + serverAuth",
           "accept", _crit_eku([CLIENT_AUTH, SERVER_AUTH]), group=G,
           reason="critical EKU still names clientAuth"),
    clause("CHN-116", "RFC5280 §4.2.1.12", "EEC EKU emailProtection + clientAuth",
           "accept", _eec(eku=[EMAIL_PROT, CLIENT_AUTH]), group=G,
           reason="clientAuth present among purposes"),
    clause("CHN-117", "RFC5280 §4.2.1.12", "EEC EKU codeSigning + clientAuth",
           "accept", _eec(eku=[CODE_SIGN, CLIENT_AUTH]), group=G,
           reason="clientAuth present among purposes"),
    clause("CHN-118", "RFC5280 §4.2.1.12", "intermediate EKU anyEKU, EEC clientAuth",
           "accept", _inter_eku([ANY_EKU], [CLIENT_AUTH]), group=G,
           reason="anyEKU on the CA delegates every purpose"),

    # ---- extra AKI / unknown-extension coverage --------------------------
    clause("CHN-119", "RFC5280 §4.2.1.1", "EEC AKI matches, SKI absent",
           "accept", _aki_match_no_ski, group=G,
           reason="issuer resolved by AKI keyid without a subject SKI"),
    clause("CHN-120", "RFC5280 §4.2", "EEC second unknown critical extension OID",
           "reject", _unknown_ext_eec2, group=G,
           reason="a different unrecognized critical extension still rejects"),
    clause("CHN-121", "RFC5280 §4.2", "EEC two unknown non-critical extensions",
           "accept", _two_noncrit_ext, group=G,
           reason="multiple unrecognized non-critical extensions are ignored"),

    # ---- extra validity / algorithm / key coverage -----------------------
    clause("CHN-122", "RFC5280 §4.1.2.5", "EEC one-year validity window",
           "accept", _eec(not_after_days=365), group=G,
           reason="ordinary one-year end-entity lifetime"),
    clause("CHN-123", "RFC5280 §4.1.2.5", "intermediate expired mid-January",
           "reject", _inter(inter_kw={"not_after_days": 30}), group=G,
           reason="intermediate notAfter precedes current date"),
    clause("CHN-124", "RFC5280 §4.1.2.5", "root one-year-old still valid",
           "accept", _root({"not_before_days": -180, "not_after_days": 3650}),
           group=G, reason="trust anchor within its validity window"),
    clause("CHN-125", "RFC5280 §4.1.1.2", "EEC EC P-256 signed SHA-384",
           "accept", _eec(key_type="ec", curve="P-256", digest_name="sha384"),
           group=G, reason="ECDSA/SHA-384 is compliant"),
    clause("CHN-126", "RFC5280 §4.1.1.2", "EEC EC P-384 signed SHA-512",
           "accept", _eec(key_type="ec", curve="P-384", digest_name="sha512"),
           group=G, reason="ECDSA/SHA-512 is compliant"),
    clause("CHN-127", "RFC5280 §4.1.1.2", "EEC RSA-2048 signed SHA-512",
           "accept", _eec(key_bits=2048, digest_name="sha512"), group=G,
           reason="RSA/SHA-512 is compliant"),
    clause("CHN-128", "RFC5280 §4.1.1.2", "intermediate signed SHA-384",
           "accept", _inter(inter_kw={"digest_name": "sha384"}), group=G,
           reason="strong intermediate signature"),
    clause("CHN-129", "IGTF key-size", "intermediate EC P-384 key",
           "accept", _inter_key({"key_type": "ec", "curve": "P-384"}), group=G,
           reason="EC P-384 intermediate above the EC floor"),
    clause("CHN-130", "IGTF key-size", "root EC P-521 key",
           "accept", _root({"key_type": "ec", "curve": "P-521"}), group=G,
           reason="EC P-521 trust anchor above the EC floor"),
    clause("CHN-131", "IGTF key-size", "EEC EC P-521 signed SHA-512",
           "accept", _eec(key_type="ec", curve="P-521", digest_name="sha512"),
           group=G, reason="P-521 with SHA-512 is compliant"),
    clause("CHN-132", "IGTF weak-alg", "EEC EC P-256 signed SHA-1",
           "reject", _eec(key_type="ec", curve="P-256", digest_name="sha1"),
           group=G, reason="SHA-1 ECDSA signature is deprecated"),
    clause("CHN-133", "RFC5280 §4.2.1.3", "root self-signed with SHA-256 baseline",
           "accept", _root({"digest_name": "sha256"}), group=G,
           reason="baseline compliant trust anchor"),
    clause("CHN-134", "RFC5280 §4.1.2.5", "EEC notBefore 180 days past",
           "accept", _eec(not_before_days=-180, not_after_days=3650), group=G,
           reason="well inside its validity window"),
    clause("CHN-135", "RFC5280 §4.2.1.9", "CA:TRUE intermediate, unlimited pathLen",
           "accept", _inter_key({"path_length": None}), group=G,
           reason="unconstrained-pathLen intermediate issuing an EEC"),
]

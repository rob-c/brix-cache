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



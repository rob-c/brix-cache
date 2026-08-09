"""signing_policy — Globus EACL / IGTF signing_policy conformance family (SPL).

One clause per row.  Each build(ctx) mints a uniquely-named CA into the shared
multi-CA dir, attaches a signing_policy (or deliberately omits/malforms one),
signs an EEC with a chosen subject DN, and returns the credential.  The server
group selects the enforcement mode (on/off/require); the EEC subject DN is what
the policy's cond_subjects globs are matched against.

Spec basis (expected is SPEC-FIRST, never bent to current code):
  * Globus EACL signing_policy grammar — access_id_CA / pos_rights /
    neg_rights / cond_subjects, single+double quoting, comments.
  * IGTF hashed-store discovery — <hash>.signing_policy via the new (SHA-1)
    or legacy (MD5) subject hash; fail-closed on malformed / wrong-CA files.
  * Glob semantics — '*' matches any run (INCLUDING '/'), '?' matches exactly
    one char, matching is case-insensitive and anchored at both ends.
  * Match surface — the OpenSSL X509_NAME_oneline slash DN ('/DC=a/CN=b'),
    where an embedded '/' renders '\\/' and non-ASCII bytes render '\\xNN'.

Everything runs on surface='davs' (the WebDAV x509 path evaluates signing_policy
during client-cert verification); an EEC out of the granted namespace fails the
handshake exactly like the smoke out-of-namespace clause.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import NameOID

import x509forge
from x509forge import (make_ca, make_eec, signing_policy_text,
                       _place_ca_in_dir, _openssl_hashes)
from clauses._helpers import clause

# --------------------------------------------------------------------------
# DN fixtures.  The CA namespace is /DC=test/DC=x509conf; a CA granting
# "<NS>/*" should sign anything under it.  EEC DNs are reused across clauses
# (each clause owns an isolated CA + creds file, so collisions are harmless).
# --------------------------------------------------------------------------

NS = "/DC=test/DC=x509conf"
ALICE = NS + "/CN=alice"

_ASN1 = x509.name._ASN1Type
_DC = [x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "test"),
       x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "x509conf")]


def _cn_name(cn, *, utf8=False):
    """A /DC=test/DC=x509conf/CN=<cn> Name, CN encoded UTF8 or PrintableString."""
    attr = (x509.NameAttribute(NameOID.COMMON_NAME, cn, _type=_ASN1.UTF8String)
            if utf8 else x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(_DC + [attr])


# --------------------------------------------------------------------------
# Build factories.  Each returns a fresh build(ctx) closure so rows stay
# one-liners while the CA/policy/credential wiring lives here.
# --------------------------------------------------------------------------

def _globs(policy_globs, subject_dn=ALICE):
    """CA whose signing_policy grants `policy_globs`; EEC subject = subject_dn."""
    def build(ctx):
        ca = ctx.ca(policy_globs=policy_globs)
        eec = make_eec(ca, subject_dn)
        return ctx.cred([eec, ca], eec)
    return build


def _globs_subj(policy_globs, name_obj):
    """As _globs but the EEC subject is a pre-built x509.Name (encoding tests)."""
    def build(ctx):
        ca = ctx.ca(policy_globs=policy_globs)
        eec = make_eec(ca, subject_name=name_obj)
        return ctx.cred([eec, ca], eec)
    return build


def _raw_policy(policy_fn, subject_dn=ALICE):
    """CA whose signing_policy is raw text from policy_fn(ca_dn) (grammar tests).

    Placed under this CA's real hash links, so discovery finds it by hash and
    only the block grammar / DN naming decides the verdict.
    """
    def build(ctx):
        ca_dn = ctx.dn()
        ca = make_ca(ca_dn)
        eec = make_eec(ca, subject_dn)
        _place_ca_in_dir(ctx.shared_ca, ca, name=ctx.clause.id,
                         policy_text=policy_fn(ca_dn))
        return ctx.cred([eec, ca], eec)
    return build


def _no_policy(subject_dn=ALICE):
    """CA placed with NO signing_policy file at all (absent-policy modes)."""
    def build(ctx):
        ca = ctx.ca()
        eec = make_eec(ca, subject_dn)
        return ctx.cred([eec, ca], eec)
    return build


def _policy_by_hash(which, subject_dn=ALICE):
    """In-namespace policy discoverable ONLY via the `which` subject hash.

    The CA cert carries both hash links (so OpenSSL finds it), but the policy
    file is written as a real <hash>.signing_policy for the selected hash(es)
    only — no non-hex-named copy, so DN-fallback cannot mask a hash miss.
    """
    def build(ctx):
        ca_dn = ctx.dn()
        ca = make_ca(ca_dn)
        eec = make_eec(ca, subject_dn)
        _place_ca_in_dir(ctx.shared_ca, ca, name=ctx.clause.id)   # cert links only
        new_h, old_h = _openssl_hashes(ctx.shared_ca / f"{ctx.clause.id}.pem")
        text = signing_policy_text(ca_dn, [NS + "/*"])
        sel = {"new": [new_h], "old": [old_h], "both": [new_h, old_h]}[which]
        for hh in dict.fromkeys(sel):
            (ctx.shared_ca / f"{hh}.signing_policy").write_text(text,
                                                               encoding="utf-8")
        return ctx.cred([eec, ca], eec)
    return build


def _policy_dn_fallback(subject_dn=ALICE):
    """Policy in a non-hex-named file; discoverable only by access_id_CA DN."""
    def build(ctx):
        ca_dn = ctx.dn()
        ca = make_ca(ca_dn)
        eec = make_eec(ca, subject_dn)
        _place_ca_in_dir(ctx.shared_ca, ca, name=ctx.clause.id)   # cert links only
        (ctx.shared_ca / f"{ctx.clause.id}-oddname.signing_policy").write_text(
            signing_policy_text(ca_dn, [NS + "/*"]), encoding="utf-8")
        return ctx.cred([eec, ca], eec)
    return build


# -- raw-policy-text builders (grammar / block structure) ------------------

def _pol_block(ca_dn, cond_value, *, rights="pos_rights"):
    """One access_id_CA block with a literal cond_subjects value region."""
    return (f"access_id_CA    X509    '{ca_dn}'\n"
            f"{rights}      globus  CA:sign\n"
            f"cond_subjects   globus  {cond_value}\n")


def _pol_double_quote_only(dn):
    return _pol_block(dn, f'"{NS}/*"')


def _pol_single_quote_only(dn):
    return _pol_block(dn, f"'{NS}/*'")


def _pol_bare(dn):
    return _pol_block(dn, f"{NS}/*")


def _pol_empty(dn):
    return _pol_block(dn, "''")


def _pol_no_value(dn):
    return (f"access_id_CA    X509    '{dn}'\n"
            f"pos_rights      globus  CA:sign\n"
            f"cond_subjects   globus\n")


def _pol_whitespace(dn):
    return _pol_block(dn, "'    '")


def _pol_unknown_directive(dn):
    return (signing_policy_text(dn, [NS + "/*"])
            + "bogus_directive globus   whatever\n")


def _pol_truncated_access_id(dn):
    return ("access_id_CA    X509\n"
            "pos_rights      globus  CA:sign\n"
            f"cond_subjects   globus  '\"{NS}/*\"'\n")


def _pol_rights_before_id(dn):
    return ("pos_rights      globus  CA:sign\n"
            f"access_id_CA    X509    '{dn}'\n"
            f"cond_subjects   globus  '\"{NS}/*\"'\n")


def _pol_cond_before_id(dn):
    return (f"cond_subjects   globus  '\"{NS}/*\"'\n"
            f"access_id_CA    X509    '{dn}'\n"
            "pos_rights      globus  CA:sign\n")


def _pol_comments_blanks(dn):
    return ("# IGTF-style signing_policy with comments and blank lines\n"
            "\n"
            f"access_id_CA    X509    '{dn}'\n"
            "   # granted rights below\n"
            "\n"
            "pos_rights      globus  CA:sign\n"
            f"cond_subjects   globus  '\"{NS}/*\"'\n"
            "\n")


def _pol_crlf(dn):
    return signing_policy_text(dn, [NS + "/*"]).replace("\n", "\r\n")


def _pol_indented(dn):
    return ("\t" f"access_id_CA    X509    '{dn}'\n"
            "    pos_rights      globus  CA:sign\n"
            f"\t cond_subjects   globus  '\"{NS}/*\"'\n")


def _pol_no_pos_rights(dn):
    return (f"access_id_CA    X509    '{dn}'\n"
            f"cond_subjects   globus  '\"{NS}/*\"'\n")


def _pol_tabs(dn):
    return (f"access_id_CA\tX509\t'{dn}'\n"
            "pos_rights\tglobus\tCA:sign\n"
            f"cond_subjects\tglobus\t'\"{NS}/*\"'\n")


def _pol_wrong_ca(dn):
    # File is placed under THIS CA's hash, but its block names a different CA.
    return signing_policy_text("/DC=test/DC=x509conf/CN=A Completely Other CA",
                               [NS + "/*"])


def _pol_multiblock_match(dn):
    return (_pol_block("/DC=test/DC=x509conf/CN=Unrelated CA", f'"{NS}/*"')
            + _pol_block(dn, f'"{NS}/*"'))


def _pol_multiblock_thisca_nomatch(dn):
    # Only THIS CA's block applies to us, and it does not match ALICE.
    return (_pol_block("/DC=test/DC=x509conf/CN=Unrelated CA", '"*"')
            + _pol_block(dn, '"/DC=test/DC=x509conf/CN=bob"'))


def _pol_multiblock_two_thisca(dn):
    # Two blocks for THIS CA; the first misses, the second matches (any-block).
    return (_pol_block(dn, '"/DC=test/DC=x509conf/CN=nobody"')
            + _pol_block(dn, f'"{NS}/*"'))


def _pol_neg_then_pos(dn):
    # neg_rights block is skipped; the independent pos_rights block grants.
    return (_pol_block(dn, f'"{NS}/*"', rights="neg_rights")
            + _pol_block(dn, f'"{NS}/*"', rights="pos_rights"))


def _pol_other_pos_this_neg(dn):
    # For THIS CA only the neg_rights block applies → nothing granted.
    return (_pol_block("/DC=test/DC=x509conf/CN=Other CA", '"*"',
                       rights="pos_rights")
            + _pol_block(dn, f'"{NS}/*"', rights="neg_rights"))

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "signing_policy_part2.py")

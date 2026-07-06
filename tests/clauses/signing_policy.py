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


def _pol_star_all(dn):
    return _pol_block(dn, '"*"')


# --------------------------------------------------------------------------
# Clause catalogue
# --------------------------------------------------------------------------

CLAUSES = [

    # ---- A: glob semantics -------------------------------------------------
    clause("SPL-001", "Globus EACL cond_subjects", "'*' matches whole subtree",
           "accept", _globs([NS + "/*"]), group="sp_on_crl_off",
           reason="namespace glob '<NS>/*' matches the EEC under it"),
    clause("SPL-002", "Globus EACL cond_subjects", "'*' crosses '/' separators",
           "accept", _globs(["/DC=test/*"]), group="sp_on_crl_off",
           reason="'*' spans DC=x509conf/CN=alice including the slashes"),
    clause("SPL-003", "Globus EACL cond_subjects", "leading '*' anchors on suffix",
           "accept", _globs(["*/CN=alice"]), group="sp_on_crl_off",
           reason="'*' absorbs the DC prefix, then /CN=alice matches"),
    clause("SPL-004", "Globus EACL cond_subjects", "exact literal DN matches",
           "accept", _globs([ALICE]), group="sp_on_crl_off",
           reason="glob equal to the full oneline DN is a literal match"),
    clause("SPL-005", "Globus EACL cond_subjects", "literal non-match rejected",
           "reject", _globs(["/DC=test/DC=x509conf/CN=bob"]),
           group="sp_on_crl_off", reason="CN=bob glob does not cover CN=alice"),
    clause("SPL-006", "Globus EACL glob anchoring", "prefix w/o '*' rejected",
           "reject", _globs([NS + "/CN=ali"]), group="sp_on_crl_off",
           reason="glob is anchored at both ends; DN is longer than the prefix"),
    clause("SPL-007", "Globus EACL glob anchoring", "prefix + '*' accepted",
           "accept", _globs([NS + "/CN=ali*"]), group="sp_on_crl_off",
           reason="'*' consumes the remaining 'ce' of alice"),
    clause("SPL-008", "Globus EACL glob anchoring", "missing leading anchor rejected",
           "reject", _globs(["DC=test/DC=x509conf/*"]), group="sp_on_crl_off",
           reason="pattern lacks the leading '/'; first char mismatch, no '*'"),
    clause("SPL-009", "Globus EACL glob anchoring", "prefix char mismatch rejected",
           "reject", _globs(["/XC=test/*"]), group="sp_on_crl_off",
           reason="'/XC' diverges from '/DC' before any '*' can rescue it"),
    clause("SPL-010", "Globus EACL cond_subjects", "'?' matches one char",
           "accept", _globs([NS + "/CN=alic?"]), group="sp_on_crl_off",
           reason="'?' matches the final 'e' of alice"),
    clause("SPL-011", "Globus EACL cond_subjects", "'?' matches EXACTLY one (excess)",
           "reject", _globs([NS + "/CN=alic?"], NS + "/CN=alicexx"),
           group="sp_on_crl_off", reason="'?' cannot absorb the trailing 'xx'"),
    clause("SPL-012", "Globus EACL cond_subjects", "'?' requires a char (deficit)",
           "reject", _globs([NS + "/CN=alice?"]), group="sp_on_crl_off",
           reason="no char remains for '?' after 'alice'"),
    clause("SPL-013", "Globus EACL cond_subjects", "'?' matches a '/' separator",
           "accept", _globs(["/DC=test?DC=x509conf/*"]), group="sp_on_crl_off",
           reason="Globus '?' has no FNM_PATHNAME; it matches the '/' after test"),
    clause("SPL-014", "IGTF signing_policy", "case-insensitive glob accepted",
           "accept", _globs(["/dc=test/dc=x509conf/*"]), group="sp_on_crl_off",
           reason="DN matching folds case; lower-case glob still matches"),
    clause("SPL-015", "IGTF signing_policy", "case-insensitive subject accepted",
           "accept", _globs([NS + "/*"], NS + "/CN=ALICE"), group="sp_on_crl_off",
           reason="upper-case subject folds to match the glob"),
    clause("SPL-016", "Globus EACL cond_subjects", "any-of multiple globs accepted",
           "accept", _globs(["/DC=other/*", NS + "/*"]), group="sp_on_crl_off",
           reason="second glob in the list matches"),
    clause("SPL-017", "Globus EACL cond_subjects", "no glob matches rejected",
           "reject", _globs(["/DC=other/*", "/DC=foo/*"]), group="sp_on_crl_off",
           reason="neither cond_subjects glob covers the EEC"),
    clause("SPL-018", "Globus EACL cond_subjects", "trailing '*' matches empty tail",
           "accept", _globs([ALICE + "*"]), group="sp_on_crl_off",
           reason="'*' after the full DN matches the empty remainder"),
    clause("SPL-019", "Globus EACL cond_subjects", "lone '*' matches everything",
           "accept", _globs(["*"]), group="sp_on_crl_off",
           reason="a single '*' grants the whole namespace"),
    clause("SPL-020", "Globus EACL cond_subjects", "consecutive '**' collapse",
           "accept", _globs([NS + "/**"]), group="sp_on_crl_off",
           reason="adjacent stars behave as one"),
    clause("SPL-021", "Globus EACL cond_subjects", "literal '-' and '_' matched",
           "accept", _globs([NS + "/CN=a-b_c"], NS + "/CN=a-b_c"),
           group="sp_on_crl_off", reason="non-wildcard punctuation is literal"),
    clause("SPL-022", "Globus EACL cond_subjects", "literal space in RDN matched",
           "accept", _globs([NS + "/CN=has space"], NS + "/CN=has space"),
           group="sp_on_crl_off", reason="oneline keeps the space; glob matches"),
    clause("SPL-023", "IGTF signing_policy", "access_id_CA DN case-folded",
           "accept", _raw_policy(lambda dn: signing_policy_text(dn.upper(),
                                                                [NS + "/*"])),
           group="sp_on_crl_off",
           reason="block CA DN differs only in case; strcasecmp still binds it"),
    clause("SPL-024", "Globus EACL glob anchoring", "inner '*' between fixed RDNs",
           "accept", _globs(["/DC=test/*/CN=alice"]), group="sp_on_crl_off",
           reason="'*' matches DC=x509conf, fixed anchors on both ends"),

    # ---- B: grammar / quoting / block structure ---------------------------
    clause("SPL-025", "Globus EACL grammar", "double-quoted glob (no outer quote)",
           "accept", _raw_policy(_pol_double_quote_only), group="sp_on_crl_off",
           reason="a lone double-quoted glob is collected"),
    clause("SPL-026", "Globus EACL grammar", "single-quoted glob, no inner double",
           "accept", _raw_policy(_pol_single_quote_only), group="sp_on_crl_off",
           reason="outer single-quote stripped, remainder is one bare glob"),
    clause("SPL-027", "Globus EACL grammar", "bare unquoted glob token",
           "accept", _raw_policy(_pol_bare), group="sp_on_crl_off",
           reason="trimmed remainder taken as a single glob"),
    clause("SPL-028", "Globus EACL grammar", "standard single+double quoting",
           "accept", _globs([NS + "/*"]), group="sp_on_crl_off",
           reason="canonical '\"glob\"' list form"),
    clause("SPL-029", "Globus EACL cond_subjects", "empty cond_subjects grants nothing",
           "reject", _raw_policy(_pol_empty), group="sp_on_crl_off",
           reason="no globs → subject can never match → reject"),
    clause("SPL-030", "Globus EACL cond_subjects", "cond_subjects with no value",
           "reject", _raw_policy(_pol_no_value), group="sp_on_crl_off",
           reason="empty value region → zero globs → reject"),
    clause("SPL-031", "Globus EACL neg_rights", "neg_rights block grants nothing",
           "reject",
           _raw_policy(lambda dn: signing_policy_text(dn, [NS + "/*"],
                                                      granted=False)),
           group="sp_on_crl_off",
           reason="a denied block is skipped; nothing else grants → reject"),
    clause("SPL-032", "IGTF signing_policy fail-closed", "unknown directive rejected",
           "reject", _raw_policy(_pol_unknown_directive), group="sp_on_crl_off",
           reason="unparseable line fails the whole file closed"),
    clause("SPL-033", "IGTF signing_policy fail-closed", "truncated access_id_CA rejected",
           "reject", _raw_policy(_pol_truncated_access_id), group="sp_on_crl_off",
           reason="access_id_CA without a quoted DN fails to parse → fail closed"),
    clause("SPL-034", "Globus EACL grammar", "pos_rights before access_id_CA rejected",
           "reject", _raw_policy(_pol_rights_before_id), group="sp_on_crl_off",
           reason="rights outside a block is a grammar error → fail closed"),
    clause("SPL-035", "Globus EACL grammar", "cond_subjects before access_id_CA rejected",
           "reject", _raw_policy(_pol_cond_before_id), group="sp_on_crl_off",
           reason="cond_subjects outside a block is a grammar error → fail closed"),
    clause("SPL-036", "IGTF signing_policy", "comments and blank lines tolerated",
           "accept", _raw_policy(_pol_comments_blanks), group="sp_on_crl_off",
           reason="'#' comments and blank lines are ignored"),
    clause("SPL-037", "IGTF signing_policy", "CRLF line endings tolerated",
           "accept", _raw_policy(_pol_crlf), group="sp_on_crl_off",
           reason="trailing '\\r' is stripped per line"),
    clause("SPL-038", "IGTF signing_policy", "indented directives tolerated",
           "accept", _raw_policy(_pol_indented), group="sp_on_crl_off",
           reason="leading whitespace before a keyword is skipped"),
    clause("SPL-039", "Globus EACL pos_rights", "block without pos_rights not granted",
           "reject", _raw_policy(_pol_no_pos_rights), group="sp_on_crl_off",
           reason="no pos_rights → block never grants → reject"),
    clause("SPL-040", "Globus EACL multi-block", "matching this-CA block accepted",
           "accept", _raw_policy(_pol_multiblock_match), group="sp_on_crl_off",
           reason="the block naming this CA grants the namespace"),
    clause("SPL-041", "Globus EACL multi-block", "only-other-CA match rejected",
           "reject", _raw_policy(_pol_multiblock_thisca_nomatch),
           group="sp_on_crl_off",
           reason="the '*' block names a different CA; our block misses"),
    clause("SPL-042", "Globus EACL multi-block", "any-of two this-CA blocks accepted",
           "accept", _raw_policy(_pol_multiblock_two_thisca), group="sp_on_crl_off",
           reason="second block for this CA matches (blocks are OR-ed)"),

    # ---- C: DN matching / encoding ----------------------------------------
    clause("SPL-043", "RFC5280 §4.1.2.6 / oneline", "UTF8String ASCII value matched",
           "accept", _globs_subj([NS + "/*"], _cn_name("alice", utf8=True)),
           group="sp_on_crl_off",
           reason="oneline of an ASCII UTF8String equals the PrintableString form"),
    clause("SPL-044", "RFC5280 §4.1.2.6 / oneline", "PrintableString value matched",
           "accept", _globs_subj([NS + "/*"], _cn_name("alice")),
           group="sp_on_crl_off", reason="baseline PrintableString oneline match"),
    clause("SPL-045", "X509_NAME_oneline escaping", "non-ASCII UTF8 under '*' matched",
           "accept", _globs_subj([NS + "/*"], _cn_name("Ünïcode",
                                                       utf8=True)),
           group="sp_on_crl_off",
           reason="'*' absorbs the '\\xNN'-escaped non-ASCII bytes"),
    clause("SPL-046", "X509_NAME_oneline escaping", "raw-unicode glob misses escaped DN",
           "reject", _globs_subj([NS + "/CN=Ünïcode"],
                                 _cn_name("Ünïcode", utf8=True)),
           group="sp_on_crl_off",
           reason="oneline renders '\\xC3\\x9C...'; a raw-UTF8 glob cannot match it"),
    clause("SPL-047", "X509_NAME_oneline escaping", "embedded '/' escaped glob matched",
           "accept", _globs_subj([NS + r"/CN=a\/b"],
                                 x509.Name(_DC + [x509.NameAttribute(
                                     NameOID.COMMON_NAME, "a/b")])),
           group="sp_on_crl_off",
           reason="oneline escapes the embedded slash to '\\/'; escaped glob matches"),
    clause("SPL-048", "X509_NAME_oneline escaping", "unescaped '/' glob misses embedded slash",
           "reject", _globs_subj([NS + "/CN=a/b"],
                                 x509.Name(_DC + [x509.NameAttribute(
                                     NameOID.COMMON_NAME, "a/b")])),
           group="sp_on_crl_off",
           reason="DN carries '\\/'; a bare '/' in the glob does not match it"),
    clause("SPL-049", "X509_NAME_oneline escaping", "embedded '+' escaped glob matched",
           "accept", _globs_subj([NS + r"/CN=a\+b"],
                                 x509.Name(_DC + [x509.NameAttribute(
                                     NameOID.COMMON_NAME, "a+b")])),
           group="sp_on_crl_off",
           reason="oneline escapes the '+' to '\\+'; escaped glob matches"),
    clause("SPL-050", "RFC5280 §4.1.2.6 RDN order", "matching-order glob accepted",
           "accept", _globs(["/CN=alice/*"], "/CN=alice/DC=x509conf/DC=test"),
           group="sp_on_crl_off",
           reason="glob follows the (reversed) RDN order of the subject"),
    clause("SPL-051", "RFC5280 §4.1.2.6 RDN order", "wrong-order glob rejected",
           "reject", _globs([NS + "/*"], "/CN=alice/DC=x509conf/DC=test"),
           group="sp_on_crl_off",
           reason="subject leads with /CN; the /DC-anchored glob cannot match"),
    clause("SPL-052", "X509_NAME_oneline escaping", "literal '*' in DN under '*'",
           "accept", _globs_subj([NS + "/*"],
                                 x509.Name(_DC + [x509.NameAttribute(
                                     NameOID.COMMON_NAME, "a*b")])),
           group="sp_on_crl_off",
           reason="a literal '*' in the value is covered by the wildcard glob"),

    # ---- D: discovery -----------------------------------------------------
    clause("SPL-053", "IGTF hashed store", "policy via new (SHA-1) hash only",
           "accept", _policy_by_hash("new"), group="sp_on_crl_off",
           reason="new-hash-named signing_policy is discovered"),
    clause("SPL-054", "IGTF hashed store", "policy via old (MD5) hash only",
           "accept", _policy_by_hash("old"), group="sp_on_crl_off",
           reason="legacy old-hash-named signing_policy is still discovered"),
    clause("SPL-055", "IGTF hashed store", "policy via both hash links",
           "accept", _policy_by_hash("both"), group="sp_on_crl_off",
           reason="both hash names resolve to the same CA policy"),
    clause("SPL-056", "IGTF signing_policy", "policy found by access_id_CA DN",
           "accept", _policy_dn_fallback(), group="sp_on_crl_off",
           reason="oddly-named file still binds via its access_id_CA DN"),
    clause("SPL-057", "IGTF signing_policy fail-closed", "wrong-CA block rejected (ON)",
           "reject", _raw_policy(_pol_wrong_ca), group="sp_on_crl_off",
           reason="file present under this CA's hash but names another CA"),
    clause("SPL-058", "brix signing_policy=on", "absent policy passes through (ON)",
           "accept", _no_policy(), group="sp_on_crl_off",
           reason="ON tolerates a CA with no signing_policy file"),
    clause("SPL-059", "brix signing_policy=require", "absent policy rejected (REQUIRE)",
           "reject", _no_policy(), group="sp_require_crl_off",
           reason="REQUIRE demands a signing_policy for every CA"),
    clause("SPL-060", "brix signing_policy=require", "in-namespace accepted (REQUIRE)",
           "accept", _globs([NS + "/*"]), group="sp_require_crl_off",
           reason="present + matching policy satisfies REQUIRE"),
    clause("SPL-061", "brix signing_policy=require", "out-of-namespace rejected (REQUIRE)",
           "reject", _globs([NS + "/*"], "/DC=evil/CN=mallory"),
           group="sp_require_crl_off",
           reason="subject outside the granted namespace"),
    clause("SPL-062", "brix signing_policy=on", "out-of-namespace rejected (ON)",
           "reject", _globs([NS + "/*"], "/DC=evil/CN=mallory"),
           group="sp_on_crl_off", reason="ON enforces when a policy is present"),
    clause("SPL-063", "brix signing_policy=on", "in-namespace accepted (ON)",
           "accept", _globs([NS + "/*"]), group="sp_on_crl_off",
           reason="present + matching policy accepts under ON"),
    clause("SPL-064", "IGTF signing_policy fail-closed", "wrong-CA block rejected (REQUIRE)",
           "reject", _raw_policy(_pol_wrong_ca), group="sp_require_crl_off",
           reason="present-but-wrong-CA is fatal under REQUIRE too"),

    # ---- E: modes matrix (present / absent / malformed x on/off/require) ---
    clause("SPL-065", "brix signing_policy=off", "OFF ignores in-namespace policy",
           "accept", _globs([NS + "/*"]), group="sp_off_crl_off",
           reason="OFF short-circuits before consulting the policy"),
    clause("SPL-066", "brix signing_policy=off", "OFF ignores out-of-namespace policy",
           "accept", _globs([NS + "/*"], "/DC=evil/CN=mallory"),
           group="sp_off_crl_off",
           reason="OFF accepts even a subject the policy would reject"),
    clause("SPL-067", "brix signing_policy=off", "OFF ignores malformed policy",
           "accept", _raw_policy(_pol_unknown_directive), group="sp_off_crl_off",
           reason="OFF never parses the table, so malformed is harmless"),
    clause("SPL-068", "brix signing_policy=off", "OFF accepts with no policy",
           "accept", _no_policy(), group="sp_off_crl_off",
           reason="OFF pass-through with absent policy"),
    clause("SPL-069", "brix signing_policy=on", "ON accepts present in-namespace",
           "accept", _globs([NS + "/*"]), group="sp_on_crl_off",
           reason="matrix: ON x present-in-ns"),
    clause("SPL-070", "brix signing_policy=on", "ON rejects present out-of-namespace",
           "reject", _globs([NS + "/*"], "/DC=evil/CN=mallory"),
           group="sp_on_crl_off", reason="matrix: ON x present-out-of-ns"),
    clause("SPL-071", "brix signing_policy=on", "ON rejects malformed policy",
           "reject", _raw_policy(_pol_unknown_directive), group="sp_on_crl_off",
           reason="matrix: ON x malformed → fail closed"),
    clause("SPL-072", "brix signing_policy=on", "ON accepts absent policy",
           "accept", _no_policy(), group="sp_on_crl_off",
           reason="matrix: ON x absent → pass-through"),
    clause("SPL-073", "brix signing_policy=require", "REQUIRE accepts present in-namespace",
           "accept", _globs([NS + "/*"]), group="sp_require_crl_off",
           reason="matrix: REQUIRE x present-in-ns"),
    clause("SPL-074", "brix signing_policy=require", "REQUIRE rejects present out-of-namespace",
           "reject", _globs([NS + "/*"], "/DC=evil/CN=mallory"),
           group="sp_require_crl_off", reason="matrix: REQUIRE x present-out-of-ns"),
    clause("SPL-075", "brix signing_policy=require", "REQUIRE rejects malformed policy",
           "reject", _raw_policy(_pol_unknown_directive),
           group="sp_require_crl_off", reason="matrix: REQUIRE x malformed"),
    clause("SPL-076", "brix signing_policy=require", "REQUIRE rejects absent policy",
           "reject", _no_policy(), group="sp_require_crl_off",
           reason="matrix: REQUIRE x absent → reject"),

    # ---- F: namespace realism + more glob edges ---------------------------
    clause("SPL-077", "IGTF namespace", "sub-OU namespace accepted",
           "accept", _globs([NS + "/OU=People/*"], NS + "/OU=People/CN=alice"),
           group="sp_on_crl_off", reason="EEC under the granted OU subtree"),
    clause("SPL-078", "IGTF namespace", "sibling OU rejected",
           "reject", _globs([NS + "/OU=People/*"], NS + "/OU=Robots/CN=bot"),
           group="sp_on_crl_off", reason="OU=Robots is outside OU=People/*"),
    clause("SPL-079", "IGTF namespace", "sibling DC namespace rejected",
           "reject", _globs([NS + "/*"], "/DC=test/DC=other/CN=alice"),
           group="sp_on_crl_off", reason="different DC subtree"),
    clause("SPL-080", "Globus EACL cond_subjects", "exact host DN accepted",
           "accept", _globs([NS + "/CN=host.example.org"],
                            NS + "/CN=host.example.org"),
           group="sp_on_crl_off", reason="literal host DN match"),
    clause("SPL-081", "Globus EACL glob anchoring", "trailing-slash prefix rejected",
           "reject", _globs([NS + "/"]), group="sp_on_crl_off",
           reason="'<NS>/' without '*' cannot match the longer DN"),
    clause("SPL-082", "Globus EACL cond_subjects", "'*' then fixed suffix accepted",
           "accept", _globs([NS + "/CN=*ice"]), group="sp_on_crl_off",
           reason="'*' matches 'al', suffix 'ice' anchors the end"),
    clause("SPL-083", "Globus EACL cond_subjects", "'*' then wrong suffix rejected",
           "reject", _globs([NS + "/CN=*XYZ"]), group="sp_on_crl_off",
           reason="alice does not end in XYZ"),
    clause("SPL-084", "Globus EACL cond_subjects", "run of '?' matches char run",
           "accept", _globs([NS + "/CN=?????"]), group="sp_on_crl_off",
           reason="five '?' match the five chars of 'alice'"),
    clause("SPL-085", "Globus EACL cond_subjects", "too-few '?' rejected",
           "reject", _globs([NS + "/CN=????"]), group="sp_on_crl_off",
           reason="four '?' cannot cover five-char 'alice'"),
    clause("SPL-086", "IGTF signing_policy", "mixed-case glob and anchors accepted",
           "accept", _globs(["/Dc=Test/dC=X509Conf/*"]), group="sp_on_crl_off",
           reason="case-folding makes the mixed-case anchors match"),
    clause("SPL-087", "brix signing_policy=on", "policy for other namespace rejects",
           "reject", _globs(["/DC=prod/DC=x509conf/*"]), group="sp_on_crl_off",
           reason="granted namespace does not include /DC=test"),
    clause("SPL-088", "Globus EACL cond_subjects", "'*' covers deep DN",
           "accept", _globs(["/DC=test/*"],
                            "/DC=test/DC=x509conf/OU=a/OU=b/CN=z"),
           group="sp_on_crl_off", reason="'*' spans multiple deeper RDNs"),
    clause("SPL-089", "Globus EACL glob anchoring", "wrong top RDN anchor rejected",
           "reject", _globs(["/O=Grid/*"]), group="sp_on_crl_off",
           reason="subject starts with /DC, not /O=Grid"),
    clause("SPL-090", "Globus EACL cond_subjects", "any-of includes matching star",
           "accept", _globs(["/DC=prod/*", "/DC=test/*"]), group="sp_on_crl_off",
           reason="the /DC=test/* alternative matches"),
    clause("SPL-091", "Globus EACL cond_subjects", "any-of all miss rejected",
           "reject", _globs(["/DC=prod/*", "/DC=dev/*"]), group="sp_on_crl_off",
           reason="no alternative covers /DC=test"),
    clause("SPL-092", "Globus EACL cond_subjects", "leading '?' matches first '/'",
           "accept", _globs(["?DC=test/DC=x509conf/*"]), group="sp_on_crl_off",
           reason="'?' matches the leading '/' of the oneline DN"),
    clause("SPL-093", "Globus EACL cond_subjects", "literal underscores/digits matched",
           "accept", _globs([NS + "/CN=user_01-x"], NS + "/CN=user_01-x"),
           group="sp_on_crl_off", reason="literal punctuation and digits match"),
    clause("SPL-094", "Globus EACL glob anchoring", "literal + extra char rejected",
           "reject", _globs([NS + "/CN=user_01-x"], NS + "/CN=user_01-xy"),
           group="sp_on_crl_off", reason="trailing 'y' breaks the anchored literal"),
    clause("SPL-095", "Globus EACL cond_subjects", "trailing '*' matches zero chars",
           "accept", _globs([NS + "/CN=alice*"]), group="sp_on_crl_off",
           reason="'*' matches the empty suffix after 'alice'"),
    clause("SPL-096", "Globus EACL cond_subjects", "'*' spanning RDN boundary",
           "accept", _globs(["/DC=test*CN=alice"]), group="sp_on_crl_off",
           reason="'*' bridges '/DC=x509conf/' between fixed anchors"),
    clause("SPL-097", "Globus EACL cond_subjects", "inner '?' matches one char",
           "accept", _globs([NS + "/CN=al?ce"]), group="sp_on_crl_off",
           reason="'?' matches the 'i' in alice"),
    clause("SPL-098", "Globus EACL cond_subjects", "inner '?' width mismatch rejected",
           "reject", _globs([NS + "/CN=al?ce"], NS + "/CN=alXXce"),
           group="sp_on_crl_off", reason="one '?' cannot cover two chars"),
    clause("SPL-099", "Globus EACL cond_subjects", "match-all star among globs",
           "accept", _globs(["*", "/DC=none/*"]), group="sp_on_crl_off",
           reason="the '*' alternative grants everything"),
    clause("SPL-100", "Globus EACL cond_subjects", "'*' grants even out-of-namespace",
           "accept", _globs(["/DC=none/*", "*"], "/DC=evil/CN=x"),
           group="sp_on_crl_off",
           reason="a bare '*' cond_subjects is an all-permit (deployment foot-gun)"),
    clause("SPL-101", "Globus EACL neg_rights", "neg block then pos block accepts",
           "accept", _raw_policy(_pol_neg_then_pos), group="sp_on_crl_off",
           reason="denied block skipped; independent granting block matches"),
    clause("SPL-102", "Globus EACL neg_rights", "this-CA neg beats other-CA pos",
           "reject", _raw_policy(_pol_other_pos_this_neg), group="sp_on_crl_off",
           reason="only the neg_rights block applies to this CA → nothing granted"),
    clause("SPL-103", "Globus EACL cond_subjects", "whitespace-only cond rejected",
           "reject", _raw_policy(_pol_whitespace), group="sp_on_crl_off",
           reason="all-space value yields zero globs → reject"),
    clause("SPL-104", "IGTF signing_policy", "tab-separated tokens tolerated",
           "accept", _raw_policy(_pol_tabs), group="sp_on_crl_off",
           reason="tabs are token separators like spaces"),
]

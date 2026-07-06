"""dn_encoding — DN / string-encoding conformance (prefix DNE).

Reference frame
---------------
* RFC 5280 §4.1.2.4 (issuer) / §4.1.2.6 (subject) — the Name structure and the
  empty-subject rule (empty subject is only legal with a critical subjectAltName).
* RFC 5280 §7.1 — Name matching is *encoding independent*: two RDNSequences are
  equal when their attribute values compare equal under the attribute's matching
  rule, regardless of the ASN.1 string CHOICE actually used on the wire
  (UTF8String / PrintableString / BMPString / TeletexString / …).  DirectoryString
  values use caseIgnoreMatch after the RFC 4518 LDAP string-prep profile
  (insignificant-whitespace folding + case folding); domainComponent uses
  caseIgnoreIA5Match.
* RFC 4514 — the string form of a DN.  '/', '*', '+', '=', ',' embedded in an
  attribute *value* are literal payload; they are NOT RDN/AVA delimiters and are
  NOT wildcards.  Only the signing_policy `cond_subjects` glob (policy side) may
  contain a shell '*' wildcard.
* Globus EACL / signing_policy — the CA namespace is expressed as an OpenSSL
  oneline (`/DC=a/DC=b/CN=...`) glob matched against the leaf subject.

The whole family runs on surface='davs' under group='sp_on_crl_off' so every row
actually exercises the signing_policy DN matcher (CRL machinery muted).

Spec-first `expected`
---------------------
Each `expected` is what RFC 5280 §7.1 / RFC 4514 REQUIRE, not what a naive
oneline-glob matcher happens to do.  Several rows are deliberate divergence
probes for a byte-string glob implementation:
  * encoding equivalence (DNE-002..007): the SAME logical DN in a different ASN.1
    string type must still match — a matcher that keys on the wire encoding fails.
  * caseIgnore on domainComponent (DNE-024/025): `/DC=TEST/...` must match a
    `/DC=test/...` namespace — a case-sensitive glob fails.
  * insignificant-whitespace folding (DNE-026): `CN=Alice ` must match `CN=Alice`.
  * literal metacharacters (DNE-011..015): an embedded '/' must not smuggle a leaf
    into the namespace through an unanchored/oneline-confused glob, and a subject
    '*' must never act as a wildcard.
These are noted in each row's `reason`; the FIX belongs in the code in a later
phase — never soften the assertion here.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

import x509forge
from clauses._helpers import clause, ns_globs

# --------------------------------------------------------------------------
# DN construction helpers
# --------------------------------------------------------------------------

# The namespace prefix that ns_globs()'s "/DC=test/DC=x509conf/*" covers.
_DC_TEST = x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "test")
_DC_CONF = x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "x509conf")


def _cn(value: str, enc: _ASN1Type = _ASN1Type.UTF8String):
    return x509.NameAttribute(NameOID.COMMON_NAME, value, _type=enc)


def _in_ns(cn_value: str, *, enc: _ASN1Type = _ASN1Type.UTF8String,
           extra: list | None = None) -> x509.Name:
    """A leaf Name whose oneline form sits inside /DC=test/DC=x509conf/."""
    return x509.Name([_DC_TEST, _DC_CONF, *(extra or []), _cn(cn_value, enc)])


def _out_ns(cn_value: str, *, enc: _ASN1Type = _ASN1Type.UTF8String) -> x509.Name:
    """A leaf Name rooted OUTSIDE the CA namespace (under /DC=evil)."""
    return x509.Name([
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "evil"),
        _cn(cn_value, enc),
    ])


def _accept_ns(ctx, name: x509.Name, *, globs=None):
    """Mint CA (namespace policy) + leaf with the given subject → cred."""
    ca = ctx.ca(policy_globs=globs if globs is not None else ns_globs())
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


# --------------------------------------------------------------------------
# Group A — DirectoryString encoding equivalence (RFC 5280 §7.1)
# The identical logical DN (CN=Alice, inside the namespace) in every ASN.1
# string CHOICE must match the same namespace glob → accept.
# --------------------------------------------------------------------------

def _b_utf8(ctx):
    return _accept_ns(ctx, _in_ns("Alice", enc=_ASN1Type.UTF8String))


def _b_printable(ctx):
    return _accept_ns(ctx, _in_ns("Alice", enc=_ASN1Type.PrintableString))


def _b_bmp(ctx):
    return _accept_ns(ctx, _in_ns("Alice", enc=_ASN1Type.BMPString))


def _b_teletex(ctx):
    return _accept_ns(ctx, _in_ns("Alice", enc=_ASN1Type.T61String))


def _b_universal(ctx):
    return _accept_ns(ctx, _in_ns("Alice", enc=_ASN1Type.UniversalString))


def _b_visible(ctx):
    return _accept_ns(ctx, _in_ns("Alice", enc=_ASN1Type.VisibleString))


def _b_numeric(ctx):
    # NumericString legal content = digits + space; CN "12345" is a valid leaf.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([_DC_TEST, _DC_CONF,
                      x509.NameAttribute(NameOID.COMMON_NAME, "12345",
                                         _type=_ASN1Type.NumericString)])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


# --------------------------------------------------------------------------
# Group B — encoding × out-of-namespace (reject partners)
# --------------------------------------------------------------------------

def _b_utf8_out(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, subject_name=_out_ns("Mallory",
                                                      enc=_ASN1Type.UTF8String))
    return ctx.cred([eec, ca], eec)


def _b_printable_out(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, subject_name=_out_ns("Mallory",
                                                      enc=_ASN1Type.PrintableString))
    return ctx.cred([eec, ca], eec)


def _b_bmp_out(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, subject_name=_out_ns("Mallory",
                                                      enc=_ASN1Type.BMPString))
    return ctx.cred([eec, ca], eec)


# --------------------------------------------------------------------------
# Group C — literal metacharacters (RFC 4514): '/', '*', '+' in a value
# --------------------------------------------------------------------------

def _b_slash_literal_in_ns(ctx):
    # CN value contains a '/'; the leaf root is still /DC=test/DC=x509conf → in NS.
    return _accept_ns(ctx, _in_ns("host/alice.example.org"))


def _b_slash_smuggle_out(ctx):
    # Out-of-NS leaf whose CN VALUE literally spells the namespace path.
    # X509_NAME_oneline yields  /DC=evil/CN=/DC=test/DC=x509conf/CN=hax
    # A correctly *anchored* glob (/DC=test/DC=x509conf/*) never matches a string
    # that begins with /DC=evil; an unanchored "contains" matcher would be fooled.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "evil"),
        x509.NameAttribute(NameOID.COMMON_NAME, "/DC=test/DC=x509conf/CN=hax"),
    ])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_star_literal_in_ns(ctx):
    # A literal '*' in the subject value is harmless when the namespace glob
    # already ends in '*'; it must be matched as data, not re-interpreted.
    return _accept_ns(ctx, _in_ns("a*b"))


def _b_star_subject_not_wildcard(ctx):
    # Policy grants ONLY the exact DN .../CN=admin (no wildcard).  A leaf whose
    # CN is the literal character '*' must NOT be treated as a wildcard that
    # matches "admin" → outside the granted set → reject.
    globs = ["/DC=test/DC=x509conf/CN=admin"]
    ca = ctx.ca(policy_globs=globs)
    eec = x509forge.make_eec(ca, subject_name=_in_ns("*"))
    return ctx.cred([eec, ca], eec)


def _b_plus_literal_in_ns(ctx):
    # '+' is the AVA separator in the string form but here it is a literal byte
    # inside a single-valued CN; the leaf stays inside the namespace.
    return _accept_ns(ctx, _in_ns("a+b"))


# --------------------------------------------------------------------------
# Group D — RDN structure (multi-valued RDN, duplicates, empty, length)
# --------------------------------------------------------------------------

def _b_multivalued_in_ns(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    rdn = x509.RelativeDistinguishedName([
        x509.NameAttribute(NameOID.COMMON_NAME, "Alice"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "People"),
    ])
    name = x509.Name([x509.RelativeDistinguishedName([_DC_TEST]),
                      x509.RelativeDistinguishedName([_DC_CONF]), rdn])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_multivalued_out_ns(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    rdn = x509.RelativeDistinguishedName([
        x509.NameAttribute(NameOID.COMMON_NAME, "Mallory"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "People"),
    ])
    name = x509.Name([
        x509.RelativeDistinguishedName(
            [x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "evil")]),
        rdn,
    ])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_duplicate_rdns(ctx):
    # Two identical CN RDNs are a legal (if odd) RDNSequence; still in namespace.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([_DC_TEST, _DC_CONF,
                      x509.NameAttribute(NameOID.COMMON_NAME, "Alice"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "Alice")])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_empty_dn(ctx):
    # RFC 5280 §4.1.2.6: an empty subject is only permitted when a CRITICAL
    # subjectAltName carries the identity.  This EEC has neither → invalid.
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, subject_name=x509.Name([]))
    return ctx.cred([eec, ca], eec)


def _b_long_dn_in_ns(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    ous = [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "unit-%02d" % i)
           for i in range(40)]
    name = x509.Name([_DC_TEST, _DC_CONF, *ous,
                      x509.NameAttribute(NameOID.COMMON_NAME, "Alice")])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_long_cn_value_in_ns(ctx):
    # A CN value at the X.520 ub-common-name ceiling (64 chars); matches the
    # trailing '*' namespace glob.
    return _accept_ns(ctx, _in_ns("A" * 64))


# --------------------------------------------------------------------------
# Group E — unusual / uncommon attribute types
# --------------------------------------------------------------------------

def _b_uid_attr(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([_DC_TEST, _DC_CONF,
                      x509.NameAttribute(NameOID.USER_ID, "alice123"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "Alice")])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_email_attr(ctx):
    # legacy emailAddress (PKCS#9, IA5String) inside the DN.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([_DC_TEST, _DC_CONF,
                      x509.NameAttribute(NameOID.COMMON_NAME, "Alice"),
                      x509.NameAttribute(NameOID.EMAIL_ADDRESS,
                                         "alice@example.org")])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_serialnumber_attr(ctx):
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([_DC_TEST, _DC_CONF,
                      x509.NameAttribute(NameOID.SERIAL_NUMBER, "SN-0001"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "Alice")])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_unknown_oid_attr(ctx):
    # A private-arc attribute type the matcher has no friendly name for; oneline
    # renders it as OID=value and it stays under the namespace prefix.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([_DC_TEST, _DC_CONF,
                      x509.NameAttribute(x509.ObjectIdentifier("1.3.6.1.4.1.99999.7"),
                                         "custom"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "Alice")])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


# --------------------------------------------------------------------------
# Group F — canonicalization / matching-rule traps
# --------------------------------------------------------------------------

def _b_dc_case_fold_in_ns(ctx):
    # domainComponent uses caseIgnoreIA5Match (RFC 4519) → /DC=TEST/DC=X509CONF
    # is EQUAL to /DC=test/DC=x509conf and MUST match the namespace.
    # Divergence: a case-sensitive byte glob rejects this.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "TEST"),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "X509CONF"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Alice"),
    ])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_dc_case_fold_out_ns(ctx):
    # Case folding does NOT rescue a genuinely different domain: /DC=EVIL is
    # still outside /DC=test/DC=x509conf/* → reject.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "EVIL"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mallory"),
    ])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_cn_whitespace_fold(ctx):
    # Policy grants exactly .../CN=Alice.  Leaf CN="Alice " (trailing space) is
    # EQUAL after RFC 4518 insignificant-whitespace folding → must be granted.
    # Divergence: an exact byte glob rejects the trailing space.
    globs = ["/DC=test/DC=x509conf/CN=Alice"]
    ca = ctx.ca(policy_globs=globs)
    eec = x509forge.make_eec(ca, subject_name=_in_ns("Alice "))
    return ctx.cred([eec, ca], eec)


def _b_cn_case_fold_exact(ctx):
    # DirectoryString caseIgnoreMatch: CN=ALICE equals the granted CN=Alice.
    # Divergence: case-sensitive glob rejects.
    globs = ["/DC=test/DC=x509conf/CN=Alice"]
    ca = ctx.ca(policy_globs=globs)
    eec = x509forge.make_eec(ca, subject_name=_in_ns("ALICE"))
    return ctx.cred([eec, ca], eec)


def _b_rdn_order_matters(ctx):
    # RDNSequence order is significant: swapping DC order puts /DC=x509conf/DC=test
    # first, which is NOT the granted /DC=test/DC=x509conf/* prefix → reject.
    ca = ctx.ca(policy_globs=ns_globs())
    name = x509.Name([
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "x509conf"),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Alice"),
    ])
    eec = x509forge.make_eec(ca, subject_name=name)
    return ctx.cred([eec, ca], eec)


def _b_embedded_nul(ctx):
    # An embedded NUL in the CN is a classic name-truncation smuggling vector;
    # RFC 5280 §4.1.2.6 + the profile forbid it — the credential must be rejected
    # regardless of whether a naive C string sees only "Al".
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, subject_name=_in_ns("Al\x00ice"))
    return ctx.cred([eec, ca], eec)


def _b_embedded_control(ctx):
    # A raw control byte (BEL) inside the CN: not printable, must not be honored
    # as a legitimate identity — reject (defense against log/ACL injection).
    ca = ctx.ca(policy_globs=ns_globs())
    eec = x509forge.make_eec(ca, subject_name=_in_ns("Al\x07ice"))
    return ctx.cred([eec, ca], eec)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

CLAUSES = [
    # Group A — encoding equivalence (accept)
    clause("DNE-001", "RFC5280 §7.1", "UTF8String CN in namespace accepted",
           "accept", _b_utf8,
           reason="baseline DirectoryString=UTF8String, in-namespace"),
    clause("DNE-002", "RFC5280 §7.1", "PrintableString CN matches same DN",
           "accept", _b_printable,
           reason="encoding-independent equality: PrintableString == UTF8String"),
    clause("DNE-003", "RFC5280 §7.1", "BMPString CN matches same DN",
           "accept", _b_bmp,
           reason="BMPString CHOICE must not change DN identity (likely divergence)"),
    clause("DNE-004", "RFC5280 §7.1", "TeletexString(T61) CN matches same DN",
           "accept", _b_teletex,
           reason="TeletexString CHOICE must not change DN identity"),
    clause("DNE-005", "RFC5280 §7.1", "UniversalString CN matches same DN",
           "accept", _b_universal,
           reason="UniversalString CHOICE must not change DN identity"),
    clause("DNE-006", "RFC5280 §7.1", "VisibleString(ISO646) CN matches same DN",
           "accept", _b_visible,
           reason="VisibleString CHOICE must not change DN identity"),
    clause("DNE-007", "RFC5280 §4.1.2.4", "NumericString CN accepted in namespace",
           "accept", _b_numeric,
           reason="NumericString value (digits) is a valid DirectoryString choice"),

    # Group B — encoding × out-of-namespace (reject)
    clause("DNE-008", "Globus EACL", "UTF8String CN out of namespace rejected",
           "reject", _b_utf8_out,
           reason="leaf rooted at /DC=evil, outside CA namespace"),
    clause("DNE-009", "Globus EACL", "PrintableString CN out of namespace rejected",
           "reject", _b_printable_out,
           reason="encoding does not rescue an out-of-namespace subject"),
    clause("DNE-010", "Globus EACL", "BMPString CN out of namespace rejected",
           "reject", _b_bmp_out,
           reason="encoding does not rescue an out-of-namespace subject"),

    # Group C — literal metacharacters
    clause("DNE-011", "RFC4514 §2.4", "literal '/' in CN value stays in namespace",
           "accept", _b_slash_literal_in_ns,
           reason="'/' inside a value is payload, not an RDN delimiter"),
    clause("DNE-012", "RFC4514 §2.4", "namespace-path text in CN does not smuggle",
           "reject", _b_slash_smuggle_out,
           reason="anchored glob must not be fooled by /DC=test/... inside a value"),
    clause("DNE-013", "RFC4514 §2.4", "literal '*' in CN value under trailing-*",
           "accept", _b_star_literal_in_ns,
           reason="'*' in subject is literal data; trailing-* namespace covers it"),
    clause("DNE-014", "RFC4514 §2.4", "subject '*' is not a wildcard vs exact policy",
           "reject", _b_star_subject_not_wildcard,
           reason="literal CN='*' must not wildcard-match the granted CN=admin"),
    clause("DNE-015", "RFC4514 §2.2", "literal '+' in single-valued CN stays in ns",
           "accept", _b_plus_literal_in_ns,
           reason="'+' inside a value is payload, not an AVA separator"),

    # Group D — RDN structure
    clause("DNE-016", "RFC5280 §4.1.2.6", "multi-valued RDN leaf accepted in ns",
           "accept", _b_multivalued_in_ns,
           reason="CN+OU in one RDN; DC prefix keeps it in namespace"),
    clause("DNE-017", "Globus EACL", "multi-valued RDN leaf out of ns rejected",
           "reject", _b_multivalued_out_ns,
           reason="multi-valued leaf rooted at /DC=evil is out of namespace"),
    clause("DNE-018", "RFC5280 §4.1.2.6", "duplicate identical RDNs accepted in ns",
           "accept", _b_duplicate_rdns,
           reason="repeated CN RDNs form a legal RDNSequence, still in namespace"),
    clause("DNE-019", "RFC5280 §4.1.2.6", "empty subject without SAN rejected",
           "reject", _b_empty_dn,
           reason="empty subject legal ONLY with critical subjectAltName; none here"),
    clause("DNE-020", "RFC5280 §4.1.2.4", "very long DN (many RDNs) accepted in ns",
           "accept", _b_long_dn_in_ns,
           reason="42-RDN subject; no RDN-count ceiling in the profile"),
    clause("DNE-021", "RFC5280 §4.1.2.4", "max-length (64) CN value accepted in ns",
           "accept", _b_long_cn_value_in_ns,
           reason="CN at ub-common-name (64 chars); matched by trailing-* glob"),

    # Group E — unusual attribute types
    clause("DNE-022", "RFC4519", "UID attribute in DN accepted in namespace",
           "accept", _b_uid_attr,
           reason="0.9.2342.19200300.100.1.1 userid is a valid RDN attribute"),
    clause("DNE-023", "RFC5280 §4.1.2.6", "legacy emailAddress in DN accepted",
           "accept", _b_email_attr,
           reason="PKCS#9 emailAddress (IA5String) is a recognized DN attribute"),
    clause("DNE-024", "RFC4519", "serialNumber attribute in DN accepted in ns",
           "accept", _b_serialnumber_attr,
           reason="X.520 serialNumber is a valid RDN attribute"),
    clause("DNE-025", "RFC5280 §4.1.2.4", "unknown private-OID attribute in ns",
           "accept", _b_unknown_oid_attr,
           reason="unrecognized attribute type must not break DN handling"),

    # Group F — matching-rule / canonicalization traps
    clause("DNE-026", "RFC4519 caseIgnoreIA5Match",
           "domainComponent case-folds into namespace",
           "accept", _b_dc_case_fold_in_ns,
           reason="/DC=TEST/DC=X509CONF == /DC=test/DC=x509conf (likely divergence)"),
    clause("DNE-027", "RFC4519 caseIgnoreIA5Match",
           "case fold does not rescue a different domain",
           "reject", _b_dc_case_fold_out_ns,
           reason="/DC=EVIL is a different value, not a case variant of the ns"),
    clause("DNE-028", "RFC4518 §2.6", "insignificant trailing space folds to match",
           "accept", _b_cn_whitespace_fold,
           reason="CN='Alice ' == granted CN='Alice' after whitespace folding"),
    clause("DNE-029", "RFC4517 caseIgnoreMatch",
           "DirectoryString case folds to match exact policy",
           "accept", _b_cn_case_fold_exact,
           reason="CN='ALICE' == granted CN='Alice' (likely divergence)"),
    clause("DNE-030", "RFC5280 §7.1", "RDN order is significant (swap → out of ns)",
           "reject", _b_rdn_order_matters,
           reason="/DC=x509conf/DC=test is a different RDNSequence, out of namespace"),
    clause("DNE-031", "RFC5280 §4.1.2.6", "embedded NUL in CN rejected",
           "reject", _b_embedded_nul,
           reason="NUL name-truncation smuggling vector must be rejected"),
    clause("DNE-032", "RFC5280 §4.1.2.6", "embedded control byte in CN rejected",
           "reject", _b_embedded_control,
           reason="non-printable control byte in identity must be rejected"),
]

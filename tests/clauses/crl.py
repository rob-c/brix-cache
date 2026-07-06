"""crl — CRL / revocation conformance family (RFC 5280 §5, §6.3.3).

Every row presents an X.509 credential that chains to a CA whose hashed
directory carries (or deliberately lacks) a CRL, and asserts the verdict the
STANDARD requires.  Verdicts are spec-first: RFC 5280 §6.3.3 (basic path
revocation), §5.1/§5.2 (CRL fields), §5.3.1 (reason codes), and the WLCG/IGTF
requirement that a "require" deployment fail closed when no fresh CRL is
available.

Three server config-groups exercise the three CRL modes:

    off      (sp_off_crl_off)   — CRL ignored entirely; a revoked cert is
                                  accepted.  Isolates chain building from
                                  revocation.
    try      (sp_off_crl_try)   — best-effort: a missing CRL is tolerated
                                  (accept), but any CRL that IS present must be
                                  fresh and validly signed, and a listed serial
                                  is rejected.
    require  (sp_on_crl_require) — strict: a valid, fresh CRL must exist for the
                                  issuing CA or the credential is rejected.

The CRL for a CA is written into the same hashed dir as the CA (`<hash>.r0`,
`<hash>.r1`).  `_place()` puts a CA plus an explicit CRL set into the shared
multi-CA directory; `ctx.ca()` is used for the CA-without-CRL / empty-CRL
shortcuts.  Credentials chain to that CA, so the oracle (which scans .r0/.r1)
evaluates them exactly as a real /etc/grid-security deployment would.
"""

from __future__ import annotations

import x509forge
from x509forge import make_ca, make_eec, make_crl
from clauses._helpers import clause, leaf_dn

# Config-groups: (try) best-effort, (require) strict, (off) CRL ignored.
_TRY = "sp_off_crl_try"
_REQ = "sp_on_crl_require"
_OFF = "sp_off_crl_off"


# --------------------------------------------------------------------------
# Placement + id helpers
# --------------------------------------------------------------------------

def _place(ctx, ca, crls=None, *, links="both"):
    """Place a single CA into the shared hashed dir with an explicit CRL set."""
    x509forge._place_ca_in_dir(ctx.shared_ca, ca, name=f"{ctx.clause.id}-ca",
                               crls=crls, links=links)


_counter = [0]


def _cid() -> str:
    _counter[0] += 1
    return f"CRL-{_counter[0]:03d}"


def _modes(ref, title, build, *, try_x=None, req_x=None, off_x=None):
    """Emit one row per applicable CRL mode (try/require/off).

    A None verdict skips that mode (used where a mode would confound the
    scenario, e.g. intermediate-CA revocation under require, which would also
    trip the missing-CRL-for-the-intermediate rule)."""
    rows = []
    for grp, exp, tag in ((_TRY, try_x, "try"),
                          (_REQ, req_x, "require"),
                          (_OFF, off_x, "off")):
        if exp is None:
            continue
        rows.append(clause(_cid(), ref, f"{title} — crl {tag}", exp, build,
                           group=grp, reason=f"crl_mode={tag} -> {exp}"))
    return rows


# --------------------------------------------------------------------------
# Scenario builders
# --------------------------------------------------------------------------

def _good_under_crl(ctx):
    """CRL present and non-empty, but the presented EEC is NOT listed."""
    ca = make_ca(ctx.dn())
    other = make_eec(ca, leaf_dn(ctx, "someone-else"))
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[other])})
    return ctx.cred([eec, ca], eec)


def _revoked_eec(ctx):
    """The presented EEC's serial is on the CA CRL."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "revoked"))
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[eec])})
    return ctx.cred([eec, ca], eec)


def _no_crl(ctx):
    """CA placed with NO CRL at all (missing-CRL matrix)."""
    ca = ctx.ca()          # placed, no .r0
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    return ctx.cred([eec, ca], eec)


def _empty_crl(ctx):
    """CA with a valid but empty CRL (revokedCertificates absent)."""
    ca = ctx.ca(empty_crl=True)
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    return ctx.cred([eec, ca], eec)


def _multi_present_clean(ctx):
    """Ten-entry CRL; the presented EEC is not among them."""
    ca = make_ca(ctx.dn())
    revoked = [make_eec(ca, leaf_dn(ctx, f"bad{i}")) for i in range(10)]
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=revoked)})
    return ctx.cred([eec, ca], eec)


def _multi_present_revoked(ctx):
    """Ten-entry CRL that DOES include the presented EEC."""
    ca = make_ca(ctx.dn())
    revoked = [make_eec(ca, leaf_dn(ctx, f"bad{i}")) for i in range(9)]
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    revoked.append(eec)
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=revoked)})
    return ctx.cred([eec, ca], eec)


def _expired_crl(ctx):
    """CRL whose nextUpdate is already in the past (stale)."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(ca, this_update_days=-40,
                                         next_update_days=-10)})
    return ctx.cred([eec, ca], eec)


def _expired_and_revoked(ctx):
    """Stale CRL that also lists the EEC — reject either way it is read."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[eec],
                                         this_update_days=-40,
                                         next_update_days=-10)})
    return ctx.cred([eec, ca], eec)


def _notyet_crl(ctx):
    """CRL whose thisUpdate is in the future (not yet valid)."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(ca, this_update_days=300,
                                         next_update_days=400)})
    return ctx.cred([eec, ca], eec)


def _wrong_signer_crl(ctx):
    """CRL carries the CA's issuer name but is signed by a rogue key."""
    ca = make_ca(ctx.dn())
    rogue = make_ca(ctx.dn("rogue"))       # not placed in the trust dir
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[], signer=rogue)})
    return ctx.cred([eec, ca], eec)


def _issuer_mismatch_crl(ctx):
    """A CRL for a DIFFERENT CA, filed under this CA's hash slot."""
    ca = make_ca(ctx.dn())
    other = make_ca(ctx.dn("other"))
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(other, revoked=[])})
    return ctx.cred([eec, ca], eec)


def _revoked_intermediate(ctx):
    """Root CRL revokes the intermediate CA that issued the leaf."""
    root = make_ca(ctx.dn("root"))
    inter = make_eec(root, ctx.dn("inter"), ca_true=True, keycert_sign=True,
                     path_length=0)
    leaf = make_eec(inter, leaf_dn(ctx, "alice"))
    _place(ctx, root, crls={"r0": make_crl(root, revoked=[inter])})
    return ctx.cred([leaf, inter, root], leaf)


def _good_intermediate(ctx):
    """Same chain, but the intermediate is NOT on the root CRL."""
    root = make_ca(ctx.dn("root"))
    inter = make_eec(root, ctx.dn("inter"), ca_true=True, keycert_sign=True,
                     path_length=0)
    leaf = make_eec(inter, leaf_dn(ctx, "alice"))
    _place(ctx, root, crls={"r0": make_crl(root, revoked=[])})
    return ctx.cred([leaf, inter, root], leaf)


def _revoked_reason(reason):
    """Factory: EEC revoked with a specific CRLReason code."""
    def build(ctx):
        ca = make_ca(ctx.dn())
        eec = make_eec(ca, leaf_dn(ctx, "revoked"))
        _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[eec], reason=reason)})
        return ctx.cred([eec, ca], eec)
    return build


def _delta_revokes(ctx):
    """Base CRL clean; delta CRL (indicator=base#) adds the EEC."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    base = make_crl(ca, revoked=[], crl_number=1)
    delta = make_crl(ca, revoked=[eec], crl_number=2, delta_indicator=1)
    _place(ctx, ca, crls={"r0": base, "r1": delta})
    return ctx.cred([eec, ca], eec)


def _delta_clean(ctx):
    """Base + delta both present; the EEC is on neither."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    other = make_eec(ca, leaf_dn(ctx, "other"))
    base = make_crl(ca, revoked=[], crl_number=1)
    delta = make_crl(ca, revoked=[other], crl_number=2, delta_indicator=1)
    _place(ctx, ca, crls={"r0": base, "r1": delta})
    return ctx.cred([eec, ca], eec)


def _delta_remove(ctx):
    """Base revokes the EEC; delta removes it via reason removeFromCRL."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    base = make_crl(ca, revoked=[eec], crl_number=1)
    delta = make_crl(ca, revoked=[eec], crl_number=2, delta_indicator=1,
                     reason="remove_from_crl")
    _place(ctx, ca, crls={"r0": base, "r1": delta})
    return ctx.cred([eec, ca], eec)


def _r0clean_r1revokes(ctx):
    """Two full CRLs; the newer (higher CRLNumber) revokes the EEC."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    r0 = make_crl(ca, revoked=[], crl_number=1)
    r1 = make_crl(ca, revoked=[eec], crl_number=2)
    _place(ctx, ca, crls={"r0": r0, "r1": r1})
    return ctx.cred([eec, ca], eec)


def _r0revokes_r1clean(ctx):
    """Two full CRLs; the newer authoritative CRL drops the EEC."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    r0 = make_crl(ca, revoked=[eec], crl_number=1)
    r1 = make_crl(ca, revoked=[], crl_number=2)
    _place(ctx, ca, crls={"r0": r0, "r1": r1})
    return ctx.cred([eec, ca], eec)


def _r0_r1_clean(ctx):
    """Two full CRLs, EEC on neither (monotonic CRLNumber, both fresh)."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    other = make_eec(ca, leaf_dn(ctx, "other"))
    r0 = make_crl(ca, revoked=[other], crl_number=1)
    r1 = make_crl(ca, revoked=[], crl_number=2)
    _place(ctx, ca, crls={"r0": r0, "r1": r1})
    return ctx.cred([eec, ca], eec)


def _ec_ca_revoked(ctx):
    """EC (P-384) CA, ECDSA-SHA384 CRL revoking the presented EEC."""
    ca = make_ca(ctx.dn(), key_type="ec", curve="P-384", digest_name="sha384")
    eec = make_eec(ca, leaf_dn(ctx, "revoked"), key_type="ec", curve="P-256")
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[eec],
                                         digest_name="sha384")})
    return ctx.cred([eec, ca], eec)


def _sha512_crl_revoked(ctx):
    """RSA CA, SHA-512-signed CRL revoking the presented EEC."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "revoked"))
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[eec],
                                         digest_name="sha512")})
    return ctx.cred([eec, ca], eec)


def _crlnumber_good(ctx):
    """Fresh CRL carrying an explicit CRLNumber; EEC not listed."""
    ca = make_ca(ctx.dn())
    eec = make_eec(ca, leaf_dn(ctx, "alice"))
    _place(ctx, ca, crls={"r0": make_crl(ca, revoked=[], crl_number=42)})
    return ctx.cred([eec, ca], eec)


# --------------------------------------------------------------------------
# Reason-code catalogue (RFC 5280 §5.3.1) — all are effective revocations.
# --------------------------------------------------------------------------

_REASONS = [
    "unspecified",
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "privilege_withdrawn",
    "aa_compromise",
]


# --------------------------------------------------------------------------
# Clause table
# --------------------------------------------------------------------------

CLAUSES = []

# --- Basic revoked / non-revoked -----------------------------------------
CLAUSES += _modes("RFC5280 §6.3.3",
                  "non-revoked EEC under a populated CRL", _good_under_crl,
                  try_x="accept", req_x="accept", off_x="accept")
CLAUSES += _modes("RFC5280 §6.3.3",
                  "EEC serial listed on the CA CRL", _revoked_eec,
                  try_x="reject", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §5.1",
                  "EEC not among ten revoked serials", _multi_present_clean,
                  try_x="accept", req_x="accept", off_x="accept")
CLAUSES += _modes("RFC5280 §5.1",
                  "EEC is one of ten revoked serials", _multi_present_revoked,
                  try_x="reject", req_x="reject", off_x="accept")

# --- Missing / empty CRL (mode matrix) -----------------------------------
CLAUSES += _modes("IGTF classic §CRL",
                  "issuing CA has no CRL", _no_crl,
                  try_x="accept", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §5.1.2.6",
                  "valid empty CRL, EEC not listed", _empty_crl,
                  try_x="accept", req_x="accept", off_x="accept")

# --- CRL validity window (RFC5280 §5.1.2.4/§5.1.2.5) ----------------------
CLAUSES += _modes("RFC5280 §5.1.2.5",
                  "CRL nextUpdate has passed (stale)", _expired_crl,
                  try_x="reject", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §5.1.2.5",
                  "stale CRL that also lists the EEC", _expired_and_revoked,
                  try_x="reject", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §5.1.2.4",
                  "CRL thisUpdate is in the future (not yet valid)",
                  _notyet_crl,
                  try_x="reject", req_x="reject", off_x="accept")

# --- CRL signature (RFC5280 §5.1.1.3 / §6.3.3) ---------------------------
CLAUSES += _modes("RFC5280 §6.3.3",
                  "CRL signed by a rogue key (wrong signer)",
                  _wrong_signer_crl,
                  try_x="reject", req_x="reject", off_x="accept")

# --- CRL scope / issuer match (RFC5280 §5.1.2.3) -------------------------
CLAUSES += _modes("RFC5280 §5.1.2.3",
                  "CRL issuer name does not match the CA", _issuer_mismatch_crl,
                  try_x="accept", req_x="reject", off_x="accept")

# --- Intermediate-CA revocation (RFC5280 §6.3.3) -------------------------
# require is skipped: it would also demand a CRL for the intermediate itself,
# which the trust dir does not carry, confounding the revocation signal.
CLAUSES += _modes("RFC5280 §6.3.3",
                  "intermediate CA revoked by the root CRL",
                  _revoked_intermediate,
                  try_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §6.3.3",
                  "intermediate CA not on the root CRL", _good_intermediate,
                  try_x="accept", off_x="accept")

# --- Reason codes (RFC5280 §5.3.1) ---------------------------------------
for _reason in _REASONS:
    CLAUSES += _modes("RFC5280 §5.3.1",
                      f"EEC revoked, reason={_reason}", _revoked_reason(_reason),
                      try_x="reject", req_x="reject", off_x="accept")
# removeFromCRL in a FULL CRL is illegal (§5.3.1) — fail closed (still listed).
CLAUSES += _modes("RFC5280 §5.3.1",
                  "EEC listed with removeFromCRL in a full CRL",
                  _revoked_reason("remove_from_crl"),
                  try_x="reject", req_x="reject", off_x="accept")

# --- Delta CRLs (RFC5280 §5.2.4) -----------------------------------------
CLAUSES += _modes("RFC5280 §5.2.4",
                  "delta CRL adds the EEC (base clean)", _delta_revokes,
                  try_x="reject", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §5.2.4",
                  "base + delta, EEC on neither", _delta_clean,
                  try_x="accept", req_x="accept", off_x="accept")
CLAUSES += _modes("RFC5280 §5.3.1",
                  "delta un-revokes the EEC via removeFromCRL", _delta_remove,
                  try_x="accept", req_x="accept", off_x="accept")

# --- Multiple full CRLs / CRLNumber monotonicity (RFC5280 §5.2.3) --------
CLAUSES += _modes("RFC5280 §5.2.3",
                  "newer CRL (higher CRLNumber) revokes the EEC",
                  _r0clean_r1revokes,
                  try_x="reject", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §5.2.3",
                  "newer authoritative CRL drops the EEC", _r0revokes_r1clean,
                  try_x="accept", req_x="accept", off_x="accept")
CLAUSES += _modes("RFC5280 §5.2.3",
                  "two fresh CRLs, EEC on neither", _r0_r1_clean,
                  try_x="accept", req_x="accept", off_x="accept")

# --- Algorithm variety ----------------------------------------------------
CLAUSES += _modes("RFC5280 §6.3.3",
                  "EC (P-384) CA, ECDSA-SHA384 CRL revokes EEC", _ec_ca_revoked,
                  try_x="reject", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §6.3.3",
                  "RSA CA, SHA-512 CRL revokes EEC", _sha512_crl_revoked,
                  try_x="reject", req_x="reject", off_x="accept")
CLAUSES += _modes("RFC5280 §5.2.3",
                  "fresh CRL with explicit CRLNumber, EEC not listed",
                  _crlnumber_good,
                  try_x="accept", req_x="accept", off_x="accept")

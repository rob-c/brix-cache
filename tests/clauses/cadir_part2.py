"""cadir — CA-directory mechanics (IGTF hashed store layout).

This family exercises how a WebDAV x509 trust store loads and finds CA material
out of a hashed certificate directory (the /etc/grid-security/certificates
shape): the SHA-1 (new) vs MD5 (old) subject-hash links, hash-slot collisions
(<hash>.0 / <hash>.1), junk/dangling files that must be ignored, the
concatenated CA-bundle-file parity path, trust-anchor validity windows, and
store isolation (only CAs actually placed in the store are trust anchors).

Every row runs on the davs surface with signing_policy OFF and CRL OFF
(group 'sp_off_crl_off') so the *only* variable is CA-directory mechanics — the
bundle rows use group 'bundle' to drive the concatenated-cafile config instead.

Expected verdicts are SPEC-FIRST (IGTF store layout + OpenSSL
X509_LOOKUP_hash_dir semantics + RFC 5280 trust-anchor validity), independent of
what our loader currently does.
"""

from __future__ import annotations

import x509forge
from x509forge import make_eec, make_ca, _place_ca_in_dir, _symlink
from clauses._helpers import clause, ns_globs, leaf_dn


# --------------------------------------------------------------------------
# id auto-numbering
# --------------------------------------------------------------------------

_ROWS: list = []
_N = [0]


def _isolation_second(ctx):
    ctx.ca()                    # CA A present but unrelated
    ca_b = ctx.ca()
    eec = make_eec(ca_b, leaf_dn(ctx, "b"))
    return ctx.cred([eec, ca_b], eec)


_add("RFC5280 §6.1",
     "two independent CAs in the store; cred chaining to the second verifies",
     "accept", _isolation_second,
     reason="the presence of an unrelated CA must not affect the verdict")


def _baseline_full_chain(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store",
     "baseline: correct EEC->CA chain against the hashed store verifies",
     "accept", _baseline_full_chain,
     reason="the reference positive path for the CA-dir family")


def _duplicate_ca(ctx):
    ca = ctx.ca()   # placed once
    # place the SAME cert again under a second file name -> identical-cert
    # collision at <hash>.0 / <hash>.1
    _place_ca_in_dir(ctx.shared_ca, ca, name=f"{ctx.clause.id}-dup")
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("OpenSSL X509_LOOKUP_hash_dir",
     "identical CA duplicated at two hash slots verifies harmlessly",
     "accept", _duplicate_ca,
     reason="a duplicate anchor in the collision run is benign")


# --------------------------------------------------------------------------
# extra key/digest variants (both-links accept / old-only reject) for coverage
# --------------------------------------------------------------------------

_FILL_VARIANTS = [
    ("EC P-521", {"key_type": "ec", "curve": "P-521"}),
    ("SHA-512-signed", {"digest_name": "sha512"}),
    ("RSA-3072", {"key_bits": 3072}),
]

for _label, _kw in _FILL_VARIANTS:
    _add("IGTF store / OpenSSL hash",
         f"{_label} CA with both hash links verifies",
         "accept", _hashlink("both", **_kw),
         reason="canonical hash link present -> anchor located")
    _add("CA-dir requires canonical hash",
         f"{_label} CA with only the legacy MD5 link is not found",
         "reject", _hashlink("old", **_kw),
         reason="legacy-only hash link is invisible to modern lookup")


# --------------------------------------------------------------------------
# signing_policy file present but the engine is OFF -> ignored
# --------------------------------------------------------------------------

def _policy_present_sp_off(ctx):
    # policy grants a namespace that EXCLUDES the EEC; with sp OFF it is ignored.
    ca = ctx.ca(policy_globs=["/DC=nowhere/DC=else/*"])
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store",
     "signing_policy file present but engine OFF is not consulted",
     "accept", _policy_present_sp_off,
     reason="with signing_policy off the <hash>.signing_policy file is inert")


def _junk_nonpem_hashfile(ctx):
    ca = ctx.ca()
    # a real-looking .0 file (unrelated hash) holding garbage, never opened.
    (ctx.shared_ca / f"{ctx.clause.id}ff.0").write_text("-----BOGUS-----\n")
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store",
     "garbage file at an unrelated hash slot does not break a valid CA",
     "accept", _junk_nonpem_hashfile,
     reason="lookup never opens a slot for a hash no placed CA has")


def _bundle_ca_also_in_chain(ctx):
    ca = ctx.ca(to_bundle=True)
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)   # CA both in bundle and presented in chain


_add("IGTF store (bundle)",
     "CA present in both the bundle and the presented chain verifies",
     "accept", _bundle_ca_also_in_chain, group="bundle",
     reason="a redundant in-chain copy of a bundle anchor is benign")


def _expired_and_valid_collision(ctx):
    """Same-DN pair where one CA is expired and one is valid; chain to valid."""
    dn = ctx.dn("mixval")
    ctx.ca(dn=dn, not_after_days=-1)     # expired, colliding slot
    good = ctx.ca(dn=dn)                 # valid, colliding slot
    eec = make_eec(good, leaf_dn(ctx))
    return ctx.cred([eec, good], eec)


_add("OpenSSL X509_LOOKUP_hash_dir",
     "collision run mixing an expired and a valid same-DN CA: valid one verifies",
     "accept", _expired_and_valid_collision,
     reason="lookup must not settle on the expired sibling in the hash run")


CLAUSES = _ROWS

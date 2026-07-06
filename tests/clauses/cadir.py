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


def _add(clause_ref, title, expected, build, *, group="sp_off_crl_off",
         surface="davs", reason=""):
    _N[0] += 1
    cid = f"CAD-{_N[0]:03d}"
    _ROWS.append(clause(cid, clause_ref, title, expected, build,
                        surface=surface, group=group, reason=reason))


# --------------------------------------------------------------------------
# hash-link builders (SHA-1 "new" vs MD5 "old" subject-hash links)
# --------------------------------------------------------------------------

def _hashlink(links, **ca_kw):
    """A CA placed with the given hash-link set; a plain EEC chained to it."""
    def build(ctx):
        ca = ctx.ca(links=links, **ca_kw)
        eec = make_eec(ca, leaf_dn(ctx, "leaf"))
        return ctx.cred([eec, ca], eec)
    return build


_KEY_VARIANTS = [
    ("RSA-2048", {}),
    ("RSA-4096", {"key_bits": 4096}),
    ("EC P-256", {"key_type": "ec", "curve": "P-256"}),
    ("EC P-384", {"key_type": "ec", "curve": "P-384"}),
    ("SHA-384-signed", {}),
]
# give the last variant a sha384 digest without disturbing the dict literal
_KEY_VARIANTS[4][1]["digest_name"] = "sha384"


for _label, _kw in _KEY_VARIANTS:
    _add("IGTF store / OpenSSL hash",
         f"{_label} CA with both (SHA-1+MD5) hash links is usable",
         "accept", _hashlink("both", **_kw),
         reason="canonical + legacy hash links both present (WLCG/IGTF ship both)")
    _add("IGTF store / OpenSSL hash",
         f"{_label} CA reachable via canonical (SHA-1) hash link",
         "accept", _hashlink("new", **_kw),
         reason="modern OpenSSL X509_LOOKUP_hash_dir keys on the new SHA-1 hash")
    _add("CA-dir requires canonical hash",
         f"{_label} CA with only the legacy (MD5) hash link is not found",
         "reject", _hashlink("old", **_kw),
         reason="MD5-only link: CA not found by OpenSSL new-hash lookup; a "
                "conformant IGTF store must carry the canonical SHA-1 hash")


# --------------------------------------------------------------------------
# explicit SHA-1-accept / MD5-reject pair (the canonical-hash requirement)
# --------------------------------------------------------------------------

_add("CA-dir / OpenSSL hash",
     "SHA-1 canonical hash link alone locates the CA",
     "accept", _hashlink("new"),
     reason="new-hash link is the one OpenSSL computes at lookup time")

_add("CA-dir / OpenSSL hash",
     "MD5 legacy hash link alone fails to locate the CA",
     "reject", _hashlink("old"),
     reason="legacy hash is never computed by a modern lookup -> CA unreachable")


# --------------------------------------------------------------------------
# hash-slot collisions: two DIFFERENT CAs sharing one subject hash
# --------------------------------------------------------------------------

def _collision(pick):
    """Two distinct CAs with the SAME subject DN (==same subject hash) placed
    into <hash>.0 and <hash>.1; the EEC chains to whichever the picker selects.
    OpenSSL must probe every cert in the collision run to find the true issuer."""
    def build(ctx):
        dn = ctx.dn("collide")
        ca0 = ctx.ca(dn=dn)
        ca1 = ctx.ca(dn=dn)
        chosen = ca0 if pick == 0 else ca1
        eec = make_eec(chosen, leaf_dn(ctx, f"leaf{pick}"))
        return ctx.cred([eec, chosen], eec)
    return build


_add("OpenSSL X509_LOOKUP_hash_dir",
     "hash collision: cred chaining to the .0-slot CA verifies",
     "accept", _collision(0),
     reason="two CAs share the subject hash; issuer resolved by probing the run")

_add("OpenSSL X509_LOOKUP_hash_dir",
     "hash collision: cred chaining to the .1-slot CA verifies",
     "accept", _collision(1),
     reason="second colliding CA must still be reachable at <hash>.1")


def _collision3(ctx):
    """Three CAs colliding into <hash>.0/.1/.2; chain to the third."""
    dn = ctx.dn("triple")
    ctx.ca(dn=dn)
    ctx.ca(dn=dn)
    ca2 = ctx.ca(dn=dn)
    eec = make_eec(ca2, leaf_dn(ctx, "leaf2"))
    return ctx.cred([eec, ca2], eec)


_add("OpenSSL X509_LOOKUP_hash_dir",
     "three-way hash collision: cred chaining to the .2-slot CA verifies",
     "accept", _collision3,
     reason="lookup must not stop early at <hash>.0/.1 when the issuer is at .2")


def _collision_ec_rsa(ctx):
    """An EC CA and an RSA CA sharing one subject DN/hash; chain to the EC one."""
    dn = ctx.dn("mix")
    ca_ec = ctx.ca(dn=dn, key_type="ec", curve="P-256")
    ctx.ca(dn=dn)   # RSA CA, same DN -> collides
    eec = make_eec(ca_ec, leaf_dn(ctx, "ec"))
    return ctx.cred([eec, ca_ec], eec)


_add("OpenSSL X509_LOOKUP_hash_dir",
     "mixed EC/RSA CAs colliding on one subject hash: correct issuer wins",
     "accept", _collision_ec_rsa,
     reason="collision run mixes key algorithms; issuer matched by signature")


# --------------------------------------------------------------------------
# junk / dangling files in the store must be ignored
# --------------------------------------------------------------------------

def _junk_dangling(ctx):
    ca = ctx.ca()
    d = ctx.shared_ca
    (d / f"{ctx.clause.id}-junk.txt").write_text("not a certificate\n")
    _symlink("does-not-exist.pem", d / f"{ctx.clause.id}-dangling.link")
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store",
     "dangling symlink + junk text file in store are ignored; valid CA verifies",
     "accept", _junk_dangling,
     reason="hash-dir lookup opens only <hash>.N by name; junk is never probed")


def _junk_subdir(ctx):
    ca = ctx.ca()
    d = ctx.shared_ca
    (d / f"{ctx.clause.id}-subdir").mkdir(exist_ok=True)
    (d / f"{ctx.clause.id}-README").write_text("site notes\n")
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store",
     "sub-directory and README in the store are ignored; valid CA verifies",
     "accept", _junk_subdir,
     reason="non-hash-named entries are invisible to X509_LOOKUP_hash_dir")


def _junk_empty_hashname(ctx):
    ca = ctx.ca()
    # an empty file whose name mimics a hash slot for a hash NO CA uses.
    (ctx.shared_ca / f"{ctx.clause.id}ee.0").write_bytes(b"")
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store",
     "empty file named like an unrelated hash slot is ignored",
     "accept", _junk_empty_hashname,
     reason="slot for a hash no placed CA has is never opened")


def _junk_dangling_crl(ctx):
    ca = ctx.ca()
    _symlink("missing.r0", ctx.shared_ca / f"{ctx.clause.id}-stale.r0")
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store",
     "dangling .r0 CRL symlink is harmless with CRL off; valid CA verifies",
     "accept", _junk_dangling_crl,
     reason="CRL loading is off; a broken .r0 for an unrelated hash is not read")


# --------------------------------------------------------------------------
# bundle-file (concatenated cafile) parity
# --------------------------------------------------------------------------

def _bundle_ok(ctx):
    ca = ctx.ca(to_bundle=True)
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store (bundle)",
     "concatenated CA-bundle file verifies an EEC",
     "accept", _bundle_ok, group="bundle",
     reason="cafile= path must reach the same verdict as a hashed dir")


def _bundle_unknown(ctx):
    ctx.ca(to_bundle=True)               # a decoy anchor lives in the bundle
    other = ctx.ca(place=False)          # this CA is NOT in the bundle
    eec = make_eec(other, leaf_dn(ctx))
    return ctx.cred([eec, other], eec)


_add("IGTF store (bundle)",
     "EEC chaining to a CA absent from the bundle is rejected",
     "reject", _bundle_unknown, group="bundle",
     reason="only CAs concatenated into cafile= are trust anchors")


def _bundle_middle(ctx):
    ctx.ca(to_bundle=True)
    mid = ctx.ca(to_bundle=True)
    ctx.ca(to_bundle=True)
    eec = make_eec(mid, leaf_dn(ctx))
    return ctx.cred([eec, mid], eec)


_add("IGTF store (bundle)",
     "CA in the middle of a multi-CA bundle still verifies",
     "accept", _bundle_middle, group="bundle",
     reason="bundle parsing must not stop at the first PEM block")


def _bundle_ec(ctx):
    ca = ctx.ca(to_bundle=True, key_type="ec", curve="P-384")
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("IGTF store (bundle)",
     "EC P-384 CA in the bundle verifies an EEC",
     "accept", _bundle_ec, group="bundle",
     reason="cafile parity holds for EC trust anchors")


def _bundle_expired(ctx):
    ca = ctx.ca(to_bundle=True, not_after_days=-1)
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("RFC5280 §4.1.2.5",
     "expired CA in the bundle is rejected as a trust anchor",
     "reject", _bundle_expired, group="bundle",
     reason="trust-anchor validity window applies to bundle CAs too")


def _bundle_many_middle(ctx):
    for _ in range(4):
        ctx.ca(to_bundle=True)
    mid = ctx.ca(to_bundle=True)
    for _ in range(4):
        ctx.ca(to_bundle=True)
    eec = make_eec(mid, leaf_dn(ctx))
    return ctx.cred([eec, mid], eec)


_add("IGTF store (bundle)",
     "CA deep inside a large concatenated bundle verifies",
     "accept", _bundle_many_middle, group="bundle",
     reason="all PEM blocks in the bundle are loaded as anchors")


def _bundle_wrong_chain(ctx):
    ca_a = ctx.ca(to_bundle=True)
    ca_b = ctx.ca(to_bundle=True)
    eec = make_eec(ca_a, leaf_dn(ctx))
    return ctx.cred([eec, ca_b], eec)     # wrong CA presented in the chain


_add("RFC5280 §6.1",
     "bundle: EEC presented under the wrong (non-issuing) CA is rejected",
     "reject", _bundle_wrong_chain, group="bundle",
     reason="issuer/subject + signature must match the true issuing CA")


# --------------------------------------------------------------------------
# trust-anchor validity windows
# --------------------------------------------------------------------------

def _expired_ca(ctx):
    ca = ctx.ca(not_after_days=-1)   # notAfter before the epoch -> long expired
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("RFC5280 §4.1.2.5",
     "expired CA in the hashed store is rejected",
     "reject", _expired_ca,
     reason="trust anchor past notAfter cannot validate a chain")


def _valid_alongside(ctx):
    ca = ctx.ca()   # a fresh valid CA in the same shared store
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("RFC5280 §6.1",
     "valid CA alongside expired/other CAs in the store still verifies",
     "accept", _valid_alongside,
     reason="one bad anchor in the store does not poison a good one")


def _not_yet_valid_ca(ctx):
    ca = ctx.ca(not_before_days=400, not_after_days=800)  # window opens in 2027
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("RFC5280 §4.1.2.5",
     "not-yet-valid CA (notBefore in the future) is rejected",
     "reject", _not_yet_valid_ca,
     reason="trust anchor before notBefore is not yet usable")


def _valid_window_ca(ctx):
    ca = ctx.ca(not_before_days=-10, not_after_days=3650)
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("RFC5280 §4.1.2.5",
     "CA inside its validity window verifies an EEC",
     "accept", _valid_window_ca,
     reason="notBefore < now < notAfter for the anchor")


# --------------------------------------------------------------------------
# store isolation: only placed CAs are trust anchors
# --------------------------------------------------------------------------

def _unknown_ca(ctx):
    ca = ctx.ca(place=False)   # minted but NOT placed in the store
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("RFC5280 §6.1",
     "EEC whose CA was never placed in the store is rejected",
     "reject", _unknown_ca,
     reason="a self-signed CA carried in the chain is not a trust anchor")


def _known_ca(ctx):
    ca = ctx.ca()
    eec = make_eec(ca, leaf_dn(ctx))
    return ctx.cred([eec, ca], eec)


_add("RFC5280 §6.1",
     "EEC whose CA is placed in the store is accepted",
     "accept", _known_ca,
     reason="chain terminates at a self-signed anchor present in the store")


def _wrong_ca_in_chain(ctx):
    ca_a = ctx.ca()
    ca_b = ctx.ca()
    eec = make_eec(ca_a, leaf_dn(ctx))
    return ctx.cred([eec, ca_b], eec)   # A signed the EEC but B is presented


_add("RFC5280 §6.1",
     "EEC presented under a different placed CA than its issuer is rejected",
     "reject", _wrong_ca_in_chain,
     reason="both CAs are trusted, but signature verification binds to the issuer")


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

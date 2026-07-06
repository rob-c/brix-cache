"""F1 — cross-user cache-hit re-authorization (threat T1).

The cache-transparency invariant: for principal B, the cache server's verdict on
(path, op) MUST equal the direct (cache-OFF) server's verdict. B is served the identical
bytes a privileged filler (svc) placed in the cache, so a cache HIT that ALLOWs — or denies
for a weaker tier — where the cold path DENIES is a cross-user leak.

Predicted RED against current main: the root cached-read path runs only the VO ACL
(open_cache.c:26), skipping the authdb + token-scope tiers the direct path enforces. carol
(same VO as the filler, NO authdb grant) is the sharpest probe.

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_authz_cachetransp.py -v
"""
import pytest

from mu_authz_lib.oracle import Cell, assert_cache_transparent

# The default policy (conftest_mu) grants /cms/secret.dat to {alice, svc} and denies
# {bob, carol, mallory}. Deciding tier for each denied subject on the DIRECT server:
#   carol   — same VO (cms), no authdb grant  -> authdb
#   mallory — same VO (cms), no authdb grant  -> authdb
#   bob     — different VO (atlas)            -> vo_acl
_DENIED = [("carol", "authdb"), ("mallory", "authdb"), ("bob", "vo_acl")]
_ALLOWED = ["alice"]

# Leak cells: {root, webdav} x {read, stat} x denied subjects (fill as svc).
_LEAK = [(proto, op, subj, tier)
         for proto in ("root", "webdav")
         for op in ("read", "stat")
         for subj, tier in _DENIED]

# Control cells: allowed subjects must be transparent (ALLOW cold and hot).
_OK = [(proto, op, subj)
       for proto in ("root", "webdav")
       for op in ("read", "stat")
       for subj in _ALLOWED]


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("proto,op,subject,tier", _LEAK,
                         ids=[f"{p}-{o}-{s}" for p, o, s, _ in _LEAK])
def test_cache_hit_does_not_leak(mu_fleet, cast, proto, op, subject, tier):
    """A denied subject must get the SAME denial (tier included) from the cache as from the
    direct server — cold and after a privileged fill. RED today (weaker VO-only hit gate)."""
    cell = Cell(proto=proto, op=op, subject=subject, path="/cms/secret.dat",
                filler="svc", expect_tier=tier)
    assert_cache_transparent(cell, cast)


@pytest.mark.privileged
@pytest.mark.parametrize("proto,op,subject", _OK,
                         ids=[f"{p}-{o}-{s}" for p, o, s in _OK])
def test_allowed_subject_is_transparent(mu_fleet, cast, proto, op, subject):
    """An authorized subject is served identically cold and hot (control — PASSES)."""
    cell = Cell(proto=proto, op=op, subject=subject, path="/cms/secret.dat", filler="svc")
    assert_cache_transparent(cell, cast)

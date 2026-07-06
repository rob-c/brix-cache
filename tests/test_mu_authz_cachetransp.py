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

from mu_authz_lib import corpus
from mu_authz_lib.oracle import Cell, assert_cache_transparent

_PROTOS = ("root", "webdav")
_OPS = ("read", "stat")

# Leak cells: every (object, denied-subject, protocol, op) — the cache must deny a denied
# subject exactly as the direct server does, cold and after a privileged (svc) fill.
_LEAK = [(o.path, proto, op, subj)
         for o in corpus.CORPUS
         for subj in corpus.denied_for(o)
         for proto in _PROTOS
         for op in _OPS]

# Control cells: every (object, authorized-subject, protocol, op) — transparent ALLOW.
_OK = [(o.path, proto, op, subj)
       for o in corpus.CORPUS
       for subj in corpus.allowed_for(o)
       for proto in _PROTOS
       for op in _OPS]


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("path,proto,op,subject", _LEAK,
                         ids=[f"{pa[1:].replace('/','_')}-{pr}-{o}-{s}"
                              for pa, pr, o, s in _LEAK])
def test_cache_hit_does_not_leak(mu_fleet, cast, path, proto, op, subject):
    """A denied subject must get the SAME verdict from the cache as from the direct server —
    cold and after a privileged fill. RED today (weaker/absent hit-path re-auth)."""
    cell = Cell(proto=proto, op=op, subject=subject, path=path, filler="svc")
    assert_cache_transparent(cell, cast)


@pytest.mark.privileged
@pytest.mark.parametrize("path,proto,op,subject", _OK,
                         ids=[f"{pa[1:].replace('/','_')}-{pr}-{o}-{s}"
                              for pa, pr, o, s in _OK])
def test_allowed_subject_is_transparent(mu_fleet, cast, path, proto, op, subject):
    """An authorized subject is served identically cold and hot (control — PASSES)."""
    cell = Cell(proto=proto, op=op, subject=subject, path=path, filler="svc")
    assert_cache_transparent(cell, cast)

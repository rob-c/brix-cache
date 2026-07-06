"""F3 — service-credential stage laundering (threat T3).

The origin fill runs under the service credential (origin_auth.c), which can read a file the
requesting user cannot. If the cache then serves those bytes to a user whose own authz would
deny them, the cache has laundered the service credential's reach. The invariant is the same
cache-transparency rule: a denied user's cache verdict must equal their direct verdict, even
though a privileged filler placed the bytes.

seed_service_only creates /cms/service-only.dat readable ONLY by svc (mode 0600). Predicted
RED against current main.

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_stage_laundering.py -v
"""
import pytest

from mu_authz_lib import corpus
from mu_authz_lib.oracle import Cell, assert_cache_transparent

# The FS-restricted objects (mode 0600) that only the service uid can physically read: the
# origin fill runs as the service identity, so these are the laundering probes.
_RESTRICTED = [o for o in corpus.CORPUS if o.mode == 0o600]

_LEAK = [(o.path, proto, op, subj)
         for o in _RESTRICTED
         for subj in corpus.denied_for(o)
         for proto in ("root", "webdav")
         for op in ("read", "stat")]


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("path,proto,op,subject", _LEAK,
                         ids=[f"{pa[1:].replace('/','_')}-{pr}-{o}-{s}"
                              for pa, pr, o, s in _LEAK])
def test_service_fill_not_served_to_denied_user(mu_fleet, cast, path, proto, op, subject):
    """A file only the service identity can read (mode 0600), filled by svc, must NOT be
    served from the cache to a user their own authz denies. RED today (stage laundering)."""
    cell = Cell(proto=proto, op=op, subject=subject, path=path, filler="svc")
    assert_cache_transparent(cell, cast)

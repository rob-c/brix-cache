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

from mu_authz_lib.oracle import Cell, assert_cache_transparent

_DENIED = ["carol", "bob", "mallory"]


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("proto", ["root", "webdav"])
@pytest.mark.parametrize("op", ["read", "stat"])
@pytest.mark.parametrize("subject", _DENIED)
def test_service_fill_not_served_to_denied_user(mu_fleet, cast, seed_service_only,
                                                proto, op, subject):
    """A file only the service identity can read, filled by svc, must NOT be served from the
    cache to a user their own authz denies."""
    cell = Cell(proto=proto, op=op, subject=subject, path=seed_service_only, filler="svc")
    assert_cache_transparent(cell, cast)

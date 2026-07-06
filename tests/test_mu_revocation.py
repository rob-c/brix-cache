"""F8 — revocation / staleness across the fill/serve boundary (threat T7).

Revocation must take effect on the NEXT request: the verdict is recomputed per operation. We
fill the cache HOT as an authorized principal (alice), revoke alice's access (expired token
or dropped gridmap entry), then measure the cache-hit serve — it must now DENY, matching the
direct server. Predicted RED on the cache-hit path (nothing re-checked on a root cache hit).

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_revocation.py -v
"""
import pytest

from mu_authz_lib import cache_state
from mu_authz_lib.oracle import authoritative, measure


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("what", ["token", "gridmap"])
def test_revoke_after_fill_denies_on_cache_hit(mu_fleet, cast, revoke, what):
    """Fill hot as alice, revoke alice, then the cache-hit serve must DENY (== direct)."""
    path = "/cms/secret.dat"
    rel = path.lstrip("/")
    cache_state.force_cold(rel)
    cache_state.fill_as(cast["alice"], rel, proto="root")
    assert cache_state.verify_hot(rel), "precondition: file must be cached before revocation"

    revoke(what, "alice")

    truth = authoritative("root", path, "read", cast["alice"])   # direct: now DENY
    got = measure("root", "cache", path, "read", cast["alice"])  # cache hit
    assert got == truth, (
        f"revocation ({what}) not honored on cache hit: cache={got} direct={truth}")

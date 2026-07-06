"""F8 — revocation / staleness across the fill/serve boundary (threat T7).

Revocation must take effect on the NEXT request: the verdict is recomputed per operation. We
fill the cache HOT as an authorized principal (alice), revoke alice's access (expired token
or dropped gridmap entry), then measure the cache-hit serve — it must now DENY, matching the
direct server. Predicted RED on the cache-hit path (nothing re-checked on a root cache hit).

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_revocation.py -v
"""
import pytest

from mu_authz_lib import cache_state, corpus
from mu_authz_lib.oracle import authoritative, measure

# Objects alice is authorized to read (so we can fill hot as alice, then revoke her).
_ALICE_OBJS = [o.path for o in corpus.CORPUS if "alice" in o.allow]

_CELLS = [(path, what, proto)
          for path in _ALICE_OBJS
          for what in ("token", "gridmap")
          for proto in ("root", "webdav")]


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("path,what,proto", _CELLS,
                         ids=[f"{pa[1:].replace('/','_')}-{w}-{pr}"
                              for pa, w, pr in _CELLS])
def test_revoke_after_fill_denies_on_cache_hit(mu_fleet, cast, revoke, path, what, proto):
    """Fill hot as alice, revoke alice (`what`), then the cache-hit serve must DENY (==direct).
    RED today on the hit path (nothing re-checked on a root cache hit)."""
    rel = path.lstrip("/")
    cache_state.force_cold(rel)
    cache_state.fill_as(cast["alice"], rel, proto=proto)
    assert cache_state.verify_hot(rel), "precondition: file must be cached before revocation"

    revoke(what, "alice")

    truth = authoritative(proto, path, "read", cast["alice"])   # direct: now DENY
    got = measure(proto, "cache", path, "read", cast["alice"])  # cache hit
    assert got == truth, (
        f"revocation ({what}) not honored on {proto} cache hit: cache={got} direct={truth}")

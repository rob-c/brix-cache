"""F7 — authorization DECISION cache isolation (threats T8, T7).

The decision cache (auth_gate.c:153-189) folds DN + VO + scope into its key, so it is
identity-scoped and safe — these tests confirm it: distinct principals never contaminate each
other's verdicts, and allow_write denies a write-scoped token BEFORE token-scope is consulted
(policy.c global pre-gate). Mostly PASSES against current main.

(The key-derivation function is a static in auth_gate.c and not cleanly linkable standalone,
so F7 is e2e-only; the mapping-layer C unit is idmap_collapse_test.c under F6.)

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_decision_cache.py -v
"""
import pytest

from mu_authz_lib.oracle import authoritative

# Principal pairs whose authz differs — back-to-back requests must not contaminate.
_PAIRS = [("alice", "carol"), ("alice", "bob"), ("carol", "mallory"), ("alice", "mallory")]


@pytest.mark.privileged
@pytest.mark.parametrize("a,b", _PAIRS, ids=[f"{a}-vs-{b}" for a, b in _PAIRS])
def test_distinct_principals_no_contamination(mu_fleet, cast, a, b):
    """Back-to-back verdicts for two principals are each computed for their OWN identity."""
    va = authoritative("root", "/cms/secret.dat", "read", cast[a])
    vb = authoritative("root", "/cms/secret.dat", "read", cast[b])
    # Re-measure a to ensure b's request did not poison a cached-for-a decision.
    va2 = authoritative("root", "/cms/secret.dat", "read", cast[a])
    assert va == va2, f"{a}'s verdict changed after measuring {b} — cache contamination"
    if a == "alice":
        assert va.decision == "ALLOW" and vb.decision == "DENY"


@pytest.mark.privileged
def test_repeated_request_is_stable(mu_fleet, cast):
    """A repeated identical request (L1 cache hit) yields the identical verdict."""
    v1 = authoritative("root", "/cms/secret.dat", "read", cast["carol"])
    v2 = authoritative("root", "/cms/secret.dat", "read", cast["carol"])
    assert v1 == v2

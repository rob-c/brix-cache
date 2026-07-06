"""Self-test for the differential oracle logic (stubbed adapters; no fleet)."""
import pytest

from mu_authz_lib import oracle
from mu_authz_lib.verdict import Verdict

_CAST = {"carol": object(), "svc": object()}


def test_passes_when_cache_matches_direct(monkeypatch):
    # direct, cache-cold, cache-hot all DENY at authdb → transparent.
    monkeypatch.setattr(oracle, "measure",
                        lambda *a, **k: Verdict("DENY", "not authorized", "authdb"))
    monkeypatch.setattr(oracle, "_fill", lambda *a, **k: None)
    monkeypatch.setattr(oracle.cache_state, "force_cold", lambda *a, **k: None)
    cell = oracle.Cell(proto="root", op="read", subject="carol", path="/cms/secret.dat")
    oracle.assert_cache_transparent(cell, _CAST)   # no raise


def test_fails_on_leak_when_cache_allows_but_direct_denies(monkeypatch):
    def fake_measure(proto, variant, path, op, principal):
        return (Verdict("DENY", "not authorized", "authdb") if variant == "direct"
                else Verdict.allow())
    monkeypatch.setattr(oracle, "measure", fake_measure)
    monkeypatch.setattr(oracle, "_fill", lambda *a, **k: None)
    monkeypatch.setattr(oracle.cache_state, "force_cold", lambda *a, **k: None)
    cell = oracle.Cell(proto="root", op="read", subject="carol", path="/cms/secret.dat")
    with pytest.raises(AssertionError) as ei:
        oracle.assert_cache_transparent(cell, _CAST)
    msg = str(ei.value)
    assert "LEAK" in msg and "carol" in msg and "open_cache.c" in msg


def test_fails_on_weaker_tier(monkeypatch):
    # direct DENIES at authdb; cache DENIES but only at the weaker vo_acl tier → still a leak.
    def fake_measure(proto, variant, path, op, principal):
        return (Verdict("DENY", "not authorized", "authdb") if variant == "direct"
                else Verdict("DENY", "VO not authorized", "vo_acl"))
    monkeypatch.setattr(oracle, "measure", fake_measure)
    monkeypatch.setattr(oracle, "_fill", lambda *a, **k: None)
    monkeypatch.setattr(oracle.cache_state, "force_cold", lambda *a, **k: None)
    cell = oracle.Cell(proto="root", op="read", subject="carol", path="/cms/secret.dat")
    with pytest.raises(AssertionError):
        oracle.assert_cache_transparent(cell, _CAST)


def test_expect_tier_mismatch_raises(monkeypatch):
    monkeypatch.setattr(oracle, "measure",
                        lambda *a, **k: Verdict("DENY", "VO not authorized", "vo_acl"))
    monkeypatch.setattr(oracle, "_fill", lambda *a, **k: None)
    monkeypatch.setattr(oracle.cache_state, "force_cold", lambda *a, **k: None)
    cell = oracle.Cell(proto="root", op="read", subject="carol", path="/cms/secret.dat",
                       expect_tier="authdb")
    with pytest.raises(AssertionError) as ei:
        oracle.assert_cache_transparent(cell, _CAST)
    assert "tier mismatch" in str(ei.value)

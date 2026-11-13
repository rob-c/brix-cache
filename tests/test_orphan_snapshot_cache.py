"""Process snapshots remain bounded and useful when native inspection is slow."""
from types import SimpleNamespace

import pytest

from brix_suite import orphans


@pytest.fixture
def snapshot_clock(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(orphans, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(orphans, "_PS_CACHE", {"at": 0.0, "table": {}})
    return clock


def test_slow_snapshot_is_cached_from_completion(monkeypatch, snapshot_clock):
    calls = []

    def snapshot():
        calls.append(True)
        snapshot_clock[0] += orphans._PS_TTL * 2
        return {701: (1, "helper", [], [])}

    monkeypatch.setattr(orphans, "_host_process_table", snapshot)
    first = orphans._ps_table()
    assert orphans._ps_table() is first
    assert len(calls) == 1


def test_expired_snapshot_cannot_keep_old_ownership(monkeypatch, snapshot_clock):
    snapshots = iter([{701: (1, "helper", [], [])}, {702: (1, "other", [], [])}])
    monkeypatch.setattr(orphans, "_host_process_table", lambda: next(snapshots))
    assert 701 in orphans._ps_table()
    snapshot_clock[0] += orphans._PS_TTL + 1
    assert 701 not in orphans._ps_table()


def test_failed_snapshot_does_not_refresh_cache_age(monkeypatch, snapshot_clock):
    def denied():
        raise RuntimeError("native process ownership unavailable")

    monkeypatch.setattr(orphans, "_host_process_table", denied)
    with pytest.raises(RuntimeError, match="ownership unavailable"):
        orphans._ps_table()
    assert orphans._PS_CACHE == {"at": 0.0, "table": {}}

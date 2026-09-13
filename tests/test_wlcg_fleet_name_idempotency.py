"""``lc-wlcg`` acquisition is idempotent: one red must not become fifteen.

``WlcgInstance`` claims the fixed lifecycle name ``lc-wlcg`` in ``__init__`` and
releases it only in ``stop()``.  Several conformance tests build an instance
purely to call ``configtest()`` and never start (so never stop) it, and any body
that fails between construction and the ``finally: inst.stop()`` leaves the name
held.  Every later construction in that worker then dies in ``register()`` with
``ValueError: server already registered: lc-wlcg`` — a lane-1 run lost 15 rows
across three files that way, and the 15 messages all named the registry rather
than whatever actually failed first.  A cascade that hides its own cause is
worse than the failure under it.

``wlcg_fleet._release_stale`` makes acquisition self-healing.  These rows pin
the three properties the fix rests on: it releases the name, it stops the prior
server BEFORE unregistering it (unregistering a live server would orphan the
process still holding ledger port 31020), and it touches nothing but the exact
name it was given.

Run:
    PYTHONPATH=tests pytest tests/test_wlcg_fleet_name_idempotency.py -v
"""

from __future__ import annotations

import pytest
from types import SimpleNamespace

import wlcg_fleet

from brix_suite.registry import (
    NginxInstanceSpec,
    register_nginx,
    registered_specs,
    unregister,
)
from wlcg_fleet import WlcgInstance, _release_stale

# The subject is the real fixed-port ledger name, and ``register()`` wipes a
# stale prefix under REGISTRY_ROOT, so this module shares the conformance
# suites' worker pin rather than racing a live instance.
pytestmark = [pytest.mark.timeout(120), pytest.mark.xdist_group("lc-wlcg")]

NAME = "lc-wlcg"


class _RecordingHarness:
    """A harness whose only job is to say what ``_release_stale`` asked it to do."""

    def __init__(self, fail: bool = False):
        self.calls: list[str] = []
        self.launcher = self
        self._fail = fail

    def stop(self, name: str) -> None:
        self.calls.append(f"stop:{name}")
        if self._fail:
            raise RuntimeError("no such instance")


def _hold(name: str) -> None:
    """Register ``name`` the way an instance that never stopped would leave it."""
    register_nginx(NginxInstanceSpec(name=name, template="nginx_wlcg_conformance.conf",
                                     protocol="https", port=1))


def _registered(name: str) -> bool:
    return any(spec.name == name for spec in registered_specs())


def test_a_stale_claim_does_not_block_the_next_instance(tmp_path):
    """(success) Two constructions in a row, the first never stopped.

    This is the exact shape the cascade came from: a test body that raises
    between ``WlcgInstance(...)`` and its ``finally``.  The second construction
    must succeed and own the ledger port, not inherit someone else's failure.
    """
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    first = WlcgInstance(tmp_path / "first", ca_dir=ca_dir, signing_policy="off")
    try:
        assert _registered(NAME)
        second = WlcgInstance(tmp_path / "second", ca_dir=ca_dir, signing_policy="off")
        try:
            assert second.davs_port == first.davs_port, (
                "the second instance did not take over the ledger port")
            assert _registered(NAME)
        finally:
            second.stop()
    finally:
        unregister(NAME)                      # first was never started
    assert not _registered(NAME)


def test_release_stops_before_unregistering_and_survives_a_dead_instance():
    """(error) Ordering, and the error path that is the common case.

    Unregistering first would drop the only record of the prefix and pidfile
    while the process still held port 31020 — trading a loud ValueError for a
    silent bind() failure one layer down.  And the usual stale claim has nothing
    running behind it, so ``stop`` raising must not abort the release.
    """
    harness = _RecordingHarness(fail=True)
    _hold(NAME)
    try:
        _release_stale(harness, NAME)
    finally:
        unregister(NAME)
    assert harness.calls == [f"stop:{NAME}"], (
        "the prior server must be stopped exactly once, before the unregister")
    assert not _registered(NAME), "a dead instance's claim was left held"


def test_release_touches_only_the_exact_name():
    """(security-negative) No prefix matching, and no work when nothing is held.

    ``lc-wlcg`` is a prefix of ``lc-wlcgconf-*``, seven live conformance
    instances on their own ports.  A release that matched by prefix — or one
    that stopped servers speculatively when the name was free — would take down
    another test's fleet to fix a registration this one does not even hold.
    """
    other = "lc-wlcgconf-bundle-idempotency-decoy"
    harness = _RecordingHarness()
    _hold(other)
    try:
        _release_stale(harness, NAME)
        assert harness.calls == [], (
            "an unheld name must cost nothing: no stop() was warranted")
        assert _registered(other), "a same-prefix instance was released"
    finally:
        unregister(other)


def _reload_subject(monkeypatch, snapshots):
    """Drive the worker transition without signalling a real fleet."""
    states = iter(snapshots)
    elapsed = [0.0]
    signals = []

    def advance(seconds):
        elapsed[0] += seconds

    monkeypatch.setattr(wlcg_fleet, "time", SimpleNamespace(
        monotonic=lambda: elapsed[0], sleep=advance))
    instance = object.__new__(WlcgInstance)
    instance._name = NAME
    instance._harness = SimpleNamespace(
        process_snapshot=lambda name: next(states, snapshots[-1]),
        reload=signals.append,
    )
    return instance, elapsed, signals


def test_reload_waits_for_old_workers_to_drain(monkeypatch):
    """New workers alongside old ones do not yet guarantee fresh trust data."""
    instance, elapsed, signals = _reload_subject(monkeypatch, [
        [(1, "master"), (2, "worker")],
        [(1, "master"), (2, "worker shutting down"), (3, "worker")],
        [(1, "master"), (3, "worker")],
    ])
    instance.reload()
    assert elapsed[0] > 0
    assert signals == [NAME]


def test_reload_without_replacement_workers_fails(monkeypatch):
    """An empty worker set must never masquerade as a successful reload."""
    instance, _, _ = _reload_subject(monkeypatch, [
        [(1, "master"), (2, "worker")], [(1, "master")],
    ])
    with pytest.raises(RuntimeError, match="reload did not replace"):
        instance.reload()


def test_reload_cannot_accept_the_old_worker_generation(monkeypatch):
    """A live old worker still has the old revocation and policy decisions."""
    instance, _, _ = _reload_subject(monkeypatch, [
        [(1, "master"), (2, "worker")],
    ])
    with pytest.raises(RuntimeError, match="reload did not replace"):
        instance.reload()

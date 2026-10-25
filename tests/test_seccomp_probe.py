"""The seccomp readiness probe must observe kernel state on real workers."""

import pytest

from lib_py import seccomp_probe as probe


@pytest.fixture
def worker_probe(monkeypatch, tmp_path):
    """Provide an owned master pid and a deterministic clock, without procfs."""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "nginx.pid").write_text("123", encoding="utf-8")
    sleeps = []
    monkeypatch.setattr(probe.time, "monotonic", lambda: len(sleeps) * 0.05)
    monkeypatch.setattr(probe.time, "sleep", sleeps.append)
    monkeypatch.setattr(probe, "children_of", lambda master: {456, 789} if master == 123 else set())
    monkeypatch.setattr(probe, "process_cmdline", lambda pid:
                        b"nginx: worker process" if pid == 456 else b"nginx: cache manager process")
    return tmp_path, sleeps


def test_probe_waits_for_worker_initialization(monkeypatch, worker_probe):
    """A listener's transient unfiltered worker is not the final filter state."""
    root, sleeps = worker_probe
    modes = iter(("0", "2"))
    monkeypatch.setattr(probe, "_seccomp_mode", lambda _: next(modes))
    assert probe.worker_seccomp(root) == "2"
    assert sleeps == [0.05]


def test_probe_does_not_hide_an_unfiltered_worker(monkeypatch, worker_probe):
    """An actual unfiltered worker still fails closed at the deadline."""
    root, _ = worker_probe
    monkeypatch.setattr(probe, "_seccomp_mode", lambda _: "0")
    assert probe.worker_seccomp(root, timeout=0) == "0"


def test_filtered_manager_cannot_masquerade_as_filtered_worker(monkeypatch, worker_probe):
    """A filtered non-worker must not turn an absent worker into a pass."""
    root, _ = worker_probe
    monkeypatch.setattr(probe, "process_cmdline", lambda _: b"nginx: cache manager process")
    monkeypatch.setattr(probe, "_seccomp_mode", lambda _: pytest.fail("non-worker inspected"))
    assert probe.worker_seccomp(root, timeout=0) is None

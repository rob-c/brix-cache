"""Rollback contracts for partially realized case graphs."""

import sys

import pytest

from brixtest import case, probe, register_extension, server
from brixtest.errors import CaseRunError
from brixtest.runtime.manager import CaseManager


def _definition(*resources, backend="local"):
    @case(*resources, backend=backend, observe=(), keep="always")
    def declared(run):
        return None

    return declared.__brixtest_case__


class _FailingBackend:
    def __init__(self):
        self.calls = []

    def validate(self, declaration):
        self.calls.append("validate")

    def plan(self, context):
        self.calls.append("plan")
        return {"backend": "transaction-test"}

    def prepare(self, context):
        self.calls.append("prepare")

    def start(self, context):
        self.calls.append("start")
        raise RuntimeError("partial start")

    def stop(self, context):
        self.calls.append("stop")

    def collect(self, context):
        self.calls.append("collect")
        return {"rollback": "observed"}


def test_backend_start_failure_runs_stop_then_collect(tmp_path):
    backend = _FailingBackend()
    register_extension("backend", "transaction-test", backend, replace=True)
    manager = CaseManager(
        _definition(backend="transaction-test"),
        "transaction::backend", root=tmp_path / "run",
    )
    with pytest.raises(CaseRunError, match="partial start"):
        manager.start()
    assert backend.calls == ["validate", "plan", "prepare", "start", "stop", "collect"]


def test_partial_local_fleet_failure_reaps_every_started_process(tmp_path):
    running = server(
        "a-running",
        command=(sys.executable, "-c", "import time; time.sleep(30)"),
        probe=probe("none"),
    )
    broken = server(
        "z-broken", command=("/definitely-not-a-brixtest-executable",),
        probe=probe("none"),
    )
    manager = CaseManager(
        _definition(running, broken),
        "transaction::processes", root=tmp_path / "run",
    )
    with pytest.raises(CaseRunError, match="z-broken"):
        manager.start()
    assert manager._started == []
    assert manager._backend.process_pids() == {}

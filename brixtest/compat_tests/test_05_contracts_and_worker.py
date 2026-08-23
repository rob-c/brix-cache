"""Compatibility tests for kind contracts and process-worker RPC.

The kind contract is how a project proves its adapter registrations
against the core's expectations without booting anything; the worker
runner is how a test drives an out-of-process client and still gets a
typed answer — including when the far side fails.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from brixtest.clients import WorkerRunner
from brixtest.fleet.kinds import get_kind
from brixtest.testing import check_kind_contract


def test_09_the_process_kind_honours_the_kind_contract():
    assert check_kind_contract(get_kind("process")) == []


def test_10_procworker_roundtrip_and_error_frames():
    worker = Path(__file__).with_name("example_worker.py")
    src = Path(__file__).resolve().parents[1] / "src"
    with WorkerRunner(
        [sys.executable, str(worker)], env={"PYTHONPATH": str(src)}
    ) as runner:
        assert runner.call("add", {"a": 2, "b": 40}) == 42
        with pytest.raises(RuntimeError) as err:
            runner.call("boom")
        assert "ValueError" in str(err.value)
        assert "deliberate failure" in str(err.value)
        with pytest.raises(RuntimeError) as err2:
            runner.call("no_such_op")
        assert "UnknownOp" in str(err2.value)


def test_11_named_client_runs_argv_without_shell_expansion(brix):
    """Shell metacharacters stay literal client arguments (security-negative)."""
    sentinel = brix.workspace / "shell-expansion-must-not-run"
    payload = "$(touch %s)" % sentinel
    result = brix.client("python").run(
        "-c", "import sys; print(sys.argv[1])", payload
    )
    assert result.stdout.strip() == payload
    assert not sentinel.exists()

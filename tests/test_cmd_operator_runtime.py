from pathlib import Path

from cmdscripts import operator_runtime
from cmdscripts.operator_runtime import run_checks


def test_operator_runtime_ports_are_importable(tmp_path: Path):
    results = run_checks(tmp_path)
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)


def test_pytest_lane_passes_through_a_green_run(monkeypatch):
    calls = []
    monkeypatch.setattr(operator_runtime, "_run_stream",
                        lambda argv, **k: (calls.append(argv), 0)[1])
    assert operator_runtime._pytest_lane(["tests"], ["-n", "4"], ["-q"]) is True
    assert len(calls) == 1
    assert calls[0][-4:] == ["tests", "-n", "4", "-q"]


def test_pytest_lane_fails_fast_with_no_retry(monkeypatch):
    """A first-pass failure is final: no --lf rerun may launder it away."""
    calls = []
    monkeypatch.setattr(operator_runtime, "_run_stream",
                        lambda argv, **k: (calls.append(argv), 1)[1])
    assert operator_runtime._pytest_lane(["tests"], ["-n", "4"], ["-q"]) is False
    assert len(calls) == 1, "retry ladder must stay dead"
    assert "--lf" not in calls[0]


def test_pytest_lane_composes_selection_main_common_in_order(monkeypatch):
    seen = {}
    monkeypatch.setattr(operator_runtime, "_run_stream",
                        lambda argv, **k: (seen.setdefault("argv", argv), 0)[1])
    operator_runtime._pytest_lane(["a", "b"], ["c"], ["d"])
    assert seen["argv"][-4:] == ["a", "b", "c", "d"]
    assert seen["argv"][:3][-2:] == ["-m", "pytest"]

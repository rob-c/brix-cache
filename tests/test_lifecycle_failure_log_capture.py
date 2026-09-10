"""
tests/test_lifecycle_failure_log_capture.py — a failed ``lifecycle`` test
carries its instances' error.log tails in the report.

History §21(g): a harness that tears its servers down must capture their
logs into the failure artifact at the moment of failure.  Fail-fast race-hunt
run 39 halted on a phase-116 lifecycle test whose only evidence, the
instance's ``logs/error.log``, was removed by the fixture's own teardown
before anyone read it — crash-vs-close became undecidable.  The
``pytest_runtest_makereport`` hookwrapper in brix_suite/harness/fixtures.py
(re-exported through tests/conftest.py) runs before fixture teardown and
appends one section per instance.

  success       — a failed call report on a ``lifecycle`` test gains one
                  section per started instance, holding the last lines of
                  its error.log, and the hook is registered on the live
                  plugin manager through the conftest re-export;
  error         — a missing log, an unreadable (directory) log and an
                  unregistered name are skipped without raising, and passing
                  or non-call reports are left untouched;
  security-neg  — a multi-megabyte, non-UTF-8 log costs one bounded read:
                  the section holds exactly the last 40 lines, decoded
                  leniently, and the hook never touches an item that has no
                  ``lifecycle`` argument.

Run:
    PYTHONPATH=tests pytest tests/test_lifecycle_failure_log_capture.py -v
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from brix_suite.harness import fixtures as harness_fixtures
from brix_suite.harness.fixtures import (
    ERROR_LOG_TAIL_LINES,
    error_log_sections,
    pytest_runtest_makereport,
)
import server_launcher
from server_launcher import LifecycleHarness


def _harness_with(paths: dict[str, Path]) -> LifecycleHarness:
    harness = LifecycleHarness.__new__(LifecycleHarness)
    harness._names = list(paths)
    harness.error_log_paths = lambda: paths  # type: ignore[method-assign]
    return harness


def _run_hook(item, report) -> object:
    """Drive the hookwrapper generator the way pluggy does."""
    gen = pytest_runtest_makereport(item, call=None)
    next(gen)
    with pytest.raises(StopIteration):
        gen.send(SimpleNamespace(get_result=lambda: report))
    return report


def _report(when: str = "call", failed: bool = True) -> SimpleNamespace:
    return SimpleNamespace(when=when, failed=failed, sections=[])


def _item(harness) -> SimpleNamespace:
    return SimpleNamespace(funcargs={"lifecycle": harness} if harness is not None else {})


def _write_log(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True)
    path.write_text(text)
    return path


def _write_huge_log(path: Path, total: int) -> Path:
    """``total`` lines, each ending in two bytes that are not UTF-8."""
    path.parent.mkdir(parents=True)
    with path.open("wb") as fh:
        for i in range(total):
            fh.write(b"line %d \xff\xfe\n" % i)
    return path


# --------------------------------------------------------------------------
# success


def test_failed_lifecycle_call_report_gains_one_section_per_instance(tmp_path):
    a = _write_log(tmp_path / "a" / "logs" / "error.log", "a line 0\na line 1\na line 2\n")
    b = _write_log(tmp_path / "b" / "logs" / "error.log",
                   "2026/09/07 12:10:14 [alert] worker process exited on signal 11\n")

    report = _run_hook(_item(_harness_with({"lc-a": a, "lc-b": b})), _report())

    assert [title for title, _ in report.sections] == [
        "lifecycle error.log tail [lc-a]",
        "lifecycle error.log tail [lc-b]",
    ]
    assert report.sections[0][1].splitlines() == ["a line 0", "a line 1", "a line 2"]
    assert "exited on signal 11" in report.sections[1][1]


def test_hook_is_registered_on_the_live_plugin_manager(request):
    impls = request.config.hook.pytest_runtest_makereport.get_hookimpls()
    ours = [impl for impl in impls if impl.function is harness_fixtures.pytest_runtest_makereport]
    assert ours, "conftest.py must re-export pytest_runtest_makereport from harness.fixtures"
    assert ours[0].hookwrapper or ours[0].wrapper


def test_error_log_paths_follow_the_registered_names(monkeypatch):
    harness = LifecycleHarness.__new__(LifecycleHarness)
    harness._names = ["lc-x", "lc-y"]
    monkeypatch.setattr(harness, "_spec", lambda name: name, raising=False)
    # server_launcher_part3 is exec-composed into server_launcher: the
    # method's globals are the parent's namespace, so patch the name there.
    monkeypatch.setattr(server_launcher, "endpoint_for",
                        lambda spec: SimpleNamespace(prefix=f"/tmp/prefix-{spec}"))
    assert harness.error_log_paths() == {
        "lc-x": Path("/tmp/prefix-lc-x/logs/error.log"),
        "lc-y": Path("/tmp/prefix-lc-y/logs/error.log"),
    }


# --------------------------------------------------------------------------
# error


def test_missing_unreadable_and_unregistered_logs_are_skipped(tmp_path, monkeypatch):
    missing = tmp_path / "gone" / "logs" / "error.log"
    directory = tmp_path / "dir"
    directory.mkdir()
    assert error_log_sections({"lc-missing": missing, "lc-dir": directory}) == []

    harness = LifecycleHarness.__new__(LifecycleHarness)
    harness._names = ["lc-unregistered"]

    def _raise(name):
        raise KeyError(name)

    monkeypatch.setattr(harness, "_spec", _raise, raising=False)
    assert harness.error_log_paths() == {}


@pytest.mark.parametrize("when,failed", [("call", False), ("setup", True), ("teardown", True)])
def test_passing_and_non_call_reports_are_left_untouched(tmp_path, when, failed):
    log = _write_log(tmp_path / "logs" / "error.log", "should not be captured\n")
    report = _run_hook(_item(_harness_with({"lc": log})), _report(when=when, failed=failed))
    assert report.sections == []


# --------------------------------------------------------------------------
# security-neg


def test_a_huge_non_utf8_log_costs_one_bounded_read(tmp_path):
    total = 200_000
    log = _write_huge_log(tmp_path / "logs" / "error.log", total)
    assert log.stat().st_size > 2 * 1024 * 1024

    (title, body), = error_log_sections({"lc-big": log})

    lines = body.splitlines()
    assert len(lines) == ERROR_LOG_TAIL_LINES
    assert lines[-1].startswith(f"line {total - 1} ")
    assert lines[0].startswith(f"line {total - ERROR_LOG_TAIL_LINES} ")
    assert "\ufffd" in lines[-1]
    assert title == "lifecycle error.log tail [lc-big]"


def test_items_without_a_lifecycle_argument_are_ignored():
    report = _run_hook(_item(None), _report())
    assert report.sections == []
    not_a_harness = SimpleNamespace(error_log_paths=lambda: {"x": Path("/nonexistent")})
    report = _run_hook(_item(not_a_harness), _report())
    assert report.sections == []

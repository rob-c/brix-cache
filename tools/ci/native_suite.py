#!/usr/bin/env python3
"""Run the canonical full suite with fresh per-lane JUnit and aggregate counts.

The caller selects the server, modules, reference tools and private TEST_ROOT
through the normal test-runner environment. No dependency or skip is hidden.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.logging_support import diagnostic  # noqa: E402


def report_counts(reports):
    """Count actual JUnit records, including setup errors and explicit skips."""
    totals = dict(tests=0, passed=0, failed=0, errors=0, skipped=0)
    for report in reports:
        for case in ET.parse(report).getroot().iter("testcase"):
            totals["tests"] += 1
            outcome = next((name for name, tag in (("errors", "error"),
                ("failed", "failure"), ("skipped", "skipped"))
                if case.find(tag) is not None), "passed")
            totals[outcome] += 1
    return totals


def _copy_diagnostic_tail(source, target, limit=1024 * 1024):
    """Keep bounded optional diagnostics, never follow a fixture's symlink."""
    if source.is_symlink() or not source.is_file():
        return
    with source.open('rb') as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - limit))
        content = stream.read(limit)
    with target.open('xb') as output:
        output.write(content)


def _retain_lane_diagnostics(report):
    """Capture kill attribution before the scheduler cleans the completed lane."""
    selected = os.environ.get('TEST_ROOT')
    if not selected or not report.is_file():
        return
    root = Path(selected).resolve()
    registry = Path(os.environ.get('TEST_REGISTRY_ROOT', str(root / 'registry')))
    sources = [('kill-diag.log', root / 'kill-diag.log'),
               ('sentinel.txt', registry / '.fleet-sentinel-abort')]
    for label, source in sources:
        try:
            source.resolve().relative_to(root)
            _copy_diagnostic_tail(source, report.with_name(report.stem + '.' + label))
        except (OSError, ValueError) as error:
            diagnostic('WARN', __file__, 'diagnostic_retention',
                       f'cannot retain {label}: {type(error).__name__}')


def execute_suite(runner, directory, workers, include_suite_jobs=False):
    """Use the existing lane scheduler; change only each lane's report path."""
    original = runner._pytest_lane
    reports = []

    def lane(selection, parallel, common, timeout=None):
        report = directory / f"lane-{len(reports) + 1}.xml"
        reports.append(report)
        try:
            return original(selection, parallel, [*common, "-p", "tools.ci.native_suite",
                                                 "--junitxml=" + str(report)],
                            timeout=timeout)
        finally:
            _retain_lane_diagnostics(report)

    runner._pytest_lane = lane
    modules = os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep)
    arguments = ["-n", str(workers)]
    arguments += [part for module in modules if module
                  for part in ("--nginx-load-module", module)]
    if include_suite_jobs:
        arguments.append("--include-suite-jobs")
    try:
        return runner.run_suite([*arguments, "--", "--tb=short"]), reports
    finally:
        runner._pytest_lane = original


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--include-suite-jobs", action="store_true")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be positive")
    return args


def _live_outcome(report):
    """Ignore successful setup/teardown and preserve explicit expected failures."""
    if report.failed:
        return "failed" if report.when == "call" else "errors"
    if report.skipped:
        return "xfailed" if hasattr(report, "wasxfail") else "skipped"
    if report.when == "call":
        return "xpassed" if hasattr(report, "wasxfail") else "passed"
    return None


class _LiveEvidence:
    """Controller-only live observations; final totals always come from JUnit."""

    def __init__(self, report):
        self.report = Path(report)
        # Match pytest's per-run XML ownership. Reusing a report path must not
        # append old failures or retain a previous finished/conserved verdict.
        # Unlink names, rather than truncate through a possible stale symlink.
        for suffix in ('.failures.jsonl', '.progress.json'):
            self.report.with_suffix(suffix).unlink(missing_ok=True)
        self.outcomes = {}
        self.collected = 0
        self.started = time.monotonic()
        self.finished = False
        self.exit_status = None

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node, ids):
        self.collected = len(ids)

    def pytest_collection_finish(self, session):
        if session.items:
            self.collected = len(session.items)

    def _snapshot(self):
        from collections import Counter

        target = self.report.with_suffix(".progress.json")
        temporary = target.with_suffix(".tmp")
        record = dict(live_observation=True, collected=self.collected,
            completed=len(self.outcomes), outcomes=dict(Counter(self.outcomes.values())),
            elapsed_seconds=time.monotonic() - self.started,
            session_finished=self.finished, exit_status=self.exit_status)
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        os.replace(temporary, target)

    def pytest_runtest_logreport(self, report):
        outcome = _live_outcome(report)
        if outcome is None:
            return
        self.outcomes[report.nodeid] = outcome
        if report.failed:
            record = dict(nodeid=report.nodeid, when=report.when,
                          outcome=outcome, detail=report.longreprtext)
            with self.report.with_suffix(".failures.jsonl").open("a") as stream:
                stream.write(json.dumps(record) + "\n")
        if report.failed or len(self.outcomes) % 250 == 0:
            self._snapshot()

    def pytest_sessionfinish(self, session, exitstatus):
        self.finished = True
        self.exit_status = int(exitstatus)
        self._snapshot()


def pytest_configure(config):
    """Nested helpers and xdist workers must not compete for controller files."""
    report = getattr(config.option, "xmlpath", None)
    if not report or hasattr(config, "workerinput"):
        return
    config.pluginmanager.register(_LiveEvidence(report), "native-live-evidence")


def _evidence_exit_code(totals, complete, code):
    """Keep runner failures and refuse zero-test or incomplete green results."""
    evidence_failure = not all((complete, totals["tests"] > 0,
                                totals["failed"] == 0, totals["errors"] == 0))
    if code == 0:
        return int(evidence_failure)
    return code


def _lane_execution_complete(report):
    """A finalized XML file cannot certify tests which never ran.

    Require the controller's final collection/execution conservation record.
    A failed assertion can finish a lane; interruption or absent evidence cannot.
    """
    try:
        record = json.loads(report.with_suffix('.progress.json').read_text())
    except (OSError, ValueError):
        return False
    if not isinstance(record, dict):
        return False
    collected, completed = record.get('collected'), record.get('completed')
    return all((record.get('session_finished') is True,
                type(collected) is int, type(completed) is int,
                isinstance(collected, int) and collected > 0,
                completed == collected,
                type(record.get('exit_status')) is int,
                record.get('exit_status') in (0, 1)))


def _report_completeness(reports, existing):
    """Keep report availability distinct from completed test execution."""
    present = bool(reports) and len(existing) == len(reports)
    executed = present and all(_lane_execution_complete(report) for report in reports)
    return present, executed


def _finalize_report(directory, reports, code, started, args):
    """Missing evidence is a failure, not an empty green test run."""
    existing = [report for report in reports if report.is_file()]
    totals = report_counts(existing)
    complete, executed = _report_completeness(reports, existing)
    code = _evidence_exit_code(totals, executed, code)
    summary = dict(platform=sys.platform, exit_code=code, reports_complete=complete,
        execution_complete=executed,
        elapsed_seconds=time.monotonic() - started, totals=totals,
        includes_suite_jobs=args.include_suite_jobs,
        excludes_linux_userns_directory=True)
    summary.update(_reference_lane_identity())
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    diagnostic("INFO" if code == 0 else "ERROR", __file__, "suite_complete",
               f"reports={directory} counts={totals} exit_code={code}")
    return code


def _reference_lane_identity():
    """The full scheduler may use remote clients, but cannot call them native."""
    if 'TEST_XRDCL_REMOTE_COMMAND' not in os.environ:
        return {}
    return dict(mode='full-suite-remote-python-reference', native_full_suite=False,
                reference_python_mode='remote', reference_cli_mode='native', reference_daemon_mode='native',
                native_dependency_results_replaced=False)


def main(argv=None):
    args = _arguments(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="native-suite-", dir=args.output.resolve()))
    os.chdir(ROOT)
    sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "brixtest/src")]
    from cmdscripts import operator_runtime as runner  # noqa: PLC0415

    started = time.monotonic()
    code, reports = execute_suite(runner, directory, args.workers, args.include_suite_jobs)
    return _finalize_report(directory, reports, code, started, args)


if __name__ == "__main__":
    raise SystemExit(main())

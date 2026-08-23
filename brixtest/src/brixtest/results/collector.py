"""Collect per-test reports, output, resource use, and service logs.

The plugin drives it from the pytest report stream: ``start_test``
opens a record and marks every relevant server log so each test gets
only the log slice produced during that test,
``record_report`` folds in each phase as pytest produces it, and
``finish_test`` writes the test's output directory and the store row.

Open records are keyed by nodeid, never held as "the" current test:
under xdist the controller receives the workers' logstart/logreport/
logfinish streams *interleaved*, so at any moment one record per
worker may be open concurrently.

The output directory is the full account —

    <lane>/results/<run_id>/tests/<safe-id>/
        record.json     the TestRecord, exactly what the store holds
        stdout.txt      captured stdout, all phases, complete
        stderr.txt      captured stderr, all phases, complete
        logs/<name>.log what each of its servers logged DURING the test

The failure text is the complete pytest long representation. Directory
names combine the node ID with a short hash to avoid collisions.
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from brixtest.config.lanes import Lane
from brixtest.results.model import PhaseResult, RunInfo, TestRecord
from brixtest.results.store import ResultStore
from brixtest.services.logs import LogMark, LogView
from brixtest.util.testprobe import read_probe_properties

__all__ = ["ResultCollector", "new_run_id"]

_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def new_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def _safe_dir(nodeid: str) -> str:
    digest = hashlib.sha256(nodeid.encode()).hexdigest()[:8]
    stem = _SAFE_RE.sub("-", nodeid.rsplit("/", 1)[-1]).strip("-")[:80]
    return "%s-%s" % (stem or "test", digest)


class _OpenTest:
    """Everything one in-flight test accumulates between start and finish."""

    def __init__(self, record: TestRecord, log_paths: Mapping[str, Path]) -> None:
        self.record = record
        self.started = time.monotonic()
        self.stdout: List[str] = []
        self.stderr: List[str] = []
        self.log_views: Dict[str, LogView] = {
            name: LogView(name, path) for name, path in sorted(log_paths.items())
        }
        self.log_marks: Dict[str, LogMark] = {
            name: view.mark() for name, view in self.log_views.items()
        }


class ResultCollector:
    def __init__(self, store: ResultStore, lane: Lane, info: RunInfo) -> None:
        self.store = store
        self.lane = lane
        self.info = info
        self.run_dir = lane.root / "results" / info.run_id
        self._counts: Dict[str, int] = {}
        self._run_started = time.monotonic()
        self._open: Dict[str, _OpenTest] = {}
        self._current = ""

    def begin_run(self) -> None:
        (self.run_dir / "tests").mkdir(parents=True, exist_ok=True)
        self.store.begin_run(self.info)

    def finish_run(self) -> RunInfo:
        self.info.finished_at = _utc_now()
        self.info.wall_seconds = round(time.monotonic() - self._run_started, 3)
        self.info.counts = dict(self._counts)
        self.store.finish_run(self.info)
        (self.run_dir / "run.json").write_text(self.info.to_json() + "\n")
        return self.info

    def start_test(
        self,
        nodeid: str,
        *,
        servers: List[str],
        log_paths: Mapping[str, Path],
        markers: Optional[List[str]] = None,
        params: Optional[Mapping[str, str]] = None,
    ) -> None:
        record = TestRecord(run_id=self.info.run_id, nodeid=nodeid)
        record.started_at = _utc_now()
        record.servers = sorted(servers)
        record.markers = sorted(markers or [])
        record.params = dict(params or {})
        record.output_dir = str(self.run_dir / "tests" / _safe_dir(nodeid))
        self._open[nodeid] = _OpenTest(record, log_paths)
        self._current = nodeid

    def _current_open(self) -> Optional[_OpenTest]:
        return self._open.get(self._current)

    def note_dynamic(self, name: str, log_path: Path) -> None:
        """A server requested mid-test joins the slice set from birth."""
        open_test = self._current_open()
        if open_test is not None and name not in open_test.record.dynamic_servers:
            open_test.record.dynamic_servers.append(name)
            open_test.log_views[name] = LogView(name, log_path)
            open_test.log_marks[name] = LogMark(0)  # its whole life is this test's

    def note_workspace(self, path: Path) -> None:
        open_test = self._current_open()
        if open_test is not None:
            open_test.record.workspace = str(path)

    def note_artifact(self, name: str) -> None:
        open_test = self._current_open()
        if open_test is not None and name not in open_test.record.artifacts:
            open_test.record.artifacts.append(name)

    @staticmethod
    def _teardown_metrics(record, report) -> None:
        properties = getattr(report, "user_properties", ())
        _apply_probe_metrics(record, read_probe_properties(properties))
        for pair in properties or ():
            _apply_dynamic_servers(record, pair)

    @staticmethod
    def _captured_output(open_test, report, stdout: str, stderr: str) -> None:
        if stdout:
            open_test.stdout.append("----- %s -----\n%s" % (report.when, stdout))
        if stderr:
            open_test.stderr.append("----- %s -----\n%s" % (report.when, stderr))

    @staticmethod
    def _report_outcome(record, report) -> None:
        if report.outcome == "failed" and not record.failure:
            record.failure = getattr(report, "longreprtext", "") or str(
                getattr(report, "longrepr", "")
            )
        if hasattr(report, "wasxfail"):
            record.outcome = "xpassed" if report.outcome == "passed" else "xfailed"

    def record_report(self, report) -> None:
        """Fold one pytest ``TestReport`` (setup | call | teardown) in."""
        open_test = self._open.get(report.nodeid)
        if open_test is None:
            return
        record = open_test.record
        stdout = getattr(report, "capstdout", "") or ""
        stderr = getattr(report, "capstderr", "") or ""
        record.phases.append(PhaseResult(
            phase=report.when,
            outcome=report.outcome,
            seconds=round(getattr(report, "duration", 0.0), 4),
            stdout_chars=len(stdout),
            stderr_chars=len(stderr),
        ))
        if report.when == "teardown":
            self._teardown_metrics(record, report)
        self._captured_output(open_test, report, stdout, stderr)
        self._report_outcome(record, report)

    def finish_test(self, nodeid: str) -> Optional[TestRecord]:
        open_test = self._open.pop(nodeid, None)
        if open_test is None:
            return None
        record = open_test.record
        if record.outcome not in ("xfailed", "xpassed"):
            record.outcome = record.fold_outcome()
        record.wall_seconds = round(time.monotonic() - open_test.started, 4)
        self._counts[record.outcome] = self._counts.get(record.outcome, 0) + 1
        self._write_output_dir(open_test)
        self.store.add_test(record)
        return record

    def _write_output_dir(self, open_test: _OpenTest) -> None:
        record = open_test.record
        out = Path(record.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        if open_test.stdout:
            (out / "stdout.txt").write_text("\n".join(open_test.stdout))
        if open_test.stderr:
            (out / "stderr.txt").write_text("\n".join(open_test.stderr))
        for name, view in open_test.log_views.items():
            slice_text = view.text(since=open_test.log_marks[name])
            if slice_text:
                logs_dir = out / "logs"
                logs_dir.mkdir(exist_ok=True)
                (logs_dir / ("%s.log" % name)).write_text(slice_text)
        (out / "record.json").write_text(record.to_json() + "\n")


def _apply_probe_metrics(record, probed) -> None:
    if not probed:
        return
    record.cpu_seconds = probed.get("brixtest_cpu_s", 0.0)
    record.rss_delta_kb = int(probed.get("brixtest_rss_delta_kb", 0))
    record.maxrss_kb = int(probed.get("brixtest_maxrss_kb", 0))


def _apply_dynamic_servers(record, pair) -> None:
    if pair[0] != "brixtest_dynamic":
        return
    for name in str(pair[1]).split(","):
        if name and name not in record.dynamic_servers:
            record.dynamic_servers.append(name)


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

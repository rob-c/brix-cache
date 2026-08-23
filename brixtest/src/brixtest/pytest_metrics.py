"""Terminal presentation hook kept separate from helper supervision."""

from __future__ import annotations

import os
import shlex
from typing import Mapping

from brixtest.pytest_state import METRICS_PAYLOAD, METRICS_SESSION, SQLITE_PATH

_HELPER_ENV = "BRIXTEST_HELPER"


def _is_controller(config) -> bool:
    helper = bool(config.getoption("--brixtest-helper") or os.environ.get(_HELPER_ENV))
    return not helper and not hasattr(config, "workerinput")


def _title(row: Mapping[str, object]) -> str:
    raw_labels = row.get("labels", {})
    labels = dict(raw_labels) if isinstance(raw_labels, Mapping) else {}
    suffix = "{%s}" % ",".join("%s=%s" % item for item in sorted(labels.items())) if labels else ""
    return "%s%s" % (row.get("name", "?"), suffix)


def _sort_key(row: Mapping[str, object]) -> tuple:
    name = str(row.get("name", ""))
    automatic = name.startswith(
        ("case.", "client.", "process.", "pytest.", "resources.", "server.")
    )
    return automatic, name, str(row.get("labels", {}))


def _metric_table(terminal, rows, top: int) -> None:
    terminal.write_sep("-", "BriXTest metrics")
    terminal.write_line("%-48s %-8s %6s %12s %12s %12s" % (
        "METRIC", "UNIT", "N", "MEAN", "P95", "MAX",
    ))
    for row in sorted((item for item in rows if isinstance(item, Mapping)), key=_sort_key)[:top]:
        terminal.write_line("%-48s %-8s %6d %12.6g %12.6g %12.6g" % (
            _title(row)[:48], str(row.get("unit", ""))[:8], int(row.get("samples", 0)),
            float(row.get("mean", 0)), float(row.get("p95", 0)), float(row.get("max", 0)),
        ))


def _metric_paths(terminal, config, session_dir) -> None:
    terminal.write_line("metrics JSON: %s" % (session_dir / "session.json"))
    terminal.write_line("metrics HTML: %s" % (session_dir / "report.html"))
    terminal.write_line("SQLite archive: %s" % config.stash.get(
        SQLITE_PATH, session_dir / "archive.sqlite3",
    ))


def _metric_details(terminal, tests) -> None:
    for test in tests:
        metrics = test.get("metrics", {})
        samples = metrics.get("samples", []) if isinstance(metrics, Mapping) else []
        terminal.write_line("  %s: %s, %d samples" % (
            test.get("nodeid", "?"), test.get("outcome", "?"), len(samples),
        ))


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    mode = config.getoption("--brixtest-metrics")
    if not _is_controller(config) or mode == "off":
        return
    payload = config.stash.get(METRICS_PAYLOAD, None)
    if not isinstance(payload, Mapping) or not payload.get("tests"):
        return
    rows = _aggregate_rows(payload)
    top = max(0, config.getoption("--brixtest-metrics-top"))
    _metric_table(terminalreporter, rows, top)
    session_dir = config.stash[METRICS_SESSION]
    _metric_paths(terminalreporter, config, session_dir)
    failures = _failed_tests(payload.get("tests", []))
    _write_rerun(terminalreporter, session_dir, failures)
    _write_details(terminalreporter, mode, payload.get("tests", []))


def _aggregate_rows(payload: Mapping[str, object]) -> list:
    rows = payload.get("aggregates", [])
    return rows if isinstance(rows, list) else []


def _write_rerun(terminal, session_dir, failures: list) -> None:
    if failures:
        terminal.write_line(
            "rerun first failure: %s" % shlex.join([
                "brixtest", "rerun", str(session_dir),
            ])
        )


def _write_details(terminal, mode: str, tests) -> None:
    if mode == "all":
        _metric_details(terminal, tests)


def _failed_tests(tests) -> list:
    return [
        test for test in tests
        if isinstance(test, Mapping) and test.get("outcome") not in ("passed", "skipped")
    ]

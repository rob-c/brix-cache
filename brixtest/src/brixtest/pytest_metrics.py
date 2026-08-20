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


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    if not _is_controller(config) or config.getoption("--brixtest-metrics") == "off":
        return
    payload = config.stash.get(METRICS_PAYLOAD, None)
    if not isinstance(payload, Mapping) or not payload.get("tests"):
        return
    rows = payload.get("aggregates", [])
    if not isinstance(rows, list):
        rows = []
    top = max(0, config.getoption("--brixtest-metrics-top"))
    terminalreporter.write_sep("-", "BriXTest metrics")
    terminalreporter.write_line(
        "%-48s %-8s %6s %12s %12s %12s" % (
            "METRIC", "UNIT", "N", "MEAN", "P95", "MAX"
        )
    )
    for row in sorted(
        (item for item in rows if isinstance(item, Mapping)), key=_sort_key
    )[:top]:
        terminalreporter.write_line(
            "%-48s %-8s %6d %12.6g %12.6g %12.6g" % (
                _title(row)[:48], str(row.get("unit", ""))[:8],
                int(row.get("samples", 0)), float(row.get("mean", 0)),
                float(row.get("p95", 0)), float(row.get("max", 0)),
            )
        )
    session_dir = config.stash[METRICS_SESSION]
    terminalreporter.write_line("metrics JSON: %s" % (session_dir / "session.json"))
    terminalreporter.write_line("metrics HTML: %s" % (session_dir / "report.html"))
    terminalreporter.write_line(
        "SQLite archive: %s" % config.stash.get(
            SQLITE_PATH, session_dir / "archive.sqlite3"
        )
    )
    failures = [
        test for test in payload.get("tests", [])
        if isinstance(test, Mapping) and test.get("outcome") not in ("passed", "skipped")
    ]
    if failures:
        terminalreporter.write_line(
            "rerun first failure: %s" % shlex.join([
                "brixtest", "rerun", str(session_dir)
            ])
        )
    if config.getoption("--brixtest-metrics") == "all":
        for test in payload.get("tests", []):
            metrics = test.get("metrics", {})
            samples = metrics.get("samples", []) if isinstance(metrics, Mapping) else []
            terminalreporter.write_line(
                "  %s: %s, %d samples" % (
                    test.get("nodeid", "?"), test.get("outcome", "?"), len(samples),
                )
            )

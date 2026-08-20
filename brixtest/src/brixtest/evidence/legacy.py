"""Adapter that publishes fleet-harness results through the evidence schema."""

from __future__ import annotations

import json
from pathlib import Path

from brixtest.archive import write_sqlite_archive
from brixtest.evidence.model import normalize_session, stable_id
from brixtest.evidence.report import render
from brixtest.metrics import aggregate_records


def _case(run_id: str, record, findings, store) -> dict:
    attempt_id = stable_id(run_id, record.nodeid, 0)
    metrics = [
        {"name": "case.wall_time", "value": record.wall_seconds, "unit": "s",
         "kind": "gauge", "labels": {}, "at_seconds": record.wall_seconds},
        {"name": "process.cpu_time", "value": record.cpu_seconds, "unit": "s",
         "kind": "gauge", "labels": {}, "at_seconds": record.wall_seconds},
        {"name": "process.max_rss", "value": record.maxrss_kb, "unit": "KiB",
         "kind": "gauge", "labels": {}, "at_seconds": record.wall_seconds},
    ]
    resources = []
    for instance in sorted(set(record.servers + record.dynamic_servers)):
        for timestamp, rss_kb, cpu_pct in store.sample_series(run_id, instance):
            resources.extend([
                {"name": "process.rss_bytes", "value": rss_kb * 1024, "unit": "bytes",
                 "labels": {"process": instance}, "timestamp": timestamp},
                {"name": "process.cpu_percent", "value": cpu_pct, "unit": "%",
                 "labels": {"process": instance}, "timestamp": timestamp},
            ])
    spans = [{
        "span_id": stable_id(attempt_id, phase.phase)[:16], "parent_id": "",
        "name": "pytest.%s" % phase.phase, "start_seconds": 0,
        "duration_seconds": phase.seconds, "status": phase.outcome,
    } for phase in record.phases]
    selected_findings = [{
        "kind": finding.kind, "severity": "warning", "process": finding.instance,
        "detail": finding.detail, "at": finding.at,
    } for finding in findings if not finding.during_test or finding.during_test == record.nodeid]
    attempt = {
        "attempt_id": attempt_id, "index": 0, "trial": 0, "warmup": False,
        "outcome": record.outcome, "started_at": record.started_at,
        "wall_seconds": record.wall_seconds, "run_root": record.workspace,
        "error": record.failure, "metrics": metrics, "resources": resources,
        "spans": spans, "artifacts": [{"name": name, "role": "input"}
                                       for name in record.artifacts],
        "logs": [{"path": record.output_dir, "role": "captured-output"}],
        "findings": selected_findings,
        "provenance": {"legacy_fleet": True, "servers": record.servers,
                       "dynamic_servers": record.dynamic_servers},
    }
    return {
        "schema": 2, "session_id": run_id, "nodeid": record.nodeid,
        "outcome": record.outcome, "backend": "local", "isolation": "pytest-worker",
        "run_root": record.workspace, "started_at": record.started_at,
        "wall_seconds": record.wall_seconds, "metrics": {
            "samples": metrics, "tags": {"source": "fleet"}, "rollups": []
        }, "properties": [], "error": record.failure, "attempts": [attempt],
    }


def publish(store, info, directory: Path) -> dict:
    """Write schema-v2 JSON/HTML/SQLite beside a completed legacy run."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    findings = store.findings(info.run_id)
    cases = [_case(info.run_id, record, findings, store) for record in store.tests(info.run_id)]
    payload = normalize_session({
        "schema": 2, "session_id": info.run_id, "generated_at": info.finished_at,
        "exitstatus": 1 if info.counts.get("failed", 0) or info.counts.get("error", 0) else 0,
        "tests": cases, "aggregates": aggregate_records(cases), "source": "fleet-harness",
    })
    (target / "session.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    (target / "report.html").write_text(render(payload))
    write_sqlite_archive(payload, target, target / "archive.sqlite3")
    return payload

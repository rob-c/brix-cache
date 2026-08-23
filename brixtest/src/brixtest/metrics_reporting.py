"""Durable session storage and presentation for BriXTest metrics."""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from brixtest.errors import SpecError
from brixtest.metrics import _SCHEMA, _utc_now, aggregate_records


def metric_sessions_root(runs_root: Path) -> Path:
    return Path(runs_root).resolve() / "metrics"


def _atomic_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_path = tempfile.mkstemp(
        dir=str(path.parent), prefix=".%s." % path.name,
    )
    temporary = Path(raw_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
    return path


def _atomic_json(path: Path, payload: object) -> Path:
    return _atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def publish_case_record(session_dir: Path, record: Mapping[str, object]) -> Path:
    nodeid = str(record.get("nodeid", "unknown"))
    digest = hashlib.sha256(nodeid.encode("utf-8")).hexdigest()
    return _atomic_json(Path(session_dir) / "cases" / (digest + ".json"), record)


def _case_records(session_dir: Path) -> List[dict]:
    records = []
    for path in sorted((Path(session_dir) / "cases").glob("*.json")):
        try:
            value = json.loads(path.read_text())
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(value, dict):
            records.append(value)
    return sorted(records, key=lambda item: str(item.get("nodeid", "")))


def _session_payload(
    session_dir: Path, records: Sequence[Mapping[str, object]],
    exitstatus: Optional[int] = None,
) -> dict:
    counts = _outcome_counts(records)
    topology = _topology_payload(session_dir)
    infrastructure = _infrastructure_metrics(topology)
    payload = {
        "schema": _SCHEMA, "session_id": Path(session_dir).name,
        "generated_at": _utc_now(), "exitstatus": exitstatus,
        "counts": counts, "tests": list(records),
        "aggregates": aggregate_records([*records, *infrastructure]),
        "topology": topology,
    }
    from brixtest.evidence.analysis import session_insights
    from brixtest.evidence.model import normalize_session
    normalized = normalize_session(payload)
    normalized["analysis"] = session_insights(normalized)
    return normalized


def _outcome_counts(records: Sequence[Mapping[str, object]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for record in records:
        outcome = str(record.get("outcome", "unknown"))
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts


def _topology_payload(session_dir: Path) -> dict:
    try:
        raw_topology = json.loads((Path(session_dir) / "topology.json").read_text())
        if isinstance(raw_topology, dict):
            return raw_topology
    except (OSError, ValueError, TypeError):
        pass
    return {}


def _infrastructure_metrics(topology: Mapping[str, object]) -> list[dict]:
    infrastructure = []
    for pool in topology.get("pools", []):
        metrics = _pool_metrics(pool)
        if metrics is not None:
            infrastructure.append({"metrics": dict(metrics)})
    return infrastructure


def _pool_metrics(pool: object) -> Optional[Mapping[str, object]]:
    if not isinstance(pool, Mapping):
        return None
    result = pool.get("result", {})
    if not isinstance(result, Mapping):
        return None
    metrics = result.get("metrics", {})
    return metrics if isinstance(metrics, Mapping) else None


def _metric_title(row: Mapping[str, object]) -> str:
    raw_labels = row.get("labels", {})
    labels = dict(raw_labels) if isinstance(raw_labels, Mapping) else {}
    suffix = "{%s}" % ",".join("%s=%s" % item for item in sorted(labels.items())) if labels else ""
    return "%s%s" % (row.get("name", "?"), suffix)


def render_metrics_html(payload: Mapping[str, object]) -> str:
    from brixtest.evidence.report import render
    return render(payload)


def write_session_outputs(
    session_dir: Path, *, exitstatus: Optional[int] = None,
    json_path: Optional[Path] = None, html_path: Optional[Path] = None,
) -> dict:
    directory = Path(session_dir)
    payload = _session_payload(directory, _case_records(directory), exitstatus)
    _atomic_json(directory / "session.json", payload)
    _atomic_json(directory / "insights.json", payload["analysis"])
    _atomic_text(directory / "report.html", render_metrics_html(payload))
    if json_path is not None:
        _atomic_json(Path(json_path), payload)
    if html_path is not None:
        _atomic_text(Path(html_path), render_metrics_html(payload))
    return payload


def list_metric_sessions(runs_root: Path) -> List[dict]:
    base = metric_sessions_root(runs_root)
    sessions: List[dict] = []
    if not base.is_dir():
        return sessions
    for directory in base.iterdir():
        if not directory.is_dir():
            continue
        try:
            payload = json.loads((directory / "session.json").read_text())
        except (OSError, ValueError, TypeError):
            records = _case_records(directory)
            payload = _session_payload(directory, records)
        payload["path"] = str(directory)
        sessions.append(payload)
    return sorted(
        sessions, key=lambda item: str(item.get("generated_at", item.get("session_id", ""))),
        reverse=True,
    )


def load_metric_session(name: str, runs_root: Path) -> dict:
    sessions = list_metric_sessions(runs_root)
    if name == "latest":
        return _latest_session(sessions)
    candidate = _session_path(name, runs_root)
    try:
        payload = json.loads((candidate / "session.json").read_text())
    except (OSError, ValueError, TypeError) as exc:
        return _recover_session(name, candidate, exc)
    payload["path"] = str(candidate)
    return payload


def _latest_session(sessions: Sequence[dict]) -> dict:
    if sessions:
        return sessions[0]
    raise SpecError("metrics session", "latest", "no BriXTest metric sessions were found")


def _session_path(name: str, runs_root: Path) -> Path:
    candidate = Path(name)
    if not candidate.is_absolute():
        candidate = metric_sessions_root(runs_root) / candidate
    return candidate.parent if candidate.name == "session.json" else candidate


def _recover_session(name: str, candidate: Path, error: Exception) -> dict:
    if candidate.is_dir():
        records = _case_records(candidate)
        if records:
            return _session_payload(candidate, records)
    raise SpecError(
        "metrics session", name, "cannot read %s: %s" % (candidate, error)
    ) from error


def write_metrics_csv(payload: Mapping[str, object], path: Path) -> Path:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(("metric", "kind", "unit", "samples", "min", "mean", "p95", "max", "sum"))
    rows = payload.get("aggregates", [])
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, Mapping):
                writer.writerow((
                    _metric_title(row), row.get("kind", ""), row.get("unit", ""),
                    row.get("samples", 0), row.get("min", 0), row.get("mean", 0),
                    row.get("p95", 0), row.get("max", 0), row.get("sum", 0),
                ))
    return _atomic_text(Path(path), output.getvalue())

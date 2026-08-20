"""Small, typed metrics API and durable pytest-session reports.

The recorder is deliberately independent of pytest.  Tests use it through
``run.metrics`` while the pytest plugin is responsible for transporting each
snapshot out of the supervised helper process and publishing session reports.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import html
import io
import json
import math
import os
import re
import statistics
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping

__all__ = [
    "MetricRecorder", "MetricSample", "MetricTimer", "aggregate_records",
    "build_case_record", "evaluate_budget", "list_metric_sessions",
    "merge_metric_snapshots",
    "load_metric_session", "metric_sessions_root", "publish_case_record",
    "render_metrics_html", "write_metrics_csv", "write_session_outputs",
]

_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,95}$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9%/_. -]{0,24}$")
_KINDS = ("gauge", "counter", "observation", "timer")
_SCHEMA = 2
LabelValue = Union[str, int, float, bool]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _name(value: str, field: str = "metric name") -> str:
    if not isinstance(value, str) or _NAME_RE.fullmatch(value) is None:
        raise SpecError(
            field, value,
            "must match [a-z][a-z0-9_.-] and be at most 96 characters",
        )
    return value


def _number(value: object, field: str = "metric value") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SpecError(field, value, "must be a finite integer or float")
    result = float(value)
    if not math.isfinite(result):
        raise SpecError(field, value, "must be finite (NaN and infinity are refused)")
    return result


def _labels(values: Optional[Mapping[str, LabelValue]]) -> Dict[str, str]:
    if values is None:
        return {}
    if not isinstance(values, Mapping) or len(values) > 8:
        raise SpecError("metric labels", values, "must contain at most 8 entries")
    checked: Dict[str, str] = {}
    for key, value in values.items():
        _name(key, "metric label name")
        if not isinstance(value, (str, int, float, bool)):
            raise SpecError(
                "metric label %s" % key, value,
                "must be a string, integer, finite float, or boolean",
            )
        if isinstance(value, float) and not math.isfinite(value):
            raise SpecError("metric label %s" % key, value, "must be finite")
        text = str(value).lower() if isinstance(value, bool) else str(value)
        if len(text) > 128 or any(ord(char) < 32 for char in text):
            raise SpecError(
                "metric label %s" % key, value,
                "must be at most 128 printable characters",
            )
        checked[key] = text
    return freeze_mapping(dict(sorted(checked.items())))


@dataclasses.dataclass(frozen=True)
class MetricSample:
    """One numeric observation relative to the start of its test case."""

    name: str
    value: float
    unit: str
    kind: str
    labels: Mapping[str, str]
    at_seconds: float

    def __post_init__(self) -> None:
        metric_name = _name(self.name)
        metric_value = _number(self.value)
        if self.kind not in _KINDS:
            raise SpecError("metric kind", self.kind, "must be one of: %s" % ", ".join(_KINDS))
        if not isinstance(self.unit, str) or _UNIT_RE.fullmatch(self.unit) is None:
            raise SpecError("metric unit", self.unit, "must be a simple unit up to 24 characters")
        instant = _number(self.at_seconds, "metric at_seconds")
        if instant < 0:
            raise SpecError("metric at_seconds", self.at_seconds, "must be >= 0")
        object.__setattr__(self, "name", metric_name)
        object.__setattr__(self, "value", metric_value)
        object.__setattr__(self, "labels", _labels(self.labels))
        object.__setattr__(self, "at_seconds", instant)

    def as_dict(self) -> dict:
        """Return this observation as a JSON-compatible record."""
        return {
            "name": self.name, "value": self.value, "unit": self.unit,
            "kind": self.kind, "labels": dict(self.labels),
            "at_seconds": self.at_seconds,
        }


class MetricTimer:
    """Context manager returned by :meth:`MetricRecorder.timer`."""

    def __init__(
        self, recorder: "MetricRecorder", name: str,
        labels: Optional[Mapping[str, LabelValue]],
    ) -> None:
        self._recorder = recorder
        self._name = name
        self._labels = labels
        self._started = 0.0
        self.elapsed = 0.0

    def __enter__(self) -> "MetricTimer":
        self._started = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.elapsed = time.perf_counter() - self._started
        self._recorder.record(
            self._name, self.elapsed, unit="s", kind="timer", labels=self._labels
        )


class MetricRecorder:
    """Thread-safe metrics owned by one isolated test invocation.

    ``gauge`` records a value, ``count`` records an increment, ``observe``
    records a member of a distribution, and ``timer`` measures a ``with``
    block.  Labels are intentionally small and bounded so accidental
    high-cardinality or unbounded records fail close to their declaration.
    """

    def __init__(
        self, sink: Optional[Callable[[str, Mapping[str, object]], None]] = None
    ) -> None:
        self._started = time.perf_counter()
        self._samples: List[MetricSample] = []
        self._tags: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._sink = sink

    def set_sink(
        self, sink: Optional[Callable[[str, Mapping[str, object]], None]], *, replay: bool = False
    ) -> None:
        """Set a journal/telemetry sink; optionally replay observations already held."""
        with self._lock:
            self._sink = sink
            samples = [sample.as_dict() for sample in self._samples] if replay else []
            tags = dict(self._tags) if replay else {}
        if sink is not None:
            for sample in samples:
                sink("metric", sample)
            for name, value in tags.items():
                sink("tag", {"name": name, "value": value})

    def record(
        self, name: str, value: Union[int, float], *, unit: str = "",
        kind: str = "gauge", labels: Optional[Mapping[str, LabelValue]] = None,
    ) -> MetricSample:
        """Record one validated numeric sample and return its immutable value."""
        metric_name = _name(name)
        metric_value = _number(value)
        if kind not in _KINDS:
            raise SpecError("metric kind", kind, "must be one of: %s" % ", ".join(_KINDS))
        if not isinstance(unit, str) or _UNIT_RE.fullmatch(unit) is None:
            raise SpecError(
                "metric unit", unit,
                "must be at most 24 simple printable unit characters",
            )
        sample = MetricSample(
            metric_name, metric_value, unit, kind, _labels(labels),
            round(time.perf_counter() - self._started, 9),
        )
        with self._lock:
            self._samples.append(sample)
            sink = self._sink
        if sink is not None:
            sink("metric", sample.as_dict())
        return sample

    def gauge(
        self, name: str, value: Union[int, float], *, unit: str = "",
        labels: Optional[Mapping[str, LabelValue]] = None,
    ) -> MetricSample:
        """Record the current value of an instantaneous measurement."""
        return self.record(name, value, unit=unit, kind="gauge", labels=labels)

    def count(
        self, name: str, value: Union[int, float] = 1, *, unit: str = "count",
        labels: Optional[Mapping[str, LabelValue]] = None,
    ) -> MetricSample:
        """Record a counter increment, defaulting to one count."""
        return self.record(name, value, unit=unit, kind="counter", labels=labels)

    def observe(
        self, name: str, value: Union[int, float], *, unit: str = "",
        labels: Optional[Mapping[str, LabelValue]] = None,
    ) -> MetricSample:
        """Record one member of a measured distribution."""
        return self.record(name, value, unit=unit, kind="observation", labels=labels)

    def timer(
        self, name: str, *, labels: Optional[Mapping[str, LabelValue]] = None,
    ) -> MetricTimer:
        """Return a context manager that records elapsed wall-clock seconds."""
        _name(name)
        _labels(labels)
        return MetricTimer(self, name, labels)

    def tag(self, name: str, value: LabelValue) -> None:
        """Attach bounded scalar metadata to the current case metrics."""
        key = _name(name, "metric tag name")
        if not isinstance(value, (str, int, float, bool)):
            raise SpecError("metric tag %s" % key, value, "must be a scalar value")
        if isinstance(value, float) and not math.isfinite(value):
            raise SpecError("metric tag %s" % key, value, "must be finite")
        text = str(value).lower() if isinstance(value, bool) else str(value)
        if len(text) > 512 or any(ord(char) < 32 for char in text):
            raise SpecError(
                "metric tag %s" % key, value,
                "must be at most 512 printable characters",
            )
        with self._lock:
            self._tags[key] = text
            sink = self._sink
        if sink is not None:
            sink("tag", {"name": key, "value": text})

    def snapshot(self) -> dict:
        """Return an isolated JSON-safe copy of samples, tags, and rollups."""
        with self._lock:
            samples = [sample.as_dict() for sample in self._samples]
            tags = dict(self._tags)
        return {"samples": samples, "tags": tags, "rollups": _rollups(samples)}


def _key(sample: Mapping[str, object]) -> Tuple[str, str, str, Tuple[Tuple[str, str], ...]]:
    raw_labels = sample.get("labels", {})
    labels = raw_labels if isinstance(raw_labels, Mapping) else {}
    label_items = tuple(sorted((str(k), str(v)) for k, v in labels.items()))
    return (
        str(sample.get("name", "")), str(sample.get("unit", "")),
        str(sample.get("kind", "gauge")), label_items,
    )


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def _rollups(samples: Iterable[Mapping[str, object]]) -> List[dict]:
    grouped: Dict[Tuple[str, str, str, Tuple[Tuple[str, str], ...]], List[float]] = {}
    for sample in samples:
        value = _number(sample.get("value"))
        grouped.setdefault(_key(sample), []).append(value)
    rows = []
    for (name, unit, kind, labels), values in sorted(grouped.items()):
        rows.append({
            "name": name, "unit": unit, "kind": kind, "labels": dict(labels),
            "samples": len(values), "last": values[-1], "min": min(values),
            "mean": statistics.fmean(values), "p95": _percentile(values, 0.95),
            "max": max(values), "sum": sum(values),
        })
    return rows


def aggregate_records(records: Sequence[Mapping[str, object]]) -> List[dict]:
    samples: List[Mapping[str, object]] = []
    for record in records:
        metrics = record.get("metrics", {})
        if isinstance(metrics, Mapping):
            found = metrics.get("samples", [])
            if isinstance(found, list):
                samples.extend(item for item in found if isinstance(item, Mapping))
    return _rollups(samples)


def merge_metric_snapshots(snapshots: Sequence[Mapping[str, object]]) -> dict:
    """Merge measured trial snapshots while preserving each sample's identity."""
    samples = []
    tags: Dict[str, str] = {}
    for trial, snapshot in enumerate(snapshots):
        raw = snapshot.get("samples", [])
        if isinstance(raw, list):
            for sample in raw:
                if isinstance(sample, Mapping):
                    row = dict(sample)
                    row.setdefault("trial", trial)
                    samples.append(row)
        found_tags = snapshot.get("tags", {})
        if isinstance(found_tags, Mapping):
            tags.update((str(key), str(value)) for key, value in found_tags.items())
    return {"samples": samples, "tags": tags, "rollups": _rollups(samples)}


def evaluate_budget(
    metrics: Mapping[str, object], name: str, *, minimum: Optional[float] = None,
    maximum: Optional[float] = None, aggregate: str = "last",
    labels: Optional[Mapping[str, LabelValue]] = None,
) -> Optional[str]:
    """Return a readable budget failure, or ``None`` when it is satisfied."""
    metric_name = _name(name, "metric budget name")
    if minimum is None and maximum is None:
        raise SpecError("metric budget", name, "needs min=, max=, or both")
    low = _number(minimum, "metric budget min") if minimum is not None else None
    high = _number(maximum, "metric budget max") if maximum is not None else None
    if low is not None and high is not None and low > high:
        raise SpecError("metric budget", name, "min cannot be greater than max")
    if aggregate not in ("last", "min", "mean", "p95", "max", "sum"):
        raise SpecError(
            "metric budget aggregate", aggregate,
            "must be last, min, mean, p95, max, or sum",
        )
    wanted_labels = _labels(labels)
    rows = metrics.get("rollups", [])
    matches = [
        row for row in rows
        if isinstance(row, Mapping) and row.get("name") == metric_name
        and (not wanted_labels or dict(row.get("labels", {})) == wanted_labels)
    ] if isinstance(rows, list) else []
    if not matches:
        suffix = " with labels %s" % wanted_labels if wanted_labels else ""
        return "metric budget %r failed: no sample was recorded%s" % (metric_name, suffix)
    values = [_number(row.get(aggregate), "metric budget observed value") for row in matches]
    observed = max(values) if high is not None else min(values)
    unit = str(matches[0].get("unit", ""))
    if low is not None and observed < low:
        return "metric budget %r failed: %s %.6g%s is below min %.6g%s" % (
            metric_name, aggregate, observed, (" " + unit) if unit else "",
            low, (" " + unit) if unit else "",
        )
    if high is not None and observed > high:
        return "metric budget %r failed: %s %.6g%s exceeds max %.6g%s" % (
            metric_name, aggregate, observed, (" " + unit) if unit else "",
            high, (" " + unit) if unit else "",
        )
    return None


def build_case_record(
    *, session_id: str, nodeid: str, outcome: str, backend: str,
    run_root: str, started_at: float, stopped_at: float,
    metrics: Optional[Mapping[str, object]] = None,
    properties: Sequence[Sequence[object]] = (), error: str = "",
    attempts: Sequence[Mapping[str, object]] = (),
) -> dict:
    snapshot = dict(metrics) if isinstance(metrics, Mapping) else {
        "samples": [], "tags": {}, "rollups": []
    }
    return {
        "schema": _SCHEMA, "schema_name": "brixtest.evidence",
        "session_id": session_id, "nodeid": nodeid,
        "outcome": outcome, "backend": backend, "run_root": run_root,
        "started_at": datetime.fromtimestamp(started_at, timezone.utc).isoformat(),
        "wall_seconds": round(max(0.0, stopped_at - started_at), 9),
        "metrics": snapshot,
        "properties": [[str(item[0]), item[1]] for item in properties if len(item) >= 2],
        "error": error, "attempts": [dict(item) for item in attempts],
    }


def metric_sessions_root(runs_root: Path) -> Path:
    return Path(runs_root).resolve() / "metrics"


def _atomic_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(path.parent),
        prefix=".%s." % path.name, delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        path.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass
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
    counts: Dict[str, int] = {}
    for record in records:
        outcome = str(record.get("outcome", "unknown"))
        counts[outcome] = counts.get(outcome, 0) + 1
    topology = {}
    try:
        raw_topology = json.loads((Path(session_dir) / "topology.json").read_text())
        if isinstance(raw_topology, dict):
            topology = raw_topology
    except (OSError, ValueError, TypeError):
        pass
    infrastructure = []
    for pool in topology.get("pools", []):
        if not isinstance(pool, Mapping):
            continue
        result = pool.get("result", {})
        metrics = result.get("metrics", {}) if isinstance(result, Mapping) else {}
        if isinstance(metrics, Mapping):
            infrastructure.append({"metrics": dict(metrics)})
    payload = {
        "schema": _SCHEMA, "session_id": Path(session_dir).name,
        "generated_at": _utc_now(), "exitstatus": exitstatus,
        "counts": counts, "tests": list(records),
        "aggregates": aggregate_records([*records, *infrastructure]),
        "topology": topology,
    }
    from brixtest.evidence.model import normalize_session
    from brixtest.evidence.analysis import session_insights
    normalized = normalize_session(payload)
    normalized["analysis"] = session_insights(normalized)
    return normalized


def _metric_title(row: Mapping[str, object]) -> str:
    raw_labels = row.get("labels", {})
    labels = dict(raw_labels) if isinstance(raw_labels, Mapping) else {}
    suffix = "{%s}" % ",".join("%s=%s" % item for item in sorted(labels.items())) if labels else ""
    return "%s%s" % (row.get("name", "?"), suffix)


def _format(value: object) -> str:
    if not isinstance(value, (int, float, str)):
        return html.escape(str(value))
    try:
        number = float(value)
    except (TypeError, ValueError):
        return html.escape(str(value))
    return "%.6g" % number


def render_metrics_html(payload: Mapping[str, object]) -> str:
    from brixtest.evidence.report import render
    return render(payload)

    # Historical schema-v1 renderer retained for direct legacy compatibility.
    rows = payload.get("aggregates", [])
    aggregate_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td class='n'>%s</td>"
        "<td class='n'>%s</td><td class='n'>%s</td><td class='n'>%s</td>"
        "<td class='n'>%s</td><td class='n'>%s</td></tr>" % (
            html.escape(_metric_title(row)), html.escape(str(row.get("kind", ""))),
            html.escape(str(row.get("unit", ""))), row.get("samples", 0),
            _format(row.get("min")), _format(row.get("mean")),
            _format(row.get("p95")), _format(row.get("max")), _format(row.get("sum")),
        ) for row in rows if isinstance(row, Mapping)
    ) if isinstance(rows, list) else ""
    tests = payload.get("tests", [])
    test_rows = "".join(
        "<tr data-key='%s'><td>%s</td><td class='%s'>%s</td>"
        "<td>%s</td><td class='n'>%s</td><td class='n'>%s</td></tr>" % (
            html.escape(str(test.get("nodeid", "")).lower(), quote=True),
            html.escape(str(test.get("nodeid", "?"))),
            html.escape(str(test.get("outcome", "unknown"))),
            html.escape(str(test.get("outcome", "unknown"))),
            html.escape(str(test.get("backend", "?"))),
            _format(test.get("wall_seconds", 0)),
            len(
                dict(test.get("metrics", {})).get("samples", [])
                if isinstance(test.get("metrics", {}), Mapping) else []
            ),
        ) for test in tests if isinstance(test, Mapping)
    ) if isinstance(tests, list) else ""
    raw_counts = payload.get("counts", {})
    counts = dict(raw_counts) if isinstance(raw_counts, Mapping) else {}
    count_text = " · ".join("%s %s" % (value, key) for key, value in sorted(counts.items()))
    return """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>BriXTest metrics</title><style>
body{margin:0;background:#0f1419;color:#d8e1ea;font:14px/1.5 system-ui,sans-serif}
main{max-width:80rem;margin:auto;padding:1.5rem}h1{margin:0}h2{margin-top:2rem;color:#a8bdd2}
.meta{color:#8495a7}.scroller{overflow:auto}table{border-collapse:collapse;width:100%%}
th,td{padding:.45rem .6rem;border-bottom:1px solid #26313b;text-align:left;white-space:nowrap}
th{color:#a8bdd2;position:sticky;top:0;background:#0f1419}.n{text-align:right;font-variant-numeric:tabular-nums}
.passed{color:#63d391}.failed,.error{color:#ff7373}.skipped{color:#94a7bc}
input{width:100%%;box-sizing:border-box;padding:.55rem;margin:.5rem 0;background:#182129;color:inherit;border:1px solid #344451;border-radius:5px}
</style></head><body><main><h1>BriXTest metrics</h1>
<div class="meta">session %s · %s</div>
<h2>Metric aggregates</h2><div class="scroller"><table><thead><tr><th>metric</th><th>kind</th><th>unit</th><th>samples</th><th>min</th><th>mean</th><th>p95</th><th>max</th><th>sum</th></tr></thead><tbody>%s</tbody></table></div>
<h2>Tests</h2><input id="q" placeholder="filter tests"><div class="scroller"><table><thead><tr><th>test</th><th>outcome</th><th>backend</th><th>wall s</th><th>samples</th></tr></thead><tbody id="tests">%s</tbody></table></div>
</main><script>document.getElementById('q').addEventListener('input',e=>{const q=e.target.value.toLowerCase();document.querySelectorAll('#tests tr').forEach(r=>r.hidden=!r.dataset.key.includes(q))})</script></body></html>
""" % (
        html.escape(str(payload.get("session_id", "unknown"))),
        html.escape(count_text or "no managed cases"), aggregate_rows, test_rows,
    )


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
        if sessions:
            return sessions[0]
        raise SpecError("metrics session", name, "no BriXTest metric sessions were found")
    candidate = Path(name)
    if not candidate.is_absolute():
        candidate = metric_sessions_root(runs_root) / candidate
    if candidate.name == "session.json":
        candidate = candidate.parent
    try:
        payload = json.loads((candidate / "session.json").read_text())
    except (OSError, ValueError, TypeError) as exc:
        if candidate.is_dir():
            records = _case_records(candidate)
            if records:
                return _session_payload(candidate, records)
        raise SpecError(
            "metrics session", name, "cannot read %s: %s" % (candidate, exc)
        ) from exc
    payload["path"] = str(candidate)
    return payload


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

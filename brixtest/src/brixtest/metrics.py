"""Small, typed metrics API and durable pytest-session reports.

The recorder is deliberately independent of pytest.  Tests use it through
``run.metrics`` while the pytest plugin is responsible for transporting each
snapshot out of the supervised helper process and publishing session reports.
"""

from __future__ import annotations

import dataclasses
import math
import re
import statistics
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping

__all__ = [
    "MetricRecorder",
    "MetricSample",
    "MetricTimer",
    "aggregate_records",
    "build_case_record",
    "evaluate_budget",
    "list_metric_sessions",
    "load_metric_session",
    "merge_metric_snapshots",
    "metric_sessions_root",
    "publish_case_record",
    "render_metrics_html",
    "write_metrics_csv",
    "write_session_outputs",
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
        checked[key] = _label_text(key, value)
    return freeze_mapping(dict(sorted(checked.items())))


def _label_text(key: str, value: object) -> str:
    if not isinstance(value, (str, int, float, bool)):
        raise SpecError(
            "metric label %s" % key, value,
            "must be a string, integer, finite float, or boolean",
        )
    _validate_finite_scalar("metric label %s" % key, value)
    text = _scalar_text(value)
    if len(text) > 128 or any(ord(char) < 32 for char in text):
        raise SpecError(
            "metric label %s" % key, value,
            "must be at most 128 printable characters",
        )
    return text


def _validate_finite_scalar(field: str, value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise SpecError(field, value, "must be finite")


def _scalar_text(value: object) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


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
            samples, tags = self._replay_state(replay)
        _replay_sink(sink, samples, tags)

    def _replay_state(self, replay: bool) -> tuple[list[dict], dict[str, str]]:
        if not replay:
            return [], {}
        return [sample.as_dict() for sample in self._samples], dict(self._tags)

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
        text = _tag_text(key, value)
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


def _replay_sink(sink, samples: list[dict], tags: Mapping[str, str]) -> None:
    if sink is None:
        return
    for sample in samples:
        sink("metric", sample)
    for name, value in tags.items():
        sink("tag", {"name": name, "value": value})


def _tag_text(key: str, value: LabelValue) -> str:
    if not isinstance(value, (str, int, float, bool)):
        raise SpecError("metric tag %s" % key, value, "must be a scalar value")
    _validate_finite_scalar("metric tag %s" % key, value)
    text = _scalar_text(value)
    if len(text) > 512 or any(ord(char) < 32 for char in text):
        raise SpecError(
            "metric tag %s" % key, value,
            "must be at most 512 printable characters",
        )
    return text


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
        samples.extend(_record_samples(record))
    return _rollups(samples)


def _record_samples(record: Mapping[str, object]) -> list[Mapping[str, object]]:
    metrics = record.get("metrics", {})
    if not isinstance(metrics, Mapping):
        return []
    found = metrics.get("samples", [])
    if not isinstance(found, list):
        return []
    return [item for item in found if isinstance(item, Mapping)]


def merge_metric_snapshots(snapshots: Sequence[Mapping[str, object]]) -> dict:
    """Merge measured trial snapshots while preserving each sample's identity."""
    samples = []
    tags: Dict[str, str] = {}
    for trial, snapshot in enumerate(snapshots):
        trial_samples, trial_tags = _merge_snapshot(snapshot, trial)
        samples.extend(trial_samples)
        tags.update(trial_tags)
    return {"samples": samples, "tags": tags, "rollups": _rollups(samples)}


def _merge_snapshot(
    snapshot: Mapping[str, object], trial: int,
) -> tuple[list[dict], dict[str, str]]:
    samples = _trial_samples(snapshot.get("samples", []), trial)
    found_tags = snapshot.get("tags", {})
    tags = {}
    if isinstance(found_tags, Mapping):
        tags = {str(key): str(value) for key, value in found_tags.items()}
    return samples, tags


def _trial_samples(raw: object, trial: int) -> list[dict]:
    if not isinstance(raw, list):
        return []
    samples = []
    for sample in raw:
        if isinstance(sample, Mapping):
            row = dict(sample)
            row.setdefault("trial", trial)
            samples.append(row)
    return samples


def _budget_bounds(
    name: str, minimum: Optional[float], maximum: Optional[float], aggregate: str,
) -> Tuple[str, Optional[float], Optional[float]]:
    metric_name = _name(name, "metric budget name")
    low, high = _budget_range(name, minimum, maximum)
    _validate_budget_aggregate(aggregate)
    return metric_name, low, high


def _budget_range(
    name: str, minimum: Optional[float], maximum: Optional[float],
) -> tuple[Optional[float], Optional[float]]:
    if minimum is None and maximum is None:
        raise SpecError("metric budget", name, "needs min=, max=, or both")
    low = _optional_number(minimum, "metric budget min")
    high = _optional_number(maximum, "metric budget max")
    if low is not None and high is not None and low > high:
        raise SpecError("metric budget", name, "min cannot be greater than max")
    return low, high


def _optional_number(value: Optional[float], field: str) -> Optional[float]:
    return _number(value, field) if value is not None else None


def _validate_budget_aggregate(aggregate: str) -> None:
    allowed = ("last", "min", "mean", "p95", "max", "sum")
    if aggregate not in allowed:
        raise SpecError(
            "metric budget aggregate", aggregate, "must be " + ", ".join(allowed),
        )


def _budget_matches(
    metrics: Mapping[str, object], name: str, labels: Mapping[str, str],
) -> List[Mapping[str, object]]:
    rows = metrics.get("rollups", [])
    if not isinstance(rows, list):
        return []
    return [
        row for row in rows
        if isinstance(row, Mapping) and row.get("name") == name
        and (not labels or dict(row.get("labels", {})) == labels)
    ]


def _budget_failure(
    name: str, aggregate: str, observed: float, unit: str,
    low: Optional[float], high: Optional[float],
) -> Optional[str]:
    suffix = (" " + unit) if unit else ""
    if low is not None and observed < low:
        return "metric budget %r failed: %s %.6g%s is below min %.6g%s" % (
            name, aggregate, observed, suffix, low, suffix,
        )
    if high is not None and observed > high:
        return "metric budget %r failed: %s %.6g%s exceeds max %.6g%s" % (
            name, aggregate, observed, suffix, high, suffix,
        )
    return None


def evaluate_budget(
    metrics: Mapping[str, object], name: str, *, minimum: Optional[float] = None,
    maximum: Optional[float] = None, aggregate: str = "last",
    labels: Optional[Mapping[str, LabelValue]] = None,
) -> Optional[str]:
    """Return a readable budget failure, or ``None`` when it is satisfied."""
    metric_name, low, high = _budget_bounds(name, minimum, maximum, aggregate)
    wanted_labels = _labels(labels)
    matches = _budget_matches(metrics, metric_name, wanted_labels)
    if not matches:
        suffix = " with labels %s" % wanted_labels if wanted_labels else ""
        return "metric budget %r failed: no sample was recorded%s" % (metric_name, suffix)
    values = [_number(row.get(aggregate), "metric budget observed value") for row in matches]
    observed = max(values) if high is not None else min(values)
    return _budget_failure(
        metric_name, aggregate, observed, str(matches[0].get("unit", "")), low, high,
    )


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


from brixtest.metrics_reporting import (  # noqa: E402 - compatibility facade
    list_metric_sessions,
    load_metric_session,
    metric_sessions_root,
    publish_case_record,
    render_metrics_html,
    write_metrics_csv,
    write_session_outputs,
)

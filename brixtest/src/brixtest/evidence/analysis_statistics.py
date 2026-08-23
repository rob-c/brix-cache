"""Descriptive, comparative, and trend statistics for evidence sessions."""

from __future__ import annotations

import hashlib
import itertools
import math
import operator
import random
import statistics
from collections import defaultdict
from typing import Iterable, Mapping, Optional, Sequence

from brixtest.evidence.model import normalize_session


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def describe(values: Iterable[float]) -> dict:
    rows = [float(value) for value in values if math.isfinite(float(value))]
    if not rows:
        return {"n": 0}
    mean, median, stddev, mad = _variability(rows)
    return {
        "n": len(rows), "min": min(rows), "max": max(rows), "sum": sum(rows),
        "mean": mean, "median": median, "stddev": stddev,
        "cv": _coefficient_of_variation(stddev, mean), "mad": mad,
        "p50": percentile(rows, 0.50), "p90": percentile(rows, 0.90),
        "p95": percentile(rows, 0.95), "p99": percentile(rows, 0.99),
    }


def _variability(rows: Sequence[float]) -> tuple[float, float, float, float]:
    mean = statistics.fmean(rows)
    median = statistics.median(rows)
    stddev = statistics.stdev(rows) if len(rows) > 1 else 0.0
    mad = statistics.median(abs(value - median) for value in rows)
    return mean, median, stddev, mad


def _coefficient_of_variation(stddev: float, mean: float) -> float:
    return stddev / abs(mean) if mean else 0.0


def bootstrap_mean_ci(
    values: Sequence[float], *, confidence: float = 0.95,
    samples: int = 2000, seed: str = "brixtest",
) -> tuple[float, float]:
    rows = [float(value) for value in values]
    if not rows:
        return 0.0, 0.0
    digest = hashlib.sha256(seed.encode()).digest()
    generator = random.Random(  # noqa: S311 - deterministic statistical resampling
        int.from_bytes(digest[:8], "big")
    )
    means = [
        statistics.fmean(generator.choice(rows) for _ in rows)
        for _ in range(samples)
    ]
    alpha = (1.0 - confidence) / 2.0
    return percentile(means, alpha), percentile(means, 1.0 - alpha)


def cliffs_delta(left: Sequence[float], right: Sequence[float]) -> float:
    if not left:
        return 0.0
    if not right:
        return 0.0
    greater = _pair_count(left, right, operator.gt)
    smaller = _pair_count(left, right, operator.lt)
    return (greater - smaller) / float(len(left) * len(right))


def _pair_count(left, right, predicate) -> int:
    return sum(1 for pair in itertools.product(left, right) if predicate(*pair))


def _series(payload: Mapping[str, object], metric: str = "") -> dict[tuple, list[float]]:
    grouped = defaultdict(list)
    for case in normalize_session(payload)["tests"]:
        for attempt in case["attempts"]:
            if attempt.get("warmup"):
                continue
            _append_metric_rows(grouped, case, attempt, metric)
    return dict(grouped)


def _append_metric_rows(grouped, case, attempt, selected: str) -> None:
    for row in attempt.get("metrics", []):
        if not isinstance(row, Mapping):
            continue
        name = str(row.get("name", ""))
        if selected and name != selected:
            continue
        labels = tuple(sorted(
            (str(key), str(value))
            for key, value in dict(row.get("labels", {})).items()
        ))
        key = (str(case.get("nodeid", "")), name, str(row.get("unit", "")), labels)
        grouped[key].append(float(row.get("value", 0)))


def provenance_compatibility(left: Mapping[str, object], right: Mapping[str, object]) -> dict:
    fields = ("backend", "isolation")
    mismatches = [
        field for field in fields
        if str(left.get(field, "")) != str(right.get(field, ""))
    ]
    return {"comparable": not mismatches, "mismatches": mismatches}


def _comparison_row(key, left, right, old_meta, new_meta) -> dict:
    old_stats, new_stats = describe(left), describe(right)
    old_mean = old_stats.get("mean", 0.0)
    new_mean = new_stats.get("mean", 0.0)
    change = (new_mean - old_mean) / abs(old_mean) if old_mean else 0.0
    return {
        "nodeid": key[0], "metric": key[1], "unit": key[2],
        "labels": dict(key[3]), "baseline": old_stats, "candidate": new_stats,
        "relative_change": change, "cliffs_delta": cliffs_delta(right, left),
        "compatibility": provenance_compatibility(
            old_meta.get(key[0], {}), new_meta.get(key[0], {}),
        ),
        "candidate_mean_ci": bootstrap_mean_ci(right, seed="\0".join(map(str, key))),
    }


def _comparison_finding(
    row: Mapping[str, object], left: Sequence[float], right: Sequence[float],
    relative_threshold: float, effect_threshold: float,
) -> Optional[dict]:
    if not left or not right:
        return None
    compatibility = row["compatibility"]
    if not compatibility["comparable"]:
        return {
            "kind": "incompatible-provenance", "severity": "warning",
            "nodeid": row["nodeid"], "metric": row["metric"],
            "detail": "comparison differs in %s" % ", ".join(compatibility["mismatches"]),
        }
    change = float(row["relative_change"])
    delta = float(row["cliffs_delta"])
    if change <= relative_threshold or delta <= effect_threshold:
        return None
    return {
        "kind": "regression", "severity": "error", "nodeid": row["nodeid"],
        "metric": row["metric"], "relative_change": change, "cliffs_delta": delta,
        "detail": "mean increased %.2f%% with effect %.3f" % (change * 100, delta),
    }


def compare(
    baseline: Mapping[str, object], candidate: Mapping[str, object], *, metric: str = "",
    relative_threshold: float = 0.05, effect_threshold: float = 0.147,
) -> dict:
    old = _series(baseline, metric)
    new = _series(candidate, metric)
    old_meta = {str(row.get("nodeid", "")): row
                for row in normalize_session(baseline)["tests"]}
    new_meta = {str(row.get("nodeid", "")): row
                for row in normalize_session(candidate)["tests"]}
    rows = []
    findings = []
    for key in sorted(set(old) | set(new)):
        left, right = old.get(key, []), new.get(key, [])
        row = _comparison_row(key, left, right, old_meta, new_meta)
        rows.append(row)
        finding = _comparison_finding(
            row, left, right, relative_threshold, effect_threshold,
        )
        if finding is not None:
            findings.append(finding)
    return {"series": rows, "findings": findings,
            "baseline": baseline.get("session_id"), "candidate": candidate.get("session_id")}


def trend(sessions: Sequence[Mapping[str, object]], *, metric: str) -> dict:
    points = _trend_points(sessions, metric)
    return {"metric": metric, "points": points, "slope_per_session": _linear_slope(points)}


def _trend_points(sessions, metric: str) -> list[dict]:
    points = []
    for index, payload in enumerate(sessions):
        values = [value for key, rows in _series(payload, metric).items() for value in rows]
        stats = describe(values)
        if stats.get("n"):
            points.append({"index": index, "session_id": payload.get("session_id"), **stats})
    return points


def _axis(points, name: str) -> list[float]:
    return [float(row[name]) for row in points]


def _linear_slope(points: Sequence[Mapping[str, object]]) -> float:
    if len(points) < 2:
        return 0.0
    xs = _axis(points, "index")
    ys = _axis(points, "mean")
    xmean, ymean = statistics.fmean(xs), statistics.fmean(ys)
    denominator = sum((value - xmean) ** 2 for value in xs)
    numerator = sum((x - xmean) * (y - ymean) for x, y in zip(xs, ys))
    return numerator / denominator

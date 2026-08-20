"""Deterministic descriptive, comparative, trend, and regression analytics."""

from __future__ import annotations

import hashlib
import itertools
import math
import random
import statistics
from collections import defaultdict
from typing import Iterable, Mapping, Optional, Sequence

from brixtest.evidence.model import normalize_session
from brixtest.errors import SpecError

__all__ = [
    "bootstrap_mean_ci", "cliffs_delta", "compare", "describe", "percentile",
    "session_insights", "trend",
]


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(math.floor(position))
    high = int(math.ceil(position))
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def describe(values: Iterable[float]) -> dict:
    rows = [float(value) for value in values if math.isfinite(float(value))]
    if not rows:
        return {"n": 0}
    mean = statistics.fmean(rows)
    median = statistics.median(rows)
    deviations = [abs(value - median) for value in rows]
    stddev = statistics.stdev(rows) if len(rows) > 1 else 0.0
    return {
        "n": len(rows), "min": min(rows), "max": max(rows), "sum": sum(rows),
        "mean": mean, "median": median, "stddev": stddev,
        "cv": stddev / abs(mean) if mean else 0.0,
        "mad": statistics.median(deviations),
        "p50": percentile(rows, 0.50), "p90": percentile(rows, 0.90),
        "p95": percentile(rows, 0.95), "p99": percentile(rows, 0.99),
    }


def bootstrap_mean_ci(values: Sequence[float], *, confidence: float = 0.95,
                      samples: int = 2000, seed: str = "brixtest") -> tuple[float, float]:
    rows = [float(value) for value in values]
    if not rows:
        return 0.0, 0.0
    digest = hashlib.sha256(seed.encode()).digest()
    generator = random.Random(int.from_bytes(digest[:8], "big"))
    means = [statistics.fmean(generator.choice(rows) for _ in rows) for _ in range(samples)]
    alpha = (1.0 - confidence) / 2.0
    return percentile(means, alpha), percentile(means, 1.0 - alpha)


def cliffs_delta(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or not right:
        return 0.0
    greater = sum(a > b for a in left for b in right)
    smaller = sum(a < b for a in left for b in right)
    return (greater - smaller) / float(len(left) * len(right))


def _series(payload: Mapping[str, object], metric: str = "") -> dict[tuple, list[float]]:
    grouped = defaultdict(list)
    for case in normalize_session(payload)["tests"]:
        for attempt in case["attempts"]:
            if attempt.get("warmup"):
                continue
            for row in attempt.get("metrics", []):
                if not isinstance(row, Mapping):
                    continue
                name = str(row.get("name", ""))
                if metric and name != metric:
                    continue
                labels = tuple(sorted((str(key), str(value))
                                      for key, value in dict(row.get("labels", {})).items()))
                grouped[(str(case.get("nodeid", "")), name, str(row.get("unit", "")), labels)] \
                    .append(float(row.get("value", 0)))
    return dict(grouped)


def provenance_compatibility(left: Mapping[str, object], right: Mapping[str, object]) -> dict:
    fields = ("backend", "isolation")
    mismatches = []
    for field in fields:
        if str(left.get(field, "")) != str(right.get(field, "")):
            mismatches.append(field)
    return {"comparable": not mismatches, "mismatches": mismatches}


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
        old_stats, new_stats = describe(left), describe(right)
        old_mean, new_mean = old_stats.get("mean", 0.0), new_stats.get("mean", 0.0)
        change = (new_mean - old_mean) / abs(old_mean) if old_mean else 0.0
        delta = cliffs_delta(right, left)
        compatibility = provenance_compatibility(
            old_meta.get(key[0], {}), new_meta.get(key[0], {})
        )
        row = {
            "nodeid": key[0], "metric": key[1], "unit": key[2],
            "labels": dict(key[3]), "baseline": old_stats, "candidate": new_stats,
            "relative_change": change, "cliffs_delta": delta,
            "compatibility": compatibility,
            "candidate_mean_ci": bootstrap_mean_ci(right, seed="\0".join(map(str, key))),
        }
        rows.append(row)
        if left and right and not compatibility["comparable"]:
            findings.append({
                "kind": "incompatible-provenance", "severity": "warning",
                "nodeid": key[0], "metric": key[1],
                "detail": "comparison differs in %s" % ", ".join(compatibility["mismatches"]),
            })
        elif left and right and change > relative_threshold and delta > effect_threshold:
            findings.append({
                "kind": "regression", "severity": "error", "nodeid": key[0],
                "metric": key[1], "relative_change": change, "cliffs_delta": delta,
                "detail": "mean increased %.2f%% with effect %.3f" % (change * 100, delta),
            })
    return {"series": rows, "findings": findings,
            "baseline": baseline.get("session_id"), "candidate": candidate.get("session_id")}


def trend(sessions: Sequence[Mapping[str, object]], *, metric: str) -> dict:
    points = []
    for index, payload in enumerate(sessions):
        values = [value for key, rows in _series(payload, metric).items() for value in rows]
        stats = describe(values)
        if stats.get("n"):
            points.append({"index": index, "session_id": payload.get("session_id"), **stats})
    if len(points) < 2:
        slope = 0.0
    else:
        xs = [float(row["index"]) for row in points]
        ys = [float(row["mean"]) for row in points]
        xmean, ymean = statistics.fmean(xs), statistics.fmean(ys)
        denominator = sum((value - xmean) ** 2 for value in xs)
        slope = sum((x - xmean) * (y - ymean) for x, y in zip(xs, ys)) / denominator
    return {"metric": metric, "points": points, "slope_per_session": slope}


def _finite_number(value: object) -> Optional[float]:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _series_name(prefix: str, row: Mapping[str, object]) -> str:
    name = str(row.get("name", "unnamed"))[:96]
    raw_labels = row.get("labels", {})
    labels = dict(raw_labels) if isinstance(raw_labels, Mapping) else {}
    suffix = ",".join(
        "%s=%s" % (str(key)[:48], str(value)[:96])
        for key, value in sorted(labels.items(), key=lambda item: str(item[0]))
    )
    return "%s.%s%s" % (prefix, name, "{%s}" % suffix if suffix else "")


def _attempt_observations(payload: Mapping[str, object]) -> list[dict]:
    observations = []
    for case in normalize_session(payload)["tests"]:
        nodeid = str(case.get("nodeid", ""))
        for attempt in case["attempts"]:
            if attempt.get("warmup"):
                continue
            values: dict[str, list[float]] = defaultdict(list)
            wall = _finite_number(attempt.get("wall_seconds"))
            if wall is not None:
                values["attempt.wall_seconds"].append(wall)
            for prefix, field in (("metric", "metrics"), ("resource", "resources")):
                rows = attempt.get(field, [])
                if not isinstance(rows, (list, tuple)):
                    continue
                for raw in rows:
                    if not isinstance(raw, Mapping):
                        continue
                    number = _finite_number(raw.get("value"))
                    if number is not None:
                        values[_series_name(prefix, raw)].append(number)
            for prefix, field in (("artifact", "artifacts"), ("log", "logs")):
                rows = attempt.get(field, [])
                if not isinstance(rows, (list, tuple)):
                    continue
                total = 0.0
                found = False
                for raw in rows:
                    if not isinstance(raw, Mapping):
                        continue
                    number = _finite_number(raw.get("size", raw.get("bytes")))
                    if number is None or number < 0:
                        continue
                    found = True
                    total += number
                    name = str(raw.get("name", raw.get("path", "unnamed")))[:96]
                    values["%s.%s.bytes" % (prefix, name)].append(number)
                if found:
                    values["%s.total_bytes" % prefix].append(total)
            observations.append({
                "nodeid": nodeid,
                "attempt_id": str(attempt.get("attempt_id", "")),
                "values": {name: statistics.fmean(rows) for name, rows in values.items()},
            })
    return observations


def _pearson(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or len(left) < 2:
        return 0.0
    left_mean, right_mean = statistics.fmean(left), statistics.fmean(right)
    numerator = sum(
        (a - left_mean) * (b - right_mean) for a, b in zip(left, right)
    )
    left_scale = math.sqrt(sum((value - left_mean) ** 2 for value in left))
    right_scale = math.sqrt(sum((value - right_mean) ** 2 for value in right))
    return numerator / (left_scale * right_scale) if left_scale and right_scale else 0.0


def _ranks(values: Sequence[float]) -> list[float]:
    ordered = sorted(enumerate(values), key=lambda item: item[1])
    result = [0.0] * len(values)
    start = 0
    while start < len(ordered):
        stop = start + 1
        while stop < len(ordered) and ordered[stop][1] == ordered[start][1]:
            stop += 1
        rank = (start + stop - 1) / 2.0 + 1.0
        for index, _ in ordered[start:stop]:
            result[index] = rank
        start = stop
    return result


def _evidence_coverage(payload: Mapping[str, object]) -> dict:
    counts = {
        "artifacts": {"count": 0, "bytes": 0, "checksummed": 0},
        "logs": {"count": 0, "bytes": 0, "checksummed": 0},
        "server_instances": {"count": 0, "config_checksummed": 0, "log_checksummed": 0},
    }
    session = normalize_session(payload)
    instances: dict[str, Mapping[str, object]] = {}
    for case in session["tests"]:
        for attempt in case["attempts"]:
            for key in ("artifacts", "logs"):
                rows = attempt.get(key, [])
                for row in rows if isinstance(rows, (list, tuple)) else ():
                    if not isinstance(row, Mapping):
                        continue
                    counts[key]["count"] += 1
                    size = _finite_number(row.get("size", row.get("bytes")))
                    if size is not None and size >= 0:
                        counts[key]["bytes"] += int(size)
                    if isinstance(row.get("sha256"), str) and len(str(row["sha256"])) == 64:
                        counts[key]["checksummed"] += 1
            servers = attempt.get("servers", [])
            for server in servers if isinstance(servers, (list, tuple)) else ():
                if not isinstance(server, Mapping):
                    continue
                identity = str(server.get("instance_id", "")) or "%s:%s" % (
                    case.get("nodeid", ""), server.get("name", len(instances)),
                )
                instances[identity] = server
    topology = session.get("topology", {})
    pools = topology.get("pools", []) if isinstance(topology, Mapping) else []
    for pool in pools if isinstance(pools, (list, tuple)) else ():
        services = pool.get("services", {}) if isinstance(pool, Mapping) else {}
        for server in services.values() if isinstance(services, Mapping) else ():
            if isinstance(server, Mapping):
                identity = str(server.get("instance_id", "")) or "topology:%d" % len(instances)
                instances[identity] = server
    for server in instances.values():
        counts["server_instances"]["count"] += 1
        if len(str(server.get("config_sha256", ""))) == 64:
            counts["server_instances"]["config_checksummed"] += 1
        artifact = server.get("log_artifact", {})
        if isinstance(artifact, Mapping) and len(str(artifact.get("sha256", ""))) == 64:
            counts["server_instances"]["log_checksummed"] += 1
    server_total = counts["server_instances"]["count"]
    counts["server_instances"]["config_checksum_coverage"] = (
        counts["server_instances"]["config_checksummed"] / server_total
        if server_total else 1.0
    )
    counts["server_instances"]["log_checksum_coverage"] = (
        counts["server_instances"]["log_checksummed"] / server_total
        if server_total else 1.0
    )
    for key in ("artifacts", "logs"):
        total = counts[key]["count"]
        counts[key]["checksum_coverage"] = (
            counts[key]["checksummed"] / total if total else 1.0
        )
    return counts


def session_insights(
    payload: Mapping[str, object], *, min_samples: int = 3,
    correlation_threshold: float = 0.7, outlier_z: float = 3.5,
    max_series: int = 128,
) -> dict:
    """Derive robust, cross-signal analytics from one normalized session.

    Metrics, process resources, wall time, and artifact/log sizes are aligned by
    attempt. Correlations are descriptive rather than causal and retain their
    exact test/series identity for follow-up SQL or notebook analysis.
    """
    if isinstance(min_samples, bool) or not isinstance(min_samples, int) or min_samples < 2:
        raise SpecError("analytics min_samples", min_samples, "must be an integer >= 2")
    if isinstance(max_series, bool) or not isinstance(max_series, int) or not 2 <= max_series <= 4096:
        raise SpecError(
            "analytics max_series", max_series, "must be an integer between 2 and 4096",
        )
    if (
        isinstance(correlation_threshold, bool)
        or not isinstance(correlation_threshold, (int, float))
        or not math.isfinite(float(correlation_threshold))
        or not 0 <= float(correlation_threshold) <= 1
    ):
        raise SpecError(
            "analytics correlation_threshold", correlation_threshold,
            "must be a finite number between 0 and 1",
        )
    if (
        isinstance(outlier_z, bool) or not isinstance(outlier_z, (int, float))
        or not math.isfinite(float(outlier_z)) or float(outlier_z) <= 0
    ):
        raise SpecError("analytics outlier_z", outlier_z, "must be a finite number > 0")

    observations = _attempt_observations(payload)
    grouped: dict[tuple[str, str], list[tuple[str, float]]] = defaultdict(list)
    by_nodeid: dict[str, list[dict]] = defaultdict(list)
    for observation in observations:
        nodeid = str(observation["nodeid"])
        by_nodeid[nodeid].append(observation)
        for name, value in dict(observation["values"]).items():
            grouped[(nodeid, name)].append((str(observation["attempt_id"]), float(value)))

    series = []
    outliers = []
    for (nodeid, name), rows in sorted(grouped.items()):
        values = [value for _, value in rows]
        stats = describe(values)
        series.append({"nodeid": nodeid, "name": name, **stats})
        if len(values) < min_samples:
            continue
        median = float(stats["median"])
        mad = float(stats["mad"])
        for attempt_id, value in rows:
            if mad:
                score = abs(0.6744897501960817 * (value - median) / mad)
                flagged = score >= float(outlier_z)
                method = "modified-z"
            else:
                score = abs(value - median)
                flagged = value != median
                method = "zero-mad-deviation"
            if flagged:
                outliers.append({
                    "nodeid": nodeid, "attempt_id": attempt_id, "series": name,
                    "value": value, "median": median, "score": score, "method": method,
                })

    correlations = []
    skipped_series = 0
    for nodeid, rows in sorted(by_nodeid.items()):
        all_names = sorted({name for row in rows for name in dict(row["values"])})
        names = all_names[:max_series]
        skipped_series += len(all_names) - len(names)
        for left_name, right_name in itertools.combinations(names, 2):
            aligned = [
                (float(row["values"][left_name]), float(row["values"][right_name]))
                for row in rows
                if left_name in row["values"] and right_name in row["values"]
            ]
            if len(aligned) < min_samples:
                continue
            left, right = zip(*aligned)
            pearson = _pearson(left, right)
            spearman = _pearson(_ranks(left), _ranks(right))
            if max(abs(pearson), abs(spearman)) < float(correlation_threshold):
                continue
            correlations.append({
                "nodeid": nodeid, "left": left_name, "right": right_name,
                "samples": len(aligned), "pearson": pearson, "spearman": spearman,
            })

    return {
        "session_id": normalize_session(payload).get("session_id", "unknown"),
        "attempts": len(observations), "series": series,
        "correlations": correlations, "outliers": outliers,
        "evidence": _evidence_coverage(payload),
        "parameters": {
            "min_samples": min_samples,
            "correlation_threshold": float(correlation_threshold),
            "outlier_z": float(outlier_z),
            "max_series": max_series,
        },
        "truncated": {"correlation_series": skipped_series},
    }

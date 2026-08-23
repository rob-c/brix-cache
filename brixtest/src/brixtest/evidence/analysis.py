"""Deterministic descriptive, comparative, trend, and regression analytics."""

from __future__ import annotations

import itertools
import math
import statistics
from collections import defaultdict
from typing import Mapping, Optional, Sequence

from brixtest.errors import SpecError
from brixtest.evidence.analysis_statistics import (
    bootstrap_mean_ci,
    cliffs_delta,
    compare,
    describe,
    percentile,
    trend,
)
from brixtest.evidence.model import normalize_session

__all__ = [
    "bootstrap_mean_ci", "cliffs_delta", "compare", "describe", "percentile",
    "session_insights", "trend",
]


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


def _observation_values(attempt) -> dict[str, list[float]]:
    values: dict[str, list[float]] = defaultdict(list)
    wall = _finite_number(attempt.get("wall_seconds"))
    if wall is not None:
        values["attempt.wall_seconds"].append(wall)
    for prefix, field in (("metric", "metrics"), ("resource", "resources")):
        _value_observations(values, prefix, attempt.get(field, []))
    for prefix, field in (("artifact", "artifacts"), ("log", "logs")):
        _size_observations(values, prefix, attempt.get(field, []))
    return values


def _value_observations(values, prefix: str, rows) -> None:
    iterable = rows if isinstance(rows, (list, tuple)) else ()
    for raw in iterable:
        if not isinstance(raw, Mapping):
            continue
        number = _finite_number(raw.get("value"))
        if number is not None:
            values[_series_name(prefix, raw)].append(number)


def _size_observations(values, prefix: str, rows) -> None:
    total = 0.0
    found = False
    for raw in rows if isinstance(rows, (list, tuple)) else ():
        if not isinstance(raw, Mapping):
            continue
        number = _finite_number(raw.get("size", raw.get("bytes")))
        if number is None or number < 0:
            continue
        found, total = True, total + number
        name = str(raw.get("name", raw.get("path", "unnamed")))[:96]
        values["%s.%s.bytes" % (prefix, name)].append(number)
    if found:
        values["%s.total_bytes" % prefix].append(total)


def _attempt_observations(payload: Mapping[str, object]) -> list[dict]:
    observations = []
    for case in normalize_session(payload)["tests"]:
        nodeid = str(case.get("nodeid", ""))
        for attempt in case["attempts"]:
            if attempt.get("warmup"):
                continue
            values = _observation_values(attempt)
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
    numerator = _covariance_numerator(left, right, left_mean, right_mean)
    denominator = _series_scale(left, left_mean) * _series_scale(right, right_mean)
    return numerator / denominator if denominator else 0.0


def _covariance_numerator(left, right, left_mean: float, right_mean: float) -> float:
    return sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))


def _series_scale(values, mean: float) -> float:
    return math.sqrt(sum((value - mean) ** 2 for value in values))


def _ranks(values: Sequence[float]) -> list[float]:
    ordered = sorted(enumerate(values), key=lambda item: item[1])
    result = [0.0] * len(values)
    start = 0
    while start < len(ordered):
        stop = start + 1
        while stop < len(ordered) and ordered[stop][1] == ordered[start][1]:
            stop += 1
        rank = _midrank(start, stop)
        for index, _ in ordered[start:stop]:
            result[index] = rank
        start = stop
    return result


def _midrank(start: int, stop: int) -> float:
    return (start + stop - 1) / 2.0 + 1.0


def _evidence_coverage(payload: Mapping[str, object]) -> dict:
    counts = {
        "artifacts": {"count": 0, "bytes": 0, "checksummed": 0},
        "logs": {"count": 0, "bytes": 0, "checksummed": 0},
        "server_instances": {"count": 0, "config_checksummed": 0, "log_checksummed": 0},
    }
    session = normalize_session(payload)
    instances = _attempt_coverage(session, counts)
    instances.update(_topology_coverage(session))
    _server_coverage(instances, counts["server_instances"])
    _coverage_ratios(counts)
    return counts


def _count_coverage(rows, values) -> None:
    for row in rows if isinstance(rows, (list, tuple)) else ():
        if not isinstance(row, Mapping):
            continue
        values["count"] += 1
        size = _finite_number(row.get("size", row.get("bytes")))
        if size is not None and size >= 0:
            values["bytes"] += int(size)
        if isinstance(row.get("sha256"), str) and len(str(row["sha256"])) == 64:
            values["checksummed"] += 1


def _attempt_coverage(session, counts) -> dict[str, Mapping[str, object]]:
    instances = {}
    for case in session["tests"]:
        for attempt in case["attempts"]:
            for key in ("artifacts", "logs"):
                _count_coverage(attempt.get(key, []), counts[key])
            _attempt_servers(instances, case, attempt.get("servers", []))
    return instances


def _attempt_servers(instances, case, servers) -> None:
    iterable = servers if isinstance(servers, (list, tuple)) else ()
    for server in iterable:
        if not isinstance(server, Mapping):
            continue
        identity = str(server.get("instance_id", "")) or "%s:%s" % (
            case.get("nodeid", ""), server.get("name", len(instances)),
        )
        instances[identity] = server


def _topology_coverage(session) -> dict[str, Mapping[str, object]]:
    instances = {}
    topology = session.get("topology", {})
    pools = topology.get("pools", []) if isinstance(topology, Mapping) else []
    for pool in pools if isinstance(pools, (list, tuple)) else ():
        _topology_pool(instances, pool)
    return instances


def _topology_pool(instances, pool) -> None:
    for server in _topology_services(pool):
        if not isinstance(server, Mapping):
            continue
        identity = _topology_identity(server, len(instances))
        instances[identity] = server


def _topology_services(pool):
    if not isinstance(pool, Mapping):
        return ()
    services = pool.get("services", {})
    return services.values() if isinstance(services, Mapping) else ()


def _topology_identity(server, index: int) -> str:
    return str(server.get("instance_id", "")) or "topology:%d" % index


def _server_coverage(instances, values) -> None:
    for server in instances.values():
        values["count"] += 1
        if len(str(server.get("config_sha256", ""))) == 64:
            values["config_checksummed"] += 1
        artifact = server.get("log_artifact", {})
        if isinstance(artifact, Mapping) and len(str(artifact.get("sha256", ""))) == 64:
            values["log_checksummed"] += 1


def _coverage_ratios(counts) -> None:
    servers = counts["server_instances"]
    total = servers["count"]
    servers["config_checksum_coverage"] = servers["config_checksummed"] / total if total else 1.0
    servers["log_checksum_coverage"] = servers["log_checksummed"] / total if total else 1.0
    for key in ("artifacts", "logs"):
        total = counts[key]["count"]
        counts[key]["checksum_coverage"] = counts[key]["checksummed"] / total if total else 1.0


def _analytics_parameters(min_samples, threshold, outlier_z, max_series) -> None:
    if not _integer_between(min_samples, 2):
        raise SpecError("analytics min_samples", min_samples, "must be an integer >= 2")
    if not _integer_between(max_series, 2, 4096):
        raise SpecError("analytics max_series", max_series, "must be an integer between 2 and 4096")
    if not _finite_between(threshold, 0, 1):
        raise SpecError(
            "analytics correlation_threshold", threshold,
            "must be a finite number between 0 and 1",
        )
    if not _finite_between(outlier_z, 0, minimum_inclusive=False):
        raise SpecError("analytics outlier_z", outlier_z, "must be a finite number > 0")


def _integer_between(value, minimum: int, maximum: Optional[int] = None) -> bool:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        return False
    return maximum is None or value <= maximum


def _finite_between(
    value, minimum: float, maximum: Optional[float] = None, *, minimum_inclusive: bool = True,
) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    numeric = float(value)
    if not math.isfinite(numeric):
        return False
    lower = numeric >= minimum if minimum_inclusive else numeric > minimum
    return lower and (maximum is None or numeric <= maximum)


def _group_observations(observations):
    grouped: dict[tuple[str, str], list[tuple[str, float]]] = defaultdict(list)
    by_nodeid: dict[str, list[dict]] = defaultdict(list)
    for observation in observations:
        nodeid = str(observation["nodeid"])
        by_nodeid[nodeid].append(observation)
        for name, value in dict(observation["values"]).items():
            grouped[(nodeid, name)].append((str(observation["attempt_id"]), float(value)))
    return grouped, by_nodeid


def _series_and_outliers(grouped, min_samples: int, outlier_z: float):
    series, outliers = [], []
    for (nodeid, name), rows in sorted(grouped.items()):
        values = [value for _, value in rows]
        stats = describe(values)
        series.append({"nodeid": nodeid, "name": name, **stats})
        if len(values) < min_samples:
            continue
        outliers.extend(_outlier_rows(nodeid, name, rows, stats, outlier_z))
    return series, outliers


def _outlier_rows(nodeid, name, rows, stats, threshold: float) -> list[dict]:
    median, mad = float(stats["median"]), float(stats["mad"])
    found = []
    for attempt_id, value in rows:
        score = _outlier_score(value, median, mad)
        if _outlier_flagged(value, median, score, mad, threshold):
            found.append({
                "nodeid": nodeid, "attempt_id": attempt_id, "series": name,
                "value": value, "median": median, "score": score,
                "method": "modified-z" if mad else "zero-mad-deviation",
            })
    return found


def _outlier_score(value: float, median: float, mad: float) -> float:
    return abs(0.6744897501960817 * (value - median) / mad) if mad \
        else abs(value - median)


def _outlier_flagged(
    value: float, median: float, score: float, mad: float, threshold: float,
) -> bool:
    return score >= threshold if mad else value != median


def _correlation_rows(by_nodeid, min_samples: int, threshold: float, max_series: int):
    correlations, skipped = [], 0
    for nodeid, rows in sorted(by_nodeid.items()):
        all_names = sorted({name for row in rows for name in dict(row["values"])})
        names = all_names[:max_series]
        skipped += len(all_names) - len(names)
        for left_name, right_name in itertools.combinations(names, 2):
            row = _correlation(
                nodeid, rows, left_name, right_name, min_samples, threshold,
            )
            if row is not None:
                correlations.append(row)
    return correlations, skipped


def _correlation(nodeid, rows, left_name, right_name, minimum: int, threshold: float):
    aligned = [
        (float(row["values"][left_name]), float(row["values"][right_name]))
        for row in rows if left_name in row["values"] and right_name in row["values"]
    ]
    if len(aligned) < minimum:
        return None
    left, right = zip(*aligned)
    pearson = _pearson(left, right)
    spearman = _pearson(_ranks(left), _ranks(right))
    if max(abs(pearson), abs(spearman)) < threshold:
        return None
    return {
        "nodeid": nodeid, "left": left_name, "right": right_name,
        "samples": len(aligned), "pearson": pearson, "spearman": spearman,
    }


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
    _analytics_parameters(min_samples, correlation_threshold, outlier_z, max_series)
    observations = _attempt_observations(payload)
    grouped, by_nodeid = _group_observations(observations)
    series, outliers = _series_and_outliers(grouped, min_samples, float(outlier_z))
    correlations, skipped_series = _correlation_rows(
        by_nodeid, min_samples, float(correlation_threshold), max_series,
    )

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

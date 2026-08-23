"""Versioned, JSON-safe records shared by runners, stores, and exporters."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Mapping, MutableMapping, Sequence

from brixtest.errors import SpecError

SCHEMA_VERSION = 2
ENTITY_TYPES = frozenset({
    "session", "case", "attempt", "metric", "resource", "span", "artifact",
    "log", "finding", "provenance", "server-instance", "server-pool",
})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(*parts: object) -> str:
    text = "\0".join(str(part) for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _list(value: object) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _mapping(value: object) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}


def _finite(value: object, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _attempt_from_v1(record: Mapping[str, object]) -> dict:
    attempt_id = stable_id(record.get("session_id", ""), record.get("nodeid", ""), 0)
    metrics = _mapping(record.get("metrics"))
    return {
        "attempt_id": attempt_id,
        "index": 0,
        "trial": 0,
        "warmup": False,
        "outcome": str(record.get("outcome", "unknown")),
        "started_at": str(record.get("started_at", "")),
        "wall_seconds": _finite(record.get("wall_seconds")),
        "run_root": str(record.get("run_root", "")),
        "error": str(record.get("error", "")),
        "metrics": _list(metrics.get("samples")),
        "resources": [],
        "spans": [],
        "artifacts": [],
        "logs": _list(record.get("logs")),
        "servers": _list(record.get("servers")),
        "findings": [],
        "provenance": {},
    }


def migrate_case(value: Mapping[str, object]) -> dict:
    """Return a schema-v2 case without mutating the caller's record."""
    record = copy.deepcopy(dict(value))
    schema = record.get("schema", 1)
    if schema not in (1, SCHEMA_VERSION):
        raise SpecError("evidence schema", schema, "supported versions are 1 and 2")
    if schema == 1:
        record["attempts"] = [_attempt_from_v1(record)]
        record["schema"] = SCHEMA_VERSION
    attempts = []
    for index, raw in enumerate(_list(record.get("attempts"))):
        if not isinstance(raw, Mapping):
            continue
        attempt = dict(raw)
        attempt.setdefault("attempt_id", stable_id(
            record.get("session_id", ""), record.get("nodeid", ""), index
        ))
        attempt.setdefault("index", index)
        attempt.setdefault("trial", index)
        attempt.setdefault("warmup", False)
        attempt.setdefault("outcome", record.get("outcome", "unknown"))
        attempt.setdefault("metrics", [])
        for field in ("resources", "spans", "artifacts", "logs", "findings", "servers"):
            attempt[field] = _list(attempt.get(field))
        attempt["provenance"] = _mapping(attempt.get("provenance"))
        attempts.append(attempt)
    record["attempts"] = attempts
    record.setdefault("case_id", stable_id(record.get("session_id", ""), record.get("nodeid", "")))
    record.setdefault("schema_name", "brixtest.evidence")
    record.setdefault("created_at", utc_now())
    return record


def normalize_session(value: Mapping[str, object]) -> dict:
    """Normalize a session and derive counts without discarding unknown fields."""
    payload = copy.deepcopy(dict(value))
    tests = [migrate_case(row) for row in _list(payload.get("tests"))
             if isinstance(row, Mapping)]
    counts = {}
    for row in tests:
        outcome = str(row.get("outcome", "unknown"))
        counts[outcome] = counts.get(outcome, 0) + 1
    payload.update({
        "schema": SCHEMA_VERSION,
        "schema_name": "brixtest.evidence",
        "tests": tests,
        "counts": counts,
    })
    payload.setdefault("generated_at", utc_now())
    payload.setdefault("session_id", "unknown")
    return payload


def validate_session(value: Mapping[str, object]) -> None:
    """Refuse malformed identifiers and non-finite numeric observations."""
    payload = normalize_session(value)
    if not str(payload.get("session_id", "")):
        raise SpecError("session_id", payload.get("session_id"), "must not be empty")
    for case in payload["tests"]:
        _validate_case(case)


def _validate_case(case: Mapping[str, object]) -> None:
    if not str(case.get("nodeid", "")):
        raise SpecError("case.nodeid", case.get("nodeid"), "must not be empty")
    for attempt in case["attempts"]:
        _validate_attempt(attempt)


def _validate_attempt(attempt: Mapping[str, object]) -> None:
    if not str(attempt.get("attempt_id", "")):
        raise SpecError("attempt_id", attempt.get("attempt_id"), "must not be empty")
    observations = _list(attempt.get("metrics")) + _list(attempt.get("resources"))
    for sample in observations:
        _validate_observation(sample)


def _validate_observation(sample: object) -> None:
    if not isinstance(sample, Mapping):
        return
    observed = _finite(sample.get("value"), float("nan"))
    if not math.isfinite(observed):
        raise SpecError("evidence value", sample.get("value"), "must be finite")


def _attempt_record(base: Mapping[str, object], attempt: Mapping[str, object]) -> dict:
    excluded = {
        "metrics", "resources", "spans", "artifacts", "logs",
        "findings", "provenance", "servers",
    }
    details = {key: value for key, value in attempt.items() if key not in excluded}
    return {"entity": "attempt", **base, **details}


def _attempt_rows(
    entity: str, field: str, base: Mapping[str, object], attempt: Mapping[str, object],
):
    for index, row in enumerate(_list(attempt.get(field))):
        if isinstance(row, Mapping):
            yield {"entity": entity, **base, "ordinal": index, **dict(row)}


def _attempt_entities(session_id: str, case, attempt):
    base = {
        "session_id": session_id, "case_id": case["case_id"],
        "nodeid": case.get("nodeid", ""), "attempt_id": attempt["attempt_id"],
    }
    yield _attempt_record(base, attempt)
    for entity, field in (
        ("metric", "metrics"), ("resource", "resources"), ("span", "spans"),
        ("artifact", "artifacts"), ("log", "logs"), ("finding", "findings"),
        ("server-instance", "servers"),
    ):
        yield from _attempt_rows(entity, field, base, attempt)
    provenance = _mapping(attempt.get("provenance"))
    if provenance:
        yield {"entity": "provenance", **base, **provenance}


def _pool_services(base: Mapping[str, object], pool: Mapping[str, object]):
    for index, service in enumerate(_mapping(pool.get("services")).values()):
        if not isinstance(service, Mapping):
            continue
        yield {"entity": "server-instance", **base, "ordinal": index, **dict(service)}
        artifact = _mapping(service.get("log_artifact"))
        if artifact:
            yield {"entity": "log", **base, "ordinal": index, **artifact}


def _pool_metrics(base: Mapping[str, object], result: Mapping[str, object]):
    metrics = _mapping(result.get("metrics"))
    for index, row in enumerate(_list(metrics.get("samples"))):
        if isinstance(row, Mapping):
            yield {"entity": "metric", **base, "ordinal": index, **dict(row)}


def _pool_evidence_rows(
    base: Mapping[str, object], evidence: Mapping[str, object],
):
    for entity, field in (
        ("resource", "resources"), ("span", "spans"),
        ("artifact", "artifacts"), ("finding", "findings"),
    ):
        for index, row in enumerate(_list(evidence.get(field))):
            if isinstance(row, Mapping):
                yield {"entity": entity, **base, "ordinal": index, **dict(row)}


def _pool_entities(session_id: str, pool):
    pool_id = str(pool.get("pool_id", ""))
    base = {
        "session_id": session_id, "pool_id": pool_id,
        "nodeid": "@shared/%s" % pool_id, "attempt_id": "shared-" + pool_id,
    }
    yield {"entity": "server-pool", **base, **dict(pool)}
    yield from _pool_services(base, pool)
    result = _mapping(pool.get("result"))
    evidence = _mapping(result.get("evidence"))
    yield from _pool_metrics(base, result)
    yield from _pool_evidence_rows(base, evidence)
    provenance = _mapping(evidence.get("provenance"))
    if provenance:
        yield {"entity": "provenance", **base, **provenance}


def _case_entities(session_id: str, cases: Sequence[Mapping[str, object]]):
    for case in cases:
        case_base = {key: value for key, value in case.items() if key != "attempts"}
        yield {"entity": "case", **case_base}
        for attempt in case["attempts"]:
            yield from _attempt_entities(session_id, case, attempt)


def _topology_entities(session_id: str, topology: Mapping[str, object]):
    for pool in _list(topology.get("pools")):
        if isinstance(pool, Mapping):
            yield from _pool_entities(session_id, pool)


def iter_entities(payload: Mapping[str, object]):
    """Yield normalized entity documents suitable for stores and transports."""
    session = normalize_session(payload)
    session_id = str(session["session_id"])
    session_record = {key: value for key, value in session.items() if key != "tests"}
    yield {"entity": "session", **session_record}
    yield from _case_entities(session_id, session["tests"])
    topology = _mapping(session.get("topology"))
    yield from _topology_entities(session_id, topology)


def canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )


def merge_attempt_metrics(attempts: Sequence[Mapping[str, object]]) -> list:
    """Flatten measured attempt metrics, retaining trial and attempt identity."""
    rows = []
    for attempt in attempts:
        if attempt.get("warmup"):
            continue
        for raw in _list(attempt.get("metrics")):
            if isinstance(raw, Mapping):
                row: MutableMapping[str, object] = dict(raw)
                row.setdefault("trial", attempt.get("trial", 0))
                row.setdefault("attempt_id", attempt.get("attempt_id", ""))
                rows.append(dict(row))
    return rows

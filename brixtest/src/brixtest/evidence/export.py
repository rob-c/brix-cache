"""Portable Parquet, OTLP/HTTP JSON, session package, and S3 exports."""

from __future__ import annotations

import json
import os
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Mapping

from brixtest.errors import SpecError
from brixtest.evidence.artifacts import upload_s3
from brixtest.evidence.model import iter_entities, normalize_session
from brixtest.util.http import http_url


def _flat_rows(payload: Mapping[str, object]) -> list[dict]:
    return [
        {
            "entity": str(entity.get("entity", "")),
            "session_id": str(entity.get("session_id", payload.get("session_id", ""))),
            "case_id": str(entity.get("case_id", "")),
            "attempt_id": str(entity.get("attempt_id", "")),
            "nodeid": str(entity.get("nodeid", "")),
            "name": str(entity.get("name", "")),
            "value": float(entity["value"]) if isinstance(entity.get("value"), (int, float)) else None,
            "unit": str(entity.get("unit", "")),
            "timestamp": str(entity.get("timestamp", entity.get("started_at", ""))),
            "payload_json": json.dumps(entity, sort_keys=True, default=str),
        }
        for entity in iter_entities(payload)
    ]


def write_parquet(payload: Mapping[str, object], path: Path) -> Path:
    try:
        import pyarrow as pa
        from pyarrow import parquet
    except ImportError as exc:
        raise SpecError("Parquet export", str(path), "install brixtest[analytics]") from exc
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(_flat_rows(payload))
    parquet.write_table(table, target, compression="zstd")
    return target


def _nano(seconds: object) -> str:
    try:
        return str(int(float(seconds) * 1_000_000_000))
    except (TypeError, ValueError):
        return "0"


def otlp_payloads(payload: Mapping[str, object]) -> dict[str, dict]:
    session = normalize_session(payload)
    metric_points, spans, log_records = [], [], []
    for entity in iter_entities(session):
        kind = entity.get("entity")
        attributes = [
            {"key": "brixtest.session.id", "value": {"stringValue": str(session["session_id"])}},
            {"key": "brixtest.test.nodeid", "value": {"stringValue": str(entity.get("nodeid", ""))}},
        ]
        if kind in ("metric", "resource"):
            metric_points.append({
                "name": str(entity.get("name", "")), "unit": str(entity.get("unit", "")),
                "gauge": {"dataPoints": [{"asDouble": float(entity.get("value", 0)),
                                             "attributes": attributes}]},
            })
        elif kind == "span":
            spans.append({
                "traceId": str(entity.get("attempt_id", ""))[:32].ljust(32, "0"),
                "spanId": str(entity.get("span_id", ""))[:16].ljust(16, "0"),
                "parentSpanId": str(entity.get("parent_id", "")),
                "name": str(entity.get("name", "")),
                "startTimeUnixNano": _nano(entity.get("start_seconds", 0)),
                "endTimeUnixNano": _nano(float(entity.get("start_seconds", 0))
                                              + float(entity.get("duration_seconds", 0))),
                "attributes": attributes,
            })
        elif kind in ("log", "finding"):
            log_records.append({
                "timeUnixNano": _nano(entity.get("at_seconds", 0)),
                "severityText": str(entity.get("severity", "INFO")).upper(),
                "body": {"stringValue": json.dumps(entity, sort_keys=True, default=str)},
                "attributes": attributes,
            })
    resource = {"attributes": [{"key": "service.name", "value": {"stringValue": "brixtest"}}]}
    return {
        "metrics": {"resourceMetrics": [{"resource": resource,
                    "scopeMetrics": [{"scope": {"name": "brixtest"}, "metrics": metric_points}]}]},
        "traces": {"resourceSpans": [{"resource": resource,
                   "scopeSpans": [{"scope": {"name": "brixtest"}, "spans": spans}]}]},
        "logs": {"resourceLogs": [{"resource": resource,
                 "scopeLogs": [{"scope": {"name": "brixtest"}, "logRecords": log_records}]}]},
    }


def write_otlp_json(payload: Mapping[str, object], path: Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(otlp_payloads(payload), indent=2, sort_keys=True) + "\n")
    return target


def post_otlp(payload: Mapping[str, object], endpoint: str, *, timeout: float = 30.0) -> None:
    endpoint = http_url(endpoint, "OTLP endpoint")
    token = os.environ.get("BRIXTEST_OTLP_BEARER_TOKEN", "")
    for signal, body in otlp_payloads(payload).items():
        request = urllib.request.Request(  # noqa: S310 - endpoint scheme validated above
            endpoint.rstrip("/") + "/v1/" + signal,
            data=json.dumps(body, separators=(",", ":")).encode(), method="POST",
            headers={"Content-Type": "application/json"},
        )
        if token:
            request.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(  # noqa: S310 - endpoint scheme validated above
                request, timeout=timeout,
            ) as response:
                response.read()
        except (OSError, urllib.error.HTTPError) as exc:
            raise SpecError("OTLP export", endpoint, "%s upload failed: %s" % (signal, exc)) from exc


def package_session(session_dir: Path, output: Path) -> Path:
    root = Path(session_dir).resolve()
    target = Path(output).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, "w:gz") as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.resolve() != target:
                archive.add(path, arcname=str(Path(root.name) / path.relative_to(root)), recursive=False)
    return target


def upload_session_s3(session_dir: Path, destination: str) -> str:
    with tempfile.TemporaryDirectory(prefix="brixtest-export-") as temporary:
        archive = package_session(session_dir, Path(temporary) / (Path(session_dir).name + ".tar.gz"))
        return upload_s3(archive, destination)

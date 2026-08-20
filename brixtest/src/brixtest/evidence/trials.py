"""Controller-side warmup/trial orchestration with fail-fast semantics."""

from __future__ import annotations

import dataclasses
import uuid
from pathlib import Path
from typing import Callable, Mapping, Sequence

from brixtest.evidence.model import stable_id
from brixtest.evidence.journal import EvidenceJournal
from brixtest.metrics import merge_metric_snapshots


@dataclasses.dataclass(frozen=True)
class Invocation:
    run_root: Path
    attempt_id: str
    index: int
    trial: int
    warmup: bool
    returncode: int
    output: str
    payload: Mapping[str, object]
    timed_out: bool
    started: float
    stopped: float
    isolation: str
    logs: Sequence[Mapping[str, object]]

    @property
    def outcome(self) -> str:
        value = str(self.payload.get("outcome", "passed" if self.returncode == 0 else "failed"))
        return value if value in ("passed", "failed", "skipped") else "failed"


def execute(
    *, nodeid: str, warmups: int, trials: int,
    root_factory: Callable[[], Path], invoke: Callable[..., tuple],
) -> list[Invocation]:
    """Run attempts in order and stop immediately on timeout/error/failure."""
    results = []
    total = warmups + trials
    for index in range(total):
        warmup = index < warmups
        trial = index if warmup else index - warmups
        attempt_id = stable_id(nodeid, index, uuid.uuid4().hex)
        root = root_factory()
        raw = invoke(root, attempt_id=attempt_id, trial=trial, warmup=warmup)
        result = Invocation(root, attempt_id, index, trial, warmup, *raw)
        results.append(result)
        if result.timed_out or result.returncode != 0 or result.outcome == "failed":
            break
    return results


def attempt_record(invocation: Invocation) -> dict:
    evidence = invocation.payload.get("evidence", {})
    observed = dict(evidence) if isinstance(evidence, Mapping) else {}
    if not observed:
        recovered = EvidenceJournal.recover(
            invocation.run_root / "evidence" / "journal.jsonl"
        )
        fields = {
            "metric": "metrics", "resource": "resources", "span": "spans",
            "artifact": "artifacts", "finding": "findings",
        }
        for row in recovered:
            field = fields.get(str(row.get("event", "")))
            data = row.get("data", {})
            if field and isinstance(data, Mapping):
                observed.setdefault(field, []).append(dict(data))
            if row.get("event") == "provenance" and isinstance(data, Mapping):
                observed["provenance"] = dict(data)
    metrics = invocation.payload.get("metrics", {})
    snapshot = dict(metrics) if isinstance(metrics, Mapping) else {}
    logs = [dict(row) for row in invocation.logs] + list(observed.get("logs", []))
    servers = []
    for raw in observed.get("servers", []):
        if not isinstance(raw, Mapping):
            continue
        server = dict(raw)
        source = str(server.get("log_source", ""))
        match = next((row for row in logs if str(row.get("source", "")) == source), None)
        if match is not None:
            server["log_artifact"] = dict(match)
        servers.append(server)
    return {
        "attempt_id": invocation.attempt_id,
        "index": invocation.index,
        "trial": invocation.trial,
        "warmup": invocation.warmup,
        "outcome": invocation.outcome,
        "started_at": observed.get("started_at", ""),
        "wall_seconds": round(invocation.stopped - invocation.started, 9),
        "run_root": str(invocation.run_root),
        "error": invocation.output if invocation.outcome == "failed" else "",
        "metrics": (
            list(snapshot.get("samples", []))
            if isinstance(snapshot.get("samples", []), list) and snapshot.get("samples")
            else list(observed.get("metrics", []))
        ),
        "resources": list(observed.get("resources", [])),
        "spans": list(observed.get("spans", [])),
        "artifacts": list(observed.get("artifacts", [])),
        "logs": logs,
        "servers": servers,
        "findings": list(observed.get("findings", [])),
        "provenance": dict(observed.get("provenance", {})),
        "journal": observed.get("journal", ""),
    }


def measured_metrics(invocations: Sequence[Invocation]) -> dict:
    snapshots = []
    for invocation in invocations:
        metrics = invocation.payload.get("metrics", {})
        if not invocation.warmup and isinstance(metrics, Mapping):
            snapshot = dict(metrics)
            for sample in snapshot.get("samples", []):
                if isinstance(sample, dict):
                    sample.setdefault("attempt_id", invocation.attempt_id)
                    sample.setdefault("trial", invocation.trial)
            snapshots.append(snapshot)
    return merge_metric_snapshots(snapshots)

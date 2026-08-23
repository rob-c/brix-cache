"""Serialize one managed case without growing the orchestration module."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone


def write_case_summary(manager, *, error: str = "") -> None:
    manager.root.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 2,
        "schema_name": "brixtest.evidence",
        "nodeid": manager.nodeid,
        "backend": manager.backend_name,
        "outcome": manager._outcome,
        "run_root": str(manager.root),
        "source": str(manager.definition.source),
        "pid": os.getpid(),
        "started_at": datetime.fromtimestamp(manager._started_at, timezone.utc).isoformat(),
        "wall_seconds": round(time.time() - manager._started_at, 6),
        "servers": {
            name: {
                "host": item.host, "ports": dict(item.ports),
                "hosts": dict(item.hosts),
                "config": str(item.config), "log": str(item.log),
                "config_filename": item.config_filename or item.config.name,
                "instance_id": item.instance_id, "scope": item.scope,
                "pool_id": item.pool_id,
                "config_sha256": item.config_sha256,
                "config_source_sha256": item.config_source_sha256,
                "config_declared_sha256": item.config_declared_sha256,
                "config_artifact": dict(item.config_artifact),
            }
            for name, item in sorted(manager._services.items())
        },
        "artifacts": {
            name: {"path": str(item.path), "size": item.size, "sha256": item.sha256}
            for name, item in sorted(manager.artifact_store._items.items())
        },
        "binaries": {
            name: {"path": str(item.path), "sha256": item.sha256}
            for name, item in sorted(manager.binary_store._captured.items())
        },
        "volumes": {
            name: item.as_dict()
            for name, item in sorted(manager._managed.volumes._items.items())
        },
        "tasks": {
            name: item.as_dict()
            for name, item in sorted(manager._managed.tasks.items())
        },
        **manager.security.summary(),
        "error": error,
        "metrics": manager.metrics.snapshot(),
        "evidence": manager.evidence.snapshot(),
    }
    (manager.root / "summary.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    )


def _environment_names(variable: str) -> list[str]:
    default = "[]" if "KEYS" in variable else "{}"
    try:
        raw = json.loads(os.environ.get(variable, default))
    except (TypeError, ValueError):
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return list(raw)
    return []


def _declared_environment_names() -> list[str]:
    names = []
    for variable in (
        "BRIXTEST_TEST_ENV_KEYS_JSON", "BRIXTEST_SERVER_ENV_JSON",
        "BRIXTEST_CLIENT_ENV_JSON",
    ):
        names.extend(_environment_names(variable))
    return names


def _finalize_extra(manager) -> dict:
    return {
        "servers": sorted(manager._services),
        "credentials": sorted(manager.definition.credentials, key=lambda item: item.name),
        "auth_stacks": [item.name for item in manager.definition.auth],
        "volumes": sorted(manager._managed.volumes._items),
        "tasks": sorted(manager._managed.tasks),
        "resource_graph": manager._resource_graph.as_dict(),
    }


def _evidence_error(errors: list[dict]) -> str:
    return "; ".join(
        str(item.get("detail", item.get("kind", "evidence error")))
        for item in errors
    )


def finalize_evidence(manager) -> str:
    configs = {name: item.rendered for name, item in manager.config_store._items.items()}
    manager.evidence.finalize(
        outcome=manager._outcome,
        binaries=manager.binary_store._captured,
        configs=configs,
        environment_names=_declared_environment_names(),
        extra=_finalize_extra(manager),
    )
    errors = manager.evidence.error_findings()
    if manager._outcome == "passed" and errors:
        manager._outcome = "teardown-failed"
        manager.metrics.tag("outcome", manager._outcome)
        return _evidence_error(errors)
    return ""

"""Durable Kubernetes ownership records used across helper failure boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping


def ownership_path(run_root: Path, environment: str = "") -> Path:
    filename = "namespace.json" if not environment else "namespace-%s.json" % environment
    return Path(run_root) / "runtime" / "kubernetes" / filename


def write_ownership(
    run_root: Path, namespace: str, uid: str, *, environment: str = "",
) -> Path:
    path = ownership_path(run_root, environment)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(
        {"schema": 1, "namespace": namespace, "uid": uid}, sort_keys=True,
    ) + "\n")
    temporary.replace(path)
    return path


def read_ownership(run_root: Path) -> Mapping[str, str]:
    try:
        payload = json.loads(ownership_path(run_root).read_text())
    except (OSError, TypeError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    namespace, uid = payload.get("namespace"), payload.get("uid")
    if not isinstance(namespace, str) or not namespace:
        return {}
    if not isinstance(uid, str) or not uid:
        return {}
    return {"namespace": namespace, "uid": uid}


__all__ = ["ownership_path", "read_ownership", "write_ownership"]

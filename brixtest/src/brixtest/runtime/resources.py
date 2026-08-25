"""Resource inventory metrics for a materialized case."""

from __future__ import annotations

from pathlib import Path


def _tree_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(candidate.stat().st_size for candidate in path.rglob("*")
               if candidate.is_file()) if path.is_dir() else 0


def record_materialized_sizes(manager) -> None:
    artifact_bytes = _artifact_bytes(manager)
    binary_bytes = _binary_bytes(manager)
    manager.metrics.gauge("resources.artifact_bytes", artifact_bytes, unit="bytes")
    manager.metrics.gauge("resources.binary_bytes", binary_bytes, unit="bytes")
    manager.metrics.gauge(
        "resources.security_bytes", _tree_size(manager.security.root), unit="bytes"
    )
    manager.metrics.gauge(
        "resources.binaries", len(manager.binary_store._captured), unit="count"
    )
    manager.metrics.gauge(
        "resources.volume_bytes", _volume_bytes(manager), unit="bytes",
    )
    manager.metrics.gauge(
        "resources.task_outputs", _task_outputs(manager), unit="count",
    )


def _artifact_bytes(manager) -> int:
    return sum(item.size for item in manager.artifact_store._items.values())


def _binary_bytes(manager) -> int:
    return sum(_tree_size(item.path.parent) for item in manager.binary_store._captured.values())


def _volume_bytes(manager) -> int:
    owned = (
        item for item in manager._managed.volumes._items.values()
        if item.kind not in ("host", "device")
    )
    return sum(_tree_size(item.path) for item in owned)


def _task_outputs(manager) -> int:
    return sum(len(item.outputs) for item in manager._managed.tasks.values())

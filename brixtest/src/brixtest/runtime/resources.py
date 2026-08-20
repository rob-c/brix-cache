"""Resource inventory metrics for a materialized case."""

from __future__ import annotations

from pathlib import Path


def _tree_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(candidate.stat().st_size for candidate in path.rglob("*")
               if candidate.is_file()) if path.is_dir() else 0


def record_materialized_sizes(manager) -> None:
    artifact_bytes = sum(item.size for item in manager.artifact_store._items.values())
    binary_bytes = sum(
        _tree_size(item.path.parent) for item in manager.binary_store._captured.values()
    )
    manager.metrics.gauge("resources.artifact_bytes", artifact_bytes, unit="bytes")
    manager.metrics.gauge("resources.binary_bytes", binary_bytes, unit="bytes")
    manager.metrics.gauge(
        "resources.security_bytes", _tree_size(manager.security.root), unit="bytes"
    )
    manager.metrics.gauge(
        "resources.binaries", len(manager.binary_store._captured), unit="count"
    )

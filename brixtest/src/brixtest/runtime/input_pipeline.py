"""Two-stage immutable input capture around managed preparation tasks."""

from __future__ import annotations

import dataclasses
from typing import Iterable

from brixtest._design_inputs import Artifact, Binary
from brixtest.resources import Reference


def _task_output(value: object) -> bool:
    return (
        isinstance(value, Reference)
        and value.kind == "task" and value.attribute == "output"
    )


def immediate_binaries(values: Iterable[Binary]) -> tuple[Binary, ...]:
    return tuple(value for value in values if not _task_output(value.path))


def deferred_binaries(values: Iterable[Binary]) -> tuple[Binary, ...]:
    return tuple(value for value in values if _task_output(value.path))


def immediate_artifacts(values: Iterable[Artifact]) -> tuple[Artifact, ...]:
    return tuple(value for value in values if not _task_output(value.source))


def deferred_artifacts(values: Iterable[Artifact]) -> tuple[Artifact, ...]:
    return tuple(value for value in values if _task_output(value.source))


def capture_immediate(manager: object) -> None:
    manager.binary_store.capture_all(immediate_binaries(manager._all_binaries()))
    manager.artifact_store.materialize_all(
        immediate_artifacts(manager.definition.artifacts),
    )


def capture_deferred(manager: object) -> None:
    for declaration in deferred_binaries(manager._all_binaries()):
        source = manager._render_value(
            declaration.path, label="binary %s task output" % declaration.name,
        )
        manager.binary_store.capture(dataclasses.replace(declaration, path=source))
    for declaration in deferred_artifacts(manager.definition.artifacts):
        source = manager._render_value(
            declaration.source, label="artifact %s task output" % declaration.name,
        )
        manager.artifact_store.materialize(
            dataclasses.replace(declaration, source=source),
        )
    manager.binary_store._write_manifest()
    manager.artifact_store._write_manifest()


__all__ = [
    "capture_deferred", "capture_immediate", "deferred_artifacts",
    "deferred_binaries", "immediate_artifacts", "immediate_binaries",
]

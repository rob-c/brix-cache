"""Local realization of graph-managed volumes and finite tasks."""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from typing import Dict, Iterable, Mapping, Sequence

from brixtest._design_managed import Task, Volume
from brixtest.errors import SpecError
from brixtest.resources import Reference
from brixtest.runtime.commands import CommandResult, CommandRunner
from brixtest.runtime.launcher_identity import process_identity_argv
from brixtest.util.configtext import render_cfg_strict


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_path(source: object, source_root: Path) -> Path:
    selected = Path(str(source))
    if not selected.is_absolute():
        selected = source_root / selected
    resolved = selected.resolve()
    if not resolved.exists():
        raise SpecError("volume.source", str(source), "does not exist")
    return resolved


@dataclasses.dataclass(frozen=True)
class MaterializedVolume:
    """One realized local volume with a stable provenance record."""

    name: str
    path: Path
    kind: str
    access: str
    persistent: bool

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe volume record."""
        return {
            "name": self.name, "path": str(self.path), "kind": self.kind,
            "access": self.access, "persistent": self.persistent,
        }


@dataclasses.dataclass(frozen=True)
class TaskOutput:
    """Checksum-backed output emitted by a finite managed task."""

    name: str
    path: Path
    size: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe output record."""
        return {
            "name": self.name, "path": str(self.path), "size": self.size,
            "sha256": self.sha256,
        }


@dataclasses.dataclass(frozen=True)
class TaskRecord:
    """Completed task result and its verified declared outputs."""

    name: str
    phase: str
    result: CommandResult
    outputs: Mapping[str, TaskOutput]

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe execution and output record."""
        return {
            "name": self.name, "phase": self.phase,
            "result": self.result.as_dict(),
            "outputs": {
                name: output.as_dict() for name, output in sorted(self.outputs.items())
            },
        }


class VolumeStore:
    """Materialize portable local volume declarations once per case."""

    def __init__(self, root: Path, source_root: Path) -> None:
        self.root = Path(root)
        self.source_root = Path(source_root)
        self._items: Dict[str, MaterializedVolume] = {}

    def materialize_all(
        self, declarations: Iterable[Volume],
    ) -> Mapping[str, MaterializedVolume]:
        for declaration in declarations:
            self.materialize(declaration)
        return dict(self._items)

    def materialize(self, declaration: Volume) -> MaterializedVolume:
        if declaration.name in self._items:
            raise SpecError("volume", declaration.name, "is declared more than once")
        path = self._path(declaration)
        item = MaterializedVolume(
            declaration.name, path, declaration.kind,
            declaration.access, declaration.persistent,
        )
        self._items[declaration.name] = item
        return item

    def _path(self, declaration: Volume) -> Path:
        if declaration.kind in ("host", "device"):
            return _source_path(declaration.source, self.source_root)
        if declaration.kind not in ("tmp", "shared", "persistent"):
            raise SpecError(
                "volume %s kind" % declaration.name, declaration.kind,
                "requires a storage provider",
            )
        path = self.root / declaration.name
        path.mkdir(parents=True, exist_ok=False)
        return path.resolve()

    def get(self, name: str) -> MaterializedVolume:
        try:
            return self._items[name]
        except KeyError:
            raise SpecError(
                "volume", name,
                "not materialized — known: %s" % ", ".join(sorted(self._items)),
            ) from None


def _task_order(
    tasks: Sequence[Task], completed: set[str], known_tasks: set[str],
) -> tuple[Task, ...]:
    pending = {task.name: task for task in tasks}
    ordered = []
    available = set(completed)
    while pending:
        ready = _ready_tasks(pending, available, known_tasks)
        if not ready:
            raise SpecError("task order", sorted(pending), "contains an unresolved dependency")
        _consume_ready_tasks(ready, pending, available, ordered)
    return tuple(ordered)


def _ready_tasks(pending, available: set[str], known_tasks: set[str]) -> list[Task]:
    return [
        task for task in pending.values()
        if all(name in available or name not in known_tasks for name in task.depends_on)
    ]


def _consume_ready_tasks(ready, pending, available, ordered) -> None:
    for task in sorted(ready, key=lambda item: item.name):
        ordered.append(task)
        available.add(task.name)
        pending.pop(task.name)


class ManagedResourceRuntime:
    """Execute local graph resources through the case's normal supervision policy."""

    def __init__(self, manager: object) -> None:
        self.manager = manager
        self.volumes = VolumeStore(
            manager.root / "runtime" / "volumes", manager.source_root,
        )
        self.tasks: Dict[str, TaskRecord] = {}
        self._values: Dict[str, object] = {}
        self._completed: set[str] = set()

    @property
    def values(self) -> Mapping[str, object]:
        """Return a snapshot of realized reference values."""
        return dict(self._values)

    def materialize_volumes(self) -> None:
        for name, item in self.volumes.materialize_all(
            self.manager.definition.volumes,
        ).items():
            self._values["volume_%s_path" % name] = item.path
            self._values["volume_%s_claim" % name] = item.path
            self.manager.evidence.event("managed-volume", item.as_dict())

    def run_phase(self, phase: str) -> None:
        kubernetes = getattr(self.manager, "_kubernetes", None)
        if kubernetes is not None:
            kubernetes.run_task_phase(phase)
            return
        self.manager._providers.start_ready()
        selected = self._phase_tasks(phase)
        known = self._known_tasks()
        for declaration in _task_order(selected, self._completed, known):
            self._run(declaration)
            self.manager._providers.start_ready()

    def _phase_tasks(self, phase: str) -> tuple[Task, ...]:
        return tuple(
            task for task in self.manager.definition.tasks
            if task.phase == phase and task.name not in self._completed
        )

    def _known_tasks(self) -> set[str]:
        return {task.name for task in self.manager.definition.tasks}

    def record_external(self, declaration: Task, result: CommandResult) -> TaskRecord:
        """Publish a result produced by a backend-native finite-task runner."""
        record = TaskRecord(declaration.name, declaration.phase, result, {})
        self.tasks[declaration.name] = record
        self._completed.add(declaration.name)
        self._publish(record)
        return record

    def _run(self, declaration: Task) -> None:
        workdir = self.manager.root / "runtime" / "tasks" / declaration.name
        workdir.mkdir(parents=True, exist_ok=False)
        values = self.manager._global_values({})
        mounts = self.manager._project_mounts(
            "task-%s" % declaration.name, declaration.mounts,
        )
        values.update(mounts)
        argv = tuple(
            self.manager._render_part(
                value, values, "task %s command" % declaration.name,
            )
            for value in declaration.command
        )
        env = self._environment(declaration, values, mounts)
        with self.manager.metrics.timer(
            "task.duration", labels={"task": declaration.name, "phase": declaration.phase},
        ):
            result = self._execute(declaration, workdir, argv, env)
        outputs = self._outputs(declaration, workdir)
        record = TaskRecord(declaration.name, declaration.phase, result, outputs)
        self.tasks[declaration.name] = record
        self._completed.add(declaration.name)
        self._publish(record)

    def _execute(self, declaration, workdir, argv, env) -> CommandResult:
        backend = declaration.placement.backend
        if backend not in ("docker", "podman"):
            return self._execute_process(declaration, workdir, argv, env)
        result = self._execute_container(declaration, workdir, argv, env)
        self._archive_container_result(workdir, result)
        return result

    def _execute_process(self, declaration, workdir, argv, env) -> CommandResult:
        runner = CommandRunner(
            workdir / "logs", cwd=workdir,
            observer=self.manager._observe_command,
        )
        identity = next((
            item for item in self.manager.definition.identities
            if item.name == declaration.placement.identity
        ), None)
        translated = process_identity_argv(identity, argv)
        result = runner.run(*translated, timeout=declaration.timeout, env=env)
        return dataclasses.replace(result, argv=tuple(argv))

    def _execute_container(self, declaration, workdir, argv, env) -> CommandResult:
        from brixtest.runtime.executors import (
            ToolExecutionContext,
            ToolExecutionRequest,
            tool_executor,
        )

        placement = declaration.placement
        context = ToolExecutionContext(
            self.manager.nodeid, self.manager.root, workdir, placement.backend,
            identities={item.name: item for item in self.manager.definition.identities},
        )
        request = ToolExecutionRequest(
            declaration.name, argv, env, workdir, declaration.timeout, None,
            (0,), 1 << 20, "capture", 0, "utf-8", True, placement,
            placement.image, {"resource_kind": "task", "phase": declaration.phase},
        )
        return tool_executor(placement.backend).execute(context, request)

    @staticmethod
    def _archive_container_result(workdir: Path, result: CommandResult) -> None:
        logs = workdir / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "0001.stdout.log").write_text(result.stdout)
        (logs / "0001.stderr.log").write_text(result.stderr)

    def _environment(
        self, declaration: Task, values: Mapping[str, object],
        mounts: Mapping[str, Path],
    ) -> dict[str, str]:
        env = {
            name: render_cfg_strict(
                str(value), values,
                template="task %s env[%s]" % (declaration.name, name),
            )
            for name, value in declaration.env.items()
        }
        env.update(self.manager.security.environment("client"))
        env.update({
            name.upper(): str(path) for name, path in mounts.items()
            if not name.rpartition("_")[2].isdigit()
        })
        from brixtest.runtime.manager import _environment
        env.update(_environment("BRIXTEST_CLIENT_ENV_JSON"))
        return env

    def _outputs(self, declaration: Task, workdir: Path) -> dict[str, TaskOutput]:
        outputs = {}
        for name, relative in declaration.outputs.items():
            path = workdir / relative
            if path.is_symlink() or not path.is_file():
                raise SpecError(
                    "task %s output %s" % (declaration.name, name), str(path),
                    "must be a regular non-symlink file produced by the task",
                )
            output = TaskOutput(name, path, path.stat().st_size, _sha256(path))
            outputs[name] = output
            self._values[Reference("task", declaration.name, "output", name).key] = path
        return outputs

    def _publish(self, record: TaskRecord) -> None:
        payload = record.as_dict()
        self.manager.evidence.event("managed-task", payload)
        self.manager.evidence.attach_json(
            "task-%s.json" % record.name, payload,
            role="task-result", description="supervised managed task result",
        )
        for name, output in record.outputs.items():
            self.manager.evidence.attach(
                output.path, name="task-%s-%s" % (record.name, name),
                role="task-output", description="declared managed task output",
            )


__all__ = [
    "ManagedResourceRuntime", "MaterializedVolume", "TaskOutput", "TaskRecord",
    "VolumeStore",
]

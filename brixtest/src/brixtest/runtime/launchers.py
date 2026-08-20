"""Per-server launch translation for local, Docker, and Podman resources.

Launchers do not monitor processes.  They translate an immutable server
request into an argv/env/cwd plan; the normal local backend then owns process
groups, readiness, crash detection, logs, and teardown uniformly.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Mapping, Optional, Sequence

from brixtest.design import Server
from brixtest.errors import SpecError
from brixtest.extensions import get_extension, register_extension
from brixtest.resources import Placement
from brixtest.runtime.container_policy import validate_network, validate_runtime_args
from brixtest.util.immutable import freeze_mapping

__all__ = [
    "ServerLaunchContext", "ServerLaunchPlan", "ServerLaunchRequest",
    "server_launcher",
]

_DIGEST_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-fA-F]{64}$")


def _argv(value: Sequence[str], field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not value:
        raise SpecError(field, value, "must be a non-empty argv sequence")
    selected = tuple(value)
    if not all(isinstance(part, str) and part and "\x00" not in part for part in selected):
        raise SpecError(field, value, "must contain non-empty NUL-free text")
    return selected


def _confined(context: "ServerLaunchContext", path: Path, field: str) -> Path:
    selected = Path(path).resolve()
    if context.root not in (selected, *selected.parents):
        raise SpecError(field, selected, "must be confined below the run root")
    return selected


@dataclasses.dataclass(frozen=True)
class ServerLaunchContext:
    """Stable run identity and confined paths supplied to server launchers."""

    nodeid: str
    root: Path
    workspace: Path

    def __post_init__(self) -> None:
        if not isinstance(self.nodeid, str) or not self.nodeid:
            raise SpecError("server launch nodeid", self.nodeid, "must be non-empty text")
        object.__setattr__(self, "root", Path(self.root).resolve())
        object.__setattr__(self, "workspace", Path(self.workspace).resolve())
        if self.root not in (self.workspace, *self.workspace.parents):
            raise SpecError(
                "server launch workspace", self.workspace,
                "must be confined below the run root",
            )


@dataclasses.dataclass(frozen=True)
class ServerLaunchRequest:
    """Fully rendered server invocation awaiting placement translation."""

    declaration: Server
    argv: Sequence[str]
    env: Mapping[str, str]
    cwd: Path

    def __post_init__(self) -> None:
        if not isinstance(self.declaration, Server):
            raise SpecError(
                "server launch declaration", self.declaration,
                "must be a brixtest.Server",
            )
        object.__setattr__(self, "argv", _argv(self.argv, "server launch argv"))
        if not isinstance(self.env, Mapping) or not all(
            isinstance(name, str) and name and "\x00" not in name
            and isinstance(value, str) and "\x00" not in value
            for name, value in self.env.items()
        ):
            raise SpecError(
                "server launch env", self.env,
                "must map non-empty NUL-free names to NUL-free text",
            )
        object.__setattr__(self, "env", freeze_mapping(self.env))
        object.__setattr__(self, "cwd", Path(self.cwd).resolve())


@dataclasses.dataclass(frozen=True)
class ServerLaunchPlan:
    """Supervised process plan plus an optional idempotent cleanup command."""

    argv: Sequence[str]
    env: Mapping[str, str]
    cwd: Path
    launcher: str
    cleanup_argv: Sequence[str] = ()
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", _argv(self.argv, "server launch plan argv"))
        object.__setattr__(
            self, "cleanup_argv",
            _argv(self.cleanup_argv, "server launch cleanup",) if self.cleanup_argv else (),
        )
        if not isinstance(self.env, Mapping) or not all(
            isinstance(name, str) and isinstance(value, str)
            for name, value in self.env.items()
        ):
            raise SpecError("server launch plan env", self.env, "must map strings to strings")
        object.__setattr__(self, "env", freeze_mapping(self.env))
        object.__setattr__(self, "cwd", Path(self.cwd).resolve())
        if not isinstance(self.launcher, str) or not self.launcher:
            raise SpecError("server launch plan launcher", self.launcher, "must be non-empty text")
        if not isinstance(self.metadata, Mapping):
            raise SpecError("server launch plan metadata", self.metadata, "must be a mapping")
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


class ProcessServerLauncher:
    """Launch a server directly under BriXTest's process-group supervisor."""

    name = "process"

    def validate(self, declaration: Server) -> None:
        placement = declaration.placement
        if placement.image is not None:
            raise SpecError(
                "server %s placement.image" % declaration.name, placement.image,
                "process placement does not consume a container image",
            )
        if placement.options:
            raise SpecError(
                "server %s placement.options" % declaration.name,
                dict(placement.options), "process placement has no options",
            )
        limits = placement.resources
        if any(value is not None for value in (limits.cpu, limits.memory_bytes, limits.pids)):
            raise SpecError(
                "server %s placement.resources" % declaration.name, limits,
                "process placement cannot enforce resource ceilings; this requires "
                "Kubernetes or a Docker/Podman placement",
            )
        if placement.namespace or placement.node_selector or placement.security_context:
            raise SpecError(
                "server %s placement" % declaration.name, placement,
                "namespace, node_selector, and security_context require Kubernetes",
            )

    def prepare(
        self, context: ServerLaunchContext, request: ServerLaunchRequest,
    ) -> ServerLaunchPlan:
        _confined(context, request.cwd, "server launch cwd")
        return ServerLaunchPlan(
            request.argv, request.env, request.cwd, self.name,
            metadata={"isolation": "process"},
        )

    def cleanup(self, context: ServerLaunchContext, plan: ServerLaunchPlan) -> None:
        return None


class ContainerServerLauncher:
    """Run one server attached to a Docker-compatible foreground CLI."""

    def __init__(self, runtime: str) -> None:
        self.name = runtime

    def validate(self, declaration: Server) -> None:
        placement = declaration.placement
        image = placement.image or declaration.image
        if not image:
            raise SpecError(
                "server %s placement.image" % declaration.name, image,
                "%s placement requires an image" % self.name,
            )
        if not placement.allow_mutable_image and _DIGEST_IMAGE.fullmatch(image) is None:
            raise SpecError(
                "server %s placement.image" % declaration.name, image,
                "must be image@sha256:<digest>; set allow_mutable_image=True only for local development",
            )
        if placement.namespace or placement.node_selector or placement.security_context:
            raise SpecError(
                "server %s placement" % declaration.name, placement,
                "namespace, node_selector, and security_context are Kubernetes-only; use labels, resources, and options for containers",
            )
        if declaration.lifecycle.shutdown_command:
            raise SpecError(
                "server %s lifecycle.shutdown_command" % declaration.name,
                declaration.lifecycle.shutdown_command,
                "container servers use shutdown_signal plus forced runtime cleanup",
            )
        allowed = {"network", "runtime_args"}
        unknown = sorted(set(placement.options) - allowed)
        if unknown:
            raise SpecError(
                "server %s placement.options" % declaration.name, unknown,
                "known for %s: %s" % (self.name, ", ".join(sorted(allowed))),
            )
        validate_runtime_args(
            placement.options.get("runtime_args", ()),
            "server %s placement.options.runtime_args" % declaration.name,
        )
        network = placement.options.get("network", "host")
        validate_network(
            network, "server %s placement.options.network" % declaration.name,
            host_only=True,
        )

    def prepare(
        self, context: ServerLaunchContext, request: ServerLaunchRequest,
    ) -> ServerLaunchPlan:
        self.validate(request.declaration)
        _confined(context, request.cwd, "server launch cwd")
        if shutil.which(self.name) is None:
            raise SpecError(
                "server launcher", self.name,
                "runtime executable is not installed or not on PATH",
            )
        placement = request.declaration.placement
        image = str(placement.image or request.declaration.image)
        digest = hashlib.sha256(
            (context.nodeid + "\0" + request.declaration.name).encode()
        ).hexdigest()[:12]
        container_name = "brixtest-%s-%s" % (
            request.declaration.name.replace("_", "-")[:32], digest,
        )
        state = context.root / "runtime" / "launchers" / request.declaration.name
        state.mkdir(parents=True, exist_ok=False)
        env_file = state / "server.env"
        for name, value in request.env.items():
            if "\n" in name or "\r" in name or "\n" in value or "\r" in value:
                raise SpecError(
                    "server %s env[%s]" % (request.declaration.name, name), value,
                    "container env-file values cannot contain newlines",
                )
        env_file.write_text("".join(
            "%s=%s\n" % item for item in sorted(request.env.items())
        ))
        env_file.chmod(0o600)
        argv = [
            self.name, "run", "--rm", "--name", container_name,
            "--network", str(placement.options.get("network", "host")),
            "--env-file", str(env_file),
            "--volume", "%s:%s:rw" % (context.root, context.root),
            "--workdir", str(request.cwd),
        ]
        limits = placement.resources
        if limits.cpu is not None:
            argv.extend(("--cpus", str(limits.cpu)))
        if limits.memory_bytes is not None:
            argv.extend(("--memory", str(limits.memory_bytes)))
        if limits.pids is not None:
            argv.extend(("--pids-limit", str(limits.pids)))
        for name, value in sorted(placement.labels.items()):
            argv.extend(("--label", "%s=%s" % (name, value)))
        argv.extend(str(value) for value in placement.options.get("runtime_args", ()))
        argv.extend((image, *request.argv))
        return ServerLaunchPlan(
            argv, {}, request.cwd, self.name,
            cleanup_argv=(self.name, "rm", "--force", container_name),
            metadata={
                "isolation": self.name, "image": image,
                "container_name": container_name, "env_file": str(env_file),
            },
        )

    def cleanup(self, context: ServerLaunchContext, plan: ServerLaunchPlan) -> None:
        if not plan.cleanup_argv:
            return
        try:
            subprocess.run(
                list(plan.cleanup_argv), stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


_BUILTINS = {
    "process": ProcessServerLauncher(),
    "local": ProcessServerLauncher(),
    "docker": ContainerServerLauncher("docker"),
    "podman": ContainerServerLauncher("podman"),
}


def server_launcher(name: str):
    """Resolve a built-in or installed per-server launcher."""
    if name in ("", "inherit"):
        name = "process"
    if name in _BUILTINS:
        return _BUILTINS[name]
    return get_extension("launcher", name)


for _name, _launcher in _BUILTINS.items():
    try:
        register_extension(
            "launcher", _name, _launcher, origin="brixtest",
            capabilities=("logs", "readiness", "supervision"),
        )
    except SpecError:
        pass

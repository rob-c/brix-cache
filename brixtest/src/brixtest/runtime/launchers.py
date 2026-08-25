"""Per-server launch translation for local, Docker, and Podman resources.

Launchers do not monitor processes.  They translate an immutable server
request into an argv/env/cwd plan; the normal local backend then owns process
groups, readiness, crash detection, logs, and teardown uniformly.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Mapping, Optional, Sequence

from brixtest.design import Identity, Server, Volume
from brixtest.errors import SpecError
from brixtest.extensions import get_extension, register_extension
from brixtest.network import HostMapping
from brixtest.planning.capabilities import backend_capabilities
from brixtest.runtime.container_policy import validate_network, validate_runtime_args
from brixtest.runtime.launcher_identity import container_identity_argv, process_identity_argv
from brixtest.util.immutable import freeze_mapping

__all__ = [
    "ServerLaunchContext", "ServerLaunchPlan", "ServerLaunchRequest",
    "server_launcher",
]

_DIGEST_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-fA-F]{64}$")
_PROPAGATION = {
    "host-to-container": "rslave",
    "bidirectional": "rshared",
}


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


def _declared_mount_argv(argv: list[str], request: "ServerLaunchRequest") -> None:
    for index, declaration in enumerate(request.declaration.mounts):
        _declared_mount_item_argv(argv, request, declaration, index)


def _declared_mount_item_argv(argv, request, declaration, index: int) -> None:
    source = declaration.source
    device = isinstance(source, Volume) and source.kind == "device"
    if not device and declaration.propagation == "none":
        return
    if not request.mounts:
        raise SpecError(
            "server launch mounts", request.mounts,
            "device and propagation mounts require realized paths",
        )
    path = request.mounts[index]
    _optional_device_argv(argv, declaration, path, device)
    _optional_propagation_argv(argv, declaration, path)


def _optional_device_argv(argv, declaration, path: Path, enabled: bool) -> None:
    if enabled:
        _device_argv(argv, declaration, path)


def _optional_propagation_argv(argv, declaration, path: Path) -> None:
    if declaration.propagation != "none":
        _propagation_argv(argv, declaration, path)


def _device_argv(argv: list[str], declaration, path: Path) -> None:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise SpecError("device volume", str(path), "cannot be inspected: %s" % exc) from exc
    if not (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)):
        raise SpecError("device volume", str(path), "must be a character or block device")
    permissions = "r" if declaration.read_only else "rwm"
    argv.extend(("--device", "%s:%s:%s" % (path, path, permissions)))


def _propagation_argv(argv: list[str], declaration, path: Path) -> None:
    if not path.is_dir():
        raise SpecError(
            "mount.propagation", str(path),
            "requires a realized directory mount",
        )
    propagation = _PROPAGATION[declaration.propagation]
    option = "type=bind,src=%s,dst=%s,bind-propagation=%s" % (
        path, path, propagation,
    )
    argv.extend(("--mount", option))


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
    mounts: Sequence[Path] = ()
    identity: Optional[Identity] = None
    host_aliases: Sequence[HostMapping] = ()

    def __post_init__(self) -> None:
        _validate_request_declaration(self.declaration)
        object.__setattr__(self, "argv", _argv(self.argv, "server launch argv"))
        _validate_request_env(self.env)
        object.__setattr__(self, "env", freeze_mapping(self.env))
        object.__setattr__(self, "cwd", Path(self.cwd).resolve())
        selected_mounts = _request_mounts(self.mounts, self.declaration)
        object.__setattr__(self, "mounts", selected_mounts)
        _validate_request_identity(self)
        object.__setattr__(self, "host_aliases", _request_host_aliases(self.host_aliases))


def _validate_request_declaration(value: object) -> None:
    if not isinstance(value, Server):
        raise SpecError(
            "server launch declaration", value, "must be a brixtest.Server",
        )


def _validate_request_env(value: object) -> None:
    valid = isinstance(value, Mapping) and all(
        isinstance(name, str) and name and "\x00" not in name
        and isinstance(item, str) and "\x00" not in item
        for name, item in value.items()
    )
    if not valid:
        raise SpecError(
            "server launch env", value,
            "must map non-empty NUL-free names to NUL-free text",
        )


def _request_mounts(value: Sequence[Path], declaration: Server) -> tuple[Path, ...]:
    selected = tuple(Path(path).resolve() for path in value)
    if selected and len(selected) != len(declaration.mounts):
        raise SpecError(
            "server launch mounts", selected,
            "must align one-to-one with declared mounts",
        )
    return selected


def _validate_request_identity(request: ServerLaunchRequest) -> None:
    declared = request.declaration.placement.identity
    if request.identity is not None and not isinstance(request.identity, Identity):
        raise SpecError("server launch identity", request.identity, "must be an Identity or None")
    actual = request.identity.name if request.identity is not None else ""
    if declared != actual:
        raise SpecError(
            "server launch identity", actual,
            "must resolve placement.identity %r" % declared,
        )


def _request_host_aliases(value: object) -> tuple[HostMapping, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError("server launch host_aliases", value, "must be a HostMapping sequence")
    selected = tuple(value)
    if not all(isinstance(item, HostMapping) for item in selected):
        raise SpecError("server launch host_aliases", value, "must contain HostMapping values")
    return selected


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
        object.__setattr__(self, "cleanup_argv", _cleanup_argv(self.cleanup_argv))
        _validate_plan_env(self.env)
        object.__setattr__(self, "env", freeze_mapping(self.env))
        object.__setattr__(self, "cwd", Path(self.cwd).resolve())
        _validate_launcher_name(self.launcher)
        _validate_plan_metadata(self.metadata)
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


def _cleanup_argv(value: Sequence[str]) -> tuple[str, ...]:
    if not value:
        return ()
    return _argv(value, "server launch cleanup")


def _validate_plan_env(value: object) -> None:
    valid = isinstance(value, Mapping) and all(
        isinstance(name, str) and isinstance(item, str)
        for name, item in value.items()
    )
    if not valid:
        raise SpecError("server launch plan env", value, "must map strings to strings")


def _validate_launcher_name(value: object) -> None:
    if not isinstance(value, str) or not value:
        raise SpecError("server launch plan launcher", value, "must be non-empty text")


def _validate_plan_metadata(value: object) -> None:
    if not isinstance(value, Mapping):
        raise SpecError("server launch plan metadata", value, "must be a mapping")


class ProcessServerLauncher:
    """Launch a server directly under BriXTest's process-group supervisor."""

    name = "process"
    brixtest_api_version = 1
    brixtest_capabilities = tuple(sorted(
        backend_capabilities("process", "launcher"),
    ))

    def validate(self, declaration: Server) -> None:
        placement = declaration.placement
        if placement.image is not None:
            raise SpecError(
                "server %s placement.image" % declaration.name, placement.image,
                "process placement does not consume a container image",
            )
        if placement.allow_mutable_image:
            raise SpecError(
                "server %s placement.allow_mutable_image" % declaration.name,
                placement.allow_mutable_image,
                "process placement does not consume mutable image policy",
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
        if (
            placement.namespace or placement.labels or placement.node_selector
            or placement.security_context
        ):
            raise SpecError(
                "server %s placement" % declaration.name, placement,
                "labels, namespace, node_selector, and security_context require a container or Kubernetes",
            )

    def prepare(
        self, context: ServerLaunchContext, request: ServerLaunchRequest,
    ) -> ServerLaunchPlan:
        _confined(context, request.cwd, "server launch cwd")
        return ServerLaunchPlan(
            process_identity_argv(request.identity, request.argv),
            request.env, request.cwd, self.name,
            metadata={"isolation": "process"},
        )

    def cleanup(self, context: ServerLaunchContext, plan: ServerLaunchPlan) -> None:
        return None


def _container_image(runtime: str, declaration: Server) -> str:
    placement = declaration.placement
    image = placement.image or declaration.image
    if not image:
        raise SpecError(
            "server %s placement.image" % declaration.name, image,
            "%s placement requires an image" % runtime,
        )
    if not placement.allow_mutable_image and _DIGEST_IMAGE.fullmatch(image) is None:
        raise SpecError(
            "server %s placement.image" % declaration.name, image,
            "must be image@sha256:<digest>; set allow_mutable_image=True only for local development",
        )
    return image


def _validate_container_scheduling(declaration: Server) -> None:
    placement = declaration.placement
    if placement.namespace or placement.node_selector or placement.security_context:
        raise SpecError(
            "server %s placement" % declaration.name, placement,
            "namespace, node_selector, and security_context are Kubernetes-only; "
            "use labels, resources, and options for containers",
        )


def _validate_container_options(runtime: str, declaration: Server) -> None:
    allowed = {"network", "runtime_args"}
    unknown = sorted(set(declaration.placement.options) - allowed)
    if unknown:
        raise SpecError(
            "server %s placement.options" % declaration.name, unknown,
            "known for %s: %s" % (runtime, ", ".join(sorted(allowed))),
        )


class ContainerServerLauncher:
    """Run one server attached to a Docker-compatible foreground CLI."""

    def __init__(self, runtime: str) -> None:
        self.name = runtime
        self.brixtest_api_version = 1
        self.brixtest_capabilities = tuple(sorted(
            backend_capabilities(runtime, "launcher"),
        ))

    def validate(self, declaration: Server) -> None:
        placement = declaration.placement
        _container_image(self.name, declaration)
        _validate_container_scheduling(declaration)
        _validate_container_options(self.name, declaration)
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
        env_file = self._environment_file(context, request)
        argv = self._container_argv(
            context, request, placement, image, container_name, env_file,
        )
        return ServerLaunchPlan(
            argv, {}, request.cwd, self.name,
            cleanup_argv=(self.name, "rm", "--force", container_name),
            metadata={
                "isolation": self.name, "image": image,
                "container_name": container_name, "env_file": str(env_file),
            },
        )

    def _environment_file(self, context, request) -> Path:
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
        return env_file

    def _container_argv(
        self, context, request, placement, image: str, container_name: str, env_file: Path,
    ) -> list[str]:
        argv = [
            self.name, "run", "--rm", "--name", container_name,
            "--network", str(placement.options.get("network", "host")),
            "--env-file", str(env_file),
            "--volume", "%s:%s:rw" % (context.root, context.root),
            "--workdir", str(request.cwd),
        ]
        self._resource_limit_argv(argv, placement.resources)
        argv.extend(container_identity_argv(self.name, request.identity, env_file.parent))
        _declared_mount_argv(argv, request)
        for mapping in request.host_aliases:
            for hostname in mapping.hostnames:
                argv.extend(("--add-host", "%s:%s" % (hostname, mapping.address)))
        for name, value in sorted(placement.labels.items()):
            argv.extend(("--label", "%s=%s" % (name, value)))
        argv.extend(str(value) for value in placement.options.get("runtime_args", ()))
        argv.extend((image, *request.argv))
        return argv

    @staticmethod
    def _resource_limit_argv(argv: list[str], limits) -> None:
        if limits.cpu is not None:
            argv.extend(("--cpus", str(limits.cpu)))
        if limits.memory_bytes is not None:
            argv.extend(("--memory", str(limits.memory_bytes)))
        if limits.pids is not None:
            argv.extend(("--pids-limit", str(limits.pids)))

    def cleanup(self, context: ServerLaunchContext, plan: ServerLaunchPlan) -> None:
        if not plan.cleanup_argv:
            return
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                list(plan.cleanup_argv), stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5.0, check=False,
            )


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
        target = _BUILTINS[name]
        register_extension(
            "launcher", name, target, replace=True, origin="brixtest",
            capabilities=tuple(sorted(backend_capabilities(name, "launcher"))),
        )
        return target
    return get_extension("launcher", name)


for _name, _launcher in _BUILTINS.items():
    with contextlib.suppress(SpecError):
        register_extension(
            "launcher", _name, _launcher, origin="brixtest",
            capabilities=tuple(sorted(backend_capabilities(_name, "launcher"))),
        )

"""Versioned client/tool execution seam with local and Kubernetes drivers."""

from __future__ import annotations

import contextlib
import dataclasses
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence, Union

from brixtest.errors import SpecError
from brixtest.extensions import get_extension, register_extension
from brixtest.planning.capabilities import backend_capabilities
from brixtest.resources import Placement
from brixtest.runtime.commands import CommandResult, CommandRunner
from brixtest.runtime.container_policy import validate_network, validate_runtime_args
from brixtest.runtime.executor_identity import execution_identity, identity_catalog
from brixtest.runtime.launcher_identity import container_identity_argv, process_identity_argv
from brixtest.util.immutable import freeze_mapping

__all__ = [
    "ToolExecutionContext", "ToolExecutionRequest", "tool_executor",
]

_DIGEST_IMAGE = re.compile(r"[^@]+@sha256:[0-9a-fA-F]{64}")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _request_argv_valid(argv: Sequence[object]) -> bool:
    return bool(argv) and all(
        isinstance(item, str) and bool(item) and "\0" not in item for item in argv
    )


def _request_env_valid(env: object) -> bool:
    if not isinstance(env, Mapping):
        return False
    return all(_request_env_item_valid(key, value) for key, value in env.items())


def _request_env_item_valid(key: object, value: object) -> bool:
    return _request_env_key_valid(key) and _request_env_value_valid(value)


def _request_env_key_valid(key: object) -> bool:
    return isinstance(key, str) and bool(key) and "=" not in key and "\0" not in key


def _request_env_value_valid(value: object) -> bool:
    return isinstance(value, str) and "\0" not in value


def _request_identity(value: "ToolExecutionRequest") -> tuple[str, ...]:
    if not isinstance(value.name, str) or not value.name:
        raise SpecError("tool execution name", value.name, "must be non-empty text")
    argv = tuple(value.argv)
    if not _request_argv_valid(argv):
        raise SpecError("tool execution argv", argv, "must be non-empty NUL-free text")
    if not _request_env_valid(value.env):
        raise SpecError(
            "tool execution env", value.env,
            "must map non-empty NUL-free process names to NUL-free text",
        )
    if value.cwd is not None and not isinstance(value.cwd, (str, Path)):
        raise SpecError("tool execution cwd", value.cwd, "must be a path or None")
    return argv


def _request_policy(value: "ToolExecutionRequest") -> tuple[int, ...]:
    _validate_timeout(value.timeout)
    _validate_input(value.input)
    exits = _validate_exits(value.expected_exit_codes)
    _validate_output_limit(value.output_limit)
    return exits


def _validate_timeout(value: object) -> None:
    if not _positive_number(value):
        raise SpecError("tool execution timeout", value, "must be > 0")


def _validate_input(value: object) -> None:
    if value is not None and not isinstance(value, (str, bytes)):
        raise SpecError("tool execution input", value, "must be text, bytes, or None")


def _validate_exits(values: Sequence[int]) -> tuple[int, ...]:
    exits = tuple(values)
    if not exits or not all(_integer(item) for item in exits):
        raise SpecError(
            "tool execution expected exits", exits,
            "must contain at least one integer status",
        )
    return exits


def _validate_output_limit(value: object) -> None:
    if not _integer(value) or value < 1:
        raise SpecError("tool execution output limit", value, "must be an integer >= 1")


def _positive_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _non_empty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _path_value(value: object) -> bool:
    return isinstance(value, (str, Path)) and bool(str(value))


def _request_contract(value: "ToolExecutionRequest") -> None:
    if value.mode not in ("capture", "stream", "pty"):
        raise SpecError("tool execution mode", value.mode, "must be capture, stream, or pty")
    if not _integer(value.retries) or value.retries < 0:
        raise SpecError("tool execution retries", value.retries, "must be an integer >= 0")
    if not isinstance(value.encoding, str) or not value.encoding:
        raise SpecError("tool execution encoding", value.encoding, "must be non-empty text")
    if not isinstance(value.check, bool):
        raise SpecError("tool execution check", value.check, "must be a boolean")
    _request_placement(value)


def _request_placement(value: "ToolExecutionRequest") -> None:
    if not isinstance(value.placement, Placement):
        raise SpecError(
            "tool execution placement", value.placement, "must be a Placement declaration"
        )
    if not isinstance(value.image, str):
        raise SpecError("tool execution image", value.image, "must be text")
    if not isinstance(value.metadata, Mapping):
        raise SpecError("tool execution metadata", value.metadata, "must be a mapping")



@dataclasses.dataclass(frozen=True)
class ToolExecutionRequest:
    """Fully rendered, shell-free invocation passed to an executor driver."""

    name: str
    argv: Sequence[str]
    env: Mapping[str, str]
    cwd: Optional[Path]
    timeout: float
    input: Optional[Union[str, bytes]]
    expected_exit_codes: Sequence[int]
    output_limit: int
    mode: str
    retries: int
    encoding: str
    check: bool
    placement: Placement
    image: str = ""
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        argv = _request_identity(self)
        exits = _request_policy(self)
        _request_contract(self)
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "env", freeze_mapping(self.env))
        object.__setattr__(self, "cwd", Path(self.cwd) if self.cwd is not None else None)
        object.__setattr__(self, "expected_exit_codes", exits)
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


@dataclasses.dataclass(frozen=True)
class ToolExecutionContext:
    """Stable execution context exposed to local and third-party executors."""

    nodeid: str
    root: Path
    workspace: Path
    backend: str
    namespace: str = ""
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)
    local_execute: Optional[Callable[[ToolExecutionRequest], CommandResult]] = dataclasses.field(
        default=None, repr=False, compare=False,
    )
    identities: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _non_empty_text(self.nodeid):
            raise SpecError("tool context nodeid", self.nodeid, "must be non-empty text")
        if not _path_value(self.root):
            raise SpecError("tool context root", self.root, "must be a path")
        if not _path_value(self.workspace):
            raise SpecError("tool context workspace", self.workspace, "must be a path")
        if not _non_empty_text(self.backend):
            raise SpecError("tool context backend", self.backend, "must be non-empty text")
        if not isinstance(self.namespace, str):
            raise SpecError("tool context namespace", self.namespace, "must be text")
        if not isinstance(self.metadata, Mapping):
            raise SpecError("tool context metadata", self.metadata, "must be a mapping")
        if self.local_execute is not None and not callable(self.local_execute):
            raise SpecError(
                "tool context local_execute", self.local_execute,
                "must be callable or None",
            )
        object.__setattr__(self, "root", Path(self.root).resolve())
        object.__setattr__(self, "workspace", Path(self.workspace).resolve())
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))
        object.__setattr__(self, "identities", identity_catalog(self.identities))

    def execute_local(self, request: ToolExecutionRequest) -> CommandResult:
        """Use BriXTest's bounded, archived local command implementation."""
        if self.local_execute is None:
            raise SpecError("local executor", self.backend, "is not available in this context")
        return self.local_execute(request)


class _LocalToolExecutor:
    brixtest_api_version = 1
    brixtest_capabilities = tuple(sorted(backend_capabilities("local", "executor")))

    def validate(self, declaration: object) -> None:
        placement = getattr(declaration, "placement", Placement())
        name = getattr(declaration, "name", "?")
        _validate_local_limits(name, placement)
        _validate_local_scheduling(name, placement)
        _validate_local_container_fields(name, placement)

    def execute(
        self, context: ToolExecutionContext, request: ToolExecutionRequest,
    ) -> CommandResult:
        identity = execution_identity(context, request)
        translated = dataclasses.replace(
            request, argv=process_identity_argv(identity, request.argv),
        )
        result = context.execute_local(translated)
        return dataclasses.replace(result, argv=tuple(request.argv))


def _validate_local_limits(name: str, placement: Placement) -> None:
    limits = placement.resources
    values = (limits.cpu, limits.memory_bytes, limits.pids)
    if any(value is not None for value in values):
        raise SpecError(
            "client %s placement.resources" % name, limits,
            "local hard limits require a cgroup-aware executor extension",
        )


def _validate_local_scheduling(name: str, placement: Placement) -> None:
    if (
        placement.namespace or placement.node_selector or placement.security_context
        or placement.environment or placement.group
        or placement.network_policy != "declared"
    ):
        raise SpecError(
            "client %s placement" % name, placement,
            "environment, group, network policy, and remote scheduling require a translated executor",
        )


def _validate_local_container_fields(name: str, placement: Placement) -> None:
    if (
        placement.image or placement.labels or placement.options
        or placement.allow_mutable_image
    ):
        raise SpecError(
            "client %s placement" % name, placement,
            "local execution does not consume image or container options",
        )


def _container_argv(
    runtime: str, context: ToolExecutionContext,
    request: ToolExecutionRequest, env_file: Path,
) -> list[str]:
    limits = request.placement.resources
    argv = [
        runtime, "run", "--rm", "--network",
        str(request.placement.options.get("network", "host")),
        "--env-file", str(env_file),
        "--volume", "%s:%s:ro" % (context.root, context.root),
        "--volume", "%s:%s:rw" % (context.workspace, context.workspace),
    ]
    argv.extend(_container_input_args(request))
    argv.extend(_container_workdir_args(request))
    argv.extend(_container_limit_args(limits))
    identity = execution_identity(context, request)
    identity_root = env_file.parent / env_file.stem
    argv.extend(container_identity_argv(runtime, identity, identity_root))
    argv.extend(_container_label_args(request.placement.labels))
    argv.extend(str(value) for value in request.placement.options.get("runtime_args", ()))
    argv.extend((request.image, *request.argv))
    return argv


def _container_label_args(labels: Mapping[str, object]) -> list[str]:
    return [
        value for item in sorted(labels.items())
        for value in ("--label", "%s=%s" % item)
    ]


def _container_input_args(request: ToolExecutionRequest) -> list[str]:
    if request.mode == "pty":
        return ["--interactive", "--tty"]
    return ["--interactive"] if request.input is not None else []


def _container_workdir_args(request: ToolExecutionRequest) -> list[str]:
    return ["--workdir", str(request.cwd)] if request.cwd is not None else []


def _container_limit_args(limits) -> list[str]:
    argv = []
    _append_limit(argv, "--cpus", limits.cpu)
    _append_limit(argv, "--memory", limits.memory_bytes)
    _append_limit(argv, "--pids-limit", limits.pids)
    return argv


def _append_limit(argv: list[str], option: str, value: object) -> None:
    if value is not None:
        argv.extend((option, str(value)))


def _container_attempts(
    argv: Sequence[str], context: ToolExecutionContext,
    request: ToolExecutionRequest, started: float,
) -> CommandResult:
    attempts = 0
    result = CommandResult(tuple(request.argv), 1, "", "not executed", 0.0)
    runner = CommandRunner(None, cwd=context.workspace)
    while attempts <= request.retries:
        attempts += 1
        try:
            invocation = runner.run(
                *argv, input=request.input, encoding=request.encoding,
                timeout=request.timeout, check=False,
                expected_exit_codes=request.expected_exit_codes,
                output_limit=request.output_limit, mode=request.mode,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            invocation = CommandResult(
                tuple(argv), 124, str(getattr(exc, "output", "") or ""),
                str(getattr(exc, "stderr", "") or "%s: %s" % (type(exc).__name__, exc)),
                time.perf_counter() - started,
            )
        result = dataclasses.replace(invocation, argv=tuple(request.argv), attempts=attempts)
        if result.returncode in request.expected_exit_codes:
            break
    return dataclasses.replace(result, elapsed_seconds=time.perf_counter() - started)


def _validate_container_image(
    runtime: str, name: str, placement: Placement, image: str,
) -> None:
    if placement.allow_mutable_image or _DIGEST_IMAGE.fullmatch(image) is not None:
        return
    raise SpecError(
        "client %s placement.image" % name, image,
        "%s tool images must be digest pinned unless allow_mutable_image=True" % runtime,
    )


def _validate_container_scheduling(
    runtime: str, name: str, placement: Placement,
) -> None:
    if (
        placement.namespace or placement.node_selector or placement.security_context
        or placement.environment or placement.group
        or placement.network_policy != "declared"
    ):
        raise SpecError(
            "client %s placement" % name, placement,
            "%s execution does not translate grouping, environment, network policy, or Kubernetes scheduling" % runtime,
        )


class _ContainerToolExecutor:
    brixtest_api_version = 1

    def __init__(self, runtime: str) -> None:
        self.runtime = runtime
        self.brixtest_capabilities = tuple(sorted(
            backend_capabilities(runtime, "executor"),
        ))

    def validate(self, declaration: object) -> None:
        placement = getattr(declaration, "placement", Placement())
        image = _declared_image(declaration)
        name = getattr(declaration, "name", "?")
        _validate_container_image(self.runtime, name, placement, image)
        _validate_container_scheduling(self.runtime, name, placement)
        unknown = sorted(set(placement.options) - {"network", "runtime_args"})
        if unknown:
            raise SpecError(
                "client %s placement.options" % name,
                unknown, "known: network, runtime_args",
            )
        validate_runtime_args(
            placement.options.get("runtime_args", ()),
            "client %s placement.options.runtime_args" % name,
        )
        network = placement.options.get("network", "host")
        validate_network(network, "client %s placement.options.network" % name)

    def execute(
        self, context: ToolExecutionContext, request: ToolExecutionRequest,
    ) -> CommandResult:
        mutable = request.placement.allow_mutable_image
        if not mutable and _DIGEST_IMAGE.fullmatch(request.image) is None:
            raise SpecError("%s tool image" % self.runtime, request.image, "must be digest pinned")
        env_file = self._environment_file(context, request)
        started = time.perf_counter()
        try:
            result = _container_attempts(
                _container_argv(self.runtime, context, request, env_file),
                context, request, started,
            )
        finally:
            with contextlib.suppress(FileNotFoundError):
                env_file.unlink()
        self._publish_result(request, result)
        return result

    def _environment_file(self, context, request) -> Path:
        env_root = context.root / "runtime" / "executor-env"
        env_root.mkdir(parents=True, exist_ok=True)
        env_file = env_root / ("%s-%s.env" % (request.name, uuid.uuid4().hex[:10]))
        unsafe = any(
            "\n" in key + value or "\0" in key + value for key, value in request.env.items()
        )
        if unsafe:
            raise SpecError(
                "%s tool environment" % self.runtime, request.name,
                "container environment values cannot contain newlines or NUL",
            )
        env_file.write_text("".join("%s=%s\n" % item for item in sorted(request.env.items())))
        env_file.chmod(0o600)
        return env_file

    @staticmethod
    def _publish_result(request, result) -> None:
        if request.mode == "stream":
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
        if request.check and result.returncode not in request.expected_exit_codes:
            raise subprocess.CalledProcessError(
                result.returncode, result.argv, output=result.stdout, stderr=result.stderr,
            )

from brixtest.runtime.executor_kubernetes import (  # noqa: E402 - executor facade cycle
    _KubernetesToolExecutor,
)
from brixtest.runtime.executor_kubernetes import (  # noqa: E402 - compatibility re-export
    _tool_pod as _tool_pod,
)
from brixtest.runtime.executor_support import (  # noqa: E402 - late facade dependency
    declared_image as _declared_image,
)

_BUILTINS = {
    "local": _LocalToolExecutor(),
    "kubernetes": _KubernetesToolExecutor(),
    "docker": _ContainerToolExecutor("docker"),
    "podman": _ContainerToolExecutor("podman"),
}

def tool_executor(name: str):
    """Resolve a built-in or installed executor through the shared contract."""
    if name in _BUILTINS:
        target = _BUILTINS[name]
        register_extension(
            "executor", name, target, replace=True, origin="brixtest",
            capabilities=tuple(sorted(backend_capabilities(name, "executor"))),
        )
        return target
    return get_extension("executor", name)


for _executor_name, _executor in _BUILTINS.items():
    with contextlib.suppress(SpecError):
        register_extension(
            "executor", _executor_name, _executor, origin="brixtest",
            capabilities=tuple(sorted(backend_capabilities(_executor_name, "executor"))),
        )

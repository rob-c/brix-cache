"""Versioned client/tool execution seam with local and Kubernetes drivers."""

from __future__ import annotations

import dataclasses
import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence, Union

from brixtest.errors import SpecError
from brixtest.extensions import get_extension, register_extension
from brixtest.resources import Placement
from brixtest.runtime.commands import CommandResult, CommandRunner
from brixtest.runtime.container_policy import validate_network, validate_runtime_args
from brixtest.util.immutable import freeze_mapping

__all__ = [
    "ToolExecutionContext", "ToolExecutionRequest", "tool_executor",
]

_DIGEST_IMAGE = re.compile(r"[^@]+@sha256:[0-9a-fA-F]{64}")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclasses.dataclass(frozen=True)
class ToolExecutionRequest:
    """Fully rendered, shell-free invocation passed to an executor driver."""

    name: str
    argv: Sequence[str]
    env: Mapping[str, str]
    cwd: Optional[Path]
    timeout: float
    input: Optional[str]
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
        if not isinstance(self.name, str) or not self.name:
            raise SpecError("tool execution name", self.name, "must be non-empty text")
        argv = tuple(self.argv)
        if not argv or not all(isinstance(value, str) and value and "\0" not in value for value in argv):
            raise SpecError("tool execution argv", argv, "must be non-empty NUL-free text")
        if not isinstance(self.env, Mapping) or not all(
            isinstance(key, str) and key and "=" not in key and "\0" not in key
            and isinstance(value, str) and "\0" not in value
            for key, value in self.env.items()
        ):
            raise SpecError(
                "tool execution env", self.env,
                "must map non-empty NUL-free process names to NUL-free text",
            )
        if self.cwd is not None and not isinstance(self.cwd, (str, Path)):
            raise SpecError("tool execution cwd", self.cwd, "must be a path or None")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or self.timeout <= 0
        ):
            raise SpecError("tool execution timeout", self.timeout, "must be > 0")
        if self.input is not None and not isinstance(self.input, str):
            raise SpecError("tool execution input", self.input, "must be text or None")
        exits = tuple(self.expected_exit_codes)
        if not exits or not all(
            isinstance(value, int) and not isinstance(value, bool) for value in exits
        ):
            raise SpecError(
                "tool execution expected exits", exits,
                "must contain at least one integer status",
            )
        if (
            isinstance(self.output_limit, bool)
            or not isinstance(self.output_limit, int)
            or self.output_limit < 1
        ):
            raise SpecError(
                "tool execution output limit", self.output_limit,
                "must be an integer >= 1",
            )
        if self.mode not in ("capture", "stream", "pty"):
            raise SpecError(
                "tool execution mode", self.mode,
                "must be capture, stream, or pty",
            )
        if (
            isinstance(self.retries, bool)
            or not isinstance(self.retries, int)
            or self.retries < 0
        ):
            raise SpecError(
                "tool execution retries", self.retries,
                "must be an integer >= 0",
            )
        if not isinstance(self.encoding, str) or not self.encoding:
            raise SpecError(
                "tool execution encoding", self.encoding,
                "must be non-empty text",
            )
        if not isinstance(self.check, bool):
            raise SpecError("tool execution check", self.check, "must be a boolean")
        if not isinstance(self.placement, Placement):
            raise SpecError(
                "tool execution placement", self.placement,
                "must be a Placement declaration",
            )
        if not isinstance(self.image, str):
            raise SpecError("tool execution image", self.image, "must be text")
        if not isinstance(self.metadata, Mapping):
            raise SpecError("tool execution metadata", self.metadata, "must be a mapping")
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

    def __post_init__(self) -> None:
        if not isinstance(self.nodeid, str) or not self.nodeid:
            raise SpecError("tool context nodeid", self.nodeid, "must be non-empty text")
        if not isinstance(self.root, (str, Path)) or not str(self.root):
            raise SpecError("tool context root", self.root, "must be a path")
        if not isinstance(self.workspace, (str, Path)) or not str(self.workspace):
            raise SpecError("tool context workspace", self.workspace, "must be a path")
        if not isinstance(self.backend, str) or not self.backend:
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

    def execute_local(self, request: ToolExecutionRequest) -> CommandResult:
        """Use BriXTest's bounded, archived local command implementation."""
        if self.local_execute is None:
            raise SpecError("local executor", self.backend, "is not available in this context")
        return self.local_execute(request)


class _LocalToolExecutor:
    brixtest_api_version = 1
    brixtest_capabilities = ("capture", "input", "pty", "retries", "stream")

    def validate(self, declaration: object) -> None:
        placement = getattr(declaration, "placement", Placement())
        limits = placement.resources
        if any(value is not None for value in (limits.cpu, limits.memory_bytes, limits.pids)):
            raise SpecError(
                "client %s placement.resources" % getattr(declaration, "name", "?"),
                limits, "local hard limits require a cgroup-aware executor extension",
            )
        if placement.namespace or placement.node_selector or placement.security_context:
            raise SpecError(
                "client %s placement" % getattr(declaration, "name", "?"), placement,
                "namespace, node_selector, and security_context require a remote executor",
            )
        if placement.image or placement.options or placement.allow_mutable_image:
            raise SpecError(
                "client %s placement" % getattr(declaration, "name", "?"), placement,
                "local execution does not consume image or container options",
            )

    def execute(
        self, context: ToolExecutionContext, request: ToolExecutionRequest,
    ) -> CommandResult:
        return context.execute_local(request)


class _KubernetesToolExecutor:
    brixtest_api_version = 1
    brixtest_capabilities = (
        "capture", "credentials", "mounts", "resources", "retries", "service-dns",
    )

    def validate(self, declaration: object) -> None:
        placement = getattr(declaration, "placement", Placement())
        image = _declared_image(declaration)
        if _DIGEST_IMAGE.fullmatch(image) is None:
            raise SpecError(
                "client %s placement.image" % getattr(declaration, "name", "?"),
                image, "Kubernetes tool images must be digest pinned",
            )
        if getattr(declaration, "mode", "capture") == "pty":
            raise SpecError(
                "client %s mode" % getattr(declaration, "name", "?"), "pty",
                "Kubernetes tools support capture or stream mode",
            )
        if placement.namespace and not isinstance(placement.namespace, str):
            raise SpecError("client placement.namespace", placement.namespace, "must be text")
        if placement.resources.pids is not None:
            raise SpecError(
                "client %s placement.resources.pids" % getattr(declaration, "name", "?"),
                placement.resources.pids,
                "Kubernetes has no portable per-container PID limit; use an executor extension",
            )
        if placement.options or placement.allow_mutable_image:
            raise SpecError(
                "client %s placement" % getattr(declaration, "name", "?"), placement,
                "Kubernetes does not consume container runtime options or mutable images",
            )

    def execute(
        self, context: ToolExecutionContext, request: ToolExecutionRequest,
    ) -> CommandResult:
        if _DIGEST_IMAGE.fullmatch(request.image) is None:
            raise SpecError(
                "Kubernetes tool image", request.image,
                "must be digest pinned",
            )
        if not context.namespace:
            raise SpecError(
                "Kubernetes tool executor", request.name,
                "requires a Kubernetes case backend namespace",
            )
        if request.input is not None:
            raise SpecError(
                "Kubernetes tool input", request.name,
                "stdin transport is not supported; mount a declared artifact instead",
            )
        kubectl = [str(context.metadata.get("kubectl", "kubectl"))]
        selected_context = str(context.metadata.get("kubectl_context", ""))
        if selected_context:
            kubectl.extend(("--context", selected_context))
        started = time.perf_counter()
        attempts = 0
        result: Optional[CommandResult] = None
        while attempts <= request.retries:
            attempts += 1
            result = self._attempt(kubectl, context, request, attempts, started)
            if result.returncode in request.expected_exit_codes:
                break
        assert result is not None
        result = dataclasses.replace(result, attempts=attempts)
        if request.mode == "stream":
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
        if request.check and result.returncode not in request.expected_exit_codes:
            raise subprocess.CalledProcessError(
                result.returncode, result.argv, output=result.stdout, stderr=result.stderr,
            )
        return result

    def _attempt(
        self, kubectl: Sequence[str], context: ToolExecutionContext,
        request: ToolExecutionRequest, attempt: int, started: float,
    ) -> CommandResult:
        pod_name = _pod_name(request.name, attempt)
        manifest = _tool_pod(pod_name, context.namespace, request)
        apply = _kubectl(
            kubectl, "apply", "-f", "-", input_text=json.dumps(manifest) + "\n",
            timeout=min(30.0, request.timeout),
        )
        if apply.returncode:
            _kubectl(
                kubectl, "-n", context.namespace, "delete", "pod", pod_name,
                "--wait=false", "--ignore-not-found=true", timeout=15.0,
            )
            return CommandResult(
                tuple(request.argv), apply.returncode, apply.stdout, apply.stderr,
                time.perf_counter() - started,
            )
        stdout = ""
        stderr = ""
        returncode = 1
        deadline = time.monotonic() + request.timeout
        try:
            while time.monotonic() < deadline:
                state = _kubectl(
                    kubectl, "-n", context.namespace, "get", "pod", pod_name,
                    "-o", "json", timeout=min(10.0, request.timeout),
                )
                if state.returncode:
                    stderr = state.stderr
                    break
                try:
                    payload = json.loads(state.stdout)
                except ValueError:
                    payload = {}
                status = payload.get("status", {}) if isinstance(payload, Mapping) else {}
                phase = status.get("phase", "") if isinstance(status, Mapping) else ""
                if phase in ("Succeeded", "Failed"):
                    rows = status.get("containerStatuses", [])
                    terminated = (
                        rows[0].get("state", {}).get("terminated", {})
                        if isinstance(rows, list) and rows and isinstance(rows[0], Mapping)
                        else {}
                    )
                    returncode = int(terminated.get("exitCode", 0 if phase == "Succeeded" else 1))
                    break
                time.sleep(0.1)
            else:
                returncode = 124
                stderr = "Kubernetes tool exceeded %.3fs" % request.timeout
            logs = _kubectl(
                kubectl, "-n", context.namespace, "logs", "pod/%s" % pod_name,
                timeout=min(30.0, request.timeout),
                output_limit=request.output_limit,
            )
            stdout = logs.stdout
            if logs.returncode and not stderr:
                stderr = logs.stderr
        finally:
            _kubectl(
                kubectl, "-n", context.namespace, "delete", "pod", pod_name,
                "--wait=false", "--ignore-not-found=true", timeout=15.0,
            )
        stdout, stdout_truncated = _bounded(stdout, request.output_limit)
        stderr, stderr_truncated = _bounded(stderr, request.output_limit)
        return CommandResult(
            tuple(request.argv), returncode, stdout, stderr,
            time.perf_counter() - started, stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )


class _ContainerToolExecutor:
    brixtest_api_version = 1
    brixtest_capabilities = ("capture", "input", "resources", "retries", "stream")

    def __init__(self, runtime: str) -> None:
        self.runtime = runtime

    def validate(self, declaration: object) -> None:
        placement = getattr(declaration, "placement", Placement())
        image = _declared_image(declaration)
        if not placement.allow_mutable_image and _DIGEST_IMAGE.fullmatch(image) is None:
            raise SpecError(
                "client %s placement.image" % getattr(declaration, "name", "?"),
                image,
                "%s tool images must be digest pinned unless allow_mutable_image=True"
                % self.runtime,
            )
        if placement.namespace or placement.node_selector or placement.security_context:
            raise SpecError(
                "client %s placement" % getattr(declaration, "name", "?"), placement,
                "%s execution does not translate Kubernetes scheduling fields" % self.runtime,
            )
        unknown = sorted(set(placement.options) - {"network", "runtime_args"})
        if unknown:
            raise SpecError(
                "client %s placement.options" % getattr(declaration, "name", "?"),
                unknown, "known: network, runtime_args",
            )
        validate_runtime_args(
            placement.options.get("runtime_args", ()),
            "client %s placement.options.runtime_args"
            % getattr(declaration, "name", "?"),
        )
        network = placement.options.get("network", "host")
        validate_network(
            network,
            "client %s placement.options.network" % getattr(declaration, "name", "?"),
        )
        if getattr(declaration, "mode", "capture") == "pty":
            raise SpecError(
                "client %s mode" % getattr(declaration, "name", "?"), "pty",
                "%s tools support capture or stream mode" % self.runtime,
            )

    def execute(
        self, context: ToolExecutionContext, request: ToolExecutionRequest,
    ) -> CommandResult:
        if (
            not request.placement.allow_mutable_image
            and _DIGEST_IMAGE.fullmatch(request.image) is None
        ):
            raise SpecError(
                "%s tool image" % self.runtime, request.image,
                "must be digest pinned",
            )
        env_root = context.root / "runtime" / "executor-env"
        env_root.mkdir(parents=True, exist_ok=True)
        env_file = env_root / ("%s-%s.env" % (request.name, uuid.uuid4().hex[:10]))
        if any("\n" in key + value or "\0" in key + value for key, value in request.env.items()):
            raise SpecError(
                "%s tool environment" % self.runtime, request.name,
                "container environment values cannot contain newlines or NUL",
            )
        env_file.write_text("".join("%s=%s\n" % item for item in sorted(request.env.items())))
        env_file.chmod(0o600)
        limits = request.placement.resources
        base = [
            self.runtime, "run", "--rm", "--network",
            str(request.placement.options.get("network", "host")),
            "--env-file", str(env_file),
            "--volume", "%s:%s:ro" % (context.root, context.root),
            "--volume", "%s:%s:rw" % (context.workspace, context.workspace),
        ]
        if request.input is not None:
            base.append("--interactive")
        if request.cwd is not None:
            base.extend(("--workdir", str(request.cwd)))
        if limits.cpu is not None:
            base.extend(("--cpus", str(limits.cpu)))
        if limits.memory_bytes is not None:
            base.extend(("--memory", str(limits.memory_bytes)))
        if limits.pids is not None:
            base.extend(("--pids-limit", str(limits.pids)))
        base.extend(str(value) for value in request.placement.options.get("runtime_args", ()))
        base.append(request.image)
        argv = [*base, *request.argv]
        started = time.perf_counter()
        attempts = 0
        result = CommandResult(tuple(request.argv), 1, "", "not executed", 0.0)
        runner = CommandRunner(None, cwd=context.workspace)
        try:
            while attempts <= request.retries:
                attempts += 1
                try:
                    invocation = runner.run(
                        *argv, input=request.input, encoding=request.encoding,
                        timeout=request.timeout, check=False,
                        expected_exit_codes=request.expected_exit_codes,
                        output_limit=request.output_limit,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    invocation = CommandResult(
                        tuple(argv), 124,
                        str(getattr(exc, "output", "") or ""),
                        str(getattr(exc, "stderr", "") or "%s: %s" % (type(exc).__name__, exc)),
                        time.perf_counter() - started,
                    )
                result = dataclasses.replace(
                    invocation, argv=tuple(request.argv), attempts=attempts,
                )
                if result.returncode in request.expected_exit_codes:
                    break
        finally:
            try:
                env_file.unlink()
            except FileNotFoundError:
                pass
        result = dataclasses.replace(
            result, elapsed_seconds=time.perf_counter() - started,
        )
        if request.mode == "stream":
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
        if request.check and result.returncode not in request.expected_exit_codes:
            raise subprocess.CalledProcessError(
                result.returncode, result.argv, output=result.stdout, stderr=result.stderr,
            )
        return result


def _kubectl(
    executable: Union[str, Sequence[str]], *args: str,
    input_text: str = "", timeout: float = 30.0,
    output_limit: int = 1 << 20,
) -> subprocess.CompletedProcess:
    prefix = [executable] if isinstance(executable, str) else list(executable)
    argv = [*prefix, *args]
    try:
        result = CommandRunner(None, cwd=Path.cwd()).run(
            *argv, input=input_text or None, timeout=timeout, check=False,
            output_limit=output_limit,
        )
        return subprocess.CompletedProcess(
            argv, result.returncode, result.stdout, result.stderr,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(
            argv, 124, "", "%s: %s" % (type(exc).__name__, exc),
        )


def _declared_image(declaration: object) -> str:
    placement = getattr(declaration, "placement", Placement())
    if placement.image:
        return placement.image
    images = {
        getattr(value, "image", None)
        for value in (
            *getattr(declaration, "command", ()), *getattr(declaration, "binaries", ()),
        )
        if getattr(value, "image", None)
    }
    return next(iter(images)) if len(images) == 1 else ""


def _pod_name(name: str, attempt: int) -> str:
    suffix = uuid.uuid4().hex[:10]
    return ("brixtest-%s-%d-%s" % (name.replace("_", "-"), attempt, suffix))[-63:]


def _tool_pod(
    name: str, namespace: str, request: ToolExecutionRequest,
) -> Mapping[str, object]:
    placement = request.placement
    runtime = dict(request.metadata)
    if not all(_ENV_NAME.fullmatch(key) is not None for key in request.env):
        raise SpecError(
            "Kubernetes tool environment", tuple(sorted(request.env)),
            "names must be portable [A-Za-z_][A-Za-z0-9_]* values",
        )
    volume_mounts = [{"name": "workspace", "mountPath": "/brixtest/workspace"}]
    volumes = [{"name": "workspace", "emptyDir": {}}]
    for volume_name, secret_key, items_key, mount_path in (
        ("secure", "secure_secret", "secure_items", "/brixtest/secure"),
        ("declared-mounts", "mount_secret", "mount_items", "/brixtest/mounts"),
    ):
        secret = str(runtime.get(secret_key, ""))
        if secret:
            volume_mounts.append({"name": volume_name, "mountPath": mount_path, "readOnly": True})
            volumes.append({
                "name": volume_name,
                "secret": {"secretName": secret, "items": list(runtime.get(items_key, ()))},
            })
    for index, target in enumerate(runtime.get("temporary_mounts", ())):
        volume_name = "temporary-%d" % index
        volume_mounts.append({
            "name": volume_name, "mountPath": "/brixtest/mounts/%s" % target,
        })
        volumes.append({"name": volume_name, "emptyDir": {}})
    container: dict[str, object] = {
        "name": "tool", "image": request.image, "imagePullPolicy": "IfNotPresent",
        "command": list(request.argv),
        "env": [{"name": key, "value": value} for key, value in sorted(request.env.items())],
        "workingDir": str(request.cwd or Path("/brixtest/workspace")),
        "volumeMounts": volume_mounts,
    }
    secret_environment = runtime.get("secret_environment", {})
    if not isinstance(secret_environment, Mapping):
        raise SpecError(
            "Kubernetes tool secret environment", secret_environment,
            "must be a mapping",
        )
    secret_name = str(runtime.get("secure_secret", ""))
    if secret_environment and not secret_name:
        raise SpecError(
            "Kubernetes tool secret environment", secret_environment,
            "requires a projected secure_secret",
        )
    for environment_name, secret_key in sorted(secret_environment.items()):
        if _ENV_NAME.fullmatch(str(environment_name)) is None or not str(secret_key):
            raise SpecError(
                "Kubernetes tool secret environment", secret_environment,
                "must map portable environment names to Secret data keys",
            )
        container["env"].append({
            "name": str(environment_name),
            "valueFrom": {"secretKeyRef": {
                "name": secret_name,
                "key": str(secret_key),
            }},
        })
    limits = placement.resources
    resources = {}
    if limits.cpu is not None:
        resources["cpu"] = str(limits.cpu)
    if limits.memory_bytes is not None:
        resources["memory"] = str(limits.memory_bytes)
    if resources:
        container["resources"] = {"limits": resources, "requests": resources}
    if placement.security_context:
        container["securityContext"] = dict(placement.security_context)
    pod_spec: dict[str, object] = {
        "restartPolicy": "Never", "containers": [container], "volumes": volumes,
    }
    if placement.node_selector:
        pod_spec["nodeSelector"] = dict(placement.node_selector)
    host_aliases = runtime.get("host_aliases", ())
    if host_aliases:
        pod_spec["hostAliases"] = list(host_aliases)
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name, "namespace": namespace,
            "labels": {"app.kubernetes.io/managed-by": "brixtest", **dict(placement.labels)},
        },
        "spec": pod_spec,
    }


def _bounded(value: str, limit: int) -> tuple[str, bool]:
    payload = value.encode("utf-8", errors="replace")
    if len(payload) <= limit:
        return value, False
    marker = b"\n[BriXTest output truncated]\n"
    available = max(0, limit - len(marker))
    head = available // 2
    tail = available - head
    selected = payload[:head] + marker[:limit] + (payload[-tail:] if tail else b"")
    return selected[:limit].decode("utf-8", errors="replace"), True


_BUILTINS = {
    "local": _LocalToolExecutor(),
    "kubernetes": _KubernetesToolExecutor(),
    "docker": _ContainerToolExecutor("docker"),
    "podman": _ContainerToolExecutor("podman"),
}


def tool_executor(name: str):
    """Resolve a built-in or installed executor through the shared contract."""
    if name in _BUILTINS:
        return _BUILTINS[name]
    return get_extension("executor", name)


for _executor_name, _executor in _BUILTINS.items():
    try:
        register_extension(
            "executor", _executor_name, _executor, origin="brixtest",
            capabilities=_executor.brixtest_capabilities,
        )
    except SpecError:
        pass

"""Declarations and command builders for supervised helper isolation."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Optional, Sequence, Tuple

from brixtest.errors import SpecError
from brixtest.runtime.container_policy import validate_runtime_args

if TYPE_CHECKING:
    from brixtest.network import HostMapping

__all__ = [
    "Isolation", "LaunchSpec", "build_launch", "docker", "kubernetes", "nsenter",
    "podman", "process", "runc",
]

_KINDS = ("process", "nsenter", "docker", "podman", "runc", "kubernetes")
_NAMESPACES = {
    "mount": "--mount", "uts": "--uts", "ipc": "--ipc", "net": "--net",
    "pid": "--pid", "user": "--user", "cgroup": "--cgroup", "time": "--time",
}
_DIGEST_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-fA-F]{64}$")
_KUBERNETES_NAME = re.compile(
    r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$"
)
_CONTAINER_OWNED_FLAGS = (
    "--env", "-e", "--env-file", "--volume", "-v", "--mount", "--name",
    "--workdir", "-w", "--network", "--privileged", "--pid", "--userns",
    "--entrypoint", "--user", "--add-host",
)
_CONTAINER_BOOLEAN_FLAGS = {"--init", "--read-only"}
_INNER_KEYS = {
    "PYTHONPATH", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "BRIXTEST_HELPER",
    "BRIXTEST_CONTROLLER_PID", "BRIXTEST_HELPER_RESULT", "BRIXTEST_CASE_RUN",
    "BRIXTEST_BACKEND", "BRIXTEST_RUNS", "BRIXTEST_METRICS_SESSION",
    "BRIXTEST_SERVER_ENV_JSON", "BRIXTEST_CLIENT_ENV_JSON",
    "BRIXTEST_BINARY_OVERRIDES_JSON", "BRIXTEST_TEST_ENV_KEYS_JSON",
    "BRIXTEST_ATTEMPT_ID", "BRIXTEST_TRIAL", "BRIXTEST_WARMUP",
    "BRIXTEST_SHARED_SERVERS_JSON",
    "BRIXTEST_HELPER_HEARTBEAT", "BRIXTEST_HELPER_CANCEL",
    "BRIXTEST_ISOLATION_KIND",
}


def _validate_container_declaration(value: "Isolation") -> None:
    if not isinstance(value.image, str):
        raise SpecError("isolation.image", value.image, "must be text")
    if not isinstance(value.allow_mutable_image, bool):
        raise SpecError(
            "isolation.allow_mutable_image", value.allow_mutable_image, "must be boolean",
        )
    if value.kind in ("docker", "podman", "kubernetes"):
        if not value.image:
            raise SpecError("isolation.image", value.image, "is required for container isolation")
        if not value.allow_mutable_image and _DIGEST_IMAGE.fullmatch(value.image) is None:
            raise SpecError(
                "isolation.image", value.image,
                "must be digest pinned (image@sha256:...) or explicitly allow_mutable=True",
            )
    elif value.image:
        raise SpecError(
            "isolation.image", value.image,
            "is valid only for docker, podman, or kubernetes",
        )


def _validate_kubernetes_declaration(value: "Isolation") -> None:
    fields = (value.context, value.namespace, value.service_account)
    if value.kind != "kubernetes":
        _reject_kubernetes_fields(fields)
        return
    if value.allow_mutable_image:
        raise SpecError(
            "isolation.allow_mutable_image", True,
            "Kubernetes helper images must be digest pinned",
        )
    _validate_kubernetes_name("namespace", value.namespace)
    _validate_kubernetes_name("service_account", value.service_account)
    _validate_kubernetes_context(value.context)


def _reject_kubernetes_fields(fields: tuple[object, ...]) -> None:
    if any(fields):
        raise SpecError(
            "isolation Kubernetes options", fields,
            "are valid only for kubernetes helper isolation",
        )


def _validate_kubernetes_name(field: str, selected: object) -> None:
    if isinstance(selected, str) and _KUBERNETES_NAME.fullmatch(selected) is not None:
        return
    raise SpecError(
        "isolation.%s" % field, selected,
        "must be a non-empty Kubernetes DNS name",
    )


def _validate_kubernetes_context(context: object) -> None:
    valid = isinstance(context, str) and not any(
        char in context for char in ("\x00", "\n", "\r")
    )
    if not valid:
        raise SpecError("isolation.context", context, "must be plain text")


def _validate_nsenter_declaration(value: "Isolation") -> None:
    if value.kind != "nsenter":
        if value.target_pid or value.namespaces:
            raise SpecError(
                "isolation.target_pid", value.target_pid,
                "target_pid/namespaces are valid only for nsenter",
            )
        return
    if isinstance(value.target_pid, bool) or not isinstance(value.target_pid, int):
        raise SpecError("isolation.target_pid", value.target_pid, "must be a positive PID")
    if value.target_pid <= 0:
        raise SpecError("isolation.target_pid", value.target_pid, "must be a positive PID")
    _validate_namespaces(value.namespaces)


def _validate_namespaces(namespaces: object) -> None:
    if isinstance(namespaces, (str, bytes)) or not isinstance(namespaces, Sequence):
        raise SpecError("isolation.namespaces", namespaces, "must be a sequence")
    if not all(isinstance(namespace, str) for namespace in namespaces):
        raise SpecError("isolation.namespaces", namespaces, "must contain namespace names")
    unknown = sorted(set(namespaces) - set(_NAMESPACES))
    if unknown:
        raise SpecError("isolation.namespaces", unknown, "contains unknown namespace names")
    if not namespaces:
        raise SpecError("isolation.namespaces", (), "must select at least one namespace")


def _validate_bundle_declaration(value: "Isolation") -> None:
    if value.bundle is not None and not isinstance(value.bundle, (str, Path)):
        raise SpecError("isolation.bundle", value.bundle, "must be a string or path")
    if value.kind == "runc" and value.bundle is None:
        raise SpecError("isolation.bundle", value.bundle, "is required for runc")
    if value.kind != "runc" and value.bundle is not None:
        raise SpecError("isolation.bundle", value.bundle, "is valid only for runc")


def _container_arg_findings(args: Sequence[str]) -> tuple[list[str], list[str], list[str]]:
    return (
        _positional_container_args(args),
        _ambiguous_container_args(args),
        _unsafe_container_args(args),
    )


def _positional_container_args(args: Sequence[str]) -> list[str]:
    return [arg for arg in args if not arg.startswith("-")]


def _ambiguous_container_args(args: Sequence[str]) -> list[str]:
    return [
        arg for arg in args if "=" not in arg and arg not in _CONTAINER_BOOLEAN_FLAGS
    ]


def _unsafe_container_args(args: Sequence[str]) -> list[str]:
    def framework_owned(arg: str) -> bool:
        return any(
            arg == flag or arg.startswith(flag + "=")
            for flag in _CONTAINER_OWNED_FLAGS
        )

    return [arg for arg in args if framework_owned(arg)]


def _valid_extra_args(args: object) -> bool:
    if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
        return False
    return all(isinstance(arg, str) and bool(arg) for arg in args)


def _validate_extra_args(value: "Isolation") -> None:
    args = value.extra_args
    if not _valid_extra_args(args):
        raise SpecError("isolation.extra_args", args, "must contain non-empty strings")
    if args and value.kind not in ("docker", "podman", "runc"):
        raise SpecError(
            "isolation.extra_args", args,
            "are valid only for docker, podman, or runc",
        )
    if value.kind not in ("docker", "podman"):
        return
    try:
        validate_runtime_args(args, "isolation.extra_args")
    except SpecError as exc:
        raise SpecError(
            "isolation.extra_args", args,
            "cannot override framework-owned privilege, process, namespace, or lifecycle policy",
        ) from exc
    positional, ambiguous, unsafe = _container_arg_findings(args)
    _reject_container_arg_findings(positional, ambiguous, unsafe)


def _reject_container_arg_findings(
    positional: Sequence[str], ambiguous: Sequence[str], unsafe: Sequence[str],
) -> None:
    if positional:
        raise SpecError(
            "isolation.extra_args", positional,
            "must use --option=value form and cannot inject a positional image/command",
        )
    if ambiguous:
        raise SpecError(
            "isolation.extra_args", ambiguous,
            "must use --option=value unless the option is an approved boolean flag",
        )
    if unsafe:
        raise SpecError(
            "isolation.extra_args", unsafe,
            "cannot override framework-owned environment, mounts, identity, or networking",
        )


def _validate_runc_args(value: "Isolation") -> None:
    owned = ("--root", "--bundle", "--detach", "--pid-file", "--console-socket")
    unsafe = value.kind == "runc" and any(
        arg in owned or arg.startswith(tuple(flag + "=" for flag in owned))
        for arg in value.extra_args
    )
    if unsafe:
        raise SpecError(
            "isolation.extra_args", value.extra_args, "overrides a framework-owned runc option"
        )



@dataclasses.dataclass(frozen=True)
class Isolation:
    """How the pytest helper process is isolated from its controller."""

    kind: str = "process"
    image: str = ""
    target_pid: int = 0
    namespaces: Tuple[str, ...] = ()
    bundle: Optional[Path] = None
    python: str = "python3"
    extra_args: Tuple[str, ...] = ()
    allow_mutable_image: bool = False
    context: str = ""
    namespace: str = ""
    service_account: str = ""

    def __post_init__(self) -> None:
        _validate_kind(self.kind)
        _validate_container_declaration(self)
        _validate_kubernetes_declaration(self)
        _validate_nsenter_declaration(self)
        _validate_bundle_declaration(self)
        _validate_python(self.python)
        _validate_extra_args(self)
        _validate_runc_args(self)
        self._normalize()

    def _normalize(self) -> None:
        object.__setattr__(self, "namespaces", tuple(self.namespaces))
        object.__setattr__(self, "extra_args", tuple(self.extra_args))
        if self.bundle is not None:
            object.__setattr__(self, "bundle", Path(self.bundle))

    def resolved(self, source_root: Path) -> "Isolation":
        """Return a copy whose relative OCI bundle is anchored to the test source."""
        if self.bundle is None or self.bundle.is_absolute():
            return self
        return dataclasses.replace(self, bundle=(source_root / self.bundle).resolve())

    def cli_args(self) -> list[str]:
        """Render this declaration as equivalent BriXTest pytest options."""
        args = ["--brixtest-isolation", self.kind]
        _append_cli_value(args, "--brixtest-isolation-image", self.image)
        _append_cli_value(args, "--brixtest-nsenter-target", self.target_pid)
        for namespace in self.namespaces:
            args.extend(("--brixtest-nsenter-namespace", namespace))
        _append_cli_value(args, "--brixtest-runc-bundle", self.bundle)
        _append_cli_value(
            args, "--brixtest-container-python", self.python,
            enabled=self.python != "python3",
        )
        for value in self.extra_args:
            args.extend(("--brixtest-isolation-arg", value))
        _append_cli_flag(args, "--brixtest-allow-mutable-image", self.allow_mutable_image)
        _append_cli_value(args, "--brixtest-kubernetes-context", self.context)
        _append_cli_value(args, "--brixtest-kubernetes-namespace", self.namespace)
        _append_cli_value(
            args, "--brixtest-kubernetes-service-account", self.service_account,
        )
        return args


def _validate_kind(kind: object) -> None:
    if not isinstance(kind, str) or kind not in _KINDS:
        raise SpecError("isolation.kind", kind, "must be one of: %s" % ", ".join(_KINDS))


def _validate_python(python: object) -> None:
    if not isinstance(python, str) or not python:
        raise SpecError("isolation.python", python, "must be one executable name/path")
    if any(char.isspace() for char in python):
        raise SpecError("isolation.python", python, "must be one executable name/path")


def _append_cli_value(
    args: list[str], option: str, value: object, *, enabled: Optional[bool] = None,
) -> None:
    selected = bool(value) if enabled is None else enabled
    if selected:
        args.extend((option, str(value)))


def _append_cli_flag(args: list[str], option: str, enabled: bool) -> None:
    if enabled:
        args.append(option)


def process() -> Isolation:
    """Run the test helper as a directly supervised local process."""
    return Isolation()


def nsenter(target_pid: int, *, namespaces: Sequence[str] = ("mount", "uts", "ipc", "net", "pid", "cgroup")) -> Isolation:
    """Run the helper after entering selected namespaces of another process."""
    return Isolation(kind="nsenter", target_pid=target_pid, namespaces=namespaces)


def docker(
    image: str, *, python: str = "python3", extra_args: Sequence[str] = (),
    allow_mutable: bool = False,
) -> Isolation:
    """Run the helper in a digest-pinned Docker container."""
    return Isolation(
        kind="docker", image=image, python=python, extra_args=extra_args,
        allow_mutable_image=allow_mutable,
    )


def podman(
    image: str, *, python: str = "python3", extra_args: Sequence[str] = (),
    allow_mutable: bool = False,
) -> Isolation:
    """Run the helper in a digest-pinned Podman container."""
    return Isolation(
        kind="podman", image=image, python=python, extra_args=extra_args,
        allow_mutable_image=allow_mutable,
    )


def kubernetes(
    image: str, *, context: str = "", namespace: str = "default",
    service_account: str = "default", python: str = "python3",
) -> Isolation:
    """Run the helper in a digest-pinned Kubernetes Job."""
    return Isolation(
        kind="kubernetes", image=image, python=python, context=context,
        namespace=namespace, service_account=service_account,
    )


def runc(bundle: Path, *, python: str = "python3", extra_args: Sequence[str] = ()) -> Isolation:
    """Run the helper in a private derivative of an OCI runc bundle."""
    return Isolation(kind="runc", bundle=bundle, python=python, extra_args=extra_args)


@dataclasses.dataclass(frozen=True)
class LaunchSpec:
    argv: Tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    cleanup: Tuple[Tuple[str, ...], ...] = ()
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)


def build_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    *, cwd: Path, readonly_roots: Sequence[Path], writable_root: Path,
    control_dir: Path, validate_executable: bool = True,
    host_aliases: Sequence[HostMapping] = (),
    helper_inputs: Sequence[Path] = (),
) -> LaunchSpec:
    """Build one shell-free helper launch and its best-effort cleanup commands."""
    from brixtest.isolation_launch import build_launch as build

    return build(
        isolation, pytest_argv, child_env, cwd=cwd, readonly_roots=readonly_roots,
        writable_root=writable_root, control_dir=control_dir,
        validate_executable=validate_executable, host_aliases=host_aliases,
        helper_inputs=helper_inputs,
    )

"""Declarations and command builders for supervised helper isolation."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Optional, Sequence, Tuple

from brixtest.errors import SpecError
from brixtest.runtime.container_policy import validate_runtime_args

if TYPE_CHECKING:
    from brixtest.network import HostMapping

__all__ = [
    "Isolation", "LaunchSpec", "build_launch", "docker", "nsenter",
    "podman", "process", "runc",
]

_KINDS = ("process", "nsenter", "docker", "podman", "runc")
_NAMESPACES = {
    "mount": "--mount", "uts": "--uts", "ipc": "--ipc", "net": "--net",
    "pid": "--pid", "user": "--user", "cgroup": "--cgroup", "time": "--time",
}
_DIGEST_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-fA-F]{64}$")
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
}


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

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in _KINDS:
            raise SpecError("isolation.kind", self.kind, "must be one of: %s" % ", ".join(_KINDS))
        if not isinstance(self.image, str):
            raise SpecError("isolation.image", self.image, "must be text")
        if not isinstance(self.allow_mutable_image, bool):
            raise SpecError(
                "isolation.allow_mutable_image", self.allow_mutable_image, "must be boolean",
            )
        if self.kind in ("docker", "podman"):
            if not self.image:
                raise SpecError("isolation.image", self.image, "is required for container isolation")
            if not self.allow_mutable_image and _DIGEST_IMAGE.fullmatch(self.image) is None:
                raise SpecError(
                    "isolation.image", self.image,
                    "must be digest pinned (image@sha256:...) or explicitly allow_mutable=True",
                )
        elif self.image:
            raise SpecError("isolation.image", self.image, "is valid only for docker or podman")
        if self.kind == "nsenter":
            if isinstance(self.target_pid, bool) or not isinstance(self.target_pid, int) \
                    or self.target_pid <= 0:
                raise SpecError("isolation.target_pid", self.target_pid, "must be a positive PID")
            if isinstance(self.namespaces, (str, bytes)) or not isinstance(self.namespaces, Sequence):
                raise SpecError("isolation.namespaces", self.namespaces, "must be a sequence")
            if not all(isinstance(namespace, str) for namespace in self.namespaces):
                raise SpecError(
                    "isolation.namespaces", self.namespaces, "must contain namespace names",
                )
            unknown = sorted(set(self.namespaces) - set(_NAMESPACES))
            if unknown:
                raise SpecError("isolation.namespaces", unknown, "contains unknown namespace names")
            if not self.namespaces:
                raise SpecError("isolation.namespaces", (), "must select at least one namespace")
        elif self.target_pid or self.namespaces:
            raise SpecError(
                "isolation.target_pid", self.target_pid,
                "target_pid/namespaces are valid only for nsenter",
            )
        if self.bundle is not None and not isinstance(self.bundle, (str, Path)):
            raise SpecError("isolation.bundle", self.bundle, "must be a string or path")
        if self.kind == "runc" and self.bundle is None:
            raise SpecError("isolation.bundle", self.bundle, "is required for runc")
        if self.kind != "runc" and self.bundle is not None:
            raise SpecError("isolation.bundle", self.bundle, "is valid only for runc")
        if not isinstance(self.python, str) or not self.python \
                or any(char.isspace() for char in self.python):
            raise SpecError("isolation.python", self.python, "must be one executable name/path")
        if isinstance(self.extra_args, (str, bytes)) or not isinstance(self.extra_args, Sequence) or not all(
            isinstance(arg, str) and arg for arg in self.extra_args
        ):
            raise SpecError("isolation.extra_args", self.extra_args, "must contain non-empty strings")
        if self.kind in ("docker", "podman"):
            try:
                validate_runtime_args(self.extra_args, "isolation.extra_args")
            except SpecError as exc:
                raise SpecError(
                    "isolation.extra_args", self.extra_args,
                    "cannot override framework-owned privilege, process, namespace, or lifecycle policy",
                ) from exc
            positional = [arg for arg in self.extra_args if not arg.startswith("-")]
            if positional:
                raise SpecError(
                    "isolation.extra_args", positional,
                    "must use --option=value form and cannot inject a positional image/command",
                )
            ambiguous = [
                arg for arg in self.extra_args
                if "=" not in arg and arg not in _CONTAINER_BOOLEAN_FLAGS
            ]
            if ambiguous:
                raise SpecError(
                    "isolation.extra_args", ambiguous,
                    "must use --option=value unless the option is an approved boolean flag",
                )
            unsafe = [
                arg for arg in self.extra_args
                if any(arg == flag or arg.startswith(flag + "=") for flag in _CONTAINER_OWNED_FLAGS)
            ]
            if unsafe:
                raise SpecError(
                    "isolation.extra_args", unsafe,
                    "cannot override framework-owned environment, mounts, identity, or networking",
                )
        if self.kind == "runc" and any(
            arg in ("--root", "--bundle", "--detach", "--pid-file", "--console-socket")
            or arg.startswith(("--root=", "--bundle=", "--pid-file=", "--console-socket="))
            for arg in self.extra_args
        ):
            raise SpecError("isolation.extra_args", self.extra_args, "overrides a framework-owned runc option")
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
        if self.image:
            args.extend(("--brixtest-isolation-image", self.image))
        if self.target_pid:
            args.extend(("--brixtest-nsenter-target", str(self.target_pid)))
        for namespace in self.namespaces:
            args.extend(("--brixtest-nsenter-namespace", namespace))
        if self.bundle is not None:
            args.extend(("--brixtest-runc-bundle", str(self.bundle)))
        if self.python != "python3":
            args.extend(("--brixtest-container-python", self.python))
        for value in self.extra_args:
            args.extend(("--brixtest-isolation-arg", value))
        if self.allow_mutable_image:
            args.append("--brixtest-allow-mutable-image")
        return args


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


def runc(bundle: Path, *, python: str = "python3", extra_args: Sequence[str] = ()) -> Isolation:
    """Run the helper in a private derivative of an OCI runc bundle."""
    return Isolation(kind="runc", bundle=bundle, python=python, extra_args=extra_args)


@dataclasses.dataclass(frozen=True)
class LaunchSpec:
    argv: Tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    cleanup: Tuple[Tuple[str, ...], ...] = ()


def _require_executable(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise SpecError("isolation executable", name, "is not installed or not on PATH")
    return found


def _write_env(path: Path, env: Mapping[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for key, value in sorted(env.items()):
        if "\n" in value or "\r" in value or "\x00" in value:
            raise SpecError("container environment %s" % key, value, "cannot contain newlines or NUL")
        lines.append("%s=%s" % (key, value))
    path.write_text("\n".join(lines) + "\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _inner_env(env: Mapping[str, str]) -> Mapping[str, str]:
    """Pass framework and explicitly requested values, never ambient secrets."""
    keys = set(_INNER_KEYS)
    try:
        requested = json.loads(env.get("BRIXTEST_TEST_ENV_KEYS_JSON", "[]"))
        if isinstance(requested, list):
            keys.update(str(item) for item in requested)
    except (TypeError, ValueError):
        pass
    return {key: env[key] for key in sorted(keys) if key in env}


def _mount_arg(source: Path, *, readonly: bool) -> str:
    text = str(source.resolve())
    if "," in text or "\n" in text:
        raise SpecError("isolation mount", text, "cannot contain comma or newline")
    return "type=bind,src=%s,dst=%s%s" % (text, text, ",readonly" if readonly else "")


def _container_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    host_env: Mapping[str, str], cwd: Path, readonly_roots: Sequence[Path],
    writable_root: Path, control_dir: Path, *, validate: bool,
    host_aliases: Sequence[HostMapping] = (),
) -> LaunchSpec:
    runtime = _require_executable(isolation.kind) if validate else isolation.kind
    env_path = control_dir / "helper.env"
    _write_env(env_path, _inner_env(child_env))
    name = "brixtest-%s" % control_dir.name[-32:].lower()
    argv = [
        runtime, "run", "--rm", "--name", name, "--network", "host",
        "--user", "%d:%d" % (os.getuid(), os.getgid()),
        "--env-file", str(env_path), "--workdir", str(cwd),
    ]
    for mapping in host_aliases:
        for hostname in mapping.hostnames:
            argv.extend(("--add-host", "%s:%s" % (hostname, mapping.address)))
    mounted = set()
    for root, readonly in [
        *((Path(path), True) for path in readonly_roots),
        (Path(writable_root), False),
    ]:
        resolved = root.resolve()
        if resolved in mounted:
            continue
        mounted.add(resolved)
        argv.extend(("--mount", _mount_arg(resolved, readonly=readonly)))
    argv.extend(isolation.extra_args)
    argv.extend((isolation.image, isolation.python, *pytest_argv[1:]))
    cleanup = ((runtime, "rm", "-f", name),)
    return LaunchSpec(tuple(argv), cwd, dict(host_env), cleanup)


def _runc_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    host_env: Mapping[str, str], cwd: Path, readonly_roots: Sequence[Path],
    writable_root: Path, control_dir: Path, *, validate: bool,
) -> LaunchSpec:
    runtime = _require_executable("runc") if validate else "runc"
    assert isolation.bundle is not None
    bundle = isolation.bundle.resolve()
    config_path = bundle / "config.json"
    try:
        config = json.loads(config_path.read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise SpecError("isolation.bundle", str(bundle), "cannot read OCI config.json: %s" % exc) from exc
    derived = control_dir / "oci-bundle"
    derived.mkdir(parents=True, exist_ok=False)
    root = dict(config.get("root", {}))
    root_path = Path(str(root.get("path", "rootfs")))
    if not root_path.is_absolute():
        root_path = (bundle / root_path).resolve()
    if not root_path.is_dir():
        raise SpecError("isolation.bundle rootfs", str(root_path), "is not a directory")
    root["path"] = str(root_path)
    root["readonly"] = True
    config["root"] = root
    linux = config.get("linux", {})
    namespaces = linux.get("namespaces", []) if isinstance(linux, Mapping) else []
    namespace_types = {
        str(item.get("type", "")) for item in namespaces
        if isinstance(item, Mapping)
    } if isinstance(namespaces, list) else set()
    missing_namespaces = sorted({"mount", "pid", "uts", "ipc", "network"} - namespace_types)
    if missing_namespaces:
        raise SpecError(
            "isolation.bundle namespaces", missing_namespaces,
            "OCI helper bundles must isolate mount, pid, uts, ipc, and network namespaces",
        )
    process_spec = dict(config.get("process", {}))
    original_env = process_spec.get("env", [])
    environment = {}
    if isinstance(original_env, list):
        for raw in original_env:
            if isinstance(raw, str) and "=" in raw:
                key, value = raw.split("=", 1)
                environment[key] = value
    environment.update(_inner_env(child_env))
    process_spec.update({
        "terminal": False, "args": [isolation.python, *pytest_argv[1:]],
        "cwd": str(cwd), "env": ["%s=%s" % item for item in sorted(environment.items())],
        "noNewPrivileges": True,
        "capabilities": {
            "bounding": [], "effective": [], "inheritable": [],
            "permitted": [], "ambient": [],
        },
    })
    config["process"] = process_spec
    mounts = list(config.get("mounts", []))
    owned_mounts = [
        *((Path(value), True) for value in readonly_roots),
        (Path(writable_root), False),
    ]
    destinations = {str(path.resolve()) for path, _ in owned_mounts}
    mounts = [
        item for item in mounts
        if not isinstance(item, Mapping)
        or str(item.get("destination", "")) not in destinations
    ]
    for path, readonly in owned_mounts:
        destination = str(path.resolve())
        options = ["rbind", "nosuid", "nodev"] + (["ro"] if readonly else ["rw"])
        mounts.append({
            "destination": destination, "type": "none", "source": destination,
            "options": options,
        })
    config["mounts"] = mounts
    derived_config = derived / "config.json"
    derived_config.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    derived_config.chmod(stat.S_IRUSR | stat.S_IWUSR)
    state_root = control_dir / "runc-state"
    state_root.mkdir()
    container_id = "brixtest-%s" % control_dir.name[-24:].lower()
    prefix = (runtime, "--root", str(state_root))
    argv = (*prefix, "run", "--bundle", str(derived), *isolation.extra_args, container_id)
    cleanup = (
        (*prefix, "kill", container_id, "KILL"),
        (*prefix, "delete", "--force", container_id),
    )
    return LaunchSpec(tuple(argv), cwd, dict(host_env), cleanup)


def build_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    *, cwd: Path, readonly_roots: Sequence[Path], writable_root: Path,
    control_dir: Path, validate_executable: bool = True,
    host_aliases: Sequence[HostMapping] = (),
) -> LaunchSpec:
    """Build one shell-free helper launch and its best-effort cleanup commands."""
    selected = isolation.resolved(cwd)
    if selected.kind == "process":
        return LaunchSpec(tuple(pytest_argv), cwd, dict(child_env))
    if selected.kind == "nsenter":
        executable = _require_executable("nsenter") if validate_executable else "nsenter"
        argv = [executable, "--target", str(selected.target_pid)]
        argv.extend(_NAMESPACES[name] for name in selected.namespaces)
        argv.extend(("--", *pytest_argv))
        return LaunchSpec(tuple(argv), cwd, dict(child_env))
    if selected.kind in ("docker", "podman"):
        return _container_launch(
            selected, pytest_argv, child_env, os.environ, cwd, readonly_roots,
            writable_root, control_dir, validate=validate_executable,
            host_aliases=host_aliases,
        )
    return _runc_launch(
        selected, pytest_argv, child_env, os.environ, cwd, readonly_roots,
        writable_root, control_dir, validate=validate_executable,
    )

"""Shell-free launch construction for BriXTest helper isolation."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.helper_bundle import build_helper_bundle
from brixtest.helper_transport import CHANNEL_ENV, STDIO_CHANNEL
from brixtest.isolation import _INNER_KEYS, _NAMESPACES, Isolation, LaunchSpec
from brixtest.kubernetes_helper_manifest import (
    REMOTE_DONE,
    REMOTE_RESULT,
    REMOTE_RUN,
    REMOTE_SESSION,
    helper_resources,
    write_helper_manifest,
)

if TYPE_CHECKING:
    from brixtest.network import HostMapping


def _require_executable(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise SpecError("isolation executable", name, "is not installed or not on PATH")
    return found


def _write_env(path: Path, env: Mapping[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for key, value in sorted(env.items()):
        _validate_env_value(key, value)
        lines.append("%s=%s" % (key, value))
    path.write_text("\n".join(lines) + "\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _validate_env_value(key: str, value: str) -> None:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise SpecError(
            "container environment %s" % key, value, "cannot contain newlines or NUL"
        )


def _requested_env_keys(env: Mapping[str, str]) -> set[str]:
    try:
        requested = json.loads(env.get("BRIXTEST_TEST_ENV_KEYS_JSON", "[]"))
    except (TypeError, ValueError):
        return set()
    if not isinstance(requested, list):
        return set()
    return {str(item) for item in requested}


def _inner_env(env: Mapping[str, str]) -> Mapping[str, str]:
    """Pass framework and explicitly requested values, never ambient secrets."""
    keys = set(_INNER_KEYS) | _requested_env_keys(env)
    return {key: env[key] for key in sorted(keys) if key in env}


def _mount_arg(source: Path, *, readonly: bool) -> str:
    text = str(source.resolve())
    if "," in text or "\n" in text:
        raise SpecError("isolation mount", text, "cannot contain comma or newline")
    suffix = ",readonly" if readonly else ""
    return "type=bind,src=%s,dst=%s%s" % (text, text, suffix)


def _append_host_aliases(argv: list[str], host_aliases: Sequence[HostMapping]) -> None:
    for mapping in host_aliases:
        for hostname in mapping.hostnames:
            argv.extend(("--add-host", "%s:%s" % (hostname, mapping.address)))


def _owned_paths(
    readonly_roots: Sequence[Path], writable_root: Path,
) -> list[tuple[Path, bool]]:
    return [
        *((Path(path), True) for path in readonly_roots),
        (Path(writable_root), False),
    ]


def _append_container_mounts(
    argv: list[str], readonly_roots: Sequence[Path], writable_root: Path,
) -> None:
    mounted = set()
    for root, readonly in _owned_paths(readonly_roots, writable_root):
        resolved = root.resolve()
        if resolved in mounted:
            continue
        mounted.add(resolved)
        argv.extend(("--mount", _mount_arg(resolved, readonly=readonly)))


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
    _append_host_aliases(argv, host_aliases)
    _append_container_mounts(argv, readonly_roots, writable_root)
    argv.extend(isolation.extra_args)
    argv.extend((isolation.image, isolation.python, *pytest_argv[1:]))
    return LaunchSpec(tuple(argv), cwd, dict(host_env), ((runtime, "rm", "-f", name),))


def _runc_config(bundle: Path) -> dict:
    try:
        config = json.loads((bundle / "config.json").read_text())
    except (OSError, ValueError, TypeError) as exc:
        raise SpecError(
            "isolation.bundle", str(bundle), "cannot read OCI config.json: %s" % exc
        ) from exc
    root = dict(config.get("root", {}))
    root_path = _runc_root_path(bundle, root)
    root.update({"path": str(root_path), "readonly": True})
    config["root"] = root
    return config


def _runc_root_path(bundle: Path, root: Mapping[str, object]) -> Path:
    root_path = Path(str(root.get("path", "rootfs")))
    if not root_path.is_absolute():
        root_path = (bundle / root_path).resolve()
    if not root_path.is_dir():
        raise SpecError("isolation.bundle rootfs", str(root_path), "is not a directory")
    return root_path


def _namespace_rows(config: Mapping[str, object]) -> list[object]:
    linux = config.get("linux", {})
    if not isinstance(linux, Mapping):
        return []
    namespaces = linux.get("namespaces", [])
    return namespaces if isinstance(namespaces, list) else []


def _selected_namespaces(config: Mapping[str, object]) -> set[str]:
    return {
        str(item.get("type", ""))
        for item in _namespace_rows(config)
        if isinstance(item, Mapping)
    }


def _validate_runc_namespaces(config: Mapping[str, object]) -> None:
    required = {"mount", "pid", "uts", "ipc", "network"}
    missing = sorted(required - _selected_namespaces(config))
    if missing:
        raise SpecError(
            "isolation.bundle namespaces", missing,
            "OCI helper bundles must isolate mount, pid, uts, ipc, and network namespaces",
        )


def _original_process_env(process_spec: Mapping[str, object]) -> dict[str, str]:
    original = process_spec.get("env", [])
    rows = original if isinstance(original, list) else []
    environment = {}
    for raw in rows:
        if isinstance(raw, str) and "=" in raw:
            key, value = raw.split("=", 1)
            environment[key] = value
    return environment


def _empty_capabilities() -> dict[str, list[str]]:
    return {
        "bounding": [], "effective": [], "inheritable": [],
        "permitted": [], "ambient": [],
    }


def _runc_process_spec(
    config: Mapping[str, object], isolation: Isolation,
    pytest_argv: Sequence[str], child_env: Mapping[str, str], cwd: Path,
) -> dict:
    process_spec = dict(config.get("process", {}))
    environment = _original_process_env(process_spec)
    environment.update(_inner_env(child_env))
    process_spec.update({
        "terminal": False,
        "args": [isolation.python, *pytest_argv[1:]],
        "cwd": str(cwd),
        "env": ["%s=%s" % item for item in sorted(environment.items())],
        "noNewPrivileges": True,
        "capabilities": _empty_capabilities(),
    })
    return process_spec


def _retained_mounts(
    config: Mapping[str, object], destinations: set[str],
) -> list[object]:
    def retained(item: object) -> bool:
        if not isinstance(item, Mapping):
            return True
        return str(item.get("destination", "")) not in destinations

    return [item for item in list(config.get("mounts", [])) if retained(item)]


def _runc_mount(path: Path, readonly: bool) -> dict[str, object]:
    destination = str(path.resolve())
    access = "ro" if readonly else "rw"
    return {
        "destination": destination,
        "type": "none",
        "source": destination,
        "options": ["rbind", "nosuid", "nodev", access],
    }


def _runc_mounts(
    config: Mapping[str, object], readonly_roots: Sequence[Path], writable_root: Path,
) -> list[object]:
    owned = _owned_paths(readonly_roots, writable_root)
    destinations = {str(path.resolve()) for path, _ in owned}
    mounts = _retained_mounts(config, destinations)
    mounts.extend(_runc_mount(path, readonly) for path, readonly in owned)
    return mounts


def _runc_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    host_env: Mapping[str, str], cwd: Path, readonly_roots: Sequence[Path],
    writable_root: Path, control_dir: Path, *, validate: bool,
) -> LaunchSpec:
    runtime = _require_executable("runc") if validate else "runc"
    assert isolation.bundle is not None
    bundle = isolation.bundle.resolve()
    config = _runc_config(bundle)
    _validate_runc_namespaces(config)
    config["process"] = _runc_process_spec(config, isolation, pytest_argv, child_env, cwd)
    config["mounts"] = _runc_mounts(config, readonly_roots, writable_root)
    derived = control_dir / "oci-bundle"
    derived.mkdir(parents=True, exist_ok=False)
    _write_runc_config(derived, config)
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


def _write_runc_config(derived: Path, config: Mapping[str, object]) -> None:
    path = derived / "config.json"
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _nsenter_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    cwd: Path, *, validate: bool,
) -> LaunchSpec:
    executable = _require_executable("nsenter") if validate else "nsenter"
    argv = [executable, "--target", str(isolation.target_pid)]
    argv.extend(_NAMESPACES[name] for name in isolation.namespaces)
    argv.extend(("--", *pytest_argv))
    return LaunchSpec(tuple(argv), cwd, dict(child_env))


def _repeated_option(argv: Sequence[str], option: str) -> list[str]:
    values = []
    for index, value in enumerate(argv[:-1]):
        if value == option:
            values.append(argv[index + 1])
    return values


def _helper_nodeid(pytest_argv: Sequence[str]) -> str:
    try:
        marker = pytest_argv.index("pytest")
        nodeid = pytest_argv[marker + 1]
    except (ValueError, IndexError) as exc:
        raise SpecError(
            "Kubernetes helper command", pytest_argv,
            "must use python -m pytest NODEID",
        ) from exc
    return nodeid


def _remote_environment(child_env: Mapping[str, str]) -> dict[str, str]:
    environment = dict(_inner_env(child_env))
    environment.update({
        "BRIXTEST_HELPER_RESULT": REMOTE_RESULT,
        "BRIXTEST_CASE_RUN": REMOTE_RUN,
        "BRIXTEST_METRICS_SESSION": REMOTE_SESSION,
        "BRIXTEST_RUNS": "/brixtest/runs",
        "BRIXTEST_HELPER_HEARTBEAT": "/brixtest/control/heartbeat.json",
        "BRIXTEST_HELPER_CANCEL": "/brixtest/control/cancel.json",
        "BRIXTEST_KUBERNETES_CONTEXT": "",
        "BRIXTEST_KUBECTL": "/opt/brixtest/bin/kubectl",
        CHANNEL_ENV: STDIO_CHANNEL,
        "PYTHONPATH": "/workspace:/opt/brixtest/python",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": "/opt/brixtest/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    })
    if environment.get("BRIXTEST_BACKEND") == "minikube":
        environment["BRIXTEST_BACKEND"] = "kubernetes"
    return environment


def _kubectl_prefix(isolation: Isolation, *, validate: bool) -> list[str]:
    executable = _require_executable("kubectl") if validate else "kubectl"
    argv = [executable]
    if isolation.context:
        argv.extend(("--context", isolation.context))
    argv.extend(("--namespace", isolation.namespace))
    return argv


def _optional_executable(name: str) -> str:
    return shutil.which(name) or ""


def _bridge_spec(
    isolation: Isolation, *, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    cwd: Path, control_dir: Path, writable_root: Path,
    host_aliases: Sequence[HostMapping], validate: bool,
) -> tuple[Path, tuple[tuple[str, ...], ...], Mapping[str, object]]:
    nodeid = _helper_nodeid(pytest_argv)
    trusted = _repeated_option(pytest_argv, "-p") + _repeated_option(
        pytest_argv, "--brixtest-safe-import",
    )
    bundle = build_helper_bundle(cwd, nodeid, control_dir / "bundles", trusted_modules=trusted)
    job = "brixtest-%s" % control_dir.name[-24:].lower()
    secret = "%s-env" % job
    manifest = control_dir / "kubernetes-helper.json"
    environment = _remote_environment(child_env)
    write_helper_manifest(
        manifest,
        helper_resources(
            isolation, job=job, secret=secret, environment=environment,
            host_aliases=host_aliases,
        ),
    )
    kubectl = _kubectl_prefix(isolation, validate=validate)
    result = Path(child_env["BRIXTEST_HELPER_RESULT"])
    heartbeat = Path(child_env["BRIXTEST_HELPER_HEARTBEAT"])
    session = Path(child_env["BRIXTEST_METRICS_SESSION"])
    spec = {
        "schema": 1, "kubectl": kubectl, "manifest": str(manifest),
        "bundle": str(bundle.path), "bundle_identity": bundle.as_dict(),
        "job": job, "secret": secret, "python": isolation.python,
        "image": isolation.image,
        "pytest": list(pytest_argv[1:]), "heartbeat": str(heartbeat),
        "result": str(result), "journal": str(control_dir / "messages.ndjson"),
        "run": child_env["BRIXTEST_CASE_RUN"], "session": str(session),
        "remote_result": REMOTE_RESULT, "remote_run": REMOTE_RUN,
        "remote_session": REMOTE_SESSION, "remote_done": REMOTE_DONE,
        "context": isolation.context,
        "docker": _optional_executable("docker"),
        "minikube": _optional_executable("minikube"),
    }
    path = control_dir / "kubernetes-bridge.json"
    path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    cleanup = (
        (
            *kubectl, "delete", "pod", "-l", "job-name=%s" % job,
            "--ignore-not-found=true", "--grace-period=0", "--force", "--wait=false",
        ),
        (
            *kubectl, "delete", "job/%s" % job, "secret/%s" % secret,
            "--ignore-not-found=true", "--wait=false",
        ),
    )
    return path, cleanup, bundle.as_dict()


def _kubernetes_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    host_env: Mapping[str, str], cwd: Path, writable_root: Path,
    control_dir: Path, *, validate: bool,
    host_aliases: Sequence[HostMapping] = (),
) -> LaunchSpec:
    spec, cleanup, identity = _bridge_spec(
        isolation, pytest_argv=pytest_argv, child_env=child_env, cwd=cwd,
        control_dir=control_dir, writable_root=writable_root,
        host_aliases=host_aliases, validate=validate,
    )
    argv = (sys.executable, "-m", "brixtest.kubernetes_helper_bridge", str(spec))
    return LaunchSpec(argv, cwd, dict(host_env), cleanup, {"helper_bundle": identity})


def _physical_host_aliases(selected, values) -> tuple[HostMapping, ...]:
    aliases = tuple(item for item in values if item.libc and "test" in item.targets)
    if aliases and selected.kind not in ("docker", "podman", "kubernetes"):
        raise SpecError(
            "helper libc host mappings", selected.kind,
            "require Docker, Podman, or Kubernetes isolation",
        )
    return aliases


def build_launch(
    isolation: Isolation, pytest_argv: Sequence[str], child_env: Mapping[str, str],
    *, cwd: Path, readonly_roots: Sequence[Path], writable_root: Path,
    control_dir: Path, validate_executable: bool = True,
    host_aliases: Sequence[HostMapping] = (),
) -> LaunchSpec:
    """Build one shell-free helper launch and its best-effort cleanup commands."""
    selected = isolation.resolved(cwd)
    host_aliases = _physical_host_aliases(selected, host_aliases)
    if selected.kind == "process":
        return LaunchSpec(tuple(pytest_argv), cwd, dict(child_env))
    if selected.kind == "nsenter":
        return _nsenter_launch(
            selected, pytest_argv, child_env, cwd, validate=validate_executable,
        )
    if selected.kind in ("docker", "podman"):
        return _container_launch(
            selected, pytest_argv, child_env, os.environ, cwd, readonly_roots,
            writable_root, control_dir, validate=validate_executable,
            host_aliases=host_aliases,
        )
    if selected.kind == "kubernetes":
        return _kubernetes_launch(
            selected, pytest_argv, child_env, os.environ, cwd, writable_root,
            control_dir, validate=validate_executable, host_aliases=host_aliases,
        )
    return _runc_launch(
        selected, pytest_argv, child_env, os.environ, cwd, readonly_roots,
        writable_root, control_dir, validate=validate_executable,
    )

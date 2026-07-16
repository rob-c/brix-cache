"""Python lifecycle owner for registry-backed test servers."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from typing import Sequence

import pytest

from config_templates import render_config_to_path
from server_registry import (
    NginxInstanceSpec,
    build_manifest,
    endpoint_for,
    read_manifest,
    register_nginx,
    registered_specs,
    replace_spec,
    unregister,
    write_manifest,
)
from settings import NGINX_BIN, REGISTRY_STRICT_TEMPLATES


@dataclass(frozen=True)
class RegistryCommandFailure(RuntimeError):
    config_path: str
    logs_dir: str
    command: tuple[str, ...]
    returncode: int
    stdout_tail: str
    stderr_tail: str

    def __str__(self) -> str:
        return (
            f"{' '.join(self.command)} failed rc={self.returncode}\n"
            f"config: {self.config_path}\n"
            f"logs: {self.logs_dir}\n"
            f"stdout:\n{self.stdout_tail}\n"
            f"stderr:\n{self.stderr_tail}"
        )


class RegistryLauncher:
    def __init__(self, tests_dir: str | None = None):
        self.tests_dir = tests_dir or os.path.dirname(__file__)
        self._owned: list[NginxInstanceSpec] = []

    def write_controller_manifest(self, specs: Sequence[NginxInstanceSpec] | None = None) -> dict:
        return write_manifest(build_manifest(specs=specs))

    def read_worker_manifest(self) -> dict:
        return read_manifest()

    def start_registered(self, specs: Sequence[NginxInstanceSpec] | None = None) -> dict:
        selected = list(specs) if specs is not None else registered_specs()
        manifest = self.write_controller_manifest(selected)
        for spec in selected:
            if "compat" in spec.tags:
                self._start_compat_fleet()
                continue
            self.start(spec)
        return manifest

    def stop_registered(self, specs: Sequence[NginxInstanceSpec] | None = None) -> None:
        selected = list(specs) if specs is not None else registered_specs()
        selected_names = {spec.name for spec in selected}
        for spec in reversed(self._owned):
            if spec.name in selected_names:
                self.stop(spec.name)
        self._owned.clear()
        if any("compat" in spec.tags for spec in selected):
            self._run_compat_fleet("stop-all", timeout=30, check=False)

    def start(self, spec: NginxInstanceSpec) -> None:
        endpoint = self.render_nginx(spec)
        self.nginx_test(spec)
        self._nginx(["-p", endpoint.prefix, "-c", "conf/nginx.conf"], spec=spec, env=spec.env)
        self._wait_ready(endpoint.host, endpoint.port, spec.readiness)
        self._owned.append(spec)

    def render_nginx(self, spec: NginxInstanceSpec):
        endpoint = endpoint_for(spec)
        Path(endpoint.prefix, "conf").mkdir(parents=True, exist_ok=True)
        Path(endpoint.prefix, "logs").mkdir(parents=True, exist_ok=True)
        Path(endpoint.prefix, "tmp").mkdir(parents=True, exist_ok=True)
        Path(endpoint.data_root).mkdir(parents=True, exist_ok=True)
        values = {
            "PORT": endpoint.port,
            "DATA_ROOT": endpoint.data_root,
            "LOG_DIR": str(Path(endpoint.prefix, "logs")),
            "TMP_DIR": str(Path(endpoint.prefix, "tmp")),
            **endpoint.extra_ports,
            **self._endpoint_template_values(),
            **spec.template_values,
        }
        render_config_to_path(
            spec.template,
            endpoint.config,
            strict=REGISTRY_STRICT_TEMPLATES,
            **values,
        )
        return endpoint

    def nginx_test(self, spec: NginxInstanceSpec) -> subprocess.CompletedProcess:
        endpoint = endpoint_for(spec)
        return self._nginx(["-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"], spec=spec)

    def start_nginx(self, spec: NginxInstanceSpec) -> None:
        self.start(spec)

    def stop_nginx(self, name: str) -> None:
        self.stop(name)

    def stop(self, name: str) -> None:
        spec = next((item for item in registered_specs() if item.name == name), None)
        if spec is None:
            return
        endpoint = endpoint_for(spec)
        master = self._read_pid(endpoint.pidfile)
        self._nginx(
            ["-p", endpoint.prefix, "-c", "conf/nginx.conf", "-s", "quit"],
            spec=spec,
            check=False,
        )
        self._kill_pidfile(endpoint.pidfile, signal.SIGTERM, process_group=True)
        # Wait for the master to actually exit: a dying master unlinks its
        # pidfile on the way out, which would race a successor started at the
        # same prefix (the next test reusing this name).
        if master is not None:
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    os.kill(master, 0)
                except OSError:
                    return
                time.sleep(0.05)
            try:
                os.kill(master, signal.SIGKILL)
            except OSError:
                pass

    def reload(self, name: str, check: bool = True) -> subprocess.CompletedProcess:
        return self._signal(name, "reload", check=check)

    def reopen(self, name: str) -> subprocess.CompletedProcess:
        return self._signal(name, "reopen")

    def restart(self, name: str) -> None:
        spec = next(item for item in registered_specs() if item.name == name)
        self.stop(name)
        self.start(spec)

    def kill_worker(self, name: str, sig: int | signal.Signals = signal.SIGTERM) -> int:
        snapshot = self.process_snapshot(name)
        workers = [pid for pid, role in snapshot if "worker" in role]
        if not workers:
            raise RuntimeError(f"{name}: no nginx worker process found")
        os.kill(workers[0], int(sig))
        return workers[0]

    def process_snapshot(self, name: str) -> list[tuple[int, str]]:
        endpoint = endpoint_for(next(item for item in registered_specs() if item.name == name))
        pidfile = Path(endpoint.pidfile)
        if not pidfile.exists():
            return []
        master = pidfile.read_text(encoding="utf-8").strip()
        if not master:
            return []
        out = subprocess.run(
            ["ps", "-o", "pid=,ppid=,command=", "-e"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        rows: list[tuple[int, str]] = []
        for line in out.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) != 3:
                continue
            pid, ppid, command = parts
            if pid == master or ppid == master:
                rows.append((int(pid), command))
        return rows

    def expect_config_failure(self, spec: NginxInstanceSpec) -> subprocess.CompletedProcess:
        endpoint = endpoint_for(spec)
        Path(endpoint.prefix, "conf").mkdir(parents=True, exist_ok=True)
        render_config_to_path(
            spec.template,
            endpoint.config,
            strict=False,
            **spec.template_values,
        )
        return self._nginx(
            ["-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
            spec=spec,
            check=False,
        )

    def run_privileged_step(self, argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        if os.geteuid() != 0:
            pytest.skip("privileged registry step requires root")
        return self.run_cmd(argv, **kwargs)

    def run_cmd(self, argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run(list(argv), capture_output=True, text=True, **kwargs)

    def final_leak_check(self) -> None:
        leaked = []
        for spec in registered_specs():
            if "compat" in spec.tags:
                continue
            endpoint = endpoint_for(spec)
            if Path(endpoint.pidfile).exists():
                leaked.append(spec.name)
        if leaked:
            raise RuntimeError("registry nginx pidfiles remained: " + ", ".join(leaked))

    def _signal(self, name: str, action: str, check: bool = True):
        spec = next(item for item in registered_specs() if item.name == name)
        endpoint = endpoint_for(spec)
        return self._nginx(
            ["-p", endpoint.prefix, "-c", "conf/nginx.conf", "-s", action],
            spec=spec,
            check=check,
        )

    def _endpoint_template_values(self) -> dict[str, str | int | None]:
        values: dict[str, str | int | None] = {}
        for spec in registered_specs():
            endpoint = endpoint_for(spec)
            key = spec.name.upper().replace("-", "_")
            values[f"{key}_HOST"] = endpoint.host
            values[f"{key}_PORT"] = endpoint.port
            values[f"{key}_URL"] = endpoint.url
        return values

    def _nginx(
        self,
        args: Sequence[str],
        spec: NginxInstanceSpec | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ):
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        result = subprocess.run(
            [NGINX_BIN, *args],
            capture_output=True,
            text=True,
            env=merged_env,
        )
        if check and result.returncode != 0:
            endpoint = endpoint_for(spec) if spec is not None else None
            config_path = endpoint.config if endpoint is not None else ""
            logs_dir = str(Path(endpoint.prefix, "logs")) if endpoint is not None else ""
            raise RegistryCommandFailure(
                config_path=config_path,
                logs_dir=logs_dir,
                command=(NGINX_BIN, *args),
                returncode=result.returncode,
                stdout_tail=result.stdout[-4000:],
                stderr_tail=result.stderr[-4000:],
            )
        return result

    def _wait_ready(self, host: str, port: int | None, readiness: str) -> None:
        if port is None or readiness == "none":
            return
        if readiness in {"root", "webdav", "s3", "metrics", "cms", "tcp"}:
            readiness = "tcp"
        if readiness != "tcp":
            raise ValueError(f"unknown registry readiness probe: {readiness}")
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"server did not become ready on {host}:{port}")

    @staticmethod
    def _read_pid(pidfile: str) -> int | None:
        try:
            return int(Path(pidfile).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def _kill_pidfile(
        self,
        pidfile: str,
        sig: signal.Signals,
        process_group: bool = False,
    ) -> None:
        try:
            pid = int(Path(pidfile).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return
        try:
            if process_group:
                try:
                    os.killpg(os.getpgid(pid), sig)
                    return
                except OSError:
                    pass
            os.kill(pid, sig)
        except OSError:
            return

    def _start_compat_fleet(self) -> None:
        for attempt in (1, 2):
            result = self._run_compat_fleet("start-all", timeout=None, check=False)
            if result.returncode == 0:
                return
            sys.stderr.write(
                f"\n[registry] compat fleet start-all failed "
                f"(attempt {attempt}/2, rc={result.returncode}).\n"
                f"--- stdout tail ---\n{(result.stdout or '')[-4000:]}\n"
                f"--- stderr tail ---\n{(result.stderr or '')[-4000:]}\n"
            )
            if attempt == 1:
                self._run_compat_fleet("stop-all", timeout=30, check=False)
                time.sleep(2)
        raise RuntimeError("compat fleet start-all failed twice")

    def _run_compat_fleet(self, action: str, timeout: int | None, check: bool):
        script = os.path.join(self.tests_dir, "manage_test_servers.sh")
        result = subprocess.run(
            [script, action],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            raise RuntimeError(result.stderr[-4000:])
        return result


class LifecycleHarness:
    """Per-test driver for throwaway registry instances.

    Lifecycle-subject tests (reload/reopen/restart/crash semantics) need their
    own short-lived nginx rather than the session fleet.  The harness registers
    uniquely-named specs so xdist workers and sequential tests never collide on
    registry prefixes, exposes the launcher's lifecycle primitives, and
    ``close()`` stops and unregisters everything it created — leaving the
    session registry exactly as it found it, even when a test body fails.
    """

    def __init__(self, launcher: RegistryLauncher | None = None):
        self.launcher = launcher or RegistryLauncher()
        self._names: list[str] = []

    def register(self, spec: NginxInstanceSpec) -> NginxInstanceSpec:
        suffix = f"-{os.getpid()}"
        unique = spec if spec.name.endswith(suffix) else replace(spec, name=spec.name + suffix)
        register_nginx(unique)
        self._names.append(unique.name)
        # Throwaway prefixes accumulate under REGISTRY_ROOT across runs; a
        # stale error.log from a dead prior instance must not satisfy this
        # test's log assertions.  Only wipe when nothing is running there.
        endpoint = endpoint_for(unique)
        if Path(endpoint.prefix).exists() and not Path(endpoint.pidfile).exists():
            shutil.rmtree(endpoint.prefix, ignore_errors=True)
        return unique

    def start(self, spec: NginxInstanceSpec):
        registered = self.register(spec)
        self.launcher.start(registered)
        return endpoint_for(registered)

    def endpoint(self, name: str):
        return endpoint_for(self._spec(name))

    def spec(self, name: str) -> NginxInstanceSpec:
        return self._spec(name)

    def start_registered(self, name: str):
        """Start an instance previously prepared via register()/reconfigure()."""
        spec = self._spec(name)
        self.launcher.start(spec)
        return endpoint_for(spec)

    def nginx_test(self, name: str) -> subprocess.CompletedProcess:
        return self.launcher.nginx_test(self._spec(name))

    def reconfigure(self, name: str, template: str | None = None, **template_values):
        """Re-render the instance's config with updated values (or a new template).

        The endpoint (ports, prefix) stays stable; callers follow up with
        ``reload()`` or ``restart()`` to make the new config live.
        """
        spec = self._spec(name)
        changes: dict = {"template_values": {**spec.template_values, **template_values}}
        if template is not None:
            changes["template"] = template
        updated = replace_spec(replace(spec, **changes))
        return self.launcher.render_nginx(updated)

    def reload(self, name: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.launcher.reload(self._spec(name).name, check=check)

    def reopen(self, name: str) -> None:
        self.launcher.reopen(self._spec(name).name)

    def restart(self, name: str) -> None:
        self.launcher.restart(self._spec(name).name)

    def stop(self, name: str) -> None:
        self.launcher.stop(self._spec(name).name)

    def kill_worker(self, name: str, sig: int | signal.Signals = signal.SIGTERM) -> int:
        return self.launcher.kill_worker(self._spec(name).name, sig)

    def process_snapshot(self, name: str):
        return self.launcher.process_snapshot(self._spec(name).name)

    def expect_config_failure(self, spec: NginxInstanceSpec) -> subprocess.CompletedProcess:
        registered = self.register(spec)
        return self.launcher.expect_config_failure(registered)

    def run_cmd(self, argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return self.launcher.run_cmd(argv, **kwargs)

    def run_privileged_step(self, argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return self.launcher.run_privileged_step(argv, **kwargs)

    def close(self) -> None:
        for name in reversed(self._names):
            try:
                self.launcher.stop(name)
            except Exception:
                pass
            unregister(name)
        self._names.clear()

    def _spec(self, name: str) -> NginxInstanceSpec:
        suffix = f"-{os.getpid()}"
        candidates = {name, name + suffix}
        for spec in registered_specs():
            if spec.name in candidates:
                return spec
        raise KeyError(f"lifecycle harness does not own a server named {name}")

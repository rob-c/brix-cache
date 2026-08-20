"""Per-instance control: render, nginx -t, stop, reload, snapshots.

Moved verbatim out of ``tests/_server_launcher_part2_mixinb.py`` by TS-4 item 4.  Bodies are
unchanged; the import block is the one part that is not a copy — each of
the four launcher modules carried the *same* 45-line header regardless of
what it used, so the block here is exactly this module's measured free
names (AST, not eyeball).
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence
import os
import shutil
import signal
import subprocess
import time

import pytest

from brix_suite.nginx_tools import _inject_nginx_load_modules, _inject_nginx_runtime_paths
from brix_suite.kinds import LAUNCHER_KINDS
from brix_suite.registry import (
    NginxInstanceSpec,
    declared_ports,
    endpoint_for,
    registered_specs,
)
from brix_suite.settings import REGISTRY_STRICT_TEMPLATES
from config_templates import render_config_to_path

class _LauncherControl:
    def _start_external(self, spec: NginxInstanceSpec) -> None:
        """Run a self-daemonizing orchestrator's ``start`` subcommand to completion.

        Meshes (``cms_mesh_servers.py``, ``hybrid_mesh_servers.py``) and the KDC
        (``kdc_helpers.py``) spawn their own daemon topology on ``start`` and
        return once converged, so completion IS readiness — there is no single
        port to probe.  Teardown runs the paired ``stop_argv``.  Every non-zero
        result is fatal to collection-time startup: tests may run only after the
        complete registered fleet has launched.
        """
        argv = list(spec.template_values.get("start_argv", ()))
        if not argv:
            raise ValueError(f"{spec.name}: external spec needs template_values['start_argv']")
        stop_argv = list(spec.template_values.get("stop_argv", ()))
        merged_env = {**os.environ, **spec.env}
        proc = subprocess.run(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=merged_env
        )
        if proc.returncode != 0:
            err = (proc.stderr or b"").decode("utf-8", "replace").strip()[:200]
            raise RuntimeError(
                f"external '{spec.name}' start rc={proc.returncode}: {err}"
            )
        if stop_argv:
            self._external_stops[spec.name] = (stop_argv, merged_env)
        self._owned.append(spec)

    def render_nginx_like(self, spec: NginxInstanceSpec, default_template: str):
        """Render a non-nginx config (haproxy) through the same value pipeline."""
        endpoint = endpoint_for(spec)
        Path(endpoint.prefix, "conf").mkdir(parents=True, exist_ok=True)
        Path(endpoint.prefix, "logs").mkdir(parents=True, exist_ok=True)
        values = {
            **self._session_values(spec),
            "PORT": endpoint.port,
            "DATA_ROOT": endpoint.data_root,
            "DATA_DIR": endpoint.data_root,
            "LOG_DIR": str(Path(endpoint.prefix, "logs")),
            "TMP_DIR": str(Path(endpoint.prefix, "tmp")),
            **endpoint.extra_ports,
            **self._endpoint_template_values(),
            **spec.template_values,
        }
        render_config_to_path(
            spec.template or default_template,
            endpoint.config,
            strict=REGISTRY_STRICT_TEMPLATES,
            **values,
        )
        return endpoint

    @staticmethod
    def _find_xrd_library(*names: str) -> Path | None:
        """Use the shared RPM/Debian-multiarch/ldconfig library resolver."""
        from lib_py.util import find_xrd_library  # noqa: PLC0415

        return find_xrd_library(*names)

    @staticmethod
    def _public_cadir(src: str, dst: str) -> None:
        """Public-only CA view for XrdHttp's http.cadir (no private key / *.srl)."""
        src_dir = Path(src) / "ca" if src else None
        dest = Path(dst)
        dest.mkdir(parents=True, exist_ok=True)
        # A prior start locked dest to 0o555 and every copy to 0o444, so a plain
        # re-copy here silently fails (copyfile can't open a 0o444 target) and the
        # stale CA survives a PKI regen — the exact cause of XrdHttp "unable to get
        # local issuer certificate" after a restart.  Reopen dest for writing and
        # drop the old entries before repopulating from the fresh CA.
        try:
            os.chmod(dest, 0o755)
        except OSError:
            pass
        for stale in dest.iterdir():
            try:
                os.chmod(stale, 0o644)
                stale.unlink()
            except OSError:
                pass
        if not src_dir or not src_dir.is_dir():
            return
        for entry in src_dir.iterdir():
            if entry.suffix in (".key", ".srl"):
                continue
            try:
                # follow symlinks so <hash>.0 -> ca.pem lands as a real file
                shutil.copyfile(entry.resolve(), dest / entry.name)
                os.chmod(dest / entry.name, 0o444)
            except OSError:
                pass
        try:
            os.chmod(dest, 0o555)
        except OSError:
            pass

    def render_nginx(self, spec: NginxInstanceSpec):
        endpoint = endpoint_for(spec)
        Path(endpoint.prefix, "conf").mkdir(parents=True, exist_ok=True)
        Path(endpoint.prefix, "logs").mkdir(parents=True, exist_ok=True)
        Path(endpoint.prefix, "tmp").mkdir(parents=True, exist_ok=True)
        Path(endpoint.data_root).mkdir(parents=True, exist_ok=True)
        values = {
            **self._session_values(spec),
            "PORT": endpoint.port,
            # Both aliases resolve to this instance's export: {DATA_ROOT} always,
            # and {DATA_DIR} per-instance too (bash set DATA_DIR=$data_root inside
            # start_dedicated_nginx's subshell — the main nginx just happens to
            # pin data_root to the shared $TEST_ROOT/data).
            "DATA_ROOT": endpoint.data_root,
            "DATA_DIR": endpoint.data_root,
            "LOG_DIR": str(Path(endpoint.prefix, "logs")),
            "TMP_DIR": str(Path(endpoint.prefix, "tmp")),
            **endpoint.extra_ports,
            **self._endpoint_template_values(),
        }
        # Dedicated roles get the per-instance data tree + export-rooted values
        # that start_dedicated_nginx's subshell derived (cache, WebDAV-TPC roots,
        # seed file). spec.template_values still wins over all of it.
        if "dedicated" in spec.tags:
            values.update(self._dedicated_data_tree(endpoint.data_root))
        values.update(spec.template_values)
        render_config_to_path(
            spec.template,
            endpoint.config,
            strict=REGISTRY_STRICT_TEMPLATES,
            **values,
        )
        _inject_nginx_load_modules(endpoint.config)
        _inject_nginx_runtime_paths(endpoint.config, endpoint.prefix)
        return endpoint

    @staticmethod
    def _dedicated_data_tree(data_root: str) -> dict[str, str]:
        """Create a dedicated instance's export subtree + seed, return its values.

        Faithful port of the ``mkdir -p`` tree, ``test.txt`` seed, and
        export-rooted vars in bash ``start_dedicated_nginx``. Every root is
        rehomed under this instance's ``data-<name>`` export.
        """
        root = Path(data_root)
        subdirs = {
            "SOURCE_REQUIRED_ROOT": "source_required",
            "SOURCE_OPEN_ROOT": "source_open",
            "DEST_CAFILE_ROOT": "dest_cafile",
            "DEST_CADIR_ROOT": "dest_cadir",
            "DEST_NO_SERVICE_CERT_ROOT": "dest_no_service_cert",
            "DEST_DISABLED_ROOT": "dest_disabled",
            "DEST_READONLY_ROOT": "dest_readonly",
            "CACHE_DIR": "cache",
        }
        root.mkdir(parents=True, exist_ok=True)
        (root / "origin").mkdir(parents=True, exist_ok=True)
        values: dict[str, str] = {"DATA_DIR": str(root)}
        for key, sub in subdirs.items():
            (root / sub).mkdir(parents=True, exist_ok=True)
            values[key] = str(root / sub)
        seed = root / "test.txt"
        if not seed.exists():
            seed.write_text("hello from nginx-xrootd\n", encoding="utf-8")
        return values

    def nginx_test(self, spec: NginxInstanceSpec, check: bool = True) -> subprocess.CompletedProcess:
        endpoint = endpoint_for(spec)
        return self._nginx(
            ["-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
            spec=spec,
            check=check,
        )

    def start_nginx(self, spec: NginxInstanceSpec) -> None:
        self.start(spec)

    def stop_nginx(self, name: str) -> None:
        self.stop(name)

    def stop(self, name: str) -> None:
        if name in self._external_stops:
            stop_argv, env = self._external_stops.pop(name)
            subprocess.run(
                stop_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env
            )
            self._owned = [item for item in self._owned if item.name != name]
            return
        if name in self._xrootd_procs:
            self._kill_xrootd(name)
            self._owned = [item for item in self._owned if item.name != name]
            return
        spec = next((item for item in registered_specs() if item.name == name), None)
        if spec is None:
            return
        endpoint = endpoint_for(spec)
        # Cross-process teardown (a fresh `stop-all` did not start these, so the
        # in-memory handles above are empty): daemon kinds other than nginx have
        # no nginx pidfile — reap them from their own on-disk state / stop CLI.
        row = LAUNCHER_KINDS.get(spec.kind)
        if row is not None and row.stop_from_disk:
            self._stop_from_disk(spec, endpoint)
            self._owned = [item for item in self._owned if item.name != name]
            return
        master = self._read_pid(endpoint.pidfile)
        # The binary used to launch the fleet may have been rebuilt, moved, or
        # explicitly supplied only to the previous runner process.  A pidfile is
        # sufficient for teardown; the friendly `nginx -s quit` path is optional.
        if master is not None:
            try:
                self._nginx(
                    ["-p", endpoint.prefix, "-c", "conf/nginx.conf", "-s", "quit"],
                    spec=spec,
                    check=False,
                )
            except OSError:
                pass
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
                    break
                time.sleep(0.05)
            else:
                # Deadline hit with the master still alive — force it down.
                try:
                    os.kill(master, signal.SIGKILL)
                except OSError:
                    pass
        self._reap_orphan_nginx_workers(spec)
        # Master exit unlinks the pidfile, but the kernel may not have released
        # the LISTEN socket yet — a worker still draining, or the master's own
        # close lagging the process death. Under the fixed-port ledger the very
        # next test rebinds this exact port, so a stop that returns before the
        # socket is free hands the successor an intermittent EADDRINUSE (the
        # stop/start reuse race the dynamic-port model used to mask). Wait until
        # the port is actually bindable before returning.
        self._wait_ports_released(spec)

    @staticmethod
    def _reap_orphan_nginx_workers(spec: NginxInstanceSpec) -> None:
        """Kill worker-only survivors still holding this spec's ledger ports.

        An interrupted master can unlink its pidfile and exit while workers are
        stuck in shutdown. Their process title no longer contains TEST_ROOT, so
        cmdline-scoped reapers cannot identify them; the registered fixed ports
        plus the exact nginx worker title provide the remaining ownership proof.
        """
        from lib_py.util import kill_pid_list, pids_on_port  # noqa: PLC0415

        candidates: set[int] = set()
        for port in declared_ports(spec):
            candidates.update(pids_on_port(port))
        workers = []
        for pid in candidates:
            try:
                import server_launcher as _launcher
                path_cls = getattr(_launcher, "Path", Path)
                title = path_cls(f"/proc/{pid}/cmdline").read_bytes().replace(
                    b"\0", b" ")
            except OSError:
                continue
            if title.strip().startswith(b"nginx: worker process"):
                workers.append(pid)
        if workers:
            kill_pid_list(workers)

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
        _inject_nginx_load_modules(endpoint.config)
        _inject_nginx_runtime_paths(endpoint.config, endpoint.prefix)
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
            if spec.kind != "nginx":
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

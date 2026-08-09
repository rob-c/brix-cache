"""Python lifecycle owner for registry-backed test servers."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from typing import Sequence

import pytest

from config_templates import render_config_to_path
from fleet_lifecycle_ports import lifecycle_ports_for
from fleet_values import session_template_values
from server_registry import (
    NginxInstanceSpec,
    build_manifest,
    declared_ports,
    endpoint_for,
    read_manifest,
    register_nginx,
    registered_specs,
    replace_spec,
    unregister,
    write_manifest,
)
from settings import BRIX_BIN, NGINX_BIN, PKI_DIR, REGISTRY_STRICT_TEMPLATES


def _nginx_bin() -> str:
    """Frozen copy of the nginx binary path, immune to concurrent relinks."""
    from cmdscripts.live_common import freeze_nginx  # noqa: PLC0415
    return str(freeze_nginx(NGINX_BIN))


def _inject_nginx_load_modules(config_path: str) -> None:
    """Prepend the runner-selected dynamic modules to a rendered nginx config."""
    from cmdscripts.live_common import inject_nginx_load_modules  # noqa: PLC0415
    inject_nginx_load_modules(config_path)


def _inject_nginx_runtime_paths(config_path: str, prefix: str) -> None:
    """Keep packaged-nginx runtime files inside its registry-owned prefix."""
    from cmdscripts.live_common import inject_nginx_runtime_paths  # noqa: PLC0415
    inject_nginx_runtime_paths(config_path, prefix)


@dataclass
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


class _RegistryLauncherMixinA:
    def __init__(self, tests_dir: str | None = None):
        self.tests_dir = tests_dir or os.path.dirname(__file__)
        self._owned: list[NginxInstanceSpec] = []
        self._xrootd_procs: dict[str, subprocess.Popen] = {}
        # External orchestrators (meshes, KDC): name -> (stop_argv, env). These
        # self-daemonize on `start` and are torn down by their own `stop`
        # subcommand, not by killing a tracked child.
        self._external_stops: dict[str, tuple[list[str], dict]] = {}

    def write_controller_manifest(self, specs: Sequence[NginxInstanceSpec] | None = None) -> dict:
        return write_manifest(build_manifest(specs=specs))

    def read_worker_manifest(self) -> dict:
        return read_manifest()

    def start_registered(self, specs: Sequence[NginxInstanceSpec] | None = None) -> dict:
        selected = list(specs) if specs is not None else registered_specs()
        manifest = self.write_controller_manifest(selected)
        workers = self._start_workers()
        if workers <= 1:
            for spec in selected:
                self._start_guarded(spec)
            return manifest
        # Bring-up is dominated by per-instance subprocess spawns (nginx -t,
        # nginx/xrootd fork) and TCP readiness polls — all GIL-releasing I/O, so
        # threads overlap it cleanly. Fan out one dependency LEVEL at a time with
        # a barrier between levels: every spec's `requires` are fully ready before
        # it launches. The DAG is shallow (backends → dependents), so the barrier
        # cost is a few levels, not a serialization of the whole fleet.
        for level in self._dependency_levels(selected):
            self._start_level(level, workers)
        return manifest

    def _start_guarded(self, spec: NginxInstanceSpec) -> None:
        if "critical" in spec.tags:
            # Main nginx / main reference xrootd: a failure here is fatal — the
            # suite cannot run without them, so let it propagate.
            self.start(spec)
            return
        # Non-critical fleet members mirror bash `start_x || true`: an
        # optional-daemon skip (missing libs/tooling) or a transient start
        # failure must not abort the whole start-all. Log and press on.
        try:
            self.start(spec)
        except (Exception, pytest.skip.Exception) as exc:  # noqa: BLE001
            sys.stderr.write(
                f"\n[registry] non-critical spec '{spec.name}' did not start "
                f"({type(exc).__name__}: {exc}); continuing.\n"
            )

    def _start_level(self, level: Sequence[NginxInstanceSpec], workers: int) -> None:
        # Each worker only ever `list.append`s to self._owned / assigns a distinct
        # key into self._xrootd_procs/_external_stops — both GIL-atomic in CPython,
        # so no extra lock is needed. Critical failures still propagate: a raised
        # future re-raises here, aborting the whole start (critical specs live at
        # level 0, so nothing dependent has launched yet).
        with ThreadPoolExecutor(max_workers=min(workers, len(level))) as pool:
            futures = {pool.submit(self.start, spec): spec for spec in level}
            for future in as_completed(futures):
                spec = futures[future]
                try:
                    future.result()
                except (Exception, pytest.skip.Exception) as exc:  # noqa: BLE001
                    if "critical" in spec.tags:
                        raise
                    sys.stderr.write(
                        f"\n[registry] non-critical spec '{spec.name}' did not start "
                        f"({type(exc).__name__}: {exc}); continuing.\n"
                    )

    @staticmethod
    def _start_workers() -> int:
        # Tunable via env; default oversubscribes cores since most of each start
        # is spent waiting on subprocesses and readiness polls, not on CPU. 1
        # forces the legacy sequential path (useful for deterministic debugging).
        raw = os.environ.get("BRIX_FLEET_START_WORKERS")
        if raw:
            try:
                return max(1, int(raw))
            except ValueError:
                pass
        return min(16, ((os.cpu_count() or 4) * 2))

    @staticmethod
    def _dependency_levels(
        selected: Sequence[NginxInstanceSpec],
    ) -> list[list[NginxInstanceSpec]]:
        # Partition specs into dependency levels: level N holds specs whose deepest
        # `requires` chain (restricted to specs present in this selection) is N.
        # Required names absent from the selection (e.g. subset boot) are treated
        # as already-satisfied and don't add depth. Original selection order is
        # preserved within each level for deterministic launch ordering.
        by_name = {spec.name: spec for spec in selected}
        depth_memo: dict[str, int] = {}

        def depth(name: str, seen: frozenset[str] = frozenset()) -> int:
            if name in depth_memo:
                return depth_memo[name]
            spec = by_name.get(name)
            reqs = [
                r
                for r in (getattr(spec, "requires", ()) or ())
                if r in by_name and r not in seen
            ]
            value = 0 if not reqs else 1 + max(depth(r, seen | {name}) for r in reqs)
            depth_memo[name] = value
            return value

        levels: dict[int, list[NginxInstanceSpec]] = {}
        for spec in selected:
            levels.setdefault(depth(spec.name), []).append(spec)
        return [levels[key] for key in sorted(levels)]

    def stop_registered(self, specs: Sequence[NginxInstanceSpec] | None = None) -> None:
        selected = list(specs) if specs is not None else registered_specs()
        # Iterate the SELECTED specs (reverse dependency order), not self._owned:
        # a separate `stop-all` process never started anything, so _owned is empty
        # and iterating it would reap nothing. stop() is stateless — it reaps each
        # instance from its on-disk pidfile / stop CLI whether or not this launcher
        # started it. _owned still short-circuits same-process teardown inside stop().
        failures: list[str] = []
        for spec in reversed(selected):
            try:
                self.stop(spec.name)
            except Exception as exc:  # noqa: BLE001 — teardown must visit every spec
                failures.append(f"{spec.name}: {exc}")
        self._owned.clear()
        if failures:
            raise RuntimeError("fleet teardown failures: " + "; ".join(failures))

    def start(self, spec: NginxInstanceSpec) -> None:
        if spec.kind == "xrootd":
            self._start_xrootd(spec)
            return
        if spec.kind == "xrdhttp":
            self._start_xrdhttp(spec)
            return
        if spec.kind == "haproxy":
            self._start_haproxy(spec)
            return
        if spec.kind == "proc":
            self._start_proc(spec)
            return
        if spec.kind == "external":
            self._start_external(spec)
            return
        endpoint = self.render_nginx(spec)
        # Root-harness export shim (bash _open_export_for_worker): the configs
        # carry no `user` directive, so nginx drops workers to `nobody`; make the
        # export the worker owns writable. No-op when unprivileged.
        if os.geteuid() == 0 and os.path.isdir(endpoint.data_root):
            self._chmod_r(endpoint.data_root, 0o777, add_only=True)
        # The logs dir is created 0755-root by the launcher and nginx's master
        # opens error.log there, but the `nobody` worker lazily creates NEW files
        # in it — the unified transfer ledger's xfer_audit.log — and gets EACCES on
        # a root-owned dir, silently disabling auditing. Open the dir for the
        # worker so the ledger sink can be created. No-op when unprivileged.
        if os.geteuid() == 0:
            logs_dir = os.path.join(endpoint.prefix, "logs")
            if os.path.isdir(logs_dir):
                self._chmod_add(logs_dir, 0o777)
        self.nginx_test(spec)
        self._nginx(["-p", endpoint.prefix, "-c", "conf/nginx.conf"], spec=spec, env=spec.env)
        self._wait_ready(endpoint.host, endpoint.port, spec.readiness)
        self._owned.append(spec)

    def _start_xrootd(self, spec: NginxInstanceSpec) -> None:
        """Spawn a STOCK XRootD data server as a registry-managed instance.

        The registry otherwise models only our nginx; the differential-conformance
        fleet also needs the reference xrootd on the same tree. It renders the
        spec's cfg template exactly like the nginx path (same PORT/DATA_ROOT/…
        substitutions, plus an ADMIN_DIR for xrootd's admin/pid unix sockets),
        launches ``xrootd -c cfg -l log`` in its own session (so the whole process
        group is reaped on stop), and tracks the handle for lifecycle teardown.
        """
        xrootd = shutil.which(BRIX_BIN)
        if not xrootd:
            pytest.skip(f"selected xrootd binary is unavailable: {BRIX_BIN}")
        endpoint = endpoint_for(spec)
        prefix = Path(endpoint.prefix)
        (prefix / "conf").mkdir(parents=True, exist_ok=True)
        (prefix / "logs").mkdir(parents=True, exist_ok=True)
        admin = prefix / "admin"
        run_dir = prefix / "run"
        admin.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir(parents=True, exist_ok=True)
        Path(endpoint.data_root).mkdir(parents=True, exist_ok=True)
        log_path = prefix / "logs" / "xrootd.log"
        values = {
            **self._session_values(spec),
            "PORT": endpoint.port,
            # xrootd templates address the export as {DATA_DIR}; alias it to the
            # per-instance endpoint root so a spec's data_root wins over the
            # session default (bash passed DATA_DIR=$data_dir per instance).
            "DATA_ROOT": endpoint.data_root,
            "DATA_DIR": endpoint.data_root,
            "LOG_DIR": str(prefix / "logs"),
            "TMP_DIR": str(prefix / "tmp"),
            "ADMIN_DIR": str(admin),
            "RUN_DIR": str(run_dir),
            **endpoint.extra_ports,
            **self._endpoint_template_values(),
            **spec.template_values,
        }
        # GSI xrootd templates need the XrdSec lib path; supply it generically so
        # a spec need not hard-code the platform libdir. A spec value still wins.
        sec_lib = self._find_xrd_library("libXrdSec-5.so", "libXrdSec.so")
        if sec_lib and "SECLIB" not in values:
            values["SECLIB"] = str(sec_lib)
        cfg = prefix / "conf" / "xrootd.cfg"
        render_config_to_path(spec.template, str(cfg), strict=REGISTRY_STRICT_TEMPLATES, **values)
        merged_env = os.environ.copy()
        if spec.env:
            merged_env.update(spec.env)
        argv = [xrootd, "-c", str(cfg), "-l", str(log_path)]
        # Root-harness privilege drop: xrootd refuses to run as superuser, so
        # open the paths the -R user must touch and hand it off with -R. Ports
        # <11024 are irrelevant here (test range is 11xxx). Non-root: no-op.
        runas = self._xrootd_runas_user(cfg.read_text(encoding="utf-8"), str(log_path))
        if runas:
            argv += ["-R", runas]
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=merged_env,
        )
        self._xrootd_procs[spec.name] = proc
        try:
            self._wait_ready(endpoint.host, endpoint.port, spec.readiness)
        except Exception:
            self._kill_xrootd(spec.name)
            raise
        self._owned.append(spec)

    def _start_xrdhttp(self, spec: NginxInstanceSpec) -> None:
        """Spawn a stock XRootD server with the XrdHttp gateway loaded.

        Modelled on bash ``start_xrdhttp``: probe for the XrdHttp/XrdHttpTPC libs
        (skip cleanly if absent — an optional daemon must not fail the fleet),
        give ``http.cadir`` a PUBLIC-only view of the CA (never the private key,
        which XrdHttpTPC's TempCA would try to open and fail on), render, launch
        through the same root-mode xrootd machinery, and probe readiness with an
        HTTPS curl (fallback TCP).
        """
        xrootd = shutil.which(BRIX_BIN)
        if not xrootd:
            pytest.skip(f"selected xrootd binary is unavailable: {BRIX_BIN}")
        http_lib = self._find_xrd_library("libXrdHttp-5.so", "libXrdHttp.so")
        tpc_lib = self._find_xrd_library("libXrdHttpTPC-5.so", "libXrdHttpTPC.so")
        sec_lib = self._find_xrd_library("libXrdSec-5.so", "libXrdSec.so")
        if not http_lib or not tpc_lib:
            pytest.skip("XrdHttp/XrdHttpTPC libraries not installed")
        endpoint = endpoint_for(spec)
        prefix = Path(endpoint.prefix)
        admin = prefix / "admin"
        run_dir = prefix / "run"
        for d in (prefix / "conf", prefix / "logs", admin, run_dir, Path(endpoint.data_root)):
            d.mkdir(parents=True, exist_ok=True)
        ca_public = prefix / "ca-public"
        # Default to the canonical test PKI root (TEST_ROOT/pki) like the rest of
        # the suite — NOT a blank fallback.  manage_test_servers start-all does not
        # export PKI_DIR, so a blank left http.cadir empty and the gateway rejected
        # every client cert ("self-signed certificate in certificate chain", rc=56).
        self._public_cadir(os.environ.get("PKI_DIR") or str(PKI_DIR), str(ca_public))
        log_path = prefix / "logs" / "xrdhttp.log"
        values = {
            **self._session_values(spec),
            "PORT": endpoint.port,
            "DATA_ROOT": endpoint.data_root,
            "DATA_DIR": endpoint.data_root,
            "LOG_DIR": str(prefix / "logs"),
            "TMP_DIR": str(prefix / "tmp"),
            "ADMIN_DIR": str(admin),
            "RUN_DIR": str(run_dir),
            "HTTP_LIB": str(http_lib),
            "TPC_LIB": str(tpc_lib),
            "SECLIB": str(sec_lib) if sec_lib else "/usr/lib64/libXrdSec-5.so",
            "CA_DIR": str(ca_public),
            **endpoint.extra_ports,
            **self._endpoint_template_values(),
            **spec.template_values,
        }
        cfg = prefix / "conf" / "xrdhttp.cfg"
        render_config_to_path(spec.template, str(cfg), strict=REGISTRY_STRICT_TEMPLATES, **values)
        merged_env = {**os.environ, **spec.env}
        argv = [xrootd, "-c", str(cfg), "-l", str(log_path)]
        runas = self._xrootd_runas_user(cfg.read_text(encoding="utf-8"), str(log_path))
        if runas:
            argv += ["-R", runas]
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=merged_env,
        )
        self._xrootd_procs[spec.name] = proc
        try:
            self._wait_ready(endpoint.host, endpoint.port, spec.readiness)
        except Exception:
            self._kill_xrootd(spec.name)
            raise
        self._owned.append(spec)

    def _start_haproxy(self, spec: NginxInstanceSpec) -> None:
        """Launch haproxy for the failover-map fleet member (skip if absent)."""
        haproxy = shutil.which("haproxy")
        if not haproxy:
            pytest.skip("haproxy not installed")
        endpoint = self.render_nginx_like(spec, "haproxy.cfg")
        prefix = Path(endpoint.prefix)
        pidfile = prefix / "logs" / "haproxy.pid"
        proc = subprocess.Popen(
            [haproxy, "-f", endpoint.config, "-p", str(pidfile)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={**os.environ, **spec.env},
        )
        self._xrootd_procs[spec.name] = proc
        try:
            self._wait_ready(endpoint.host, endpoint.port, spec.readiness)
        except Exception:
            self._kill_xrootd(spec.name)
            raise
        self._owned.append(spec)

    def _start_proc(self, spec: NginxInstanceSpec) -> None:
        """Launch a Python background helper (protocol/CMS stubs, mesh CLIs).

        ``spec.template_values['argv']`` is the argv list; ``kind='external'``
        helpers take a ``start`` subcommand and self-daemonize, ``kind='proc'``
        stubs are tracked Popen children. Gating (missing tooling) is the
        helper's own concern; a non-zero exit propagates as a start failure.
        """
        argv = list(spec.template_values.get("argv", ()))
        if not argv:
            raise ValueError(f"{spec.name}: proc/external spec needs template_values['argv']")
        merged_env = {**os.environ, **spec.env}
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=merged_env,
        )
        self._xrootd_procs[spec.name] = proc
        try:
            self._wait_ready(endpoint_for(spec).host, endpoint_for(spec).port, spec.readiness)
        except Exception:
            self._kill_xrootd(spec.name)
            raise
        self._owned.append(spec)

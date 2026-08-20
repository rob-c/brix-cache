# ARCHIVE — the pre-TS-4 flat body of ``tests/_server_launcher_part2_mixina.py``, kept byte-identical so
# the "verbatim move" claim in the TS-4 decision note is checkable on disk
# rather than only in git history.  Nothing imports this; the live launcher is
# ``brix_suite.launcher``.  ``test_ci_ts4_launcher_move.py`` diffs every moved
# method against this text.
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
from settings import BRIX_BIN, PKI_DIR, REGISTRY_STRICT_TEMPLATES
from server_launcher_errors import RegistryCommandFailure


from brix_suite.nginx_tools import (  # noqa: F401 — re-exported for importers
    _inject_nginx_load_modules,
    _inject_nginx_runtime_paths,
    _nginx_bin,
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
        """Start one declared server or fail the collection-time fleet barrier."""
        try:
            self.start(spec)
        except (Exception, pytest.skip.Exception) as exc:  # noqa: BLE001
            raise RuntimeError(
                f"registered server '{spec.name}' failed to launch: {exc}"
            ) from exc

    def _start_level(self, level: Sequence[NginxInstanceSpec], workers: int) -> None:
        # Each worker only ever `list.append`s to self._owned / assigns a distinct
        # key into self._xrootd_procs/_external_stops — both GIL-atomic in CPython,
        # so no extra lock is needed. Every failed future is fatal: collection
        # cannot release a test until every registered listener is available.
        with ThreadPoolExecutor(max_workers=min(workers, len(level))) as pool:
            futures = {pool.submit(self.start, spec): spec for spec in level}
            for future in as_completed(futures):
                spec = futures[future]
                try:
                    future.result()
                except (Exception, pytest.skip.Exception) as exc:  # noqa: BLE001
                    raise RuntimeError(
                        f"registered server '{spec.name}' failed to launch: {exc}"
                    ) from exc

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
        from lib_py.util import listening_port_pids  # noqa: PLC0415

        failures: list[str] = []
        listeners = listening_port_pids()
        for spec in reversed(selected):
            if self._quiescent(spec, listeners):
                continue
            try:
                self.stop(spec.name)
            except Exception as exc:  # noqa: BLE001 — teardown must visit every spec
                failures.append(f"{spec.name}: {exc}")
        self._owned.clear()
        if failures:
            raise RuntimeError("fleet teardown failures: " + "; ".join(failures))

    def _quiescent(
        self,
        spec: NginxInstanceSpec,
        listeners: dict[int, set[int]] | None,
    ) -> bool:
        """Proof from ONE fleet-wide listener snapshot that stop() would be a
        pure no-op for this spec: no in-memory handle, no on-disk pidfile, and
        nobody listening on any declared port.

        stop() on an already-down spec still walks its full teardown chain —
        per-port `ss` scans (~50-100ms of subprocess spawn each) in
        _reap_orphan_nginx_workers/_stop_from_disk — so an idle-fleet stop-all
        (every pytest session runs one at start AND finish) burned ~15s doing
        nothing. Ports listed in the snapshot, live handles, `external` specs
        (their stop CLI owns state we cannot see), and hosts without `ss`
        (snapshot is None) all keep today's exact stop() path. Workers orphaned
        by a dead master still hold their LISTEN socket, so they show in the
        snapshot and are never skipped.
        """
        if listeners is None:
            return False
        if spec.name in self._external_stops or spec.name in self._xrootd_procs:
            return False
        if spec.kind == "external":
            return False
        if any(port in listeners for port in declared_ports(spec)):
            return False
        try:
            endpoint = endpoint_for(spec)
        except ValueError:
            return False
        if spec.kind in ("xrootd", "xrdhttp"):
            pidfile = os.path.join(endpoint.prefix, "run", "xrootd.pid")
        elif spec.kind == "haproxy":
            pidfile = os.path.join(endpoint.prefix, "logs", "haproxy.pid")
        elif spec.kind == "proc":
            return True  # port-tracked only; _stop_from_disk would just re-scan the port
        else:
            pidfile = endpoint.pidfile
        return not os.path.exists(pidfile)

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
        try:
            self._nginx(["-p", endpoint.prefix, "-c", "conf/nginx.conf"],
                        spec=spec, env=spec.env)
        except RegistryCommandFailure:
            # xdist's controller/worker hand-off can overlap a second registry
            # launch with the first one.  If the pidfile still names a live
            # master whose argv proves this exact prefix, EADDRINUSE is the
            # duplicate launch losing the race—not a missing fleet server.
            master = self._read_pid(endpoint.pidfile)
            owned = False
            if master is not None:
                try:
                    os.kill(master, 0)
                    with open(f"/proc/{master}/cmdline", "rb") as proc_cmd:
                        cmdline = proc_cmd.read().replace(b"\0", b" ")
                    owned = endpoint.prefix.encode() in cmdline
                except (OSError, ValueError):
                    owned = False
            if not owned:
                raise
            self._wait_ready(endpoint.host, endpoint.port, spec.readiness)
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

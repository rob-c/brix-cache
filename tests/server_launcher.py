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
from fleet_values import session_template_values
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
from settings import NGINX_BIN, PKI_DIR, REGISTRY_STRICT_TEMPLATES


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


def launch_fleet_nginx(
    config_path: str,
    *,
    prefix: str | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Launch a fully-rendered nginx config as a detached, fire-and-forget daemon.

    This is the registry's raw-launch seam for a *standing fleet* backend (the
    CMS mesh, brought up once by ``cms_mesh_servers.py``; the HA-failover group,
    brought up from the ``haproxy`` spec kind) whose fixed-port,
    real-daemon (xrootd/cmsd/haproxy) co-tenancy model is incompatible with the
    per-instance prefix ownership of ``RegistryLauncher.start``.  Unlike that
    path, the caller owns the config text, the listen ports, and the pid file
    (written by the config's own ``pid`` directive), and reaps the daemon itself
    by pid file / port sweep: nginx daemonizes (``daemon on``) and survives this
    process.  ``start_new_session`` makes the master its own process-group leader
    so the fleet's ``killpg`` reaps orphaned workers too.  ``prefix`` adds the
    ``-p`` flag so a fleet member with a fixed prefix tree (relative ``pid`` /
    ``error_log`` / ``conf`` paths) relaunches into its own directory.  Keeping
    this the sole home of the ``NGINX_BIN`` invocation is what lets a fleet lib
    route its launch through the registry infra instead of shelling out to nginx
    directly.
    """
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    cmd = [NGINX_BIN]
    if prefix is not None:
        cmd += ["-p", prefix]
    cmd += ["-c", config_path]
    return subprocess.run(
        cmd,
        check=False,
        start_new_session=True,
        cwd=cwd,
        env=merged_env,
    )


class RegistryLauncher:
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
        for spec in reversed(selected):
            self.stop(spec.name)
        self._owned.clear()

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
        xrootd = shutil.which("xrootd")
        if not xrootd:
            pytest.skip("stock xrootd not installed")
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
        xrootd = shutil.which("xrootd")
        if not xrootd:
            pytest.skip("stock xrootd not installed")
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

    def _start_external(self, spec: NginxInstanceSpec) -> None:
        """Run a self-daemonizing orchestrator's ``start`` subcommand to completion.

        Meshes (``cms_mesh_servers.py``, ``hybrid_mesh_servers.py``) and the KDC
        (``kdc_helpers.py``) spawn their own daemon topology on ``start`` and
        return once converged, so completion IS readiness — there is no single
        port to probe.  Teardown runs the paired ``stop_argv``.  A return code in
        ``skip_returncodes`` (e.g. the KDC's rc 3 = tooling absent) is a clean
        skip; any other non-zero, like bash's ``|| true``, is logged and swallowed
        so an optional subsystem never aborts start-all.
        """
        argv = list(spec.template_values.get("start_argv", ()))
        if not argv:
            raise ValueError(f"{spec.name}: external spec needs template_values['start_argv']")
        stop_argv = list(spec.template_values.get("stop_argv", ()))
        skip_rcs = set(spec.template_values.get("skip_returncodes", ()))
        merged_env = {**os.environ, **spec.env}
        proc = subprocess.run(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=merged_env
        )
        if proc.returncode in skip_rcs:
            pytest.skip(f"{spec.name}: subsystem unavailable (rc={proc.returncode})")
        if proc.returncode != 0:
            err = (proc.stderr or b"").decode("utf-8", "replace").strip()[:200]
            sys.stderr.write(
                f"\n[registry] external '{spec.name}' start rc={proc.returncode}: {err}\n"
            )
            return
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
        for name in names:
            for root in (Path("/usr/lib64"), Path("/usr/lib")):
                candidate = root / name
                if candidate.exists():
                    return candidate
        return None

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
        if spec.kind in ("xrootd", "xrdhttp", "haproxy", "proc", "external"):
            self._stop_from_disk(spec, endpoint)
            self._owned = [item for item in self._owned if item.name != name]
            return
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

    def _xrootd_runas_user(self, cfg_text: str, log_path: str) -> str | None:
        """Port of bash ``_ref_launch``'s root branch: open the drop-user's paths.

        xrootd terminates with "Security reasons prohibit running as superuser",
        so under a root harness we run it via ``-R <user>`` and pre-open the
        paths that user must then touch — its adminpath/pidpath dirs (chown), the
        exported localroot (a+rwX, shared with the root-owned nginx fleet), the
        log dir + file, and the GSI PKI it reads. Returns the drop user, or
        ``None`` when unprivileged (caller omits ``-R`` and launches as-is).
        """
        if os.geteuid() != 0:
            return None
        user = os.environ.get("REF_RUNAS_USER", "nobody")

        def _directive(name: str) -> str | None:
            m = re.search(rf"^{re.escape(name)}\s+(\S+)", cfg_text, re.M)
            return m.group(1) if m else None

        for key in ("all.adminpath", "all.pidpath"):
            path = _directive(key)
            if path:
                Path(path).mkdir(parents=True, exist_ok=True)
                self._chown_r(path, user)
        localroot = _directive("oss.localroot")
        if localroot:
            self._chmod_r(localroot, 0o777, add_only=True)
        log_dir = os.path.dirname(log_path)
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        os.chmod(log_dir, 0o777)
        Path(log_path).write_text("", encoding="utf-8")
        shutil.chown(log_path, user)
        pki_dir = os.environ.get("PKI_DIR")
        if pki_dir and os.path.isdir(pki_dir):
            for sub in (pki_dir, os.path.join(pki_dir, "ca"), os.path.join(pki_dir, "server")):
                if os.path.isdir(sub):
                    self._chmod_add(sub, 0o555)
            hostcert = os.path.join(pki_dir, "server", "hostcert.pem")
            if os.path.exists(hostcert):
                self._chmod_add(hostcert, 0o444)
            import glob
            for pem in glob.glob(os.path.join(pki_dir, "ca", "*.pem")):
                self._chmod_add(pem, 0o444)
            # Private hostkey: XrdHttp refuses a group/world-readable key, so give
            # the -R user exclusive read (own + 0400); root nginx ignores mode.
            hostkey = os.path.join(pki_dir, "server", "hostkey.pem")
            if os.path.exists(hostkey):
                shutil.chown(hostkey, user)
                os.chmod(hostkey, 0o400)
        return user

    @staticmethod
    def _chown_r(path: str, user: str) -> None:
        for root, dirs, files in os.walk(path):
            for name in [root] + [os.path.join(root, f) for f in dirs + files]:
                try:
                    shutil.chown(name, user)
                except OSError:
                    pass

    @staticmethod
    def _chmod_add(path: str, bits: int) -> None:
        try:
            os.chmod(path, os.stat(path).st_mode | bits)
        except OSError:
            pass

    def _chmod_r(self, path: str, bits: int, add_only: bool = False) -> None:
        for root, dirs, files in os.walk(path):
            for name in [root] + [os.path.join(root, f) for f in dirs + files]:
                if add_only:
                    self._chmod_add(name, bits)
                else:
                    try:
                        os.chmod(name, bits)
                    except OSError:
                        pass

    def _session_values(self, spec: NginxInstanceSpec) -> dict[str, str]:
        """The PKI/token/directory placeholder dict, per-spec env applied.

        Faithfully reproduces the old bash ``substitute_config``: it read the
        per-instance subshell env, so a role that exported e.g. ``CMS_PORT`` saw
        that override.  We therefore compute the value dict against
        ``os.environ`` overlaid with ``spec.env``.  It sits at the LOWEST render
        precedence — per-instance ``PORT``/``DATA_ROOT``/``LOG_DIR``/``TMP_DIR``,
        endpoint cross-refs, and ``spec.template_values`` all win over it.
        """
        env = os.environ if not spec.env else {**os.environ, **spec.env}
        return session_template_values(env=env)

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

    def _stop_from_disk(self, spec: NginxInstanceSpec, endpoint) -> None:
        """Reap a non-nginx daemon kind with no in-memory handle (cross-process
        stop-all). Each kind is torn down from state it left on disk:

          * xrootd/xrdhttp  → RUN_DIR/xrootd.pid  (SIGTERM the group, then KILL)
          * haproxy         → logs/haproxy.pid
          * external        → its paired ``stop_argv`` (self-daemonizing meshes/KDC)
          * proc            → whatever is listening on the tracked port (Python
                              stubs self-daemonize without a pidfile)
        """
        prefix = Path(endpoint.prefix)
        if spec.kind == "external":
            stop_argv = list(spec.template_values.get("stop_argv", ()))
            if stop_argv:
                subprocess.run(
                    stop_argv,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={**os.environ, **spec.env},
                )
            return
        if spec.kind == "proc":
            from lib_py.util import pids_on_port  # noqa: PLC0415

            for pid in pids_on_port(int(endpoint.port)):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            return
        if spec.kind == "haproxy":
            self._kill_pidfile(str(prefix / "logs" / "haproxy.pid"), signal.SIGTERM,
                               process_group=True)
            return
        # xrootd / xrdhttp
        pidfile = prefix / "run" / "xrootd.pid"
        master = self._read_pid(str(pidfile))
        self._kill_pidfile(str(pidfile), signal.SIGTERM, process_group=True)
        if master is None:
            return
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                os.kill(master, 0)
            except OSError:
                return
            time.sleep(0.05)
        self._kill_pidfile(str(pidfile), signal.SIGKILL, process_group=True)

    def _kill_xrootd(self, name: str) -> None:
        proc = self._xrootd_procs.pop(name, None)
        if proc is None:
            return
        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            pgid = None
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                if pgid is not None:
                    os.killpg(pgid, sig)
                else:
                    proc.send_signal(sig)
            except (ProcessLookupError, OSError):
                break
            try:
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                continue

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

    def nginx_test(self, name: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.launcher.nginx_test(self._spec(name), check=check)

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

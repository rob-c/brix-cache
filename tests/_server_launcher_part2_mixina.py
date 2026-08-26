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

from brix_suite.nginx_tools import sanitized_env as _sanitized_env
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
from brix_suite.kinds import LAUNCHER_KINDS
from brix_suite.launcher.start_operations import (
    quiescent as _launcher_quiescent,
    start_nginx as _launcher_start_nginx,
    start_xrdhttp as _launcher_start_xrdhttp,
    start_xrootd as _launcher_start_xrootd,
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
    def _required_names(spec, by_name, seen):
        return [
            name
            for name in (getattr(spec, "requires", ()) or ())
            if name in by_name and name not in seen
        ]

    @classmethod
    def _required_depth(cls, required, by_name, depth_memo, seen):
        if not required:
            return 0
        depths = (
            cls._dependency_depth(name, by_name, depth_memo, seen)
            for name in required
        )
        return 1 + max(depths)

    @classmethod
    def _dependency_depth(cls, name, by_name, depth_memo, seen=frozenset()):
        if name in depth_memo:
            return depth_memo[name]
        spec = by_name.get(name)
        required = cls._required_names(spec, by_name, seen)
        value = cls._required_depth(
            required, by_name, depth_memo, seen | {name}
        )
        depth_memo[name] = value
        return value

    @classmethod
    def _dependency_levels(
        cls, selected: Sequence[NginxInstanceSpec],
    ) -> list[list[NginxInstanceSpec]]:
        # Partition specs into dependency levels: level N holds specs whose deepest
        # `requires` chain (restricted to specs present in this selection) is N.
        # Required names absent from the selection (e.g. subset boot) are treated
        # as already-satisfied and don't add depth. Original selection order is
        # preserved within each level for deterministic launch ordering.
        by_name = {spec.name: spec for spec in selected}
        depth_memo: dict[str, int] = {}
        levels: dict[int, list[NginxInstanceSpec]] = {}
        for spec in selected:
            depth = cls._dependency_depth(spec.name, by_name, depth_memo)
            levels.setdefault(depth, []).append(spec)
        return [levels[key] for key in sorted(levels)]

    def _stop_selected_spec(self, spec, listeners):
        if self._quiescent(spec, listeners):
            return None
        try:
            self.stop(spec.name)
        except Exception as exc:  # noqa: BLE001 — report every teardown failure
            return f"{spec.name}: {exc}"
        return None

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
            failure = self._stop_selected_spec(spec, listeners)
            if failure is not None:
                failures.append(failure)
        self._owned.clear()
        if failures:
            raise RuntimeError("fleet teardown failures: " + "; ".join(failures))

    def _quiescent(self, spec: NginxInstanceSpec, listeners: dict[int, set[int]] | None) -> bool:
        return _launcher_quiescent(self, spec, listeners, globals())

    def start(self, spec: NginxInstanceSpec) -> None:
        _launcher_start_nginx(self, spec, globals())

    def _start_xrootd(self, spec: NginxInstanceSpec) -> None:
        _launcher_start_xrootd(self, spec, globals())

    def _start_xrdhttp(self, spec: NginxInstanceSpec) -> None:
        _launcher_start_xrdhttp(self, spec, globals())

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
            env=_sanitized_env(spec.env),
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
        merged_env = _sanitized_env(spec.env)
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

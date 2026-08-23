# ARCHIVE — the pre-TS-4 flat body of ``tests/_server_launcher_part2_mixinb.py``, kept byte-identical so
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
from brix_suite.kinds import LAUNCHER_KINDS
from brix_suite.launcher.control_operations import (
    process_snapshot as _launcher_process_snapshot,
    public_cadir as _launcher_public_cadir,
    reap_orphan_nginx_workers as _launcher_reap_workers,
    stop as _launcher_stop,
)


from brix_suite.nginx_tools import (  # noqa: F401 — re-exported for importers
    _inject_nginx_load_modules,
    _inject_nginx_runtime_paths,
    _nginx_bin,
)


class _RegistryLauncherMixinB:
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
        _launcher_public_cadir(src, dst)

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
        _launcher_stop(self, name, globals())
    @staticmethod
    def _reap_orphan_nginx_workers(spec: NginxInstanceSpec) -> None:
        _launcher_reap_workers(spec, declared_ports)
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
        return _launcher_process_snapshot(name, globals())

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

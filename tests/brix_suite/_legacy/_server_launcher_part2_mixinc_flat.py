# ARCHIVE — the pre-TS-4 flat body of ``tests/_server_launcher_part2_mixinc.py``, kept byte-identical so
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
from brix_suite.kinds import LAUNCHER_KINDS, external_stop
from brix_suite.launcher.internal_operations import (
    chmod_recursive as _launcher_chmod_recursive,
    nginx as _launcher_nginx,
    stop_from_disk as _launcher_stop_from_disk,
    wait_ports_released as _launcher_wait_ports_released,
    wait_ready as _launcher_wait_ready,
    xrootd_runas_user as _launcher_xrootd_runas_user,
)
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


class _RegistryLauncherMixinC:
    def _xrootd_runas_user(self, cfg_text: str, log_path: str) -> str | None:
        return _launcher_xrootd_runas_user(self, cfg_text, log_path, globals())

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
        _launcher_chmod_recursive(self, path, bits, add_only)

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
        return _launcher_nginx(args, spec, env, check, globals())

    def _wait_ready(self, host: str, port: int | None, readiness: str) -> None:
        _launcher_wait_ready(host, port, readiness)

    def _wait_ports_released(self, spec: NginxInstanceSpec, timeout: float = 8.0) -> None:
        """Block until every fixed port ``spec`` declared is bindable again.

        The stop/start reuse race on a fixed-port ledger: ``stop()`` returns once
        the master process is gone, but the kernel can still hold the listen
        socket for a beat (a worker draining, close() lagging the exit). The next
        test reusing this exact port then loses ``bind()`` to the stale socket
        with ``Address already in use``. We probe each declared port exactly the
        way nginx binds it — wildcard address, ``SO_REUSEADDR`` set — so a socket
        merely in ``TIME_WAIT`` does NOT read as busy (nginx would rebind over it
        fine), only a still-live overlapping listener does. That is precisely the
        condition worth waiting out.

        Best-effort: on timeout we return quietly rather than raise. A genuinely
        stuck port surfaces as the successor's own EADDRINUSE with full nginx
        diagnostics — a clearer failure than one raised from teardown.
        """
        _launcher_wait_ports_released(spec, timeout, declared_ports)

    def _stop_from_disk(self, spec: NginxInstanceSpec, endpoint) -> None:
        """Reap a non-nginx daemon kind with no in-memory handle (cross-process
        stop-all). Each kind is torn down from state it left on disk:

          * xrootd/xrdhttp  → RUN_DIR/xrootd.pid  (SIGTERM the group, then KILL)
          * haproxy         → logs/haproxy.pid
          * external        → its paired ``stop_argv`` (self-daemonizing meshes/KDC)
          * proc            → whatever is listening on the tracked port (Python
                              stubs self-daemonize without a pidfile)
        """
        _launcher_stop_from_disk(self, spec, endpoint, globals())

    @staticmethod
    def _process_exited(pid: int) -> bool:
        """Whether ``pid`` no longer owns resources that a successor needs.

        ``kill(pid, 0)`` reports success for a zombie until its parent reaps it.
        A controller-side teardown deliberately uses a fresh launcher, so its
        xrootd ``Popen`` handles are unavailable and a just-SIGTERM'd child can
        remain a zombie for the entire shutdown.  Treating that as live burned
        the five-second xrootd grace period once per reference server.  A zombie
        owns no sockets or process group members, so it is already stopped for
        fixed-port reuse purposes.
        """
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                suffix = fh.read().rsplit(b")", 1)[1].split()
        except (OSError, IndexError):
            return True
        # Field 3 is the first token after the rightmost ')' of comm.  Do not
        # split the complete line: a process name may itself contain spaces or
        # parentheses.
        return bool(suffix and suffix[0] == b"Z")

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
        # Verify the pid STILL belongs to this instance before signalling it.
        # A pidfile can outlive its process (crash / unclean exit); the OS then
        # recycles that pid to some unrelated process — most dangerously a shared
        # test-fleet server.  Signalling it (worse, its whole group via killpg)
        # would take the fleet down.  The instance's own prefix is the pidfile's
        # grandparent dir (<prefix>/logs/nginx.pid) and appears in the live
        # master's argv (nginx -p <prefix>); require that match.
        try:
            # <prefix>/logs/nginx.pid -> <prefix>, matched as-passed to `nginx -p`.
            prefix = os.path.dirname(os.path.dirname(str(pidfile)))
            with open(f"/proc/{pid}/cmdline", "rb") as _fh:
                cmdline = _fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
            if prefix and prefix not in cmdline:
                return
        except OSError:
            return
        try:
            if process_group:
                try:
                    pgid = os.getpgid(pid)
                    # Only signal the whole PROCESS GROUP when this pid is its
                    # OWN group leader (pgid == pid), i.e. it was started in a
                    # fresh session/group and the group contains only it and its
                    # workers.  If pid is NOT the group leader, it shares a group
                    # with unrelated servers — most dangerously the shared test
                    # fleet, all launched together under one group by
                    # manage_test_servers start-all.  A killpg there SIGTERMs the
                    # ENTIRE fleet (dozens of masters at once) — the fleet
                    # mass-death that made every downstream test ConnectionRefuse.
                    # Also guards a stale/recycled pidfile pid that now belongs to
                    # some other process's group.  Fall back to signalling just
                    # the pid in that case.
                    if pgid == pid:
                        os.killpg(pgid, sig)
                        return
                except OSError:
                    pass
            os.kill(pid, sig)
        except OSError:
            return

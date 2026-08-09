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
    """The nginx binary to exec: a per-process frozen copy of ``NGINX_BIN``.

    The shared build tree's ``objs/nginx`` can be relinked by a concurrent
    incremental build at any moment; ``exec`` during the relink window fails
    with EACCES (and ``ldd``-style probes misread the half-written file), which
    surfaced as whole-lane storms of ``PermissionError: /tmp/.../objs/nginx``
    the instant an external ``make`` ran. ``freeze_nginx`` copies + validates
    the binary once per process, so every launcher spawn is immune to relinks;
    it falls back to the live path only if no stable copy can be taken.
    """
    from cmdscripts.live_common import freeze_nginx  # noqa: PLC0415 — lazy, avoids cycle
    return str(freeze_nginx(NGINX_BIN))


def _inject_nginx_load_modules(config_path: str) -> None:
    """Prepend the runner-selected dynamic modules to a rendered nginx config."""
    from cmdscripts.live_common import inject_nginx_load_modules  # noqa: PLC0415
    inject_nginx_load_modules(config_path)


def _inject_nginx_runtime_paths(config_path: str, prefix: str) -> None:
    """Keep packaged-nginx runtime files inside its registry-owned prefix."""
    from cmdscripts.live_common import inject_nginx_runtime_paths  # noqa: PLC0415
    inject_nginx_runtime_paths(config_path, prefix)


# NOT frozen: Python assigns __traceback__/__context__ on (re-)raise — e.g.
# contextlib's __exit__ does `exc.__traceback__ = traceback` — and a frozen
# dataclass blocks that, masking the real failure with FrozenInstanceError.
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
    cmd = [_nginx_bin()]
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

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "server_launcher_part2.py",
                    "server_launcher_part3.py")

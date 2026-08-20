# ARCHIVE — the pre-TS-4 flat body of ``tests/server_launcher.py``, kept byte-identical so
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

# DEVIATION from verbatim: the original ended with
#     from split_continuation import load as _load_continuations
#     _load_continuations(globals(), __file__,
#                         "server_launcher_part2.py",
#                         "server_launcher_part3.py")
# which is exactly the mechanism TS-4 item 4 dissolved.  The two
# shards it pulled in are archived beside this file.

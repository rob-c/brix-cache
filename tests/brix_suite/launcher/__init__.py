"""Python lifecycle owner for registry-backed test servers.

TS-4 item 4 moved the six flat launcher modules here.  Before the move the
class was assembled by ``exec``: ``server_launcher.py`` compiled
``server_launcher_part2.py`` and ``server_launcher_part3.py`` into its own
globals, and part 2 in turn imported three mixin modules whose only reason
to be separate was line count.  The composition is ordinary imports now,
and the three parts are named for what they hold rather than for the order
they were sliced in:

    errors      ``RegistryCommandFailure``, importable on its own
    start       fleet start-up — dependency levels, spawn, quiescence
    control     per-instance render / ``nginx -t`` / stop / reload
    internals   privilege drop, readiness waits, teardown mechanics
    harness     ``LifecycleHarness``, the per-test facade

The historical class names are kept as aliases: ``server_launcher_part2``
spelled the mixins by their slice letters, and guard #3 pins those names.
"""

from __future__ import annotations

import os
import subprocess

from brix_suite.launcher.control import _LauncherControl
from brix_suite.launcher.errors import RegistryCommandFailure  # noqa: F401
from brix_suite.launcher.harness import LifecycleHarness  # noqa: F401
from brix_suite.launcher.internals import _LauncherInternals
from brix_suite.launcher.start import _LauncherStart
from brix_suite.nginx_tools import (  # noqa: F401 — re-exported for importers
    _inject_nginx_load_modules,
    _inject_nginx_runtime_paths,
    _nginx_bin,
    env_entry_ok as _env_entry_ok,
)

#: Slice-letter names from the pre-TS-4 split.  Aliases, not subclasses, so
#: the MRO below is the same object graph either way.
_RegistryLauncherMixinA = _LauncherStart
_RegistryLauncherMixinB = _LauncherControl
_RegistryLauncherMixinC = _LauncherInternals

__all__ = [
    "LifecycleHarness",
    "RegistryCommandFailure",
    "RegistryLauncher",
    "launch_fleet_nginx",
]


class RegistryLauncher(_LauncherStart, _LauncherControl, _LauncherInternals):
    """Owns the lifecycle of every registry-declared instance in one lane."""


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
    # A concurrent os.putenv() from a loaded C extension (the XRootD/GSI python
    # bindings do this) can briefly leave os.environ carrying a malformed name;
    # subprocess then rejects the WHOLE env with ValueError("illegal environment
    # variable name"), erroring the launch — and for a module-scoped
    # LifecycleHarness that one failure cascades to every test on the fixture.
    # Drop any entry subprocess would reject; the filtered dict we pass is
    # immune to further os.environ mutation.
    merged_env = {k: v for k, v in merged_env.items() if _env_entry_ok(k, v)}
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

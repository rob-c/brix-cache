"""The six kinds this suite runs, as rows instead of ladders (TS-4 item 2).

`brixtest.fleet.kinds` supplies the mechanism and ships no rows: the
generic engine must not know what an nginx is.  This module is the
adapter half — the nginx-xrootd fleet's own six kinds, registered once.

Two tables, one fact each, because the grown launcher and the core
backend are genuinely different readers:

`KIND_PROFILES` is the core view, consumed by `LocalBackend` and by
anything else built on BriXTest.  `LAUNCHER_KINDS` is the view the grown
`RegistryLauncher` needs while it still exists: it wraps the same core
profile and adds only what the core vocabulary cannot express — which
of the launcher's `_start_*` methods spawns the kind, and how
`_quiescent` treats it.  Nothing is duplicated between them; the pidfile
path and stop strategy have exactly one home.

`quiescence` is a third value rather than a flag because the launcher
really does three things.  `"pidfile"` means "no declared port is
listening and no pidfile is on disk, therefore already stopped".
`"ports-only"` is the `proc` kind: Python stubs self-daemonize without a
pidfile, so an idle port is the whole proof.  `"never"` is `external`:
a mesh or KDC we did not start is never assumed quiescent, because the
consequence of guessing wrong is skipping the stop of something another
lane owns (§14).

Read off the launcher as it behaves today, not off the plan sketch —
`_server_launcher_part2_mixina._quiescent` and `.start`,
`_server_launcher_part2_mixinb.stop`, and
`_server_launcher_part2_mixinc._stop_from_disk`.  TS-4 item 5 flips
those four ladders onto these rows one at a time.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
from typing import Dict, Optional, Tuple

from brixtest.fleet.kinds import KindProfile, register_kind

from brix_suite.nginx_tools import _nginx_bin

__all__ = [
    "KIND_PROFILES",
    "LAUNCHER_KINDS",
    "LauncherKind",
    "external_stop",
    "kind_names",
    "launcher_kind",
    "nginx_quit",
    "register_all",
]


# --- the two adapter-supplied stop strategies ------------------------------


def nginx_quit(backend, spec) -> None:
    """`nginx -s quit` first, then the pidfile.

    The graceful path lets workers finish in-flight requests, which is
    what makes a stop-all safe to run against a fleet under load.  It is
    optional, though: the binary that started the fleet can have been
    rebuilt or moved since, and a missing binary must not turn a stop
    into a leak — so a failed quit falls through to signalling the pid,
    exactly as the grown launcher does.
    """
    endpoint = backend.endpoint(spec.name)
    try:
        subprocess.run(
            [_nginx_bin(), "-p", str(endpoint.workdir),
             "-c", "conf/nginx.conf", "-s", "quit"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    except OSError:
        pass
    pid = backend.pidfile_pid(endpoint)
    if pid is not None:
        backend.term_then_kill({pid}, spec.stop_timeout)


def external_stop(backend, spec) -> None:
    """Run the instance's paired `stop_argv`.

    An `external` instance is a self-daemonizing orchestrator (a mesh, a
    KDC): it left no pid we own and no pidfile we wrote, and its own stop
    CLI is the only thing that knows what it started.  A spec that
    declares no `stop_argv` is left strictly alone — refusing to guess is
    the point of the kind.
    """
    stop_argv = list(spec.config_values.get("stop_argv", ()))
    if not stop_argv:
        return
    subprocess.run(
        stop_argv,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, **dict(spec.env or {})}, check=False,
    )


# --- the rows --------------------------------------------------------------

KIND_PROFILES: Dict[str, KindProfile] = {
    profile.name: profile
    for profile in (
        KindProfile("nginx", "logs/nginx.pid", nginx_quit),
        KindProfile("xrootd", "run/xrootd.pid", "signal-pidfile"),
        KindProfile("xrdhttp", "run/xrootd.pid", "signal-pidfile"),
        KindProfile("haproxy", "logs/haproxy.pid", "signal-pidfile"),
        KindProfile("proc", None, "port-kill", ports_only_quiescence=True),
        KindProfile("external", None, external_stop),
    )
}


#: A kind is "quiescent" when the launcher may skip stopping it.  Three
#: values because the launcher really does three things — see the module
#: docstring for why `external` is never assumed quiescent.
_QUIESCENCE = ("pidfile", "ports-only", "never")


@dataclasses.dataclass(frozen=True)
class LauncherKind:
    """What the grown `RegistryLauncher`'s ladders need on top of a row."""

    profile: KindProfile
    start_method: Optional[str]   # RegistryLauncher method; None = the nginx render path
    quiescence: str               # see _QUIESCENCE
    #: Seconds `_stop_from_disk` waits for a SIGTERM'd master before it
    #: escalates to SIGKILL.  0 means no escalation, which is what haproxy
    #: has always had: it writes its own pidfile and exits promptly on TERM,
    #: so the launcher never learned to chase it.  Held as a per-row value
    #: rather than one shared constant because giving haproxy the escalating
    #: path is a behaviour change and TS-4 item 5 is a refactor.
    kill_grace: float = 0.0

    def __post_init__(self) -> None:
        if self.quiescence not in _QUIESCENCE:
            raise ValueError(
                "kind %r: quiescence %r is not one of %s"
                % (self.profile.name, self.quiescence, ", ".join(_QUIESCENCE))
            )

    @property
    def name(self) -> str:
        return self.profile.name

    @property
    def pidfile(self) -> Optional[str]:
        """Workdir-relative, or None when the kind keeps no pidfile."""
        return self.profile.pidfile

    @property
    def stop_from_disk(self) -> bool:
        """Whether `stop()` reaps this kind from its own on-disk state.

        True for everything but nginx: only nginx leaves a pidfile the
        launcher itself wrote, so only nginx has the `nginx -s quit`
        path.  Derived from `start_method` rather than stored, because
        they are the same fact — a kind the launcher does not spawn in
        process is a kind it cannot stop from memory.
        """
        return self.start_method is not None


LAUNCHER_KINDS: Dict[str, LauncherKind] = {
    row.name: row
    for row in (
        LauncherKind(KIND_PROFILES["nginx"], None, "pidfile"),
        LauncherKind(KIND_PROFILES["xrootd"], "_start_xrootd", "pidfile", 5.0),
        LauncherKind(KIND_PROFILES["xrdhttp"], "_start_xrdhttp", "pidfile", 5.0),
        LauncherKind(KIND_PROFILES["haproxy"], "_start_haproxy", "pidfile"),
        LauncherKind(KIND_PROFILES["proc"], "_start_proc", "ports-only"),
        LauncherKind(KIND_PROFILES["external"], "_start_external", "never"),
    )
}


def launcher_kind(name: str) -> LauncherKind:
    """The launcher view of `name`, or a KeyError naming the known kinds."""
    try:
        return LAUNCHER_KINDS[name]
    except KeyError:
        raise KeyError(
            "unknown server kind %r; known kinds: %s"
            % (name, ", ".join(sorted(LAUNCHER_KINDS)))
        ) from None


def kind_names() -> Tuple[str, ...]:
    return tuple(sorted(KIND_PROFILES))


def register_all(*, replace: bool = True) -> None:
    """Push the six rows into the core registry.

    Called at import, and idempotent by default so that a contract test
    which calls `clear_kinds()` can restore the fleet by calling this
    again — re-importing the module would not, since Python caches it.
    """
    for profile in KIND_PROFILES.values():
        register_kind(profile, replace=replace)


register_all()

"""TS-4 item 5 — the launcher's four kind ladders, flipped onto the rows.

`RegistryLauncher` used to answer four separate questions with four
hand-written `if spec.kind == ...` chains: which method starts this kind
(`start`), whether stop() can be skipped entirely (`_quiescent`), whether
stop() reaps from disk or from memory (`stop`), and how the from-disk reap
works (`_stop_from_disk`).  Four ladders over the same six kinds means a
seventh kind can be added to one and forgotten in the other three, and the
forgetting is silent: every ladder has an `else` that quietly does the
nginx thing.

They now read `brix_suite.kinds.LAUNCHER_KINDS`.  These tests execute the
flipped bodies rather than reading them, because the failure mode the flip
introduces is a wrong attribute name on a row — which imports fine, passes
every static check, and only raises when a real teardown runs it.

Each test builds its specs unregistered.  `endpoint_for` and
`declared_ports` are pure functions of a spec, so nothing here has to touch
the `_SPECS` singleton, and no stray name can leak into a later fleet boot.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re

import pytest

from brix_suite.kinds import LAUNCHER_KINDS
from server_registry import NginxInstanceSpec, endpoint_for
import server_launcher

TESTS = pathlib.Path(__file__).resolve().parent

#: method -> the module whose body holds it, for the static checks.
_FLIPPED = {
    "start": "_server_launcher_part2_mixina.py",
    "_quiescent": "_server_launcher_part2_mixina.py",
    "stop": "_server_launcher_part2_mixinb.py",
    "_stop_from_disk": "_server_launcher_part2_mixinc.py",
}


def _body(method: str) -> str:
    path = TESTS / _FLIPPED[method]
    source = path.read_text()
    tree = ast.parse(source)
    match = next(filter(lambda node: getattr(node, "name", None) == method,
                        ast.walk(tree)), None)
    assert match is not None, "%s not found in %s" % (method, path.name)
    return ast.get_source_segment(source, match)


def _spec(name: str, kind: str, port: int) -> NginxInstanceSpec:
    return NginxInstanceSpec(name=name, template="unused.conf.in",
                             port=port, kind=kind)


@pytest.fixture
def prefixes(request):
    """Create and remove the on-disk prefixes a test's specs resolve to.

    The prefix comes from `endpoint_for`, i.e. the real lane, so the test
    exercises the same path resolution the launcher does.  Names are keyed
    to this file so they cannot collide with a fleet instance.
    """
    import shutil

    made: list[str] = []

    def make(spec, relpath: str | None = None, pid: int | None = None) -> str:
        prefix = endpoint_for(spec).prefix
        made.append(prefix)
        if relpath is None:
            os.makedirs(prefix, exist_ok=True)
            return prefix
        target = os.path.join(prefix, relpath)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if pid is not None:
            with open(target, "w") as fh:
                fh.write("%d\n" % pid)
        return target

    yield make
    for prefix in made:
        shutil.rmtree(prefix, ignore_errors=True)


class _Recorder(server_launcher.RegistryLauncher):
    """A launcher that records the branch taken instead of taking it."""

    def __init__(self):
        super().__init__()
        self.calls: list[tuple] = []

    def render_nginx(self, spec):            # the `else` of the start ladder
        self.calls.append(("render_nginx", spec.kind))
        raise _Stop()

    def _kill_pidfile(self, path, sig, process_group=False):
        self.calls.append(("kill", path, sig))

    #: Whether a SIGTERM'd master is treated as gone.  False makes the
    #: escalating kinds actually wait out their grace, which is the only way
    #: to observe the SIGKILL; tests that set it shorten `kill_grace` to
    #: match so the wait is milliseconds, not the production five seconds.
    exits_on_term = True

    def _process_exited(self, pid):
        return self.exits_on_term

    def _start_xrootd(self, spec):   self.calls.append(("_start_xrootd", spec.kind))
    def _start_xrdhttp(self, spec):  self.calls.append(("_start_xrdhttp", spec.kind))
    def _start_haproxy(self, spec):  self.calls.append(("_start_haproxy", spec.kind))
    def _start_proc(self, spec):     self.calls.append(("_start_proc", spec.kind))
    def _start_external(self, spec): self.calls.append(("_start_external", spec.kind))


class _Stop(Exception):
    """Raised in place of really rendering and spawning nginx."""


# ---------------------------------------------------------------------------
# success


def test_start_dispatches_every_kind_to_the_method_its_row_names():
    launcher = _Recorder()
    for offset, (kind, row) in enumerate(sorted(LAUNCHER_KINDS.items())):
        spec = _spec("ts4-flip-start-%s" % kind, kind, 29500 + offset)
        _record_start(launcher, spec)
    taken = dict((kind, method) for method, kind in launcher.calls)
    for kind, row in LAUNCHER_KINDS.items():
        assert taken[kind] == _start_method(row), kind


def _start_method(row):
    return row.start_method if row.start_method else "render_nginx"


def _record_start(launcher, spec):
    try:
        launcher.start(spec)
    except _Stop:
        pass


def test_quiescent_reads_the_pidfile_the_row_names(prefixes):
    """The row's `pidfile` is workdir-relative and differs per kind — this is
    the assertion that would have caught a wrong attribute name on the row,
    which imports cleanly and only raises when a teardown runs it."""
    launcher = server_launcher.RegistryLauncher()
    for offset, kind in enumerate(("nginx", "xrootd", "xrdhttp", "haproxy")):
        row = LAUNCHER_KINDS[kind]
        spec = _spec("ts4-flip-quiet-%s" % kind, kind, 29520 + offset)
        prefixes(spec)
        # Nothing on disk and nothing listening: stop() would be a no-op.
        assert launcher._quiescent(spec, {}) is True, kind
        # Now the kind's own pidfile exists, so stop() has work to do.
        prefixes(spec, row.pidfile, pid=1)
        assert launcher._quiescent(spec, {}) is False, kind


def test_quiescent_defers_to_a_listening_port_before_any_pidfile(prefixes):
    spec = _spec("ts4-flip-quiet-listen", "nginx", 29540)
    prefixes(spec)
    assert launcher_is_quiet(spec) is True
    assert launcher_is_quiet(spec, {29540: {4242}}) is False


def launcher_is_quiet(spec, listeners=None):
    return server_launcher.RegistryLauncher()._quiescent(
        spec, {} if listeners is None else listeners)


def test_stop_from_disk_uses_the_row_pidfile_and_its_kill_grace(prefixes, monkeypatch):
    """haproxy TERMs and returns; xrootd TERMs, waits out `kill_grace`, KILLs.

    Both facts used to be branches; both are now row values, and the two
    kinds must still behave differently or the flip has quietly unified
    them.
    """
    import dataclasses
    import signal

    launcher = _Recorder()
    launcher.exits_on_term = False  # force the grace to elapse, if there is one
    for offset, kind in enumerate(("haproxy", "xrootd")):
        _assert_disk_stop(launcher, prefixes, monkeypatch, dataclasses,
                          signal, kind, offset)


def _assert_disk_stop(launcher, prefixes, monkeypatch, dataclasses,
                      signal, kind, offset):
    row = _short_grace(monkeypatch, dataclasses, kind)
    spec = _spec("ts4-flip-disk-%s" % kind, kind, 29560 + offset)
    pidfile = prefixes(spec, row.pidfile, pid=os.getpid())
    launcher.calls.clear()
    launcher._stop_from_disk(spec, endpoint_for(spec))
    assert list(map(lambda call: call[1], launcher.calls)) == [pidfile] * len(launcher.calls)
    signals = list(map(lambda call: call[2], launcher.calls))
    assert signals == _expected_signals(signal, row), kind


def _short_grace(monkeypatch, dataclasses, kind):
    row = LAUNCHER_KINDS[kind]
    if not row.kill_grace:
        return row
    replacement = dataclasses.replace(row, kill_grace=0.05)
    monkeypatch.setitem(LAUNCHER_KINDS, kind, replacement)
    return replacement


def _expected_signals(signal, row):
    if row.kill_grace:
        return [signal.SIGTERM, signal.SIGKILL]
    return [signal.SIGTERM]


def test_no_flipped_body_still_names_a_kind():
    """The literals are the ladder.  If one comes back, so has the drift."""
    offenders = dict(filter(lambda pair: pair[1],
                     ((_method, _named_kinds(_body(_method)))
                      for _method in _FLIPPED)))
    assert offenders == {}


def _named_kinds(body):
    literals = set(re.findall(r"['\"]([^'\"]+)['\"]", body))
    return sorted(literals.intersection(LAUNCHER_KINDS))


# ---------------------------------------------------------------------------
# error


def test_an_unknown_kind_takes_the_nginx_path_rather_than_raising(prefixes):
    """Every ladder had an `else`, and the flip keeps it: `LAUNCHER_KINDS.get`,
    not `launcher_kind()`, which would raise.  A kind nobody registered is a
    spec bug to be caught by the registry's own validation, not a crash in
    the middle of a fleet teardown."""
    launcher = _Recorder()
    spec = _spec("ts4-flip-unknown", "not-a-kind", 29580)
    prefixes(spec)

    with pytest.raises(_Stop):
        launcher.start(spec)
    assert launcher.calls == [("render_nginx", "not-a-kind")]

    # ... and it is judged on the nginx pidfile, the same `else` the ladder had.
    plain = server_launcher.RegistryLauncher()
    assert plain._quiescent(spec, {}) is True
    prefixes(spec, "logs/nginx.pid", pid=1)
    assert plain._quiescent(spec, {}) is False


def test_stop_from_disk_is_never_reached_for_nginx():
    """`stop_from_disk` is derived from `start_method`, not stored: the one
    kind the launcher spawns itself is the one kind it can stop from memory.
    A row that gained a start method without gaining a from-disk reap would
    silently take the nginx `-s quit` path for a daemon it never rendered."""
    assert LAUNCHER_KINDS["nginx"].stop_from_disk is False
    assert all(row.stop_from_disk for name, row in LAUNCHER_KINDS.items()
               if name != "nginx")


# ---------------------------------------------------------------------------
# security-negative


def test_external_is_never_reported_quiescent(prefixes):
    """An `external` kind is a self-daemonizing mesh or KDC whose stop CLI
    owns state the launcher cannot see.  Nothing listening and nothing on
    disk is exactly what a half-torn-down one looks like, so the row says
    `never` and no amount of local evidence may override it — a false
    "already down" leaks the process past the end of the session."""
    spec = _spec("ts4-flip-external", "external", 29590)
    prefixes(spec)
    assert LAUNCHER_KINDS["external"].quiescence == "never"
    assert launcher_is_quiet(spec) is False
    assert launcher_is_quiet(spec, {}) is False


def test_a_row_cannot_declare_a_quiescence_the_launcher_does_not_implement():
    """`_quiescent` handles three values.  A fourth would fall through to the
    pidfile branch and silently report a live instance as stopped."""
    from brix_suite.kinds import KIND_PROFILES, LauncherKind

    assert {row.quiescence for row in LAUNCHER_KINDS.values()} <= {
        "pidfile", "ports-only", "never"}
    with pytest.raises(ValueError, match="quiescence"):
        LauncherKind(KIND_PROFILES["nginx"], None, "whenever")

"""TS-3 proof against a REAL fleet — the lane, not a simulation of one.

`test_ci_ts3_settings_object.py` pins the settings shim hermetically: 20
tests, every one of them arithmetic over an environment dict.  That is the
right shape for the ladder maths, and it is structurally unable to answer
the question the migration actually raises — *does a server started under
the rebased ladder bind where `SETTINGS` says it does?*  Appendix E has
claimed a real-fleet round trip for TS-3 since it landed; nothing in the
tree re-ran it, so the claim decayed into prose.  This file is that round
trip, committed and repeatable.

It boots ONE real instance (the core `main` nginx, ~3 s including artifact
generation) in a lane of its own and asserts the four properties no
hermetic test can reach:

  * the ladder the settings object *reports* is the ladder the kernel
    *granted* — read back out of `ss`, not out of the same arithmetic;
  * the import-time side effects (TEST_ROOT normalise + republish, the
    TMPDIR pin, the ladder rebase and its env republish) fired in a child
    that imported settings for the first time in a foreign lane;
  * the conftest lane gate, driven by a live socket rather than a
    monkeypatched flag: own-and-complete attaches without touching the
    tree, foreign refuses and leaves the listener running;
  * ownership-based leak accounting over processes that really exist,
    including the nginx worker whose own command line never names the lane.

**The tests in this file are a stream, not a set** (plan ask vii).  The
fixture boots the lane once, the last test stops it and is the leak check,
and the fixture teardown repeats the stop idempotently for a run that is
cut short.

**The lane is held under an exclusive file lock, because `serial` is not
enough.**  `--dist=loadgroup` split this module across two workers on its
first parallel run, `serial` marker and all: the marker is applied in
`pytest_collection_modifyitems`, which each *worker* runs, while the
controller's loadgroup scheduler keys on the `@group` suffix in the nodeid
— which is exactly why conftest appends one by hand for the two families
that already hit this (`cvmfs-fixed-ports`, `ci-guards`) and why `serial`,
which never got that treatment, does not survive scheduling.  The split
put two module fixtures on the same lane at once; one wiped `pki/` while
the other was generating into it, and the boot failed on a half-generated
CA with no warning from either side.  A lock is the fix that lives in this
file: whichever worker gets here first owns the lane end to end, the other
waits and then runs its own complete cycle.  Making `serial` authoritative
belongs in conftest, and conftest is off-limits until TS-7.

**Lane choice is derived, never a literal.**  A lane reserves
`port_ladder.TOTAL_PORT_COUNT` ports — 18505 today — of which only the
first 178 are visible in `ss`.  Two lanes a few hundred apart therefore
look like they coexist while their `free_port` pools overlap almost
entirely, and the collision arrives later, out of a draw rather than out of
a boot.  The first version of this proof was written for lane 15000, which
sits *inside* the default lane's span; that mistake is why the base below
is computed rather than typed in.

**And a lane must clear the kernel, not only the other lanes.**  Deriving
the base as the top tile of 1024..65535 — the arithmetic `port_ladder`
itself validates — produced a lane at 47029 that failed `bind()` with
EADDRINUSE on a host where nothing was listening: `ip_local_port_range` is
32768..60999 here, so the tile sat inside the range the kernel hands to
*outbound* sockets, and a connection this very suite had open owned the
port.  The failure is nondeterministic by construction, which is the worst
possible shape for a lane.  The documented tiling (1023 / 19503 / 37983)
has the same defect: the third tile is entirely inside the ephemeral range
and the second tile'''s mock pool crosses into it at 32768.  The base below
is therefore the highest one whose complete *named* ledger still clears the
ephemeral floor, read from the kernel at import.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import port_ladder
import settings as S
from brix_suite.orphans import find_orphans, kill_orphans
from lib_py.util import pids_on_port

pytestmark = [pytest.mark.serial, pytest.mark.timeout(120)]

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
SRC = REPO / "brixtest" / "src"

def _ephemeral_range():
    """The port range the kernel hands to outbound sockets.

    A listening lane inside it collides with connections nobody declared,
    at a moment nobody controls.  Read rather than assumed because it is
    tunable per host; the fallback is the Linux default, used only where
    the file is absent (a non-Linux runner, where the suite does not boot
    a fleet anyway).
    """
    try:
        low, high = Path(
            "/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
    except (OSError, ValueError):
        return 32768, 60999
    return int(low), int(high)


EPHEMERAL_LOW, EPHEMERAL_HIGH = _ephemeral_range()
#: The highest base whose complete NAMED ledger (`PORT_COUNT` wide — the span
#: servers actually bind) still clears the ephemeral floor.  Derived from the
#: ladder's own constants and the kernel's own range, so a change to either
#: moves the lane instead of making this file flaky.
LANE_BASE = EPHEMERAL_LOW - port_ladder.PORT_COUNT - 1
LANE_ROOT = "/tmp/xrd-test-ts3-live-lane"
#: A prefix sibling of LANE_ROOT, used to prove ownership matches whole paths.
SIBLING_ROOT = LANE_ROOT + "-sibling"
#: Lane ownership, held for the life of the module fixture.  Deliberately NOT
#: inside LANE_ROOT: the fixture wipes that tree, and a lock file that the
#: lock holder deletes is not a lock.
LANE_LOCK = LANE_ROOT + ".lock"
#: The instance: the always-on core nginx, the one spec with no `requires`.
INSTANCE = "main"
#: Written into the lane before the attach probe; a wipe would remove it.
SENTINEL = "attach-must-not-wipe-this"

#: Child-side boot.  Runs the same three calls `manage_test_servers start-all`
#: runs — prepare, launcher.start, publish manifest + ready marker — restricted
#: to one spec.  Publishing through `write_manifest`/`build_manifest` rather
#: than by hand matters: the attach branch believes the manifest, so a
#: hand-rolled one would prove only that this file can write JSON.
_BOOT_SRC = """
import json, sys
from pathlib import Path
import fleet_prep, fleet_specs, settings as S
from server_registry import build_manifest, registered_specs, write_manifest
from server_launcher import RegistryLauncher

fleet_prep.prepare()
fleet_specs.register_full_fleet()
specs = [s for s in registered_specs() if s.name == sys.argv[1]]
launcher = RegistryLauncher()
for spec in specs:
    launcher.start(spec)
write_manifest(build_manifest(specs=specs))
marker = Path(S.FLEET_READY)
marker.parent.mkdir(parents=True, exist_ok=True)
marker.write_text(S.TEST_ROOT + "\\n", encoding="utf-8")
json.dump({
    "test_root": S.TEST_ROOT,
    "tmpdir": __import__("os").environ.get("TMPDIR"),
    "env_test_root": __import__("os").environ.get("TEST_ROOT"),
    "port_start": S.TEST_PORT_START,
    "ports": {n: getattr(S, n) for n in (
        "NGINX_ANON_PORT", "NGINX_GSI_PORT", "NGINX_TOKEN_PORT")},
    "object_ports": {n: getattr(S.SETTINGS.ports, n) for n in (
        "NGINX_ANON_PORT", "NGINX_GSI_PORT", "NGINX_TOKEN_PORT")},
    "shim_is_package": S is sys.modules["brix_suite.settings"],
    "env_ports": {n: __import__("os").environ.get(n) for n in (
        "NGINX_ANON_PORT", "TEST_NGINX_ANON_PORT")},
}, sys.stdout)
"""


def _lane_env(root=LANE_ROOT, **extra):
    """The environment of a lane — never `os.environ` mutated in place."""
    env = dict(os.environ)
    env.update(TEST_ROOT=root, TEST_PORT_START=str(LANE_BASE))
    env["PYTHONPATH"] = os.pathsep.join([str(TESTS), str(SRC)])
    env.pop("TEST_SERVER_HOST", None)
    env.pop("TEST_OWN_FLEET", None)
    env.update(extra)
    return env


def _probe_session(root, **extra):
    """A pytest session in `root` that selects no tests.

    The lane decision is taken at session start, before collection is
    consulted, so an empty selection exercises the gate and nothing else —
    no fixture runs, no server is asked for, and a session that wrongly
    decides it owns the lane still cannot boot anything on top of ours.
    A session that reaches the end therefore exits `NO_TESTS_COLLECTED`,
    and one the gate stops exits `USAGE_ERROR`; those two codes are the
    whole result, which is why they are named rather than numbered.
    """
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(Path(__file__).name),
         "-k", "__no_such_test__", "-q", "-p", "no:cacheprovider"],
        cwd=str(TESTS), env=_lane_env(root, **extra),
        capture_output=True, text=True, timeout=90)


def _stop_lane():
    subprocess.run(
        [sys.executable, "-m", "cmdscripts.manage_test_servers", "stop-all"],
        cwd=str(TESTS), env=_lane_env(), capture_output=True, text=True,
        timeout=90)


@pytest.fixture(scope="module")
def lane():
    """One real instance, in a lane of this file's own, for the whole module."""
    if not os.path.exists(S.NGINX_BIN):
        pytest.skip(f"no nginx binary at {S.NGINX_BIN}")
    ambient = int(os.environ.get("TEST_PORT_START", S.TEST_PORT_START))
    if abs(ambient - LANE_BASE) < port_ladder.TOTAL_PORT_COUNT:
        pytest.skip(
            f"ambient lane {ambient} overlaps the proof lane {LANE_BASE}; "
            "a second lane here would collide out of a free_port draw")

    lock = open(LANE_LOCK, "w")
    fcntl.flock(lock, fcntl.LOCK_EX)  # blocks: a split module waits its turn
    kill_orphans(LANE_ROOT)          # ours by definition: it is this file's root
    shutil.rmtree(LANE_ROOT, ignore_errors=True)
    boot = subprocess.run([sys.executable, "-c", _BOOT_SRC, INSTANCE],
                          cwd=str(TESTS), env=_lane_env(),
                          capture_output=True, text=True, timeout=180)
    if boot.returncode != 0:
        # The tree listing is part of the message: a boot failure is almost
        # always a missing artifact, and the fixture wipes the lane on the way
        # out, so a report without it cannot be diagnosed after the fact.
        tree = sorted(str(q)[len(LANE_ROOT) + 1:]
                      for q in Path(LANE_ROOT).rglob("*"))
        pytest.fail("lane boot failed:\n%s\n%s\nlane tree (%d entries): %s"
                    % (boot.stdout, boot.stderr, len(tree), tree[:40]))
    info = json.loads(boot.stdout[boot.stdout.index("{"):])
    Path(LANE_ROOT, "registry", SENTINEL).write_text("keep me\n", encoding="utf-8")
    try:
        yield info
    finally:
        _stop_lane()
        kill_orphans(LANE_ROOT)
        shutil.rmtree(LANE_ROOT, ignore_errors=True)
        shutil.rmtree(SIBLING_ROOT, ignore_errors=True)
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


# --- success ---------------------------------------------------------------


def test_the_lane_bound_the_ladder_it_reports(lane):
    """The kernel agrees with `SETTINGS.ports`.

    Every hermetic check of the rebase compares arithmetic against the same
    arithmetic.  This one reads the bound set back out of `ss` and requires
    the owning pids to be the lane's own, which is the only way to catch a
    rebase that computes correctly and is then not handed to the servers.
    """
    owned = {pid for pid, _ in find_orphans(LANE_ROOT)}
    assert owned, "the lane owns no process at all"
    for name, port in lane["ports"].items():
        holders = set(pids_on_port(port))
        assert holders, f"{name}={port} is reported but nothing is listening"
        assert holders <= owned, (
            f"{name}={port} is held by {sorted(holders - owned)}, "
            f"which this lane does not own")


def test_the_shim_and_the_package_agree_on_the_rebased_ladder(lane):
    """One module object, one ladder — measured inside the live lane.

    The failure this excludes is a second `settings` module object holding
    the *unrebased* constants: every port would still be an int, every
    hermetic test would still pass, and half the fleet would boot on the
    default lane's ports while the other half used ours.
    """
    assert lane["shim_is_package"] is True
    assert lane["ports"] == lane["object_ports"]
    assert lane["port_start"] == LANE_BASE
    for name, port in lane["ports"].items():
        assert port > LANE_BASE, f"{name} was not rebased onto this lane"
        assert port != getattr(S, name), (
            f"{name} kept this session's value in a lane that is not this one")


def test_import_time_side_effects_fired_in_the_live_lane(lane):
    """TEST_ROOT republish, TMPDIR pin, ladder env republish.

    All three are side effects of *importing* settings, so they exist only
    in a process that imported it fresh under the lane's environment — this
    session imported settings long ago, under a different lane.
    """
    assert lane["env_test_root"] == LANE_ROOT == lane["test_root"]
    assert lane["tmpdir"] == os.path.join(LANE_ROOT, "tmp")
    anon = str(lane["ports"]["NGINX_ANON_PORT"])
    assert lane["env_ports"]["NGINX_ANON_PORT"] == anon
    assert lane["env_ports"]["TEST_NGINX_ANON_PORT"] == anon, (
        "the TEST_* compatibility spelling did not receive the lane")


def test_a_session_in_this_root_attaches_without_touching_the_tree(lane):
    """Own + complete + live master ⇒ attach, and attach means *hands off*.

    The footgun this branch exists to close: an operator keeps a fleet up
    out of band, runs one file, and session teardown stops the fleet and
    rmtree's the root out from under every still-open export fd.  Proving
    it needs a real manifest, a real marker and a real master — the whole
    predicate is about processes and files that exist.
    """
    sentinel = Path(LANE_ROOT, "registry", SENTINEL)
    probe = _probe_session(LANE_ROOT)

    assert probe.returncode == pytest.ExitCode.NO_TESTS_COLLECTED, (
        probe.stdout + probe.stderr)
    assert "attaching WITHOUT lifecycle management" in probe.stdout
    assert sentinel.is_file(), "the attaching session wiped the tree it attached to"
    assert pids_on_port(lane["ports"]["NGINX_ANON_PORT"]), "attach stopped the fleet"


# --- error -----------------------------------------------------------------


def test_the_proof_lane_clears_both_the_other_lane_and_the_kernel(lane):
    """The base is arithmetic over two constraints, not a number someone liked.

    18505 ports are reserved and 178 are visible, so an overlapping base is
    invisible until a `free_port` draw collides mid-suite; and a base inside
    `ip_local_port_range` collides with outbound sockets instead, which is
    invisible until `bind()` fails on a host where `ss` shows nothing.  Both
    are pinned as properties so a change to the ladder width or to the host's
    range moves this lane rather than making this file flaky.
    """
    ambient = int(os.environ.get("TEST_PORT_START", S.TEST_PORT_START))

    assert abs(ambient - LANE_BASE) >= port_ladder.TOTAL_PORT_COUNT
    assert LANE_BASE + port_ladder.PORT_COUNT < EPHEMERAL_LOW, (
        "the named ledger reaches into the kernel's outbound range")
    assert max(lane["ports"].values()) < EPHEMERAL_LOW
    assert LANE_BASE > 1024


def test_a_foreign_root_on_this_base_is_refused(lane):
    """A live socket the manifest cannot account for aborts the session."""
    probe = _probe_session(SIBLING_ROOT)

    assert probe.returncode == pytest.ExitCode.USAGE_ERROR, (
        "a foreign session was allowed to proceed:\n"
        + probe.stdout + probe.stderr)
    assert "refusing to start" in probe.stdout + probe.stderr


def test_the_refusal_names_the_port_this_lane_really_bound(lane):
    """Operators act on this message; it must name the socket, not a default.

    A refusal quoting the default lane's port would send an operator to
    inspect a lane that is not the one colliding — the failure mode that
    made the text single-sourced in `brixtest.config.lanes` to begin with.
    """
    probe = _probe_session(SIBLING_ROOT)
    text = probe.stdout + probe.stderr

    assert f"{S.HOST}:{lane['ports']['NGINX_ANON_PORT']}" in text
    assert SIBLING_ROOT in text
    assert str(S.NGINX_ANON_PORT) not in text.split("refusing to start", 1)[1]


def test_the_ownership_view_sees_the_worker_the_command_line_never_names(lane):
    """Why the leak check is `find_orphans` and never `pgrep -af "$LANE"`.

    nginx re-execs its workers with the command line `nginx: worker process`
    — the lane string appears only on the master.  `find_orphans` follows
    parent argv, so it returns both; a grep over command lines returns the
    master and, worse, the shell that ran the grep, so "1 survivor" reads as
    clean and a genuine survivor reads as 2.
    """
    owned = find_orphans(LANE_ROOT)
    named = [(pid, cmd) for pid, cmd in owned if LANE_ROOT in cmd]
    unnamed = [(pid, cmd) for pid, cmd in owned if LANE_ROOT not in cmd]

    assert named, "no process names the lane; ownership cannot be established"
    assert unnamed, (
        "expected at least one inherited process (the nginx worker) whose own "
        "command line never mentions the lane")


# --- security-negative -----------------------------------------------------


def test_the_skip_switch_is_not_a_way_past_a_foreign_lane(lane):
    """`TEST_SKIP_SERVER_SETUP=1` must not downgrade a collision to a warning.

    The knob says "do not manage a fleet", which reads like "so a collision
    cannot matter".  It must not: the session would still run its tests
    against someone else's servers and report their state as its own.
    """
    probe = _probe_session(SIBLING_ROOT, TEST_SKIP_SERVER_SETUP="1")

    assert probe.returncode == pytest.ExitCode.USAGE_ERROR, (
        "the skip switch bypassed the lane refusal:\n"
        + probe.stdout + probe.stderr)
    assert "refusing to start" in probe.stdout + probe.stderr


def test_the_refused_session_left_the_foreign_listener_running(lane):
    """Refuse, never reap — asserted against the process, not the promise.

    The message ends "The foreign listener was not modified."  A refusal
    that also killed the listener would be strictly worse than attaching,
    because the operator whose fleet it was gets no message at all.
    """
    before = {pid for pid, _ in find_orphans(LANE_ROOT)}
    _probe_session(SIBLING_ROOT)
    after = {pid for pid, _ in find_orphans(LANE_ROOT)}

    assert before and before == after, "the refused session touched the lane"
    assert pids_on_port(lane["ports"]["NGINX_ANON_PORT"])


def test_lane_ownership_does_not_leak_to_a_sibling_root(lane):
    """Ownership matches whole paths, so a prefix sibling owns nothing.

    `SIBLING_ROOT` starts with `LANE_ROOT`.  Under substring matching every
    process of this lane would answer to it — which is how one lane's reaper
    once SIGTERMed every lane whose root merely shared its prefix.
    """
    assert find_orphans(LANE_ROOT), "the lane under test owns nothing"
    assert find_orphans(SIBLING_ROOT) == [], (
        "a prefix sibling claimed this lane's processes")


def test_no_second_owner_can_take_the_lane_while_this_one_holds_it(lane):
    """The lock is a lock, asserted from a process that is not holding it.

    `flock` is per-open-file-description, so a second `open()` in *this*
    process would succeed and prove nothing.  The probe therefore runs in a
    child, non-blocking, and must be refused — otherwise a split module
    would put two boots on one lane again and the failure would come back
    as a half-generated CA rather than as a lock error.
    """
    probe = subprocess.run(
        [sys.executable, "-c",
         "import fcntl, sys\n"
         "f = open(sys.argv[1], 'w')\n"
         "fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
         "print('TOOK THE LANE')\n",
         LANE_LOCK],
        capture_output=True, text=True, timeout=30)

    assert probe.returncode != 0, "a second owner took a lane we are holding"
    assert "TOOK THE LANE" not in probe.stdout
    assert "BlockingIOError" in probe.stderr


def test_stopping_the_lane_leaves_nothing_it_owned(lane):
    """The leak check, and the last test in the stream — it stops the lane.

    Ownership-based by construction: a port-window scan would have missed
    the mesh ports a lane takes from its own cfg files, and this file's own
    boot showed a foreign `cmsd` sitting inside the window of an unrelated
    lane, so the window says "dirty" for a clean lane and "clean" for a
    lane whose listeners are outside it.
    """
    _stop_lane()

    assert find_orphans(LANE_ROOT) == []
    assert not pids_on_port(lane["ports"]["NGINX_ANON_PORT"])

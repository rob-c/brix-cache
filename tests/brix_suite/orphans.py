"""Detect (and reap) test-fleet processes owned by a given TEST_ROOT.

A process is OWNED by a TEST_ROOT when its own argv OR its parent's argv
references that TEST_ROOT path.  The parent-argv rule is essential: an nginx
WORKER's own cmdline is only ``nginx: worker process`` and carries no path, so a
worker is recognised through the MASTER (its parent), whose argv holds
``-p <TEST_ROOT>/registry/<name>``.  Without that rule, a SIGKILL of the master
strands its workers as orphans — one of the two teardown-leak bugs this module
closes.

``cmsd`` is included explicitly in FLEET_EXES: the historical in-conftest reaper
scanned only nginx/xrootd/krb5kdc/kadmind/haproxy, so every ``cmsd`` a manager
lane spawned survived teardown (43 leaked cmsd in the incident that motivated
this).

TEST_ROOT is the ownership boundary — never a shared marker like ``/tmp`` — so a
reap in one lane can never touch a parallel lane bound to a different root, and
the real SYSTEM nginx (``/usr/sbin/nginx -g "daemon on"``, no test path in argv)
is never matched.  That boundary is a WHOLE PATH, not a text fragment: see
``_owns``.
"""
import os
import signal
import subprocess
import time

# Daemons a fleet launches.  Matched by EXACT process name (pgrep -x) so a
# `python -m ... nginx` helper or an editor buffer named "xrootd" is never hit.
FLEET_EXES = ("nginx", "xrootd", "cmsd", "krb5kdc", "kadmind", "haproxy")
FLEET_HELPER_MARKERS = ("/tests/",)


def _cmdline(pid):
    """Argv of ``pid`` as a space-joined string, or "" if it is gone/unreadable."""
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as fh:
            return fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _ppid(pid):
    """Parent pid of ``pid`` from /proc/<pid>/stat (0 if unreadable).

    comm (field 2) is wrapped in parens and may itself contain spaces or ')';
    splitting on the LAST ')' makes the remaining fields positional again, so
    ppid is the second whitespace token after it."""
    try:
        with open("/proc/%s/stat" % pid, "rb") as fh:
            data = fh.read().decode("latin-1")
        return int(data.rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return 0


def _environ(pid):
    """Environment of ``pid`` as bytes, or empty bytes if unreadable."""
    try:
        with open("/proc/%s/environ" % pid, "rb") as fh:
            return fh.read()
    except OSError:
        return b""


def _is_fleet_process(pid, cmd, exes):
    """Return whether a process is a supported daemon/helper executable.

    The registry launches nginx from a per-session copy whose Linux comm is
    randomized (for example ``nginx-5eb3c53f``), so ``pgrep -x nginx`` misses
    exactly the masters and workers the reaper must own.  Python support
    daemons likewise do not put TEST_ROOT in argv, but inherit it in their
    environment.  Keep both matches narrow: only the randomized daemon names
    and test helper command lines qualify.
    """
    comm = _process_name(pid)
    if comm is None:
        return False
    if _daemon_name_matches(comm, exes):
        return True
    return _helper_matches(pid, comm, cmd)


def _process_name(pid):
    try:
        name = open("/proc/%s/comm" % pid, "r").read().strip()
    except OSError:
        return None
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    return name.split("\x00", 1)[0].strip()


def _daemon_name_matches(name, exes):
    return name in exes or ("nginx" in exes and name.startswith("nginx-"))


def _helper_matches(pid, name, command):
    return all((name.startswith("python"), "/tests/" in command,
                "pytest" not in command, bool(_environ(pid))))


def _owns(marker, blob):
    """Whether ``blob`` (argv/environ bytes) references the PATH ``marker``.

    A plain ``marker in blob`` is wrong in both directions, and the failure is a
    cross-lane kill — the one thing this module promises never to do:

      * ``/tmp/xrd-test`` is a literal substring of ``/tmp/xrd-test-a15aa``, so
        the default lane would own — and SIGKILL — every side lane whose root is
        merely spelled as its root plus a suffix.
      * ``/tmp/xrd-test`` also occurs inside ``/var/tmp/xrd-test``, so an
        unrelated absolute path ending in the same tail would be owned too.

    So a hit counts only where the match is a whole path component run: the byte
    before it must start the path (string start, or a shell/environ delimiter)
    and the byte after it must END the path (delimiter or string end) or else
    CONTINUE that same path (``/`` — how ``-p <root>/registry/<name>`` is owned
    by <root>).
    """
    lead = b" \t\r\n\"'=:,\x00"
    tail = b"/ \t\r\n\"'=:,\x00"
    start = 0
    while True:
        hit = blob.find(marker, start)
        if hit < 0:
            return False
        if _bounded_hit(marker, blob, hit, lead, tail):
            return True
        start = hit + 1


def _bounded_hit(marker, blob, hit, lead, tail):
    after = blob[hit + len(marker):hit + len(marker) + 1]
    valid_lead = hit == 0 or blob[hit - 1:hit] in lead
    valid_tail = not after or after in tail
    return valid_lead and valid_tail


def owns(test_root, text):
    """Whether ``text`` (a cmdline or environ blob, str or bytes) references a
    path at or under ``test_root``.

    ``_owns`` with the caller's root resolved for them — exported so the operator
    CLIs that scan cmdlines themselves (``operator_build.brutal_teardown``,
    ``run_suite_unprivileged``) decide ownership by the SAME boundary rule as the
    reaper, instead of each keeping its own substring test.
    """
    if isinstance(text, str):
        text = text.encode("utf-8", "replace")
    return _owns(os.path.realpath(str(test_root)).encode(), text)


def find_orphans(test_root, exes=FLEET_EXES):
    """Return sorted ``[(pid, cmdline)]`` of LIVE fleet processes owned by
    ``test_root`` (own argv or parent argv references it)."""
    marker = os.path.realpath(str(test_root)).encode()
    owned = {}
    pids = _candidate_pids(exes)
    for pid in sorted(pids):
        cmd = _owned_command(pid, marker, exes)
        if cmd is not None:
            owned[pid] = cmd or "<pid %d>" % pid
    return sorted(owned.items())


def _candidate_pids(exes):
    pids = {int(entry) for entry in os.listdir("/proc") if entry.isdigit()}
    for executable in exes:
        pids.update(_pgrep_pids(executable))
    return pids


def _pgrep_pids(executable):
    try:
        result = subprocess.run(["pgrep", "-x", executable],
                                capture_output=True, text=True)
        return {int(line) for line in result.stdout.split() if line.isdigit()}
    except (OSError, ValueError, AttributeError):
        return set()


def _owned_command(pid, marker, exes):
    command = _cmdline(pid)
    if not _is_fleet_process(pid, command, exes):
        return None
    parent = _cmdline(_ppid(pid))
    blobs = (command.encode("utf-8", "replace"),
             parent.encode("utf-8", "replace"), _environ(pid))
    return command if any(_owns(marker, blob) for blob in blobs) else None



class ForeignLaneError(RuntimeError):
    """Raised when a reap is asked for a lane another live process claims.

    Carries ``test_root`` and ``claimants`` so a caller that legitimately means
    it (an operator teardown) can report *whose* lane it is about to take
    rather than printing a pid list.
    """

    def __init__(self, test_root, claimants):
        self.test_root = str(test_root)
        self.claimants = list(claimants)
        super().__init__(
            "%s is claimed by %d live process(es) outside this one: %s — pass "
            "force=True only if you know the claimant is finished"
            % (self.test_root, len(self.claimants),
               ", ".join("%d %s" % (pid, cmd[:60])
                         for pid, cmd in self.claimants[:3])))


def _ancestry(pid=None):
    """The pid chain from ``pid`` (default: this process) up to init.

    A harness reaping its OWN lane runs inside the process that declared it —
    directly, or as an xdist worker whose controller declared it — so "mine"
    means "the claimant is me or an ancestor of me".
    """
    pid = os.getpid() if pid is None else int(pid)
    chain = []
    while pid > 0 and pid not in chain:
        chain.append(pid)
        pid = _ppid(pid)
    return chain


def _declared_root(pid):
    """The value of ``TEST_ROOT`` in ``pid``'s environment, or None.

    Declaration, not reference: `_owns` answers "does this process touch that
    tree", which every daemon in a lane does.  Only a harness *declares* the
    lane, and it is the declaration that says who may end it.
    """
    for entry in _environ(pid).split(b"\x00"):
        if entry.startswith(b"TEST_ROOT="):
            value = entry[len(b"TEST_ROOT="):].decode("utf-8", "replace")
            return os.path.realpath(value) if value else None
    return None


def lane_claimants(test_root, exes=FLEET_EXES, exclude_self=True):
    """LIVE processes that declare ``test_root`` as their own ``TEST_ROOT``.

    Excludes the fleet daemons themselves — they inherit the variable from the
    harness, so counting them would make every lane look claimed — and, by
    default, this process and its ancestors, so a harness tearing down its own
    lane is never blocked by itself.

    A non-empty result means the lane belongs to something that is still
    running.  Nothing in a `ps` listing distinguishes that from a lane whose
    owner died, which is why this reads the declaration instead of the
    command line.
    """
    marker = os.path.realpath(str(test_root))
    mine = set(_ancestry()) if exclude_self else set()
    claimants = {}
    entries = filter(str.isdigit, os.listdir("/proc"))
    for pid in map(int, entries):
        if pid in mine:
            continue
        command = _cmdline(pid)
        matches = all((not _is_fleet_process(pid, command, exes),
                       _declared_root(pid) == marker))
        if matches:
            claimants[pid] = command or "<pid %d>" % pid
    return sorted(claimants.items())


#: What a lane's OWNER looks like on the command line.  Deliberately a short
#: explicit list rather than a heuristic: a false negative here reopens the
#: cross-session kill this gate exists to prevent, so the entries are the
#: harness entry points that actually start fleets, and nothing else.
HARNESS_MARKERS = ("pytest", "manage_test_servers", "brixtest", "run_suite")


def _is_harness_cmd(cmd):
    """Whether a command line is a harness ENTRY POINT, not merely near one.

    Matched against each argv token's BASENAME, never the raw string.  A raw
    substring test reads the directories a process works in as if they were
    the program it runs, and the directories are exactly where these words
    turn up by accident: every path under pytest's own ``tmp_path`` begins
    ``/tmp/pytest-of-<user>/``, so under a plain ``"pytest" in cmd`` any tool
    handed a temp path — a linter, a fixture's helper, an unrelated worker —
    is read as a running pytest and holds the lane it merely borrowed.

    Basenames keep both real spellings: ``python -m pytest`` puts the marker in
    a token of its own, and ``-m cmdscripts.manage_test_servers`` has no
    separator for ``basename`` to strip.
    """
    return any(marker in os.path.basename(token)
               for token in cmd.split()
               for marker in HARNESS_MARKERS)


def lane_harnesses(test_root, exes=FLEET_EXES, exclude_self=True):
    """The claimants that are test HARNESSES — the ones a reap must not cut off.

    Narrower than :func:`lane_claimants` on purpose.  ``TEST_ROOT`` is inherited
    by everything a harness shell launches, so a lane legitimately shows live
    processes that merely *use* its tree — a CodeChecker analyze fleet working
    in ``<root>/tmp/…``, a container init — and none of them owns the fleet or
    would be harmed by its teardown.  Blocking on those would break the routine
    case (a harness reaping the default lane) to guard against the rare one.

    So: :func:`lane_claimants` answers "who is live in this lane" for the
    operator view, and this answers "whose lane is it" for the reaper.
    """
    return [(pid, cmd)
            for pid, cmd in lane_claimants(test_root, exes, exclude_self)
            if _is_harness_cmd(cmd)]


def live_lanes(exes=FLEET_EXES):
    """Every lane a live process claims, as ``{test_root: [(pid, cmdline)]}``.

    The operator view behind "which lanes are in use on this host" — and the
    check to run BEFORE a reap, since it answers the question a per-root query
    cannot: not "who is in this lane" but "which lanes are anyone's".
    """
    lanes = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        cmd = _cmdline(pid)
        if _is_fleet_process(pid, cmd, exes):
            continue
        root = _declared_root(pid)
        if root:
            lanes.setdefault(root, []).append((pid, cmd or "<pid %d>" % pid))
    return {root: sorted(procs) for root, procs in lanes.items()}

def kill_orphans(test_root, exes=FLEET_EXES, grace=1.0, force=False):
    """Reap every fleet process owned by ``test_root``: SIGTERM the current set,
    wait ``grace`` seconds, then SIGKILL whatever remains (survivors plus any
    worker re-parented in between).  Returns the list of ``(pid, cmdline)`` that
    were STILL alive after the SIGKILL pass — the empty list means a clean reap.

    Refuses with :class:`ForeignLaneError` when a live process outside this
    one's ancestry claims the lane, unless ``force=True``.

    The refusal exists because the boundary this module enforces so carefully
    is the one the CALLER supplies, and a caller who names the wrong root gets
    a precise, thorough, cross-session kill.  That happened: a lane root read
    off a `ps` listing looked like an abandoned fleet and was in fact a
    concurrent run's, and ~200 of its processes were killed mid-suite.  The
    lane is derived from the test file name (`test_audit16aa…` →
    `/tmp/xrd-16aa`), so nothing about the listing looked wrong.  Checking is
    cheap, the failure is expensive and silent, and a harness reaping its own
    lane is exempt automatically — so the check is on by default rather than
    documented as the caller's job.
    """
    claimants = []
    if not force:
        claimants = lane_harnesses(test_root, exes)
    if claimants:
        raise ForeignLaneError(test_root, claimants)
    owned = find_orphans(test_root, exes)
    _signal_processes(owned, signal.SIGTERM)
    if owned:
        time.sleep(grace)
    _signal_processes(find_orphans(test_root, exes), signal.SIGKILL)
    if owned:
        time.sleep(0.3)
    return find_orphans(test_root, exes)


def _signal_processes(processes, selected):
    for pid, _command in processes:
        try:
            os.kill(pid, selected)
        except (OSError, ValueError):
            pass

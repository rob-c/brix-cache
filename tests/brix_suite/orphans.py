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
import re
import signal
import subprocess
import sys
import time
from lib_py.process_host import native_process_table, procfs_available

# Daemons a fleet launches.  Matched by an EXACT process name or argv[0]
# basename so a `python -m ... nginx` helper or an editor buffer named
# "xrootd" is never hit.  The argv fallback matters for Nix wrappers: a copied
# executable named `cmsd` re-execs the store interpreter, so Linux reports
# `python3.13` in comm while preserving the exact `cmsd` invocation in argv[0].
FLEET_EXES = ("nginx", "xrootd", "cmsd", "krb5kdc", "kadmind", "haproxy")
FLEET_HELPER_MARKERS = ("/tests/",)


#: procfs is the primary, read-only process source.  Hosts without it
#: (Darwin/BSD) fall back to one ``ps`` snapshot per query burst below.
_HAVE_PROCFS = procfs_available()


def _all_pids():
    """Every live pid on the host."""
    if _HAVE_PROCFS:
        return [int(entry) for entry in os.listdir("/proc") if entry.isdigit()]
    return list(_ps_table())


_PS_CACHE = {"at": 0.0, "table": {}}
_PS_TTL = 1.0


def _refresh_ps_cache():
    if not _HAVE_PROCFS:
        _PS_CACHE["at"], _PS_CACHE["table"] = 0.0, {}


def _ps_snapshot():
    """Native BSD argv/environment rows; failed inspection is not an empty host."""
    environment_flag = "-e" if sys.platform.startswith("freebsd") else "-E"
    try:
        result = subprocess.run(
            ["ps", "-ax", environment_flag, "-ww", "-o", "pid=", "-o", "ppid=",
             "-o", "ucomm=", "-o", "command="],
            capture_output=True, text=True, check=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("cannot inspect native process ownership") from error
    if not result.stdout.strip():
        raise RuntimeError("native process ownership snapshot is empty")
    return result.stdout.splitlines()


def _ps_split_command(command):
    """Darwin appends the environment; FreeBSD prepends it to the command."""
    argv, env = [], []
    for token in command.split():
        destination = env if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token) else argv
        destination.append(token)
    return argv, env


def _ps_parse(line):
    """One ps row → (pid, (ppid, comm, argv, environ_tokens)) or None."""
    parts = line.split(None, 3)
    if len(parts) < 3 or not parts[0].isdigit():
        return None
    ppid = int(parts[1]) if parts[1].isdigit() else 0
    argv, env = _ps_split_command(parts[3] if len(parts) > 3 else "")
    return int(parts[0]), (ppid, os.path.basename(parts[2]), argv, env)


def _ps_table():
    """``{pid: (ppid, comm, argv, environ_tokens)}`` from a host snapshot.

    Native BSD/macOS APIs retain argument and environment boundaries: values
    containing spaces must never impersonate a harness argument. Cached for
    ``_PS_TTL`` seconds because the reaper asks about hundreds of pids per pass.
    """
    now = time.monotonic()
    if now - _PS_CACHE["at"] < _PS_TTL and _PS_CACHE["table"]:
        return _PS_CACHE["table"]
    table = _host_process_table()
    # A busy host can take longer than the TTL to read. Start cache age after
    # collection, or every PID lookup immediately repeats the whole snapshot.
    _PS_CACHE["at"], _PS_CACHE["table"] = time.monotonic(), table
    return table


def _host_process_table():
    """Select the host reader separately from snapshot caching."""
    if sys.platform == "darwin" or sys.platform.startswith("freebsd"):
        return native_process_table()
    rows = (_ps_parse(line) for line in _ps_snapshot())
    return dict(row for row in rows if row is not None)


def _cmdline(pid):
    """Argv of ``pid`` as a space-joined string, or "" if it is gone/unreadable."""
    return " ".join(_process_argv(pid)).strip()


def _process_argv(pid):
    """Read argument boundaries so option values cannot impersonate a program."""
    if not _HAVE_PROCFS:
        row = _ps_table().get(int(pid))
        return list(row[2]) if row else []
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as fh:
            return fh.read().decode("utf-8", "replace").rstrip("\0").split("\0")
    except OSError:
        return []


def _ppid(pid):
    """Parent pid of ``pid`` from /proc/<pid>/stat (0 if unreadable).

    comm (field 2) is wrapped in parens and may itself contain spaces or ')';
    splitting on the LAST ')' makes the remaining fields positional again, so
    ppid is the second whitespace token after it."""
    if not _HAVE_PROCFS:
        row = _ps_table().get(int(pid))
        return row[0] if row else 0
    try:
        with open("/proc/%s/stat" % pid, "rb") as fh:
            data = fh.read().decode("latin-1")
        return int(data.rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return 0


def _environ(pid):
    """Environment of ``pid`` as bytes, or empty bytes if unreadable."""
    if not _HAVE_PROCFS:
        row = _ps_table().get(int(pid))
        return b"\x00".join(tok.encode("utf-8", "replace") for tok in (row[3] or [])) if row else b""
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
    if (_daemon_name_matches(comm, exes)
            or _argv_daemon_name_matches(pid, exes)):
        return True
    return _helper_matches(pid, comm, cmd)


def _argv_daemon_name_matches(pid, exes):
    arguments = _process_argv(pid)
    return bool(arguments) and _daemon_name_matches(
        os.path.basename(arguments[0]), exes)


def _process_name(pid):
    if not _HAVE_PROCFS:
        row = _ps_table().get(int(pid))
        return row[1] if row else None
    try:
        name = open("/proc/%s/comm" % pid, "r").read().strip()
    except OSError:
        return None
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    return name.split("\x00", 1)[0].strip()


def _daemon_name_matches(name, exes):
    normalized = name.lower()
    return normalized in exes or ("nginx" in exes
                                  and normalized.startswith("nginx-"))


def _helper_matches(pid, name, command):
    """Only a Python script entrypoint inside this tests tree is a helper.

    A suite runner can carry test paths in --ignore options. Matching those
    arguments used to classify the parent operator as a daemon and kill it.
    """
    if not name.lower().startswith("python") or _is_harness_cmd(command):
        return False
    script = _python_script(_process_argv(pid))
    if script is None or not os.path.isabs(script):
        return False
    tests_root = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
    script = os.path.realpath(script)
    return all((script.endswith(".py"), bool(_environ(pid)),
                os.path.commonpath((tests_root, script)) == tests_root))


def _python_script(arguments):
    """Locate a script after ordinary interpreter flags; modules/code fail closed."""
    for argument in arguments[1:]:
        if argument in ("-u", "-B", "-E", "-I", "-s", "-S", "-P", "-O", "-OO"):
            continue
        return None if argument.startswith("-") else argument
    return None


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
    return any(_owns(marker, text) for marker in _ownership_markers(test_root))


def _ownership_markers(test_root):
    """Raw and resolved spellings of one root (notably /tmp on Darwin)."""
    raw = os.path.abspath(str(test_root)).encode()
    resolved = os.path.realpath(str(test_root)).encode()
    return tuple(dict.fromkeys((raw, resolved)))


def find_orphans(test_root, exes=FLEET_EXES):
    """Return sorted ``[(pid, cmdline)]`` of LIVE fleet processes owned by
    ``test_root`` (own argv or parent argv references it)."""
    _refresh_ps_cache()
    markers = _ownership_markers(test_root)
    owned = {}
    pids = _candidate_pids(exes)
    for pid in sorted(pids):
        cmd = _owned_command(pid, markers, exes)
        if cmd is not None:
            owned[pid] = cmd or "<pid %d>" % pid
    return sorted(owned.items())


def _listening_socket_inodes(port):
    """Kernel socket inodes listening on ``port`` (IPv4 or IPv6).

    Reading procfs is deliberately read-only and avoids shelling out to
    ``ss``/``lsof``, either of which may be absent in a minimal CI image.
    Malformed or permission-denied tables simply provide no ownership proof.
    """
    try:
        port_hex = "%04X" % int(port)
    except (TypeError, ValueError):
        return set()
    if not 0 < int(port) <= 65535:
        return set()
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        inodes.update(_table_listener_inodes(table, port_hex))
    return inodes


def _table_listener_inodes(path, port_hex):
    try:
        rows = open(path, "r", encoding="ascii").read().splitlines()[1:]
    except OSError:
        return set()
    return {_tcp_inode(fields) for row in rows
            if (fields := row.split()) and _tcp_listener(fields, port_hex)}


def _tcp_listener(fields, port_hex):
    return (len(fields) > 9 and fields[3] == "0A"
            and fields[1].rsplit(":", 1)[-1].upper() == port_hex)


def _tcp_inode(fields):
    return fields[9]


def _process_socket_inodes(pid):
    """Socket inodes held by one process, tolerating concurrent process exit."""
    directory = "/proc/%d/fd" % int(pid)
    try:
        entries = os.listdir(directory)
    except OSError:
        return set()
    sockets = set()
    for entry in entries:
        try:
            target = os.readlink(os.path.join(directory, entry))
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            sockets.add(target[8:-1])
    return sockets


def listener_owned_by_test_root(test_root, port, exes=FLEET_EXES):
    """Prove that the listener on ``port`` belongs to this exact test root.

    This is the recovery proof used when an interrupted manager lost its
    manifest or completion marker.  A textual argv match alone is insufficient:
    the process proven to reference ``test_root`` must hold the actual kernel
    listening socket.  Failure to prove ownership is always ``False`` and never
    licenses cleanup of the listener.
    """
    if not _HAVE_PROCFS:
        owners = _listener_pids_lsof(port)
        return bool(owners) and any(pid in owners
                                    for pid, _command in find_orphans(test_root, exes))
    listeners = _listening_socket_inodes(port)
    if not listeners:
        return False
    return any(listeners & _process_socket_inodes(pid)
               for pid, _command in find_orphans(test_root, exes))


def _listener_pids_lsof(port):
    """Pids holding a TCP listener on ``port`` (hosts without /proc/net/tcp)."""
    try:
        out = subprocess.run(
            ["lsof", "-a", "-nP", "-t", "-iTCP:%d" % int(port), "-sTCP:LISTEN"],
            capture_output=True, text=True, check=False, timeout=10,
        ).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return set()
    return {int(tok) for tok in out.split() if tok.isdigit()}


def _candidate_pids(exes):
    pids = set(_all_pids())
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


def _owned_command(pid, markers, exes):
    command = _cmdline(pid)
    if not _is_fleet_process(pid, command, exes):
        return None
    parent = _cmdline(_ppid(pid))
    blobs = (command.encode("utf-8", "replace"),
             parent.encode("utf-8", "replace"), _environ(pid))
    return command if any(_owns(marker, blob)
                          for marker in markers for blob in blobs) else None



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


def _require_readable_native_environment(pid):
    """Refresh one unknown snapshot, but refuse a still-live unknown owner."""
    row = _ps_table().get(int(pid))
    if row is None or row[3] is not None:
        return
    _refresh_ps_cache()
    row = _ps_table().get(int(pid))
    if row is None:
        return
    if row[3] is None:
        raise RuntimeError(f"cannot inspect an owned process environment (pid={pid})")


def _declared_root(pid):
    """The value of ``TEST_ROOT`` in ``pid``'s environment, or None.

    Declaration, not reference: `_owns` answers "does this process touch that
    tree", which every daemon in a lane does.  Only a harness *declares* the
    lane, and it is the declaration that says who may end it.
    """
    if not _HAVE_PROCFS:
        _require_readable_native_environment(pid)
    for entry in _environ(pid).split(b"\x00"):
        if entry.startswith(b"TEST_ROOT="):
            value = entry[len(b"TEST_ROOT="):].decode("utf-8", "replace")
            return os.path.realpath(value) if value else None
    return None


def _claimant_candidate(pid, command, exes, harness_only):
    """Filter known non-harness programs before asking for their private env.

    Unknown argv still requires inspection and may refuse cleanup. A visible
    non-harness is not a lane owner merely because its environment is sealed.
    """
    if _is_fleet_process(pid, command, exes):
        return False
    if harness_only and command:
        return _is_harness_cmd(command)
    return True


def lane_claimants(test_root, exes=FLEET_EXES, exclude_self=True, *, _harness_only=False):
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
    _refresh_ps_cache()
    marker = os.path.realpath(str(test_root))
    mine = set(_ancestry()) if exclude_self else set()
    claimants = {}
    for pid in _all_pids():
        if pid in mine:
            continue
        command = _cmdline(pid)
        if not _claimant_candidate(pid, command, exes, _harness_only):
            continue
        if _declared_root(pid) == marker:
            claimants[pid] = command or "<pid %d>" % pid
    return sorted(claimants.items())


#: What a lane's OWNER looks like on the command line.  Deliberately a short
#: explicit list rather than a heuristic: a false negative here reopens the
#: cross-session kill this gate exists to prevent, so the entries are the
#: harness entry points that actually start fleets, and nothing else.
HARNESS_MARKERS = ("pytest", "manage_test_servers", "brixtest", "run_suite",
                   "operator_runtime")


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
            for pid, cmd in lane_claimants(test_root, exes, exclude_self, _harness_only=True)
            if _is_harness_cmd(cmd)]


def live_lanes(exes=FLEET_EXES):
    """Every lane a live process claims, as ``{test_root: [(pid, cmdline)]}``.

    The operator view behind "which lanes are in use on this host" — and the
    check to run BEFORE a reap, since it answers the question a per-root query
    cannot: not "who is in this lane" but "which lanes are anyone's".
    """
    _refresh_ps_cache()
    lanes = {}
    for pid in _all_pids():
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

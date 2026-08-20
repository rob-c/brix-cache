"""ARCHIVE — the pre-TS-4 flat `fleet_orphans.py`, frozen.

Diffed against `brix_suite/orphans.py` by
`test_ci_ts4_prep_and_declares.py::test_every_moved_body_is_byte_identical`.
Nothing imports this; it exists so "verbatim" is a checkable claim
rather than an assertion in a commit message.
"""

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
    try:
        comm = open("/proc/%s/comm" % pid, "r").read().strip()
        if isinstance(comm, bytes):
            comm = comm.decode("utf-8", "replace")
        comm = comm.split("\x00", 1)[0].strip()
    except OSError:
        return False
    if comm in exes or ("nginx" in exes and comm.startswith("nginx-")):
        return True
    return (comm.startswith("python")
            and "/tests/" in cmd
            and "pytest" not in cmd
            and bool(_environ(pid)))


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
        after = blob[hit + len(marker):hit + len(marker) + 1]
        if ((hit == 0 or blob[hit - 1:hit] in lead)
                and (not after or after in tail)):
            return True
        start = hit + 1


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
    pids = {int(entry) for entry in os.listdir("/proc") if entry.isdigit()}
    # Keep the exact-name probe as well as the /proc sweep.  Besides making the
    # detector cheap on hosts with a large process table, this preserves the
    # old reaper's narrow pgrep contract for callers/tests that virtualise the
    # daemon list; randomized nginx masters are still found by the /proc sweep.
    for exe in exes:
        try:
            listed = subprocess.run(["pgrep", "-x", exe],
                                    capture_output=True, text=True)
            pids.update(int(line) for line in listed.stdout.split()
                        if line.isdigit())
        except (OSError, ValueError, AttributeError):
            pass
    for pid in sorted(pids):
        cmd = _cmdline(pid)
        if not _is_fleet_process(pid, cmd, exes):
            continue
        parent_cmd = _cmdline(_ppid(pid))
        # argv is compared as bytes too: one matcher, one boundary rule, and the
        # decode's U+FFFD replacements can never manufacture a boundary.
        if (_owns(marker, cmd.encode("utf-8", "replace"))
                or _owns(marker, parent_cmd.encode("utf-8", "replace"))
                or _owns(marker, _environ(pid))):
            owned[pid] = cmd or "<pid %d>" % pid
    return sorted(owned.items())


def kill_orphans(test_root, exes=FLEET_EXES, grace=1.0):
    """Reap every fleet process owned by ``test_root``: SIGTERM the current set,
    wait ``grace`` seconds, then SIGKILL whatever remains (survivors plus any
    worker re-parented in between).  Returns the list of ``(pid, cmdline)`` that
    were STILL alive after the SIGKILL pass — the empty list means a clean reap."""
    owned = find_orphans(test_root, exes)
    for pid, _cmd in owned:
        try:
            os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError):
            pass
    if owned:
        time.sleep(grace)
    for pid, _cmd in find_orphans(test_root, exes):
        try:
            os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError):
            pass
    if owned:
        time.sleep(0.3)
    return find_orphans(test_root, exes)

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
is never matched.
"""
import os
import signal
import subprocess
import time

# Daemons a fleet launches.  Matched by EXACT process name (pgrep -x) so a
# `python -m ... nginx` helper or an editor buffer named "xrootd" is never hit.
FLEET_EXES = ("nginx", "xrootd", "cmsd", "krb5kdc", "kadmind", "haproxy")


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


def find_orphans(test_root, exes=FLEET_EXES):
    """Return sorted ``[(pid, cmdline)]`` of LIVE fleet processes owned by
    ``test_root`` (own argv or parent argv references it)."""
    marker = os.path.realpath(str(test_root))
    owned = {}
    for exe in exes:
        try:
            out = subprocess.run(
                ["pgrep", "-x", exe], capture_output=True, text=True
            ).stdout
        except Exception:
            continue
        for tok in out.split():
            try:
                pid = int(tok)
            except ValueError:
                continue
            cmd = _cmdline(pid)
            if marker in cmd or marker in _cmdline(_ppid(pid)):
                owned[pid] = cmd or "<%s pid %d>" % (exe, pid)
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

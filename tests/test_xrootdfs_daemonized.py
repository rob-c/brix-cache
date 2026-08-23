"""
xrootdfs mounted DAEMONIZED — the default invocation, without `-f`.

Why this file exists as its own lane: every other xrootdfs test mounts with
`-f` (see test_xrootdfs.py::_mount), so the documented default — plain
`xrootdfs root://host/ /mnt`, which forks into the background — had no coverage
at all, and shipped broken. fuse_main() daemonizes by forking AFTER the driver
has built its async data-stream manager, and the manager's event-loop thread
does not survive fork(): the daemon inherited the sockets but nobody to drive
them. Metadata still answered (the connection pool is synchronous on the
calling thread), so `ls` and `stat` looked healthy while the first read()
blocked forever in the kernel. The fix forks FIRST, so every thread is created
on the daemon side.

  success:      a daemonized mount serves readdir, stat AND read; bytes are
                byte-exact; the mount is already live when the launcher returns
                (the parent waits for the FUSE session, so `xrootdfs … && ls`
                cannot race); writes reach the origin.
  error:        an unreachable endpoint still exits non-zero with its message
                on stderr and leaves nothing mounted — daemonizing must not
                swallow the exit status the way a bare fuse_daemonize() would.
  security-neg: the daemon must not inherit the launcher's controlling terminal
                or working directory (it is a session leader rooted at /), so a
                mount cannot be steered by, or hold open, the invoking shell.

EVERY read here runs out-of-process behind _read_with_deadline(), which on
expiry DETACHES the mount before reaping. The regression mode is an
uninterruptible (D-state) wait inside the kernel's FUSE client: SIGKILL does
not land until the filesystem answers, so neither an in-process read nor
subprocess.run(timeout=...) can recover — the latter hangs in its own
kill()/wait() cleanup. Detaching the mount is what releases the reader, and it
is the difference between this lane REPORTING the bug and hanging on it.

Run (serial, against a manually-started fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \\
    pytest tests/test_xrootdfs_daemonized.py -v -p no:xdist
"""

import hashlib
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

def _guard_built_1():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")

def _guard_built_2():
    if not _FUSE_OK:
        pytest.skip("no /dev/fuse or fusermount3")

def _guard_built_3(proc):
    if proc.returncode != 0:
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")

def _guard_built_4():
    if not _port_up(SERVER_HOST, NGINX_ANON_PORT):
        pytest.skip("anon server not running")


pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
_XROOTDFS_NAME = os.environ.get("XROOTDFS_BIN", "xrootdfs")
XROOTDFS = _XROOTDFS_NAME if os.path.isabs(_XROOTDFS_NAME) \
    else os.path.join(CLIENT_DIR, "bin", _XROOTDFS_NAME)
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"

_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None

# Long enough that a slow-but-working read still passes, short enough that the
# regression (an infinite block) is reported as a failure in reasonable time.
IO_TIMEOUT = 30


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _md5(b):
    return hashlib.md5(b).hexdigest()


@pytest.fixture(scope="module")
def built():
    _guard_built_1()
    _guard_built_2()
    proc = subprocess.run(["make", "-C", CLIENT_DIR, os.path.basename(XROOTDFS)],
                          capture_output=True, text=True, timeout=300)
    _guard_built_3(proc)
    _guard_built_4()
    return True


@pytest.fixture()
def remote_file(built):
    """A known file in the shared data root the anon export serves."""
    name = f"_xrdfsd_{os.getpid()}_{int(time.time() * 1000)}.bin"
    payload = os.urandom(200000)
    path = os.path.join(DATA_ROOT, name)
    with open(path, "wb") as fh:
        fh.write(payload)
    yield name, payload
    try:
        os.unlink(path)
    except OSError:
        pass


class _DaemonMount:
    """A mount made WITHOUT -f: xrootdfs forks and the launcher returns."""

    def __init__(self, mnt):
        self.mnt = mnt

    def __enter__(self):
        return self

    def detach(self):
        """Lazily unmount. Idempotent, and safe while a read is wedged.

        `-z` (detach now, clean up when idle) is required, not cosmetic: a plain
        `fusermount3 -u` refuses a busy mount, and the mount is busy precisely
        when a reader is stuck in it.
        """
        subprocess.run(["fusermount3", "-u", "-z", self.mnt], capture_output=True)
        for _ in range(100):
            if not os.path.ismount(self.mnt):
                return
            time.sleep(0.1)

    def __exit__(self, *exc):
        self.detach()
        # Reap the daemon by mountpoint. A healthy driver exits on its own once
        # the session is torn down; a WEDGED one does not, and because it is an
        # orphan (its launcher already exited) nothing else will collect it —
        # leaking one per test would slowly fill the box during a failing run.
        subprocess.run(["pkill", "-9", "-f", f"xrootdfs.*{self.mnt}"],
                       capture_output=True)
        try:
            os.rmdir(self.mnt)
        except OSError:
            pass


def _mount_daemonized(*conn_args):
    """Mount the default way — no -f — and return once the launcher exits."""
    mnt = subprocess.check_output(
        ["mktemp", "-d", os.path.join(os.environ["TMPDIR"], "xrdfsd.XXXXXX")]
    ).decode().strip()
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)

    proc = subprocess.run([XROOTDFS, *conn_args, ANON_URL, mnt],
                          env=env, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 or not os.path.ismount(mnt):
        subprocess.run(["fusermount3", "-u", "-z", mnt], capture_output=True)
        try:
            os.rmdir(mnt)
        except OSError:
            pass
        pytest.skip("daemonized xrootdfs failed to mount "
                    f"(rc={proc.returncode}, unprivileged FUSE unavailable?): "
                    f"{proc.stderr}")
    return _DaemonMount(mnt)


class _ReadTimeout(Exception):
    """The read did not return within IO_TIMEOUT; the mount has been detached."""


def _run_with_deadline(m, argv, stdin_bytes=None):
    """Run `argv` against mount `m`, bounded by IO_TIMEOUT.

    Returns (rc, stdout, stderr). On expiry it DETACHES `m` first — an I/O
    request blocked with no server behind it sits in uninterruptible sleep,
    where SIGKILL is queued but never delivered, so detaching the mount is the
    only way to make the process return — and then raises _ReadTimeout.
    subprocess.run(timeout=...) cannot be used here: it raises, then deadlocks
    in its own kill()/wait() cleanup on exactly this case.

    communicate() runs on a daemon thread rather than being polled, because the
    pipes must be DRAINED while we wait: a payload larger than the 64 KiB pipe
    buffer would otherwise block the child on write() forever and look exactly
    like the hang this lane is testing for.
    """
    proc = subprocess.Popen(argv,
                            stdin=subprocess.PIPE if stdin_bytes else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = {}

    def _pump():
        try:
            out, err = proc.communicate(input=stdin_bytes)
            result["rc"], result["out"], result["err"] = proc.returncode, out, err
        except Exception as exc:                      # noqa: BLE001
            result["exc"] = exc

    worker = threading.Thread(target=_pump, daemon=True)
    worker.start()
    worker.join(IO_TIMEOUT)

    if worker.is_alive():
        m.detach()                  # unwedge the process, then let it drain
        worker.join(30)
        raise _ReadTimeout(" ".join(argv))
    if "exc" in result:
        raise result["exc"]
    return result["rc"], result["out"], result["err"]


def _read_with_deadline(m, path):
    """Read `path` out-of-process, bounded by IO_TIMEOUT."""
    return _run_with_deadline(m, ["cat", path])


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_daemonized_read_returns_bytes(built, remote_file):
    """The regression: metadata worked, read() blocked forever."""
    name, payload = remote_file
    with _mount_daemonized() as m:
        target = os.path.join(m.mnt, name)
        try:
            rc, out, err = _read_with_deadline(m, target)
        except _ReadTimeout:
            pytest.fail(
                f"read of a daemonized mount blocked for {IO_TIMEOUT}s — the "
                "async event-loop thread did not survive the daemonize fork, so "
                "nothing drives the data streams (mount with -f as a workaround)")
        assert rc == 0, err
        assert _md5(out) == _md5(payload), \
            "daemonized FUSE read bytes differ from origin"


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_daemonized_metadata_still_works(built, remote_file):
    """readdir + stat: healthy both before and after the fix — the control."""
    name, payload = remote_file
    with _mount_daemonized() as m:
        assert name in os.listdir(m.mnt), "daemonized readdir did not list the file"
        assert os.stat(os.path.join(m.mnt, name)).st_size == len(payload)


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_daemonized_mount_is_live_when_launcher_returns(built, remote_file):
    """No sleep, no poll: `xrootdfs … && cat` must not race the mount.

    The parent blocks until the FUSE session is up, so a script may use the
    mount on the very next line.
    """
    name, payload = remote_file
    with _mount_daemonized() as m:
        # Deliberately no settling delay between mount and first I/O.
        try:
            rc, out, _ = _read_with_deadline(m, os.path.join(m.mnt, name))
        except _ReadTimeout:
            pytest.fail("first read after a daemonized mount never returned")
        assert rc == 0
        assert _md5(out) == _md5(payload)


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_daemonized_write_reaches_origin(built):
    """A write through a daemonized mount lands in the export."""
    payload = os.urandom(65536)
    name = f"_xrdfsd_w_{os.getpid()}_{int(time.time() * 1000)}.bin"
    disk = os.path.join(DATA_ROOT, name)
    try:
        with _mount_daemonized() as m:
            try:
                rc, _, err = _run_with_deadline(
                    m, ["dd", f"of={os.path.join(m.mnt, name)}",
                        "bs=65536", "count=1", "status=none"],
                    stdin_bytes=payload)
            except _ReadTimeout:
                pytest.fail("write to a daemonized mount never completed")
            assert rc == 0, err
        assert os.path.exists(disk), "daemonized write never reached the export"
        with open(disk, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload), "written bytes differ"
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_daemonized_unreachable_endpoint_exits_nonzero(built):
    """Daemonizing must not swallow the failure.

    A bare fuse_daemonize() exits the parent 0 the moment it forks, so a
    connect failure in the child would be invisible to the caller.
    """
    mnt = subprocess.check_output(
        ["mktemp", "-d", os.path.join(os.environ["TMPDIR"], "xrdfsd.XXXXXX")]
    ).decode().strip()
    try:
        env = {k: v for k, v in os.environ.items()}
        env.pop("X509_USER_PROXY", None)
        # Port 1 is reserved and never listening.
        p = subprocess.run([XROOTDFS, f"root://{SERVER_HOST}:1/", mnt],
                           env=env, capture_output=True, text=True, timeout=120)
        assert p.returncode != 0, \
            "daemonized mount of an unreachable endpoint reported success"
        assert "xrootdfs:" in p.stderr, \
            f"connect failure produced no diagnostic on stderr: {p.stderr!r}"
        assert not os.path.ismount(mnt), "failed mount left something mounted"
    finally:
        subprocess.run(["fusermount3", "-u", "-z", mnt], capture_output=True)
        try:
            os.rmdir(mnt)
        except OSError:
            pass


@pytest.mark.skipif(not _FUSE_OK, reason="no /dev/fuse or fusermount3")
def test_daemonized_detaches_from_terminal_and_cwd(built, remote_file):
    """security-neg: the daemon must not keep a handle on the invoking shell.

    A backgrounded mount that stayed in the caller's session and working
    directory would keep the terminal open and pin the cwd (blocking unmount of
    whatever filesystem the caller happened to be sitting on).
    """
    name, _ = remote_file
    with _mount_daemonized() as m:
        pids = subprocess.run(
            ["pgrep", "-f", f"{os.path.basename(XROOTDFS)}.*{m.mnt}"],
            capture_output=True, text=True).stdout.split()
        if not pids:
            pytest.skip("cannot locate the daemon process to inspect")
        pid = pids[0]

        # Session leader: its own sid, not the test runner's.
        stat_line = open(f"/proc/{pid}/stat").read()
        sid = int(stat_line[stat_line.rindex(")") + 2:].split()[3])
        assert sid == int(pid), f"daemon sid {sid} != pid {pid} (not detached)"

        # Rooted at / so it pins no other filesystem.
        assert os.readlink(f"/proc/{pid}/cwd") == "/", "daemon did not chdir(/)"

        # And it is still serving, so detaching did not cost functionality.
        assert name in os.listdir(m.mnt)

"""test_chkpoint_recover_export.py — startup checkpoint recovery vs the export root.

brix_chkpoint_recover_root() (src/protocols/root/write/chkpoint_recover.c) runs in
every worker's init and drops an exclusive lock file at the export root before it
scans for abandoned <path>.ckp snapshots.  That makes worker startup depend on the
WRITABILITY of the export — a coupling with three distinct required behaviours,
one per test here:

  success   a writable export with a stale <path>.ckp is rolled back and the
            snapshot removed (the recovery contract itself still holds).

  tolerance an export this worker cannot write is NOT a recovery failure.  A .ckp
            is only ever produced by a worker writing INTO the root, so a root
            that refuses our writes cannot hold a journal to roll back.  Recovery
            is skipped with a warning and the worker SERVES; it must not die.
            Regression guard: this path used to return NGX_ERROR, which fails
            brix_init_one_server -> the worker exits "fatal code 2 and cannot be
            respawned" while the master keeps the listener bound, so the port
            still accepts TCP and every request hangs forever.

  security  the tolerance is NARROW.  The lock is opened O_NOFOLLOW, so a symlink
            planted at the lock path yields ELOOP — an attacker redirecting the
            lock must still be refused loudly, never swallowed by the skip branch.

Self-provisioning throwaway nginx (same shape as test_acc_residual.py); skips
cleanly when the nginx binary is absent or lacks the engine.

WHY 0555 for the unwritable case: r-x keeps reads and traversal working — the
export must still SERVE, which is the whole claim — while the missing write bit
denies the lock.  The two tolerance tests additionally require master != worker
(see _needs_split_identity): brix already rejects a non-writable export at config
time via access(path, W_OK), so the condition only survives to worker init when
that access() ran as a DIFFERENT (root) uid than the worker.  That is not a
contrivance — root master + unprivileged workers is nginx's default posture, and
it is exactly where the config-time check gives false assurance.
"""

import os
import re
import socket
import struct
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-chkpoint-recover")]

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

LOCK_NAME = ".nginx-xrootd-ckp-recovery.lock"

kXR_login = 3007
kXR_ok = 0


def _have_nginx():
    if not os.path.exists(NGINX_BIN):
        return False
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        return "brix_chkpoint_recover_root" in syms.stdout
    except Exception:
        return True


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed mid-response")
        b += c
    return b


def _serves(port, timeout=6):
    """True when a worker actually answers the root:// handshake+login.

    Deliberately NOT a bare TCP connect: the failure this guards against leaves
    the master's listener bound with no worker behind it, so connect() succeeds
    and the session then hangs.  Only a real login proves a worker is alive.
    """
    try:
        s = socket.create_connection((HOST, port), timeout=timeout)
    except OSError:
        return False
    try:
        s.settimeout(timeout)
        s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(s, 16)
        s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x02", kXR_login, 0x1234,
                              b"anon\x00\x00\x00\x00", 0, 0, 5, 0, 0))
        _sid, status, dlen = struct.unpack("!2sHI", _recv_exact(s, 8))
        if dlen:
            _recv_exact(s, dlen)
        return status == kXR_ok
    except (OSError, EOFError, struct.error):
        return False
    finally:
        s.close()


class _Export:
    """A throwaway anonymous root:// server over a private export root, driven
    through the registry LifecycleHarness."""

    def __init__(self, lifecycle, tmp_path):
        self._lc = lifecycle
        self.root = str(tmp_path)
        self.data = os.path.join(self.root, "data")
        os.makedirs(self.data, exist_ok=True)
        # Default: an export the worker can WRITE, under either harness identity.
        # As root the worker is `nobody` and would otherwise be denied by this
        # root-owned tree (0755) — which is the very condition freeze() sets up
        # deliberately, so it must not be the accidental default here.
        os.chmod(self.root, 0o755)
        os.chmod(self.data, 0o777)
        self.port = None
        self.errlog = None

    def file(self, relpath, data=b"x\n", mode=0o644):
        full = os.path.join(self.data, relpath.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)
        os.chmod(full, mode)
        return full

    def read(self, relpath):
        with open(os.path.join(self.data, relpath.lstrip("/")), "rb") as f:
            return f.read()

    def exists(self, relpath):
        return os.path.exists(os.path.join(self.data, relpath.lstrip("/")))

    def freeze(self):
        """Make the export readable+traversable but NOT writable by the worker."""
        os.chmod(self.data, 0o555)

    def start(self, expect_serving=True):
        ep = self._lc.start(NginxInstanceSpec(
            name="lc-chkpoint-recover",
            template="nginx_lc_chkpoint_recover.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": self.data},
            reason="startup checkpoint recovery vs export writability"))
        self.port = ep.port
        self.errlog = os.path.join(ep.prefix, "logs", "error.log")
        # The master binds the listener before forking the worker, so harness
        # TCP-readiness proves the listener is up but not that worker init (the
        # recovery pass, or any fatal exit) has landed in the log yet; settle
        # briefly so the log-based assertions see it either way.
        time.sleep(0.6)

    def log(self):
        if self.errlog is None:
            return ""
        try:
            with open(self.errlog, "r", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def unfreeze(self):
        # Undo freeze() so pytest's tmp_path teardown can remove the tree.
        try:
            os.chmod(self.data, 0o755)
        except OSError:
            pass


@pytest.fixture
def export(lifecycle, tmp_path):
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without checkpoint recovery")
    srv = _Export(lifecycle, tmp_path)
    try:
        yield srv
    finally:
        srv.unfreeze()


# The unwritable-export condition is only REACHABLE when the worker's identity
# differs from the master's.  brix validates the export at config time with
# access(path, W_OK) (src/core/config/helpers.c), evaluated as the master:
#
#   root master        access() bypasses mode bits -> config accepted -> the
#                      worker (dropped to `nobody`) then hits EACCES on the lock.
#                      This is the deployment the tolerance exists for, and the
#                      one where the config check gives false assurance.
#   unprivileged       master IS the worker, so access() sees the same denial and
#                      nginx -t rejects the config up front — the worker never
#                      starts, so there is nothing for recovery to tolerate.
#
# So these two skip cleanly under a single-user harness rather than pretending to
# cover it.  Constructing the condition there would need EROFS (also caught by the
# same access() check) or chattr +i, both of which need privileges we do not have
# precisely because we are unprivileged.
_needs_split_identity = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="unwritable-export tolerance requires master != worker (root master "
           "-> unprivileged worker); unprivileged, the config-time access(W_OK) "
           "check rejects the export before a worker ever starts",
)


# --------------------------------------------------------------------------- #
# success — the recovery contract still holds on a writable export             #
# --------------------------------------------------------------------------- #

def test_stale_ckp_is_rolled_back_on_a_writable_export(export):
    """<path>.ckp is copied back over <path> and the snapshot removed."""
    export.file("f.txt", b"DIRTY-uncommitted\n")
    export.file("f.txt.ckp", b"SNAPSHOT-committed\n")

    export.start()

    assert _serves(export.port), "worker must serve a writable export"
    # Rollback restores the snapshot's bytes over the dirty file...
    assert export.read("f.txt") == b"SNAPSHOT-committed\n"
    # ...and retires the snapshot, so a later restart is not a second rollback.
    assert not export.exists("f.txt.ckp"), "stale .ckp must be removed"
    assert "checkpoint recovery skipped" not in export.log()


# --------------------------------------------------------------------------- #
# tolerance — an unwritable export is skipped, NOT fatal                       #
# --------------------------------------------------------------------------- #

@_needs_split_identity
def test_unwritable_export_skips_recovery_and_still_serves(export):
    """A worker that cannot write the export must serve reads, not crash-loop."""
    export.file("f.txt", b"readable\n", mode=0o444)
    export.freeze()

    export.start()

    log = export.log()
    # The regression this guards: NGX_ERROR here killed worker init outright.
    assert "cannot be respawned" not in log, (
        "worker died on an unwritable export; recovery must skip, not fail:\n"
        + log[-2000:]
    )
    assert "checkpoint recovery skipped" in log, (
        "expected the skip warning on an unwritable export:\n" + log[-2000:]
    )
    # The whole point of skipping: the export still serves.
    assert _serves(export.port), (
        "worker must still answer after skipping recovery:\n" + log[-2000:]
    )
    # And it is a warning, not an error — an unwritable export is a supported
    # (read-only) deployment, not a misconfiguration to shout about.
    assert not re.search(r"\[error\].*checkpoint recovery", log)


@_needs_split_identity
def test_unwritable_export_does_not_create_a_lock(export):
    """The skip must leave no lock behind — it never opened one."""
    export.file("f.txt", b"readable\n", mode=0o444)
    export.freeze()

    export.start()

    assert "checkpoint recovery skipped" in export.log()
    assert not export.exists(LOCK_NAME)


# --------------------------------------------------------------------------- #
# security-negative — the tolerance must not swallow a symlink attack          #
# --------------------------------------------------------------------------- #

def test_symlinked_lock_path_is_refused_not_skipped(export):
    """O_NOFOLLOW => ELOOP, which is NOT in the tolerated errno set.

    A symlink planted at the lock path is an attempt to make worker init create
    or lock a file outside the export.  ELOOP must fail loudly; if the skip
    branch ever widened to a blanket "open failed -> carry on", this silently
    becomes a no-op and the guard is gone.
    """
    export.file("f.txt", b"readable\n")
    target = os.path.join(export.root, "outside-the-export")
    os.symlink(target, os.path.join(export.data, LOCK_NAME))

    export.start()

    log = export.log()
    assert "checkpoint recovery lock failed" in log, (
        "a symlinked lock path must be refused:\n" + log[-2000:]
    )
    assert "checkpoint recovery skipped" not in log, (
        "ELOOP must NOT be tolerated as an unwritable-export skip:\n" + log[-2000:]
    )
    # It must never have followed the symlink to touch the outside path.
    assert not os.path.exists(target), "O_NOFOLLOW must not create the link target"

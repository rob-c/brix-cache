"""
tests/test_frm_staging.py

Nearline (tape) recall UX, modernised 2026-07-18 for the src/frm dissolution.

The original drove recall by marking a file offline with a ``user.frm.residency``
xattr on a plain ``posix:`` export and letting the legacy FRM open-staging gate
recall it on open.  That gate has been retired: the offline/recall model now lives
in the storage BACKEND's residency seam (``brix_vfs_residency``, phase-64 §9), and
the live nearline-serving surface is the ``frm://exec`` MSS backend composed with a
``brix_cache_store`` recall target — the recall runs in the cache-fill path exactly
as in tests/test_frm_async.py.  A ``posix:`` export therefore no longer recalls on
open, so the recall cases are rebuilt on ``frm://exec``.

Kept on ``posix:`` (unchanged behaviour, still true):
  * an online file is NOT reported offline on stat;
  * the FRM residency xattr does NOT drive the stat offline flag on a posix export
    (residency is a backend property, not a filesystem xattr).

Rebuilt on ``frm://exec`` (the live recall surface):
  S  a read of a nearline object recalls it and serves the true tape bytes;
  S  N concurrent reads of one nearline object collapse to exactly ONE recall (the
     cache tier single-flights the fill — empirically 8 opens → 1 exec recall);
  E  a nearline object whose recall verb FAILS returns an error, not a hang.

Deferred (asserts a path not yet on the live surface):
  * the unified transfer-ledger ``kind=tape`` line is emitted only by the
    stage_engine RECALL path; driving that from a read/prepare is the future
    engine-integration step flagged in src/protocols/root/query/prepare.c
    (``the former frm_stage_kick() ... moves to brix_stage_submit(RECALL)``).  The
    read-fault recall in sd_frm is synchronous and writes no ledger line, so the
    assertion is skipped until that integration lands.

Self-contained: own nginx on a dedicated port, no fleet.  Skips cleanly without
the xrootd client tools or (for the two posix stat cases) user xattrs.
"""

import os
import shutil
import socket
import struct
import subprocess
import time

import pytest

from cmdscripts import frm_stagecmd
from settings import NGINX_BIN, free_port, HOST, BIND_HOST
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure

pytestmark = pytest.mark.uses_lifecycle_harness

PORT = int(os.environ.get("TEST_FRM_STAGING_PORT") or free_port())

kXR_login   = 3007
kXR_stat    = 3017
kXR_ok      = 0
kXR_offline = 8

XRDCP = shutil.which("xrdcp")
XRDFS = shutil.which("xrdfs")

TAPE_BYTES = b"TAPE-RECALLED-CONTENT-" + b"z" * 200 + b"\n"

from frm_helpers import xattr_ok as _xattr_ok


# --------------------------------------------------------------------------- wire
def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    _, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return status, (_recv_exact(sock, dlen) if dlen else b"")


def _session(port):
    sock = socket.create_connection((HOST, port), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    assert _read_response(sock)[0] == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00",
                             0, 0, 5, 0, 0))
    assert _read_response(sock)[0] == kXR_ok
    return sock


def _stat_flags(port, path):
    """Return the integer flags field from a kXR_stat response for `path`."""
    s = _session(port)
    pb = path.encode() + b"\x00"
    req = struct.pack("!2sHB11s4sI", b"\x00\x07", kXR_stat, 0,
                      b"\x00" * 11, b"\x00" * 4, len(pb))
    s.sendall(req + pb)
    status, body = _read_response(s)
    s.close()
    assert status == kXR_ok, f"stat status {status}: {body!r}"
    parts = body.rstrip(b"\x00").split()
    return int(parts[2])


# ------------------------------------------------------------------ posix fixture
@pytest.fixture
def posix_stat(lifecycle, tmp_path):
    """A plain posix export carrying an xattr-marked file — used only to prove the
    posix backend does NOT treat the FRM residency xattr as a stat signal."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")

    d = tmp_path
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    (data / "online.bin").write_bytes(b"resident-bytes\n")
    stub = data / "near.dat"
    stub.write_bytes(b"")
    os.setxattr(str(stub), "user.frm.residency", b"nearline")

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-frm-posix-stat",
            template="nginx_lc_frm_posix_stat.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
            reason="frm posix stat semantics"))
    except RegistryCommandFailure as exc:
        pytest.skip(f"posix stat server did not start: {exc}")

    class S:
        pass
    s = S()
    s.port = ep.port
    yield s


def test_online_file_not_offline(posix_stat):
    assert (_stat_flags(posix_stat.port, "/online.bin") & kXR_offline) == 0


def test_nearline_xattr_not_a_stat_signal(posix_stat):
    """kXR_stat's offline flag comes from the storage BACKEND's residency model
    (the brix_vfs_residency seam), NOT the legacy user.frm.residency xattr.  An
    xattr-marked file on a POSIX export is therefore NOT flagged offline."""
    assert (_stat_flags(posix_stat.port, "/near.dat") & kXR_offline) == 0, \
        "the FRM residency xattr must NOT drive the stat offline flag on a posix export"


# ------------------------------------------------------------- frm://exec fixture
@pytest.fixture
def frm_recall(lifecycle, tmp_path):
    """The live nearline surface: frm://exec MSS backend + posix cache store."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if XRDCP is None:
        pytest.skip("xrdcp not available")

    d = tmp_path
    (d / "logs").mkdir()
    base = d / "base"; base.mkdir()
    tape = d / "tape"; tape.mkdir()
    cache = d / "cache"; cache.mkdir()
    recall_log = d / "recall.log"

    (tape / "near.dat").write_bytes(TAPE_BYTES)
    (tape / "dedup.dat").write_bytes(TAPE_BYTES)
    # failfile.dat is present on tape but its recall verb fails.
    (tape / "failfile.dat").write_bytes(b"unrecallable\n")

    # Exec MSS adapter: every recall appends "recall <key>" to recall_log so the
    # dedup test can count them; recall of the fail key exits non-zero so an
    # unrecallable object errors rather than hangs. Config rides in a JSON
    # sidecar (nginx rewrites its worker environ — a spawned command sees only
    # argv plus BRIX_FRM_STAGECMD).
    stagecmd = frm_stagecmd.install(
        d, tape=str(tape), failkey="failfile.dat", recall_log=str(recall_log))

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-frm-recall",
            template="nginx_lc_frm_exec.conf",
            protocol="root",
            readiness="tcp",
            template_values={"STORAGE_BACKEND": f"frm://exec{base}",
                             "CACHE_DIR": str(cache)},
            env={"BRIX_FRM_STAGECMD": str(stagecmd)},
            reason="frm nearline recall (frm://exec)"))
    except RegistryCommandFailure as exc:
        pytest.skip(f"recall server did not start: {exc}")

    class S:
        pass
    s = S()
    s.port = ep.port
    s.tape_content = TAPE_BYTES
    s.recall_log = str(recall_log)
    yield s


def _xrdcp(port, path, out, timeout=30):
    return subprocess.run(
        [XRDCP, "-f", "-s", f"root://{HOST}:{port}/{path}", out],
        capture_output=True, timeout=timeout)


def _recall_count(recall_log):
    if not os.path.exists(recall_log):
        return 0
    return sum(1 for ln in open(recall_log) if ln.startswith("recall "))


def test_open_nearline_stages_and_serves(frm_recall, tmp_path):
    out = str(tmp_path / "near.out")
    r = _xrdcp(frm_recall.port, "/near.dat", out)
    assert r.returncode == 0, f"xrdcp failed: {r.stderr.decode(errors='replace')}"
    assert open(out, "rb").read() == frm_recall.tape_content, \
        "recalled content does not match the tape bytes"


def test_concurrent_opens_dedup_to_one_recall(frm_recall, tmp_path):
    # NB: DEVNULL, not PIPE — an unread PIPE fills with xrdcp's progress output
    # and blocks the child.
    procs = [subprocess.Popen(
                [XRDCP, "-f", "-s", f"root://{HOST}:{frm_recall.port}//dedup.dat",
                 str(tmp_path / f"d{i}.out")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for i in range(8)]
    for p in procs:
        p.wait(timeout=30)
    ok = sum(1 for p in procs if p.returncode == 0)
    assert ok >= 1, "no concurrent xrdcp succeeded"
    n = _recall_count(frm_recall.recall_log)
    assert n == 1, \
        f"expected exactly one recall for 8 concurrent opens (cache single-flight), got {n}"


def test_failed_recall_returns_error_not_hang(frm_recall, tmp_path):
    # failfile.dat's recall verb exits non-zero → the open must error, not stall.
    r = _xrdcp(frm_recall.port, "/failfile.dat", str(tmp_path / "f.out"), timeout=30)
    assert r.returncode != 0, "open of an unstageable file should fail, not hang"


@pytest.mark.skip(reason="unified transfer-ledger kind=tape line is emitted only by "
                         "the stage_engine RECALL path; driving it from a read/prepare "
                         "is the future engine-integration step noted in "
                         "src/protocols/root/query/prepare.c (frm_stage_kick -> "
                         "brix_stage_submit(RECALL)). The sd_frm read-fault recall is "
                         "synchronous and writes no ledger line.")
def test_recall_emits_unified_tape_audit_line(frm_recall, tmp_path):
    pass

"""
Phase 40 (a) — native client (xrdcp) robustness edges.

WHAT: Verifies the synchronous xrdcp transfer engine never leaves a corrupt or
      half-written local destination, and that a checksum hiccup can't delete a
      byte-perfect download. Covers:
        - atomic temp+rename (no .xrdcp-tmp.* orphan after success)
        - refuse-overwrite without -f / overwrite with -f
        - checksum MISMATCH removes the destination + nonzero exit
        - checksum match keeps the destination
        - SIGINT mid-transfer leaves NO partial destination and NO temp sibling
WHY:  These are the "more robust" guarantees of Phase 40 (a): an interrupted or
      failed copy must be all-or-nothing on the final path, and the control-plane
      (checksum query) must never destroy good data.
HOW:  Drives the real `xrdcp` binary against the already-running anon root://
      server on :11094 (export root /tmp/xrd-test/data). Skips cleanly if that
      server or its fixtures are not present. The transfer's atomicity is the
      invariant asserted; the SIGINT test asserts the invariant regardless of
      whether it caught the transfer mid-flight (robust to machine speed).
"""
import os
import signal
import socket
import subprocess
import time

import pytest
from settings import HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

ROOT_HOST, ROOT_PORT = HOST, 11094
# The export of the :11094 server for the ACTIVE posture — never a literal
# /tmp/xrd-test, which under the unprivileged runner is the (stale) root tree.
DATA_DIR = os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "data")
SMALL = "//test.txt"          # 24 bytes, "hello from nginx-xrootd"
BIG = "//large200.bin"        # 200 MiB — big enough to interrupt mid-flight


def _server_up():
    try:
        with socket.create_connection((ROOT_HOST, ROOT_PORT), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not os.path.exists(XRDCP)
    or not _server_up()
    or not os.path.exists(os.path.join(DATA_DIR, "test.txt")),
    reason="needs built xrdcp + running anon root:// server on :11094 with fixtures",
)


def _url(path):
    return f"root://{ROOT_HOST}:{ROOT_PORT}{path}"


def _run(args, timeout=60):
    """Run xrdcp with a clean env (no stray BEARER_TOKEN noise)."""
    env = dict(os.environ)
    env.pop("BEARER_TOKEN", None)
    return subprocess.run([XRDCP] + args, env=env, capture_output=True,
                          text=True, timeout=timeout)


def _temps(dest):
    """List any leftover atomic temp siblings for `dest`."""
    d, base = os.path.dirname(dest), os.path.basename(dest)
    pre = base + ".xrdcp-tmp."
    return [f for f in os.listdir(d) if f.startswith(pre)]


def test_download_atomic_no_temp_leftover(tmp_path):
    dest = str(tmp_path / "out.txt")
    r = _run(["-f", "-s", _url(SMALL), dest])
    assert r.returncode == 0, r.stderr
    assert open(dest, "rb").read() == b"hello from nginx-xrootd\n"
    assert _temps(dest) == [], "atomic temp sibling was left behind"


def test_refuse_overwrite_without_force(tmp_path):
    dest = str(tmp_path / "out.txt")
    dest_path = tmp_path / "out.txt"
    dest_path.write_bytes(b"ORIGINAL-CONTENT")
    r = _run(["-s", _url(SMALL), dest])
    assert r.returncode != 0
    # The pre-existing file must be untouched (not clobbered, not truncated).
    assert dest_path.read_bytes() == b"ORIGINAL-CONTENT"
    assert _temps(dest) == []


def test_force_overwrites(tmp_path):
    dest_path = tmp_path / "out.txt"
    dest_path.write_bytes(b"ORIGINAL-CONTENT")
    r = _run(["-f", "-s", _url(SMALL), str(dest_path)])
    assert r.returncode == 0, r.stderr
    assert dest_path.read_bytes() == b"hello from nginx-xrootd\n"


def test_cksum_mismatch_removes_dest(tmp_path):
    dest = str(tmp_path / "ck.txt")
    # A literal that cannot match the file's real adler32 → genuine mismatch.
    r = _run(["-f", "-s", "--cksum", "adler32:0000dead", _url(SMALL), dest])
    assert r.returncode != 0
    assert not os.path.exists(dest), "a checksum-mismatched download was left in place"
    assert _temps(dest) == []


def test_cksum_match_keeps_dest(tmp_path):
    import zlib
    real = "%08x" % zlib.adler32(open(os.path.join(DATA_DIR, "test.txt"), "rb").read())
    dest = str(tmp_path / "ck.txt")
    r = _run(["-f", "-s", "--cksum", f"adler32:{real}", _url(SMALL), dest])
    assert r.returncode == 0, r.stderr
    assert os.path.exists(dest)
    assert open(dest, "rb").read() == b"hello from nginx-xrootd\n"


@pytest.mark.skipif(not os.access(DATA_DIR, os.W_OK),
                    reason="needs a writable server export dir for fixtures")
def test_parallel_batch_same_basename_not_corrupt(tmp_path):
    """`-j` batch workers are threads sharing one pid; two same-basename sources
    into one dir must NOT collide on the temp name and interleave-corrupt it.
    After the unique-temp fix the result is always a byte-INTACT copy of one of
    the two inputs (last rename wins), never a garbage interleave."""
    import hashlib
    a_dir = os.path.join(DATA_DIR, "p40_a")
    b_dir = os.path.join(DATA_DIR, "p40_b")
    os.makedirs(a_dir, exist_ok=True)
    os.makedirs(b_dir, exist_ok=True)
    a_blob, b_blob = b"A" * (10 << 20), b"B" * (10 << 20)  # >8MiB chunk → multi-write
    try:
        with open(os.path.join(a_dir, "f.dat"), "wb") as f:
            f.write(a_blob)
        with open(os.path.join(b_dir, "f.dat"), "wb") as f:
            f.write(b_blob)
        md5s = {hashlib.md5(a_blob).hexdigest(), hashlib.md5(b_blob).hexdigest()}
        for _ in range(3):
            destdir = tmp_path / "d"
            if destdir.exists():
                for f in os.listdir(destdir):
                    os.unlink(destdir / f)
            else:
                destdir.mkdir()
            r = _run(["-f", "-s", "-j", "2",
                      _url("//p40_a/f.dat"), _url("//p40_b/f.dat"), str(destdir) + "/"])
            assert r.returncode == 0, r.stderr
            out = destdir / "f.dat"
            assert out.exists(), "batch produced no output file"
            got = hashlib.md5(out.read_bytes()).hexdigest()
            assert got in md5s, "parallel batch produced a CORRUPT (interleaved) file"
            assert [f for f in os.listdir(destdir) if ".xrdcp-tmp." in f] == []
    finally:
        import shutil
        shutil.rmtree(a_dir, ignore_errors=True)
        shutil.rmtree(b_dir, ignore_errors=True)


@pytest.mark.skipif(not os.path.exists(os.path.join(DATA_DIR, "large200.bin")),
                    reason="needs large200.bin fixture")
def test_sigint_leaves_no_partial_or_temp(tmp_path):
    """SIGINT during a transfer must leave the final path absent-or-complete and
    never an orphan temp — the all-or-nothing invariant, robust to timing."""
    dest = str(tmp_path / "big.bin")
    full = os.path.getsize(os.path.join(DATA_DIR, "large200.bin"))
    env = dict(os.environ)
    env.pop("BEARER_TOKEN", None)
    caught = False
    for _ in range(3):
        for f in _temps(dest):
            os.unlink(os.path.join(tmp_path, f))
        if os.path.exists(dest):
            os.unlink(dest)
        p = subprocess.Popen([XRDCP, "-f", "-s", _url(BIG), dest],
                             env=env, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        time.sleep(0.02)
        p.send_signal(signal.SIGINT)
        rc = p.wait(timeout=60)
        # Invariant 1: never an orphan temp sibling.
        assert _temps(dest) == [], "SIGINT left an orphan .xrdcp-tmp file"
        # Invariant 2: the final path is either absent or byte-complete.
        if os.path.exists(dest):
            assert os.path.getsize(dest) == full, "SIGINT left a PARTIAL destination"
        else:
            caught = True  # interrupted before commit → cleanly removed
            assert rc != 0
    # At least one of the three attempts should have been interrupted mid-flight
    # on a normally-paced host; if all completed first, the invariant still held.
    assert caught or os.path.exists(dest)

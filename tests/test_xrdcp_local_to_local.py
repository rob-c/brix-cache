"""xrdcp local→local + file:// copy (parity-audit §7.17).

BriX used to reject every local→local copy outright ("unsupported copy
direction"); stock xrdcp copies local→local, and file:// already parsed to
the local scheme, so the only missing piece was the direction itself.  The
new copy_l2l.c reuses the transfer pump: a file source opens through the VFS
(size-bounded), stdin is an EOF-driven read; a file destination is an atomic
temp+rename (honoring -f), stdout is a raw write.  --xrate pacing and --cksum
(literal/print, post-commit) ride along.

Entirely fleet-free — every case is pure local I/O.

  * success   — file://→file://, bare local→local, stdin→file, file→stdout,
                and a --cksum literal verify all reproduce byte-exact
  * error     — an existing destination without -f is refused with the "-f"
                message (not the internal VFS flag name); a wrong --cksum
                literal drops the destination
  * security  — a self-copy with -f does not truncate the source to empty
                (atomic temp+rename reads the original inode)

Run:
    PYTHONPATH=tests pytest tests/test_xrdcp_local_to_local.py -v
"""

import hashlib
import os
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

pytestmark = [
    pytest.mark.timeout(60),
    pytest.mark.skipif(not os.path.exists(XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
]

CONTENT = bytes((i * 37 + 13) % 251 for i in range(300 * 1024))


def _src(tmp_path, name="src.bin", data=CONTENT):
    p = tmp_path / name
    p.write_bytes(data)
    return p


class TestLocalToLocalSuccess:

    def test_file_url_both_sides(self, tmp_path):
        src = _src(tmp_path)
        dst = tmp_path / "out.bin"
        res = subprocess.run(
            [XRDCP, "-f", f"file://{src}", f"file://{dst}"],
            capture_output=True, text=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT

    def test_bare_local_paths(self, tmp_path):
        src = _src(tmp_path)
        dst = tmp_path / "out.bin"
        res = subprocess.run([XRDCP, "-f", str(src), str(dst)],
                             capture_output=True, text=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT

    def test_stdin_to_file(self, tmp_path):
        src = _src(tmp_path)
        dst = tmp_path / "out.bin"
        with open(src, "rb") as f:
            res = subprocess.run([XRDCP, "-f", "-", str(dst)],
                                 stdin=f, capture_output=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT

    def test_file_to_stdout(self, tmp_path):
        src = _src(tmp_path)
        res = subprocess.run([XRDCP, str(src), "-"],
                             capture_output=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert res.stdout == CONTENT

    def test_cksum_literal_verify(self, tmp_path):
        src = _src(tmp_path)
        dst = tmp_path / "out.bin"
        digest = hashlib.md5(CONTENT).hexdigest()
        res = subprocess.run(
            [XRDCP, "-f", "--cksum", f"md5:{digest}", str(src), str(dst)],
            capture_output=True, text=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT


class TestLocalToLocalErrors:

    def test_existing_destination_refused(self, tmp_path):
        src = _src(tmp_path)
        dst = tmp_path / "out.bin"
        dst.write_bytes(b"keep me\n")
        res = subprocess.run([XRDCP, str(src), str(dst)],
                             capture_output=True, text=True, timeout=30)
        assert res.returncode != 0
        assert "use -f to overwrite" in res.stderr
        assert "XRDC_VFS_FORCE" not in res.stderr   # no internal flag leak
        assert dst.read_bytes() == b"keep me\n"

    def test_wrong_cksum_drops_destination(self, tmp_path):
        src = _src(tmp_path)
        dst = tmp_path / "out.bin"
        res = subprocess.run(
            [XRDCP, "-s", "-f", "--cksum", "md5:" + "0" * 32,
             str(src), str(dst)],
            capture_output=True, text=True, timeout=30)
        assert res.returncode != 0
        assert not dst.exists()


class TestLocalToLocalHostile:

    def test_self_copy_preserves_source(self, tmp_path):
        """(security-neg) `xrdcp -f X X` must not truncate X to empty — the
        atomic temp+rename reads the original inode, then swaps."""
        src = _src(tmp_path, "self.bin")
        res = subprocess.run([XRDCP, "-f", str(src), str(src)],
                             capture_output=True, text=True, timeout=30)
        # succeeds or refuses, but NEVER leaves a truncated/empty file
        assert src.read_bytes() == CONTENT, "self-copy corrupted the source"

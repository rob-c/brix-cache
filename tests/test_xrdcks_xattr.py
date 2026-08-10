"""xrdcks — XrdCks checksum-in-xattr tool (parity-audit §7.20).

Files often carry a `user.XrdCks.<algo>` extended attribute holding an XRootD
`XrdCksData` checksum record; BriX had no tool to read/write/verify them.
`xrdcks <path> <cksname> [<cksval>|delete]` now does: no value → print the
stored checksum (compute+store on a miss); a hex value → store it; `delete` →
remove it.

The on-disk record is the fixed 96-byte XrdCksData layout (verified against
the stock XrdCksData.hh):
    Name[16]  fmTime[8 BE]  csTime[4 BE]  Rsvd[3]  Length[1]  Value[64]
This implementation is correct to that FORMAT — deliberately NOT bug-compatible
with the stock CLI, which on some builds segfaults on get and drops the leading
value byte on set.

Entirely fleet-free (local file + xattr syscalls only).

  * success   — get-on-miss computes the right digest (matches xrdadler32),
                stores a well-formed 96-byte record with the correct mtime and
                FULL value length, and prints it; set→get round-trips
  * error     — a bad hex value and an unknown checksum name are clean errors
  * lifecycle — delete removes the attribute; a second get recomputes

Run:
    PYTHONPATH=tests pytest tests/test_xrdcks_xattr.py -v
"""

import os
import struct
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCKS = os.path.join(REPO, "client", "bin", "xrdcks")
XRDADLER32 = os.path.join(REPO, "client", "bin", "xrdadler32")

pytestmark = [
    pytest.mark.timeout(30),
    pytest.mark.skipif(not os.path.exists(XRDCKS),
                       reason="brix-xrdcks not built (client/bin/xrdcks)"),
]

CONTENT = b"123456789"                       # adler32 = 091e01de


def _xattr_ok(p):
    try:
        os.setxattr(p, "user.probe", b"1")
        os.removexattr(p, "user.probe")
        return True
    except OSError:
        return False


@pytest.fixture()
def target(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(CONTENT)
    if not _xattr_ok(str(p)):
        pytest.skip("filesystem lacks user xattrs")
    return str(p)


def _decode_record(rec):
    assert len(rec) == 96, f"record not 96 bytes: {len(rec)}"
    name = rec[0:16].split(b"\x00", 1)[0].decode()
    fmtime = struct.unpack(">q", rec[16:24])[0]
    length = rec[31]
    value = rec[32:32 + length]
    return name, fmtime, length, value


class TestGet:

    def test_get_on_miss_computes_and_stores(self, target):
        """(success) no stored attr → compute+store the FULL digest, print it,
        and leave a well-formed record with the file's mtime."""
        res = subprocess.run([XRDCKS, target, "adler32"],
                             capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        assert res.stdout.strip() == "adler32 091e01de", res.stdout

        rec = os.getxattr(target, "user.XrdCks.adler32")
        name, fmtime, length, value = _decode_record(rec)
        assert name == "adler32"
        assert length == 4 and value.hex() == "091e01de"   # full 4 bytes
        assert fmtime == int(os.stat(target).st_mtime)

    def test_computed_matches_standalone(self, target):
        """(cross-check) the digest xrdcks computes equals the standalone
        xrdadler32 output — same engine, same bytes."""
        if not os.path.exists(XRDADLER32):
            pytest.skip("xrdadler32 not built")
        std = subprocess.run([XRDADLER32, target],
                             capture_output=True, text=True).stdout.split()[0]
        got = subprocess.run([XRDCKS, target, "adler32"],
                             capture_output=True, text=True).stdout.split()[1]
        assert got == std


class TestSet:

    def test_set_then_get(self, target):
        """(success) an explicit hex value stores and reads back byte-exact."""
        assert subprocess.run([XRDCKS, target, "crc32c", "deadbeef"]).returncode == 0
        res = subprocess.run([XRDCKS, target, "crc32c"],
                             capture_output=True, text=True)
        assert res.stdout.strip() == "crc32c deadbeef", res.stdout
        _, _, length, value = _decode_record(
            os.getxattr(target, "user.XrdCks.crc32c"))
        assert length == 4 and value.hex() == "deadbeef"

    def test_bad_hex_is_error(self, target):
        res = subprocess.run([XRDCKS, target, "crc32c", "xyz"],
                             capture_output=True, text=True)
        assert res.returncode == 4
        assert "hex" in res.stderr

    def test_unknown_algo_is_error(self, target):
        res = subprocess.run([XRDCKS, target, "nosuchalgo"],
                             capture_output=True, text=True)
        assert res.returncode == 4
        assert "unknown checksum" in res.stderr


class TestDelete:

    def test_delete_removes_attr(self, target):
        subprocess.run([XRDCKS, target, "adler32", "01020304"])
        assert subprocess.run([XRDCKS, target, "adler32", "delete"]).returncode == 0
        with pytest.raises(OSError):
            os.getxattr(target, "user.XrdCks.adler32")
        # a get after delete recomputes cleanly
        res = subprocess.run([XRDCKS, target, "adler32"],
                             capture_output=True, text=True)
        assert res.returncode == 0 and res.stdout.strip() == "adler32 091e01de"

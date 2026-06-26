"""
tests/test_xrdckverify.py — the `xrdckverify` on-disk checksum-verify tool.

Verifies a local file against the checksum recorded for it, in every place this
project records one:
  * storage endpoint — the "user.XrdCks.<alg>" xattr (our text form AND the stock
    binary XrdCksData record) + the "<file>.cks" sidecar fallback;
  * proxy cache      — the "<file>.cinfo" / "<file>.meta" cks fields.

For each location: a correct record -> OK (exit 0); a wrong record OR corrupted
file bytes -> MISMATCH (exit 1); no record -> exit 2.  The xattr cases skip when
the test filesystem has no user-xattr support.

The recorded-record binary layouts here mirror the canonical definitions in
src/compat/integrity_info.c (XrdCksData), src/cache/meta.h and src/cache/cinfo.h.
"""

import hashlib
import os
import struct
import subprocess
import zlib

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TOOL = os.path.join(_REPO, "client", "bin", "xrdckverify")

pytestmark = pytest.mark.skipif(not os.path.exists(_TOOL),
                                reason="xrdckverify not built (make -C client)")


# --------------------------------------------------------------------------- #
# Recorded-checksum writers (one per on-disk location).                        #
# --------------------------------------------------------------------------- #
def _adler32(data):
    return "%08x" % (zlib.adler32(data) & 0xffffffff)


def _stat_fields(path):
    st = os.stat(path)
    return int(st.st_mtime), st.st_mtime_ns % 10**9, st.st_size


def _write_xattr_text(path, algo, hexval):
    sec, nsec, size = _stat_fields(path)
    os.setxattr(path, "user.XrdCks.%s" % algo,
                ("%s %d %d %d" % (hexval, sec, nsec, size)).encode())


def _write_xattr_binary(path, algo, hexval):
    """Stock XrdCksData (src/compat/integrity_info.c): Name[16], fmTime(q),
    csTime(i), Rsvd1(h), Rsvd2(b), Length(b), Value[64]."""
    digest = bytes.fromhex(hexval)
    sec, _nsec, _size = _stat_fields(path)
    rec = struct.pack("<16s q i h b b 64s",
                      algo.encode(), sec, 0, 0, 0, len(digest),
                      digest + b"\x00" * (64 - len(digest)))
    assert len(rec) == 96
    os.setxattr(path, "user.XrdCks.%s" % algo, rec)


def _write_cks_sidecar(path, algo, hexval):
    sec, nsec, size = _stat_fields(path)
    with open(path + ".cks", "w") as f:
        f.write("%s %s %d %d %d\n" % (algo, hexval, sec, nsec, size))


def _write_meta(path, algo, hexval, size, mtime=0):
    """src/cache/meta.h xrootd_cache_meta_t (256 bytes); version>=1 + cks_*."""
    rec = struct.pack(
        "<Q Q B 55s B 7x Q Q Q B 16s B 129s 5x",
        mtime, size, 0, b"", 1, 0, 0, 0,
        len(algo), algo.encode(),
        len(hexval), hexval.encode())
    assert len(rec) == 256, len(rec)
    with open(path + ".meta", "wb") as f:
        f.write(rec)


def _write_cinfo(path, algo, hexval, size, block_size=1 << 20, mtime=0):
    """src/cache/cinfo.h xrootd_cache_cinfo_t header (272 bytes) + a bitmap."""
    nblocks = (size + block_size - 1) // block_size if size else 0
    hdr = struct.pack(
        "<I H H I I Q Q Q Q Q Q B 55s B 16s B 129s 5x",
        0x58434931, 2, 1, block_size, 0, size, mtime, nblocks, 0, 0, 0,
        0, b"", len(algo), algo.encode(), len(hexval), hexval.encode())
    assert len(hdr) == 272, len(hdr)
    bitmap = b"\xff" * ((nblocks + 7) // 8)
    with open(path + ".cinfo", "wb") as f:
        f.write(hdr + bitmap)


# --------------------------------------------------------------------------- #
# Fixtures / helpers                                                           #
# --------------------------------------------------------------------------- #
@pytest.fixture
def datafile(tmp_path):
    p = tmp_path / "object.dat"
    data = os.urandom(50000)
    p.write_bytes(data)
    return str(p), data


def _xattr_supported(path):
    try:
        os.setxattr(path, "user.xrdck.probe", b"1")
        os.removexattr(path, "user.xrdck.probe")
        return True
    except OSError:
        return False


def _run(*args):
    r = subprocess.run([_TOOL, *args], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


# --------------------------------------------------------------------------- #
# Storage endpoint: xattr (text + binary) and the .cks sidecar.                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("writer", [_write_xattr_text, _write_xattr_binary],
                         ids=["xattr-text", "xattr-binary"])
def test_storage_xattr_ok_and_mismatch(datafile, writer):
    path, data = datafile
    if not _xattr_supported(path):
        pytest.skip("filesystem has no user-xattr support")
    writer(path, "adler32", _adler32(data))

    rc, out, _ = _run("--storage", path)
    assert rc == 0 and out.startswith("OK "), out

    # corrupt the recorded digest -> mismatch
    writer(path, "adler32", "00000000")
    rc, out, _ = _run("--storage", path)
    assert rc == 1 and "MISMATCH" in out, out


def test_storage_cks_sidecar_ok_and_file_corruption(datafile):
    path, data = datafile
    _write_cks_sidecar(path, "adler32", _adler32(data))
    rc, out, _ = _run("--storage", path)
    assert rc == 0 and out.startswith("OK ") and "(cks)" in out, out

    # corrupt the FILE itself -> the recorded checksum no longer matches
    with open(path, "r+b") as f:
        f.seek(100)
        f.write(b"\xff")
    rc, out, _ = _run("--storage", path)
    assert rc == 1 and "MISMATCH" in out, out


def test_storage_md5_via_xattr(datafile):
    path, data = datafile
    if not _xattr_supported(path):
        pytest.skip("filesystem has no user-xattr support")
    _write_xattr_text(path, "md5", hashlib.md5(data).hexdigest())
    rc, out, _ = _run("--storage", path)
    assert rc == 0 and out.startswith("OK ") and "md5" in out, out


# --------------------------------------------------------------------------- #
# Proxy cache: the .cinfo / .meta recorded digest.                            #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("writer", [_write_cinfo, _write_meta],
                         ids=["cinfo", "meta"])
def test_cache_sidecar_ok_and_mismatch(datafile, writer):
    path, data = datafile
    writer(path, "adler32", _adler32(data), len(data))
    rc, out, _ = _run("--cache", path)
    assert rc == 0 and out.startswith("OK "), out

    writer(path, "adler32", "00000000", len(data))
    rc, out, _ = _run("--cache", path)
    assert rc == 1 and "MISMATCH" in out, out


def test_auto_finds_cache_record(datafile):
    path, data = datafile
    _write_cinfo(path, "adler32", _adler32(data), len(data))
    rc, out, _ = _run(path)                 # default mode = --auto
    assert rc == 0 and out.startswith("OK ") and "(cinfo)" in out, out


# --------------------------------------------------------------------------- #
# Negative / edge cases.                                                       #
# --------------------------------------------------------------------------- #
def test_no_recorded_checksum_exits_2(datafile):
    path, _ = datafile
    rc, _out, err = _run(path)
    assert rc == 2 and "no recorded checksum" in err, err


def test_algo_filter_skips_other_algos(datafile):
    path, data = datafile
    _write_cks_sidecar(path, "adler32", _adler32(data))
    # only crc32c requested, but only adler32 recorded -> nothing to verify
    rc, _out, _err = _run("--storage", "--algo", "crc32c", path)
    assert rc == 2, "expected no-record exit when the requested algo is absent"


def test_quiet_suppresses_ok_output(datafile):
    path, data = datafile
    _write_cks_sidecar(path, "adler32", _adler32(data))
    rc, out, _ = _run("-q", "--storage", path)
    assert rc == 0 and out.strip() == "", "quiet OK should print nothing"


def test_storage_mode_ignores_cache_record(datafile):
    """--storage must not consult the cache .cinfo (mode isolation)."""
    path, data = datafile
    _write_cinfo(path, "adler32", _adler32(data), len(data))
    rc, _out, err = _run("--storage", path)
    assert rc == 2, "storage mode wrongly read the cache .cinfo: %s" % err

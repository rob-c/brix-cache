# tests/test_oci_tar_corpus.py — the D6 streaming tar reader against a
# Python-generated corpus (phase-104 D6.4). Three layers:
#   * the in-C unit suite (shared/oci/tar_unittest.c) compiled + run;
#   * `tar_unittest dump` cross-checked against Python's tarfile as the
#     oracle (GNU + PAX formats, long names/links, hardlinks, pax xattrs,
#     gzip variant, system GNU tar when installed);
#   * malformed/hostile archives crafted byte-by-byte here (flipped
#     checksum, truncation, data smuggled after the end marker, base-256
#     size overflow/negative) — all must be refused, never crash.
# Needs only a C compiler + sqlite3/crypto/z devel libs; no server.
import io
import os
import shutil
import subprocess
import tarfile
import zlib

import pytest

def _check_tar_ut_1(comp):
    assert comp.returncode == 0, \
        "tar unit driver failed to COMPILE:\n%s" % comp.stderr


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARED = os.path.join(REPO, "shared")
SRC = [os.path.join(SHARED, "oci", f)
       for f in ("tar_unittest.c", "tar.c", "tar_pax.c", "tar_digest.c", "digest.c")] + \
      [os.path.join(SHARED, "cvmfs", "catalog", "catalog_write.c"),
       os.path.join(SHARED, "cvmfs", "catalog", "xattr_pack.c"),
       os.path.join(SHARED, "cvmfs", "catalog", "catalog.c"),
       os.path.join(SHARED, "cvmfs", "grammar", "hash.c")]


def _zstd_flags():
    r = subprocess.run(["pkg-config", "--exists", "libzstd"],
                       capture_output=True)
    return ["-DBRIX_HAVE_ZSTD=1", "-lzstd"] if r.returncode == 0 else []


@pytest.fixture(scope="module")
def tar_ut(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not all(os.path.exists(s) for s in SRC):
        pytest.skip("tar reader sources missing")
    out = str(tmp_path_factory.mktemp("bin") / "tar_ut")
    comp = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", SHARED, "-o", out,
         *SRC, "-lsqlite3", "-lcrypto", "-lz", *_zstd_flags()],
        capture_output=True, text=True)
    _check_tar_ut_1(comp)
    return out


def _dump(tar_ut, archive):
    return subprocess.run([tar_ut, "dump", str(archive)],
                          capture_output=True, text=True, timeout=60)


def _entries(stdout):
    """Parse dump output into dicts; asserts the archive parsed cleanly."""
    out = []
    for ln in stdout.splitlines():
        if ln == "EOF":
            return out
        assert not ln.startswith("ERROR:"), ln
        f = ln.split("\t")
        out.append({"type": f[0], "mode": int(f[1], 8), "size": int(f[2]),
                    "mtime": int(f[3]), "uid": int(f[4]), "gid": int(f[5]),
                    "path": f[6].rstrip("/"), "link": f[7],
                    "crc": int(f[8], 16),
                    "xattrs": {kv.split("=", 1)[0]:
                               bytes.fromhex(kv.split("=", 1)[1])
                               for kv in f[9:]}})
    raise AssertionError("dump ended without EOF:\n" + stdout)


_TYPES = {tarfile.REGTYPE: "REG", tarfile.AREGTYPE: "REG",
          tarfile.DIRTYPE: "DIR", tarfile.SYMTYPE: "SYM",
          tarfile.LNKTYPE: "HLNK", tarfile.FIFOTYPE: "FIFO",
          tarfile.CHRTYPE: "CHR", tarfile.BLKTYPE: "BLK"}


def _expected(archive):
    """tarfile is the oracle: re-read the archive it just wrote."""
    out = []
    with tarfile.open(str(archive), "r:*") as tf:
        for m in tf.getmembers():
            data = tf.extractfile(m).read() if m.isreg() else b""
            out.append({"type": _TYPES[m.type], "mode": m.mode & 0o7777,
                        "mtime": int(m.mtime), "uid": m.uid, "gid": m.gid,
                        "path": m.name.rstrip("/"), "link": m.linkname,
                        "crc": zlib.crc32(data) & 0xFFFFFFFF})
    return out


def _check_against_tarfile(tar_ut, archive):
    got = _entries(_dump(tar_ut, archive).stdout)
    want = _expected(archive)
    assert len(got) == len(want), (got, want)
    for g, w in zip(got, want):
        for k in w:
            assert g[k] == w[k], "field %r: got %r want %r for %s" % (
                k, g[k], w[k], w["path"])


def _add(tf, name, data=None, typ=tarfile.REGTYPE, mode=0o644, link="",
         uid=0, gid=0, mtime=1700000000, pax=None):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.uid, ti.gid, ti.mtime = typ, mode, uid, gid, mtime
    ti.linkname = link
    if pax:
        ti.pax_headers = pax
    if data is not None:
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    else:
        tf.addfile(ti)


LONG_DIR = "deep/" + "component-" * 12 + "leaf"       # > 100 bytes
LONG_TARGET = "../" * 5 + "t" * 100                   # > 100-byte linkname


def _write_corpus(path, fmt, mode="w"):
    with tarfile.open(str(path), mode, format=fmt) as tf:
        _add(tf, "top", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "top/file.bin", bytes(range(256)) * 12, mode=0o600,
             uid=1000, gid=100)
        _add(tf, LONG_DIR, typ=tarfile.DIRTYPE, mode=0o750)
        _add(tf, LONG_DIR + "/payload", b"under a GNU-long name")
        _add(tf, "top/sym", typ=tarfile.SYMTYPE, link=LONG_TARGET, mode=0o777)
        _add(tf, "top/hard", typ=tarfile.LNKTYPE, link="top/file.bin")
        _add(tf, "top/fifo", typ=tarfile.FIFOTYPE, mode=0o600)


# ---- success: tarfile as the oracle -------------------------------------

def test_unit_suite(tar_ut, tmp_path):
    r = subprocess.run([tar_ut], capture_output=True, text=True, timeout=60,
                       cwd=str(tmp_path))
    print(r.stdout)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "all checks passed" in r.stdout

def test_dump_matches_tarfile_gnu(tar_ut, tmp_path):
    ar = tmp_path / "gnu.tar"
    _write_corpus(ar, tarfile.GNU_FORMAT)
    _check_against_tarfile(tar_ut, ar)

def test_dump_matches_tarfile_pax(tar_ut, tmp_path):
    ar = tmp_path / "pax.tar"
    with tarfile.open(str(ar), "w", format=tarfile.PAX_FORMAT) as tf:
        _add(tf, "x" * 130, b"pax long name")
        # uid > the 7-digit octal ceiling forces a pax uid record
        _add(tf, "biguid", b"", uid=2097152)
        _add(tf, "tagged", b"payload",
             pax={"SCHILY.xattr.user.color": "red",
                  "SCHILY.xattr.user.rank": "7"})
    _check_against_tarfile(tar_ut, ar)
    got = _entries(_dump(tar_ut, ar).stdout)
    assert got[2]["xattrs"] == {"user.color": b"red", "user.rank": b"7"}

def test_dump_gzip_variant(tar_ut, tmp_path):
    ar = tmp_path / "corpus.tar.gz"
    _write_corpus(ar, tarfile.GNU_FORMAT, mode="w:gz")
    _check_against_tarfile(tar_ut, ar)

def test_system_gnu_tar_when_present(tar_ut, tmp_path):
    if shutil.which("tar") is None:
        pytest.skip("no system tar")
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "a.txt").write_bytes(b"alpha")
    os.symlink("a.txt", tree / "sub" / "s")
    os.link(tree / "sub" / "a.txt", tree / "sub" / "h")
    ar = tmp_path / "system.tar"
    r = subprocess.run(["tar", "--format=gnu", "-C", str(tree),
                        "-cf", str(ar), "."], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    got = _entries(_dump(tar_ut, ar).stdout)
    by_path = {e["path"].lstrip("./"): e for e in got}
    def _assert_test_system_gnu_tar_when_present_1():
        assert by_path["sub/a.txt"]["crc"] == zlib.crc32(b"alpha")
        assert by_path["sub/s"]["type"] == "SYM"

    _assert_test_system_gnu_tar_when_present_1()
    # tar stores whichever of h/a.txt it met second as the hardlink
    assert "HLNK" in {by_path["sub/h"]["type"], by_path["sub/a.txt"]["type"]}


# ---- error: malformed archives crafted here ------------------------------

def _cksum(h):
    h[148:156] = b" " * 8
    h[148:156] = b"%06o\0 " % sum(h)


def _hdr(name, typ=b"0", size=0, mode=0o644):
    h = bytearray(512)
    h[0:len(name)] = name
    h[100:108] = b"%07o\0" % mode
    h[108:116] = b"%07o\0" % 0
    h[116:124] = b"%07o\0" % 0
    h[124:136] = b"%011o\0" % size
    h[136:148] = b"%011o\0" % 1234567
    h[156:157] = typ
    h[257:263] = b"ustar\0"
    h[263:265] = b"00"
    _cksum(h)
    return h


END = b"\0" * 1024


def _refused(tar_ut, tmp_path, blob, needle):
    ar = tmp_path / "bad.tar"
    ar.write_bytes(bytes(blob))
    r = _dump(tar_ut, ar)
    assert r.returncode == 3, r.stdout
    assert needle in r.stdout, r.stdout

def test_flipped_checksum_refused(tar_ut, tmp_path):
    h = _hdr(b"ok")
    h[0] ^= 0x01                       # corrupt after the sum was written
    _refused(tar_ut, tmp_path, h + END, "checksum")

def test_truncated_body_refused(tar_ut, tmp_path):
    _refused(tar_ut, tmp_path, _hdr(b"f", size=100) + b"short", "truncated")


# ---- security-negative: smuggling + crafted numerics ---------------------

def test_data_after_end_marker_never_surfaced(tar_ut, tmp_path):
    # a header where the marker's second zero block belongs → refused
    _refused(tar_ut, tmp_path,
             _hdr(b"seen") + b"\0" * 512 + _hdr(b"smuggled") + END,
             "end-of-archive")
    # after a COMPLETE marker the reader stops (real tars pad past it):
    # the smuggled member must never appear as an entry
    ar = tmp_path / "padded.tar"
    ar.write_bytes(bytes(_hdr(b"seen") + END + _hdr(b"smuggled") + END))
    got = _entries(_dump(tar_ut, ar).stdout)
    assert [e["path"] for e in got] == ["seen"]

def test_base256_overflow_size_refused(tar_ut, tmp_path):
    h = _hdr(b"huge")
    h[124:136] = b"\x81" + b"\xff" * 11        # > INT64_MAX
    _cksum(h)
    _refused(tar_ut, tmp_path, h + END, "size")

def test_base256_negative_size_refused(tar_ut, tmp_path):
    h = _hdr(b"neg")
    h[124:136] = b"\xff" * 12                  # base-256 for -1
    _cksum(h)
    _refused(tar_ut, tmp_path, h + END, "negative size")

# ---- security-negative: metadata bombs ----------------------------------- #

def test_oversized_pax_header_refused_before_it_is_parsed(tar_ut, tmp_path):
    """A pax header is metadata, and metadata has a size a real writer stays under.

    The record parser is O(records), so an entry carrying a million
    zero-length records is a CPU bomb that costs the attacker one 512-byte
    header to declare. Two bounds stand behind that: this 160 KiB cap on the
    whole pax body, checked against the DECLARED size before a byte is read,
    and TAR_PAX_REC_MAX behind it. The byte cap is the one that fires — at
    five bytes per minimal record it caps the count below the record cap — so
    the inner bound is a belt, not the trousers.
    """
    body = b"5 a=\n" * 40000                      # 200 KiB of legal records
    h = _hdr(b"pax-bomb", typ=b"x", size=len(body))
    pad = b"\0" * ((512 - len(body) % 512) % 512)

    _refused(tar_ut, tmp_path, h + body + pad + _hdr(b"f") + END,
             "oversized metadata")


def test_xattr_flood_on_one_entry_refused(tar_ut, tmp_path):
    """255 xattrs is already generous; the 256th is someone probing the arena.

    The xattr set is packed into a fixed arena and handed to the changeset
    writer, so an unbounded count is an unbounded write. It fits inside the
    pax byte cap — which is exactly why this bound has to exist separately.
    """
    def _rec(key, value):
        rest = b" %s=%s\n" % (key, value)
        n = len(rest) + 1
        while len(str(n).encode()) + len(rest) != n:
            n += 1
        return str(n).encode() + rest

    recs = b"".join(_rec(b"SCHILY.xattr.user.k%04d" % i, b"v")
                    for i in range(300))
    h = _hdr(b"xattr-bomb", typ=b"x", size=len(recs))
    pad = b"\0" * ((512 - len(recs) % 512) % 512)

    _refused(tar_ut, tmp_path, h + recs + pad + _hdr(b"f") + END, "xattrs")


# ---- chunked layer shapes: multi-member gzip, multi-frame zstd -----------
# eStargz is a chain of gzip MEMBERS (one per file, plus a TOC member and a
# footer); zstd:chunked is a chain of zstd FRAMES with the TOC in trailing
# skippable frames. Both decompress to one ordinary tar — a reader that stops
# at the first member/frame truncates the layer silently, which is the one
# failure mode a publisher must never have.

def _split(blob, parts):
    """Split at 512-byte (tar block) boundaries, as a per-file chunker does."""
    step = ((len(blob) // parts) // 512) * 512 or 512
    return [blob[i:i + step] for i in range(0, len(blob), step)]


def _gz_member(chunk):
    co = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    return co.compress(chunk) + co.flush()


def _zstd():
    return pytest.importorskip("zstandard", reason="python-zstandard missing")


def _skippable(payload):
    """A zstd skippable frame — how zstd:chunked carries its TOC."""
    return (b"\x50\x2a\x4d\x18"
            + len(payload).to_bytes(4, "little") + payload)


def test_multi_member_gzip_layer_reads_whole_stream(tar_ut, tmp_path):
    plain = tmp_path / "corpus.tar"
    _write_corpus(plain, tarfile.GNU_FORMAT)
    chunks = _split(plain.read_bytes(), 4)
    assert len(chunks) > 2, "the corpus must span several members"
    ar = tmp_path / "estargz.tar.gz"
    ar.write_bytes(b"".join(_gz_member(c) for c in chunks))
    _check_against_tarfile(tar_ut, ar)

def test_gzip_trailing_padding_is_not_a_member(tar_ut, tmp_path):
    plain = tmp_path / "corpus.tar"
    _write_corpus(plain, tarfile.GNU_FORMAT)
    ar = tmp_path / "padded.tar.gz"
    ar.write_bytes(_gz_member(plain.read_bytes()) + b"\0" * 1024)
    got = _entries(_dump(tar_ut, ar).stdout)
    assert [e["path"] for e in got] == [e["path"] for e in _expected(plain)]

def test_multi_frame_zstd_layer_reads_whole_stream(tar_ut, tmp_path):
    zstd = _zstd()
    plain = tmp_path / "corpus.tar"
    _write_corpus(plain, tarfile.GNU_FORMAT)
    cc = zstd.ZstdCompressor(level=3)
    ar = tmp_path / "chunked.tar.zst"
    ar.write_bytes(b"".join(cc.compress(c)
                            for c in _split(plain.read_bytes(), 4)))
    got = _entries(_dump(tar_ut, ar).stdout)
    if not got:
        pytest.skip("tar reader built without zstd support")
    assert got == _entries(_dump(tar_ut, plain).stdout)

def test_zstd_skippable_toc_frames_are_ignored(tar_ut, tmp_path):
    zstd = _zstd()
    plain = tmp_path / "corpus.tar"
    _write_corpus(plain, tarfile.GNU_FORMAT)
    cc = zstd.ZstdCompressor(level=3)
    toc = _skippable(b'{"version":1,"entries":[]}')
    chunks = _split(plain.read_bytes(), 3)
    blob = toc + cc.compress(chunks[0]) + toc
    blob += b"".join(cc.compress(c) for c in chunks[1:]) + toc
    ar = tmp_path / "toc.tar.zst"
    ar.write_bytes(blob)
    got = _entries(_dump(tar_ut, ar).stdout)
    if not got:
        pytest.skip("tar reader built without zstd support")
    assert got == _entries(_dump(tar_ut, plain).stdout)

def test_truncated_last_gzip_member_refused(tar_ut, tmp_path):
    """The dangerous shape: a layer that LOOKS whole because the reader gave
    up at a member boundary. It must be refused, never silently short."""
    plain = tmp_path / "corpus.tar"
    _write_corpus(plain, tarfile.GNU_FORMAT)
    chunks = _split(plain.read_bytes(), 4)
    members = [_gz_member(c) for c in chunks]
    ar = tmp_path / "cut.tar.gz"
    # cut a MIDDLE member: the last one carries only the end-of-archive
    # padding, which the reader legitimately never reaches
    ar.write_bytes(members[0] + members[1][:len(members[1]) // 2])
    r = _dump(tar_ut, ar)
    assert r.returncode == 3, r.stdout
    assert "ERROR" in r.stdout and "EOF" not in r.stdout, r.stdout

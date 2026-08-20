# tests/test_oci_stargz.py — the D15.8 eStargz WRITER: ordinary OCI layers
# (built here with Python's tarfile) converted by the `stargz_unittest
# convert` driver and checked against the format spec with nothing but
# zlib + tarfile, which is the only honest oracle available offline.
#   * success: the 51-byte footer and its TOC pointer, every gzip-member
#     boundary the format mandates, per-file offsets that decompress to the
#     exact payload, the three digests the caller rewrites a manifest from,
#     xattrs/symlinks/long names surviving the reframe verbatim;
#   * round-trip: the converted layer flattens to the tree its original
#     flattens to (the D7 flattener drops the format's own entries);
#   * error: a non-archive, a truncated blob, an unwritable destination;
#   * security-negative: reserved root names in the SOURCE are dropped
#     rather than carried (no second TOC to shadow ours), a same-named file
#     deeper in the tree survives, and a tampered blob fails its own TOC
#     digests.
# Needs only a C compiler + sqlite3/crypto/z devel libs; no server.
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import zlib

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARED = os.path.join(REPO, "shared")

_OCI = ("tar.c", "tar_pax.c", "tar_digest.c", "digest.c",
        "stargz.c", "stargz_toc.c")
_CVMFS = [os.path.join(SHARED, "cvmfs", "catalog", "catalog_write.c"),
          os.path.join(SHARED, "cvmfs", "catalog", "catalog.c"),
          os.path.join(SHARED, "cvmfs", "grammar", "hash.c")]

SGZ_SRC = [os.path.join(SHARED, "oci", f)
           for f in ("stargz_unittest.c",) + _OCI] + _CVMFS
FLAT_SRC = [os.path.join(SHARED, "oci", f)
            for f in ("flatten_unittest.c", "flatten.c") + _OCI] + _CVMFS

FOOTER_LEN = 51
STARGZ_META = ("stargz.index.json", ".prefetch.landmark",
               ".no.prefetch.landmark")


def _build(cc, src, out):
    comp = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", SHARED, "-o", out,
         *src, "-lsqlite3", "-lcrypto", "-lz"],
        capture_output=True, text=True)
    assert comp.returncode == 0, \
        "driver failed to COMPILE:\n%s" % comp.stderr
    return out


@pytest.fixture(scope="module")
def drivers(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not all(os.path.exists(s) for s in SGZ_SRC + FLAT_SRC):
        pytest.skip("eStargz writer sources missing")
    binp = tmp_path_factory.mktemp("bin")
    return (_build(cc, SGZ_SRC, str(binp / "stargz_ut")),
            _build(cc, FLAT_SRC, str(binp / "flatten_ut")))


@pytest.fixture(scope="module")
def stargz_ut(drivers):
    return drivers[0]


@pytest.fixture(scope="module")
def flatten_ut(drivers):
    return drivers[1]


# ---- fixture helpers ------------------------------------------------------

def _add(tf, name, data=None, typ=tarfile.REGTYPE, mode=0o644, link="",
         uid=0, gid=0, pax=None, devmajor=0, devminor=0):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.uid, ti.gid = typ, mode, uid, gid
    ti.mtime = 1700000000
    ti.linkname = link
    ti.devmajor, ti.devminor = devmajor, devminor
    if pax:
        ti.pax_headers = pax
    if data is not None:
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    else:
        tf.addfile(ti)


def _layer(path, build, compress=True):
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w",
                      format=tarfile.PAX_FORMAT) as tf:
        build(tf)
    raw = plain.getvalue()
    with open(str(path), "wb") as fh:
        if compress:
            co = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
            fh.write(co.compress(raw) + co.flush())
        else:
            fh.write(raw)
    return path


def _convert(stargz_ut, src, dst):
    return subprocess.run([stargz_ut, "convert", str(src), str(dst)],
                          capture_output=True, text=True, timeout=60)


def _stats(r):
    assert r.returncode == 0, r.stdout + r.stderr
    line = r.stdout.strip().splitlines()[-1]
    assert line.startswith("stats "), r.stdout
    out = {}
    for kv in line.split()[1:]:
        k, v = kv.split("=", 1)
        out[k] = v if v.startswith("sha256:") else int(v)
    return out


def _refused(r, needle):
    assert r.returncode == 1, r.stdout + r.stderr
    assert r.stdout.startswith("ERROR:"), r.stdout
    assert needle in r.stdout, r.stdout


def _member_at(blob, off):
    """Decompress the ONE gzip member starting at `off` — which is exactly
    what a snapshotter fetching a single file's Range does, and so is the
    check that the file really begins at a member boundary."""
    return zlib.decompressobj(31).decompress(blob[off:])


def _stream(blob):
    """The whole decompressed tar: every member of the chain concatenated,
    which is what a runtime unpacking the layer sees."""
    return gzip.decompress(blob)


def _toc_offset(blob):
    foot = blob[-FOOTER_LEN:]
    assert foot[:10] == bytes([0x1f, 0x8b, 0x08, 0x04, 0, 0, 0, 0, 0, 0xff])
    assert foot[10:12] == b"\x1a\x00"          # XLEN = 26
    assert foot[12:14] == b"SG"                # SI1, SI2
    assert foot[14:16] == b"\x16\x00"          # LEN = 22
    assert foot[32:38] == b"STARGZ"
    return int(foot[16:32].decode("ascii"), 16)


def _toc(blob):
    off = _toc_offset(blob)
    tf = tarfile.open(fileobj=io.BytesIO(_member_at(blob, off)))
    m = tf.next()
    assert m.name == "stargz.index.json", m.name
    raw = tf.extractfile(m).read()
    return json.loads(raw), raw, off


def _entries(blob):
    toc, _, _ = _toc(blob)
    return {e["name"]: e for e in toc["entries"]}


def _tar_names(blob):
    tf = tarfile.open(fileobj=io.BytesIO(_stream(blob)))
    return [(m.name, m.size, m.type) for m in tf]


def _simple(tf):
    _add(tf, "usr", typ=tarfile.DIRTYPE, mode=0o755)
    _add(tf, "usr/bin", typ=tarfile.DIRTYPE, mode=0o755)
    _add(tf, "usr/bin/tool", b"#!/bin/sh\nexec true\n", mode=0o755)
    _add(tf, "usr/bin/big", bytes(range(256)) * 40)
    _add(tf, "usr/bin/alias", typ=tarfile.SYMTYPE, link="tool")
    _add(tf, "etc/empty", b"")


# ---- success: the format's own arithmetic --------------------------------

def test_footer_points_at_the_toc(stargz_ut, tmp_path):
    src = _layer(tmp_path / "src.tar.gz", _simple)
    st = _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = (tmp_path / "out.estargz").read_bytes()

    assert st["size"] == len(blob)
    assert st["blob"] == "sha256:" + hashlib.sha256(blob).hexdigest()

    toc, raw, off = _toc(blob)
    assert toc["version"] == 1
    # the annotation a snapshotter verifies the TOC against is the digest of
    # the JSON bytes alone — not of the tar entry or the gzip member
    assert st["toc"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert 0 < off < len(blob) - FOOTER_LEN
    # the TOC member starts on a gzip header, which is what makes a single
    # ranged read of the tail enough to find it
    assert blob[off:off + 2] == b"\x1f\x8b"


def test_reframed_layer_is_the_same_tar_plus_the_formats_own(stargz_ut,
                                                             tmp_path):
    src = _layer(tmp_path / "src.tar.gz", _simple)
    st = _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = (tmp_path / "out.estargz").read_bytes()

    plain = _stream(blob)
    assert len(plain) % 512 == 0
    assert st["diffid"] == "sha256:" + hashlib.sha256(plain).hexdigest()

    want = [(m.name, m.size, m.type) for m in
            tarfile.open(fileobj=io.BytesIO(_stream(src.read_bytes())))]
    got = _tar_names(blob)
    # the landmark leads (no prioritized files) and the TOC is last; between
    # them the source's entries in their original order, byte-identical
    assert got[0] == (".no.prefetch.landmark", 1, tarfile.REGTYPE)
    assert got[-1][0] == "stargz.index.json"
    assert got[1:-1] == want
    assert st["entries"] == len(want) + 1        # + the landmark, - the TOC
    assert st["dropped"] == 0


def test_every_file_offset_decompresses_to_its_own_bytes(stargz_ut, tmp_path):
    bodies = {"usr/bin/tool": b"#!/bin/sh\nexec true\n",
              "usr/bin/big": bytes(range(256)) * 40}
    src = _layer(tmp_path / "src.tar.gz", _simple)
    _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = (tmp_path / "out.estargz").read_bytes()
    ent = _entries(blob)

    for name, body in bodies.items():
        e = ent[name]
        assert e["type"] == "reg" and e["size"] == len(body)
        assert blob[e["offset"]:e["offset"] + 2] == b"\x1f\x8b"
        assert _member_at(blob, e["offset"])[:len(body)] == body
        dig = "sha256:" + hashlib.sha256(body).hexdigest()
        assert e["digest"] == dig and e["chunkDigest"] == dig

    # a zero-length file gets no member and no offset: there is nothing to
    # fetch lazily, and an offset would point at the NEXT file's payload
    assert "offset" not in ent["etc/empty"]
    assert ent["etc/empty"]["size"] == 0
    assert ent["usr/bin"]["type"] == "dir" and "offset" not in ent["usr/bin"]
    assert ent["usr/bin/alias"]["type"] == "symlink"
    assert ent["usr/bin/alias"]["linkName"] == "tool"


def test_metadata_and_landmark_carry_the_prescribed_shape(stargz_ut,
                                                          tmp_path):
    src = _layer(tmp_path / "src.tar.gz", _simple)
    _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = (tmp_path / "out.estargz").read_bytes()

    assert blob[:2] == b"\x1f\x8b"               # top of blob is a header
    lm = _entries(blob)[".no.prefetch.landmark"]
    assert lm["size"] == 1
    assert _member_at(blob, lm["offset"])[:1] == b"\x0f"
    assert lm["digest"] == \
        "sha256:" + hashlib.sha256(b"\x0f").hexdigest()
    # modtime is RFC3339 in UTC, which is the only form the spec allows
    for e in _entries(blob).values():
        assert e["modtime"].endswith("Z") and "T" in e["modtime"]


def test_pax_extras_survive_the_reframe(stargz_ut, tmp_path):
    long_name = "usr/share/" + "d/" * 60 + "deep.txt"
    xattr = b"\x00\x01\x02rare"

    def build(tf):
        _add(tf, "usr", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, long_name, b"deep\n")
        _add(tf, "usr/xa", b"x", pax={"SCHILY.xattr.user.brix":
                                      xattr.decode("latin-1")})
        _add(tf, "dev/null", typ=tarfile.CHRTYPE, mode=0o666,
             devmajor=1, devminor=3)

    src = _layer(tmp_path / "src.tar.gz", build)
    _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = (tmp_path / "out.estargz").read_bytes()
    ent = _entries(blob)

    assert ent[long_name]["size"] == 5
    assert _member_at(blob, ent[long_name]["offset"])[:5] == b"deep\n"
    assert ent["dev/null"]["type"] == "char"
    assert ent["dev/null"]["devMajor"] == 1
    assert ent["dev/null"]["devMinor"] == 3

    import base64
    got = ent["usr/xa"]["xattrs"]["user.brix"]
    assert base64.b64decode(got) == xattr

    # and the pax records themselves are copied through, not regenerated:
    # the reframed tar still resolves the long name from its own header
    names = [n for n, _, _ in _tar_names(blob)]
    assert long_name in names


def test_a_plain_uncompressed_tar_converts_too(stargz_ut, tmp_path):
    """The reader sniffs its input, so an uncompressed layer converts by the
    same path — and lands the same entries as the gzip'd one."""
    plain = _layer(tmp_path / "src.tar", _simple, compress=False)
    gz = _layer(tmp_path / "src.tar.gz", _simple)
    a = _stats(_convert(stargz_ut, plain, tmp_path / "a.estargz"))
    b = _stats(_convert(stargz_ut, gz, tmp_path / "b.estargz"))

    assert a["diffid"] == b["diffid"]
    assert a["toc"] == b["toc"]
    assert _tar_names((tmp_path / "a.estargz").read_bytes()) == \
        _tar_names((tmp_path / "b.estargz").read_bytes())


# ---- round-trip: it still publishes the tree its original does -----------

def _shape(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(str(root)):
        for n in sorted(dirnames + filenames):
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, str(root))
            if os.path.islink(p):
                out[rel] = "link:" + os.readlink(p)
            elif os.path.isdir(p):
                out[rel] = "dir"
            else:
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return out


def _apply(flatten_ut, upper, layer):
    upper.mkdir(exist_ok=True)
    r = subprocess.run([flatten_ut, "apply", str(upper), str(layer)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    return r


def test_converted_layer_flattens_to_the_original_rootfs(stargz_ut,
                                                         flatten_ut,
                                                         tmp_path):
    src = _layer(tmp_path / "src.tar.gz", _simple)
    _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))

    _apply(flatten_ut, tmp_path / "want", src)
    _apply(flatten_ut, tmp_path / "got", tmp_path / "out.estargz")
    assert _shape(tmp_path / "got") == _shape(tmp_path / "want")


# ---- security-negative ---------------------------------------------------

def test_source_bookkeeping_entries_are_dropped_not_carried(stargz_ut,
                                                            tmp_path):
    """Converting a layer that already carries the reserved names must not
    leave a second TOC or a second landmark in the output: a reader trusts
    the FIRST `stargz.index.json` it walks to, so a smuggled one that
    survived conversion would shadow the real index."""
    def hostile(tf):
        _add(tf, "stargz.index.json", b'{"version":1,"entries":[]}')
        _add(tf, ".prefetch.landmark", b"\x0f")
        _add(tf, ".no.prefetch.landmark", b"\x0f")
        _add(tf, "./stargz.index.json", b"dotted")
        _simple(tf)

    src = _layer(tmp_path / "src.tar.gz", hostile)
    st = _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = (tmp_path / "out.estargz").read_bytes()

    assert st["dropped"] == 4
    names = [n for n, _, _ in _tar_names(blob)]
    assert names.count("stargz.index.json") == 1
    assert names.index("stargz.index.json") == len(names) - 1
    assert names.count(".no.prefetch.landmark") == 1
    assert names.index(".no.prefetch.landmark") == 0
    assert ".prefetch.landmark" not in names


def test_a_reserved_name_deeper_in_the_tree_is_ordinary_content(stargz_ut,
                                                                tmp_path):
    """The three names are reserved at the archive ROOT only. Dropping a
    `usr/share/stargz.index.json` would silently delete real content from
    every image that happens to ship one."""
    def build(tf):
        _add(tf, "usr", typ=tarfile.DIRTYPE, mode=0o755)
        _add(tf, "usr/stargz.index.json", b"payload\n")
        _add(tf, "usr/.prefetch.landmark", b"also mine\n")

    src = _layer(tmp_path / "src.tar.gz", build)
    st = _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = (tmp_path / "out.estargz").read_bytes()
    ent = _entries(blob)

    assert st["dropped"] == 0
    assert _member_at(blob, ent["usr/stargz.index.json"]["offset"])[:8] \
        == b"payload\n"
    assert ent["usr/.prefetch.landmark"]["size"] == 10


def test_a_tampered_blob_fails_its_own_toc_digests(stargz_ut, tmp_path):
    """The per-file digests are over the real payload, so a blob edited
    after conversion no longer matches the TOC a snapshotter verifies
    against — which is the whole point of recording them."""
    src = _layer(tmp_path / "src.tar.gz", _simple)
    _stats(_convert(stargz_ut, src, tmp_path / "out.estargz"))
    blob = bytearray((tmp_path / "out.estargz").read_bytes())
    e = _entries(bytes(blob))["usr/bin/big"]

    body = _member_at(bytes(blob), e["offset"])[:e["size"]]
    assert e["chunkDigest"] == \
        "sha256:" + hashlib.sha256(body).hexdigest()

    # flip one byte inside the member's deflate stream; the payload it
    # decompresses to changes (or the member fails outright) — either way
    # the recorded digest no longer describes it
    blob[e["offset"] + 30] ^= 0x40
    try:
        tampered = _member_at(bytes(blob), e["offset"])[:e["size"]]
    except zlib.error:
        return
    assert "sha256:" + hashlib.sha256(tampered).hexdigest() != e["chunkDigest"]


# ---- error paths ---------------------------------------------------------

def test_a_non_archive_is_refused(stargz_ut, tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"this is not a tar, nor gzip, nor zstd\n" * 40)
    _refused(_convert(stargz_ut, junk, tmp_path / "out.estargz"), "estargz:")


def test_a_truncated_gzip_layer_is_refused(stargz_ut, tmp_path):
    src = _layer(tmp_path / "src.tar.gz", _simple)
    cut = tmp_path / "cut.tar.gz"
    cut.write_bytes(src.read_bytes()[:len(src.read_bytes()) // 2])
    _refused(_convert(stargz_ut, cut, tmp_path / "out.estargz"), "estargz:")


def test_a_missing_source_is_refused(stargz_ut, tmp_path):
    r = _convert(stargz_ut, tmp_path / "nope.tar.gz", tmp_path / "out")
    assert r.returncode == 1 and "cannot open source" in r.stdout

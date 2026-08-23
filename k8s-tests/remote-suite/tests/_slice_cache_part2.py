def _seed(xc, name, size=_FILESIZE):
    """Write `size` random bytes to the origin under `name`; return the bytes.
    Random content makes every slice unique, so a mis-offset read is caught and
    each test's file is independent in the cache."""
    data = os.urandom(size)
    with open(os.path.join(xc["origin_data"], name), "wb") as f:
        f.write(data)
    return data


def _record_cached_object(obj, ci, slices, wholes):
    stat_result = os.stat(obj)
    on_disk = stat_result.st_blocks * 512
    if ci is None:
        wholes.append(obj)
        return
    fields, present = ci
    block_size = fields["block_size"]
    for index in present:
        slices[index] = min(
            block_size, fields["size"] - index * block_size)
    complete = fields["flags"] & _CINFO_F_COMPLETE
    if not complete and on_disk > sum(slices.values()) + block_size:
        wholes.append(obj)


def _cached(xc, name):
    """Inspect cache_root for `name` under the phase-64 sd_cache on-disk format:
    ONE SPARSE object file named exactly `name` (filesystem holes for the slices
    not yet fetched) plus a `<name>.cinfo` present-bitmap sidecar — the old
    per-slice `<name>.__xrds_<k>_<idx>` files are gone.

    Returns (slices, wholes, metas) with the SAME contract the assertions expect:
      slices : {slice-index -> logical slice size} for each block the .cinfo
               bitmap records present (last slice clamped to the remainder),
      wholes : [] for a correctly SPARSE object; [obj] only if a PARTIAL object is
               materialized full on disk (a genuine whole-file copy — the
               invariant these tests guard). A COMPLETE file is legitimately full,
               so it is NOT a whole-file copy,
      metas  : the `.cinfo` sidecar list (the file-level record)."""
    root = xc["cache_root"]
    metas = glob.glob(os.path.join(root, "**", name + ".cinfo"), recursive=True)
    objs = [f for f in glob.glob(os.path.join(root, "**", name), recursive=True)
            if os.path.isfile(f)]
    slices = {}
    wholes = []
    ci = _read_cinfo(xc, name)
    for obj in objs:
        _record_cached_object(obj, ci, slices, wholes)
    return slices, wholes, metas


def _slice_bytes(xc, name, idx):
    """Read slice `idx`'s bytes from the sparse cache object (the slice must be
    present, else the read returns hole zeros)."""
    matches = [f for f in glob.glob(os.path.join(xc["cache_root"], "**", name),
                                    recursive=True) if os.path.isfile(f)]
    assert matches, "cache object %s not on disk" % name
    with open(matches[0], "rb") as f:
        f.seek(idx * _SLICE)
        return f.read(_SLICE)


def _assert_partial_slice_cache(xcache, name, data, got, off, length):
    assert got == data[off:off + length], "served bytes != origin range"
    slices, wholes, metas = _cached(xcache, name)
    assert wholes == [], "cache stored a WHOLE-FILE copy: %r" % wholes
    assert set(slices) <= {0, 2}, \
        "non-sparse: cached slices beyond {0,2}: %s" % sorted(slices)
    assert 2 in slices, "touched slice 2 not cached: %s" % sorted(slices)
    assert sum(slices.values()) <= 2 * _SLICE < _FILESIZE, \
        "stored %d bytes — not sparse vs %d-byte file" % (sum(slices.values()), _FILESIZE)
    assert metas, "file-level .__xrds.meta sidecar missing"
    assert _slice_bytes(xcache, name, 2) == data[2 * _SLICE:3 * _SLICE], \
        "cached slice 2 bytes != origin"


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)
def test_partial_read_caches_only_the_touched_slice(xcache):
    name = "partial_one.bin"
    data = _seed(xcache, name)
    off = 2 * _SLICE + _SLICE // 2       # inside slice 2
    length = 64 * 1024
    sock = _session(xcache["host"], xcache["port"])
    fh = _open_read(sock, "/" + name)
    got = _read(sock, fh, off, length)
    sock.close()

    _assert_partial_slice_cache(xcache, name, data, got, off, length)


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)
def test_multislice_range_caches_only_spanning_slices(xcache):
    name = "range_span.bin"
    data = _seed(xcache, name)
    off = 5 * _SLICE                     # spans slice 5 and slice 6
    length = 3 * (_SLICE // 2)           # 1.5 MiB
    sock = _session(xcache["host"], xcache["port"])
    fh = _open_read(sock, "/" + name)
    got = _read(sock, fh, off, length)
    sock.close()

    assert got == data[off:off + length], "stitched range != origin"
    slices, wholes, _ = _cached(xcache, name)
    assert wholes == [], "cache stored a WHOLE-FILE copy: %r" % wholes
    assert set(slices) <= {0, 5, 6}, \
        "non-sparse: cached slices beyond {0,5,6}: %s" % sorted(slices)
    assert {5, 6} <= set(slices), "spanning slices 5,6 not both cached: %s" % sorted(slices)
    assert sum(slices.values()) <= 3 * _SLICE < _FILESIZE


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)
def test_disjoint_reads_leave_the_gaps_uncached(xcache):
    name = "disjoint.bin"
    data = _seed(xcache, name)
    sock = _session(xcache["host"], xcache["port"])
    fh = _open_read(sock, "/" + name)
    for idx in (2, 12):                  # two far-apart 4 KiB reads
        off = idx * _SLICE + 4096
        got = _read(sock, fh, off, 4096)
        assert got == data[off:off + 4096], "slice %d read wrong bytes" % idx
    sock.close()

    _assert_disjoint_cache(xcache, name)


def _assert_disjoint_cache(xcache, name):
    slices, wholes, _ = _cached(xcache, name)
    assert wholes == [], "cache stored a WHOLE-FILE copy: %r" % wholes
    assert set(slices) <= {0, 2, 12}, "non-sparse: %s" % sorted(slices)
    assert {2, 12} <= set(slices), "touched slices not cached: %s" % sorted(slices)
    for gap in (1, 4, 7, 10, 13, 15):
        assert gap not in slices, "gap slice %d was cached (not sparse)" % gap
    assert sum(slices.values()) <= 3 * _SLICE < _FILESIZE


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)
def test_complete_read_caches_all_slices_byte_exact_no_whole_copy(xcache):
    name = "complete.bin"
    data = _seed(xcache, name)
    sock = _session(xcache["host"], xcache["port"])
    fh = _open_read(sock, "/" + name)
    whole = b""
    for o in range(0, _FILESIZE, _SLICE):
        whole += _read(sock, fh, o, _SLICE)
    sock.close()

    assert whole == data, "full read != origin file"
    slices, wholes, _ = _cached(xcache, name)
    # The headline guarantee: even a COMPLETE read keeps the file as discrete
    # slices and never collapses it into a single whole-file blob.
    assert wholes == [], "a full read created a WHOLE-FILE copy: %r" % wholes
    assert set(slices) == set(range(_NSLICES)), \
        "expected all %d slices, got %s" % (_NSLICES, sorted(slices))
    assert sum(slices.values()) == _FILESIZE, "slice bytes != file size"
    for idx in range(_NSLICES):          # every slice byte-exact vs origin
        assert _slice_bytes(xcache, name, idx) == data[idx * _SLICE:(idx + 1) * _SLICE], \
            "cached slice %d bytes != origin" % idx


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)
def test_last_partial_slice_is_clamped(xcache):
    # A file that is NOT a whole number of slices: the final slice must store
    # only the remainder, not a padded full slice.
    name = "ragged.bin"
    size = 3 * _SLICE + 100 * 1024       # 3 full slices + 100 KiB
    data = _seed(xcache, name, size)
    off = 3 * _SLICE + 10 * 1024         # inside the ragged final slice (idx 3)
    sock = _session(xcache["host"], xcache["port"])
    fh = _open_read(sock, "/" + name)
    got = _read(sock, fh, off, 20 * 1024)
    sock.close()

    assert got == data[off:off + 20 * 1024], "ragged-slice read wrong bytes"
    slices, wholes, _ = _cached(xcache, name)
    assert wholes == [], "cache stored a WHOLE-FILE copy: %r" % wholes
    assert 3 in slices, "ragged final slice 3 not cached: %s" % sorted(slices)
    assert slices[3] == 100 * 1024, \
        "final slice not clamped to the remainder: %d" % slices[3]
    assert _slice_bytes(xcache, name, 3) == data[3 * _SLICE:size]


# ===========================================================================
# §9 .cinfo block-present bitmap — record-keeping of which blocks are cached.
#
# Two layers, mirroring the slice tests above:
#   * TestCinfoLibrary — the standalone C unit tests for src/fs/cache/cinfo.c
#     (format roundtrip, bit ops, garbage handling, record_block RMW). No server.
#   * The integration tests assert that as the slice cache fills windows, the
#     "<cachefile>.cinfo" bitmap records EXACTLY the blocks fetched (and flips to
#     COMPLETE only once every block is present) — the durable record of what the
#     node holds, alongside the per-slice files.
# ===========================================================================

class TestCinfoLibrary:
    """The .cinfo bitmap C unit tests, linked against the real cinfo.o."""

    def test_cinfo_library_unit_tests_pass(self):
        cinfo_o = os.path.join(_OBJS, "addon", "cache", "cinfo.o")
        if not os.path.exists(cinfo_o):
            pytest.skip("cinfo.o not built under %s; build the module first" % _OBJS)
        runner = os.path.join(_HERE, "c", "run_cinfo_tests.sh")
        proc = subprocess.run([runner, _OBJS], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=120)
        out = proc.stdout.decode(errors="replace")
        assert proc.returncode == 0, "cinfo unit tests failed:\n%s" % out
        assert ", 0 failed" in out, "unexpected cinfo unit output:\n%s" % out


def _read_cinfo(xc, name):
    """Parse "<cache_root>/.../<name>.cinfo": return (fields, present_set) where
    fields has magic/version/flags/block_size/size/nblocks and present_set is the
    set of block indices whose bit is 1. None if the sidecar is absent.

    The bitmap is the LAST ceil(nblocks/8) bytes of the file (the store truncates
    to header+bitmap), so we never need to hardcode the header size."""
    matches = glob.glob(os.path.join(xc["cache_root"], "**", name + ".cinfo"),
                        recursive=True)
    if not matches:
        return None
    with open(matches[0], "rb") as f:
        blob = f.read()
    magic = struct.unpack_from("<I", blob, 0)[0]
    version = struct.unpack_from("<H", blob, 4)[0]
    flags = struct.unpack_from("<H", blob, 6)[0]
    block_size = struct.unpack_from("<I", blob, 8)[0]
    size = struct.unpack_from("<Q", blob, 16)[0]
    nblocks = struct.unpack_from("<Q", blob, 32)[0]
    blen = (nblocks + 7) // 8
    bitmap = blob[len(blob) - blen:] if blen else b""
    present = {i for i in range(nblocks)
               if (bitmap[i >> 3] >> (i & 7)) & 1}
    fields = {"magic": magic, "version": version, "flags": flags,
              "block_size": block_size, "size": size, "nblocks": nblocks}
    return fields, present


_CINFO_MAGIC = 0x58434931
_CINFO_F_COMPLETE = 0x1
_CINFO_F_PARTIAL = 0x2


def _wait_cinfo(xc, name, want_block, timeout=8.0):
    """Poll until the .cinfo for `name` exists and records `want_block` present
    (the fill thread writes the bitmap just after the slice file lands, so it can
    lag the client read by a moment); return (fields, present_set)."""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = _read_cinfo(xc, name)
        if last is not None and want_block in last[1]:
            return last
        time.sleep(0.1)
    raise AssertionError("cinfo for %s never recorded block %d (got %r)"
                         % (name, want_block, last))


def _assert_partial_cinfo(fields, present):
    assert fields["magic"] == _CINFO_MAGIC, \
        "bad .cinfo magic: %#x" % fields["magic"]
    assert fields["block_size"] == _SLICE, "block_size != slice size"
    assert (fields["size"], fields["nblocks"]) == (_FILESIZE, _NSLICES), \
        "validity wrong: %r" % fields
    assert present <= {0, 2}, \
        "non-sparse cinfo: blocks beyond {0,2}: %s" % sorted(present)
    assert 2 in present, "touched block 2 not recorded: %s" % sorted(present)
    assert fields["flags"] & _CINFO_F_PARTIAL, "partial fill not flagged PARTIAL"
    assert not (fields["flags"] & _CINFO_F_COMPLETE), "partial wrongly COMPLETE"


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)
def test_cinfo_partial_read_records_only_touched_blocks(xcache):
    name = "cinfo_partial.bin"
    _seed(xcache, name)
    off = 2 * _SLICE + _SLICE // 2       # inside block 2
    sock = _session(xcache["host"], xcache["port"])
    fh = _open_read(sock, "/" + name)
    _read(sock, fh, off, 64 * 1024)
    sock.close()

    fields, present = _wait_cinfo(xcache, name, want_block=2)
    _assert_partial_cinfo(fields, present)


@pytest.mark.xfail(reason=_SLICE_DEFERRED, strict=False)
def test_cinfo_complete_read_marks_all_blocks_complete(xcache):
    name = "cinfo_complete.bin"
    _seed(xcache, name)
    sock = _session(xcache["host"], xcache["port"])
    fh = _open_read(sock, "/" + name)
    for o in range(0, _FILESIZE, _SLICE):
        _read(sock, fh, o, _SLICE)
    sock.close()

    fields, present = _wait_cinfo(xcache, name, want_block=_NSLICES - 1)
    assert present == set(range(_NSLICES)), \
        "cinfo missing blocks: %s" % sorted(set(range(_NSLICES)) - present)
    assert fields["flags"] & _CINFO_F_COMPLETE, "fully-cached file not flagged COMPLETE"
    assert not (fields["flags"] & _CINFO_F_PARTIAL), "complete wrongly PARTIAL"

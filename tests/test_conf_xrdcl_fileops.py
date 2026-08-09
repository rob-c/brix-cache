from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_xrdcl_fileops_helpers")

@pytest.mark.parametrize("rel", list(SZ.keys()))
def test_open_read_status_parity(srv, rel):
    """open(READ) on an existing file -> ok on both, identical status fields."""
    fo, so = _open(srv["our"], rel, OpenFlags.READ)
    fO, sO = _open(srv["off"], rel, OpenFlags.READ)
    fo.close()
    fO.close()
    assert so.ok and sO.ok, (rel, _status_tuple(so), _status_tuple(sO))
    assert _status_tuple(so) == _status_tuple(sO), rel


@pytest.mark.parametrize("rel", [
    "no_such_file.bin", "deep/missing.txt", "empty_dir/ghost",
    "sub/not/here.dat",
])
def test_open_read_missing_status_parity(srv, rel):
    """open(READ) on a missing path -> not ok, same code/errno (3011) both servers."""
    fo, so = _open(srv["our"], rel, OpenFlags.READ)
    fO, sO = _open(srv["off"], rel, OpenFlags.READ)
    fo.close()
    fO.close()
    assert not so.ok and not sO.ok, (rel, so.ok, sO.ok)
    assert _status_tuple(so) == _status_tuple(sO), \
        f"{rel}: ours={_status_tuple(so)} stock={_status_tuple(sO)}"


# =========================================================================== #
# 2. read() — offset / size matrix, exact byte equality our-vs-stock          #
# =========================================================================== #

@pytest.mark.parametrize("rel,off,size", _read_cases(),
                         ids=lambda v: str(v))
def test_read_bytes_parity(srv, rel, off, size):
    """read(off,size) returns byte-identical data on both servers."""
    so, do = _read(srv["our"], rel, off, size)
    sO, dO = _read(srv["off"], rel, off, size)
    assert so == sO, f"{rel}@{off}+{size}: status ours={so} stock={sO}"
    assert do == dO, (
        f"{rel}@{off}+{size}: bytes diverge "
        f"(ours {None if do is None else len(do)}B vs "
        f"stock {None if dO is None else len(dO)}B)")


@pytest.mark.parametrize("rel", ["sz_4095.bin", "sz_4096.bin", "sz_4097.bin",
                                 "sz_8192.bin", "sz_65536.bin"])
def test_read_whole_file_parity(srv, rel):
    """A single read large enough to span the file returns identical full bytes."""
    sz = SZ[rel]
    so, do = _read(srv["our"], rel, 0, sz)
    sO, dO = _read(srv["off"], rel, 0, sz)
    assert so == sO, (rel, so, sO)
    assert do == dO and do is not None and len(do) == sz, \
        (rel, None if do is None else len(do))


@pytest.mark.parametrize("rel", ["sz_4096.bin", "big1m.bin"])
def test_read_at_eof_zero_bytes(srv, rel):
    """read() exactly at EOF -> ok with 0 bytes on both (do_ReadAll semantics)."""
    sz = SZ[rel]
    so, do = _read(srv["our"], rel, sz, 4096)
    sO, dO = _read(srv["off"], rel, sz, 4096)
    assert so == sO, (rel, so, sO)
    assert do == dO == b"", (rel, do, dO)


@pytest.mark.parametrize("rel", ["sz_4096.bin", "big1m.bin"])
def test_read_beyond_eof_zero_bytes(srv, rel):
    """read() far beyond EOF -> ok with 0 bytes on both."""
    sz = SZ[rel]
    so, do = _read(srv["our"], rel, sz + 100000, 4096)
    sO, dO = _read(srv["off"], rel, sz + 100000, 4096)
    assert so == sO, (rel, so, sO)
    assert do == dO == b"", (rel, do, dO)


# =========================================================================== #
# 3. vector_read() — segment-count + boundary matrix                          #
# =========================================================================== #

@pytest.mark.parametrize("rel,chunks", _vread_cases(),
                         ids=lambda v: str(v) if not isinstance(v, list)
                         else f"{len(v)}seg")
def test_vector_read_parity(srv, rel, chunks):
    """vector_read returns identical VectorReadInfo.size and per-chunk
    offset/length/bytes on both servers."""
    so, po = _vread(srv["our"], rel, chunks)
    sO, pO = _vread(srv["off"], rel, chunks)
    assert so == sO, f"{rel}: vread status ours={so} stock={sO}"
    assert po is not None and pO is not None, (rel, po, pO)
    assert po["size"] == pO["size"], \
        f"{rel}: total size ours={po['size']} stock={pO['size']}"
    # offsets + lengths must agree, in order
    off_len_o = [(o, l) for (o, l, _) in po["chunks"]]
    off_len_O = [(o, l) for (o, l, _) in pO["chunks"]]
    assert off_len_o == off_len_O, \
        f"{rel}: chunk offset/length diverge ours={off_len_o} stock={off_len_O}"
    # and the data bytes of each chunk
    bytes_o = [b for (_, _, b) in po["chunks"]]
    bytes_O = [b for (_, _, b) in pO["chunks"]]
    assert bytes_o == bytes_O, f"{rel}: chunk bytes diverge"


@pytest.mark.parametrize("rel", ["sz_4096.bin", "sz_8192.bin",
                                 "sz_65536.bin", "big1m.bin"])
def test_vector_read_matches_read_bytes(srv, rel):
    """The bytes returned by vector_read equal those returned by read() for the
    same ranges (the readv-vs-read byte-identity invariant; the same property
    pgread asserts against read). Checked independently on OUR and on stock."""
    sz = SZ[rel]
    seg = [(0, 128), (sz // 2, 128), (max(sz - 128, 0), 128)]
    for tag in ("our", "off"):
        url = srv[tag]
        st, parsed = _vread(url, rel, seg)
        assert parsed is not None, (tag, rel, st)
        for (off, ln, vbytes) in parsed["chunks"]:
            rst, rbytes = _read(url, rel, off, ln)
            assert rbytes == vbytes, \
                f"{tag} {rel}@{off}+{ln}: vread bytes != read bytes"


# =========================================================================== #
# 4. write / sync / truncate / stat-on-open round trips + read-back parity     #
# =========================================================================== #

@pytest.mark.parametrize("payload_sz", [1, 100, 4096, 4097, 8192, 70000])
def test_write_readback_byte_parity(srv, payload_sz):
    """Write the SAME deterministic payload to a scratch file on each server
    (NEW|MAKEPATH), sync, close, then read it back; bytes must match on both
    and equal what we wrote."""
    payload = bytes((i * 31 + 7) & 0xFF for i in range(payload_sz))
    rel = _scratch(None, f"wb_{payload_sz}.bin")
    back = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, f"{tag}: open NEW|MAKEPATH failed {_status_tuple(st)}"
        wst, _ = w.write(payload, 0)
        assert wst.ok, f"{tag}: write failed {_status_tuple(wst)}"
        w.sync()
        w.close()
        rst, data = _read(url, rel, 0, payload_sz)
        assert rst[0], (tag, rst)
        back[tag] = data
    assert back["our"] == back["off"] == payload, \
        f"sz={payload_sz}: readback diverges"


def test_truncate_then_stat_size_parity(srv):
    """write 5000B -> truncate(100) -> stat: size must read 100 on both."""
    payload = b"T" * 5000
    rel = _scratch(None, "trunc.bin")
    sizes = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, (tag, _status_tuple(st))
        w.write(payload, 0)
        w.sync()
        tst, _ = w.truncate(100)
        assert tst.ok, (tag, _status_tuple(tst))
        sst, si = w.stat(force=True)
        assert sst.ok and si is not None, (tag, _status_tuple(sst))
        sizes[tag] = int(si.size)
        w.close()
    assert sizes["our"] == sizes["off"] == 100, sizes


@pytest.mark.parametrize("trunc_to", [0, 1, 123, 4096, 10000])
def test_truncate_various_sizes_parity(srv, trunc_to):
    """truncate to a range of sizes; stat size and read-back length agree."""
    payload = b"Z" * 6000
    rel = _scratch(None, f"trv_{trunc_to}.bin")
    result = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, (tag, _status_tuple(st))
        w.write(payload, 0)
        w.truncate(trunc_to)
        w.sync()
        _, si = w.stat(force=True)
        w.close()
        rst, data = _read(url, rel, 0, max(trunc_to, 1) + 10)
        result[tag] = (int(si.size), len(data) if data is not None else None)
    assert result["our"] == result["off"], result
    assert result["our"][0] == trunc_to, result


def test_stat_on_open_size_flags_parity(srv):
    """stat() on an open handle: size + flags agree across servers. The
    StatInfo.id formula is a known divergence (see dedicated xfail)."""
    rel = "sz_8192.bin"
    out = {}
    for tag in ("our", "off"):
        f, st = _open(srv[tag], rel, OpenFlags.READ)
        assert st.ok, (tag, _status_tuple(st))
        sst, si = f.stat()
        f.close()
        assert sst.ok and si is not None, (tag, _status_tuple(sst))
        out[tag] = (int(si.size), int(si.flags))
    assert out["our"] == out["off"], \
        f"stat size/flags diverge ours={out['our']} stock={out['off']}"
    assert out["our"][0] == SZ[rel]


# DIVERGENCE: StatInfo.id (chunks[0] of the stat wire response). Stock encodes a
# composite (dev<<...|ino) per XrdXrootdProtocol::StatGen
# (/tmp/brix-src/src/XrdXrootd/XrdXrootdXeq.cc); ours emits the bare inode.
# XrdCl exposes StatInfo.id (XrdClXRootDResponses.cc:140) though gfal ignores it.
@pytest.mark.xfail(reason="DIVERGENCE: StatInfo.id is bare inode vs stock "
                          "composite dev/ino (XrdXrootdXeq.cc StatGen); "
                          "gfal ignores id, alignment is cosmetic",
                   strict=False)
def test_stat_on_open_id_parity(srv):
    """StatInfo.id should match stock's composite id formula."""
    rel = "sz_4096.bin"
    ids = {}
    for tag in ("our", "off"):
        f, st = _open(srv[tag], rel, OpenFlags.READ)
        _, si = f.stat()
        f.close()
        ids[tag] = int(si.id)
    assert ids["our"] == ids["off"], ids


# =========================================================================== #
# 5. open() flags: NEW-on-existing / UPDATE / WRITE / DELETE truncate-on-open  #
# =========================================================================== #
def test_open_new_on_existing_error_parity(srv):
    """open(NEW) on an existing file -> error with the same code/errno (3018)."""
    rel = _scratch(None, "exists_new.bin")
    out = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, (tag, _status_tuple(st))
        w.write(b"hi", 0)
        w.close()
        f2, st2 = _open(url, rel, OpenFlags.NEW, 0o644)
        f2.close()
        out[tag] = (bool(st2.ok), int(st2.code), int(st2.errno))
    assert not out["our"][0] and not out["off"][0], out
    assert out["our"] == out["off"], \
        f"NEW-on-existing status diverges ours={out['our']} stock={out['off']}"


def test_open_update_existing_parity(srv):
    """open(UPDATE) on an existing file succeeds on both."""
    rel = _scratch(None, "upd.bin")
    out = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        w.write(b"abcd", 0)
        w.close()
        u, ust = _open(url, rel, OpenFlags.UPDATE, 0o644)
        out[tag] = _status_tuple(ust)
        if ust.ok:
            u.close()
    assert out["our"] == out["off"] and out["our"][0], out


def test_open_write_creates_parity(srv):
    """open(WRITE|NEW|MAKEPATH) creates a writable handle on both."""
    rel = _scratch(None, "wr.bin")
    out = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel,
                      OpenFlags.WRITE | OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        out[tag] = _status_tuple(st)
        if st.ok:
            w.write(b"payload", 0)
            w.close()
    assert out["our"] == out["off"] and out["our"][0], out


def test_open_delete_truncates_on_open_parity(srv):
    """open(DELETE|WRITE) on an existing non-empty file truncates it to 0 on
    open (kXR_delete semantics); size==0 on both servers afterward."""
    rel = _scratch(None, "del.bin")
    sizes = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, (tag, _status_tuple(st))
        w.write(b"X" * 4096, 0)
        w.sync()
        w.close()
        d, dst = _open(url, rel, OpenFlags.DELETE | OpenFlags.WRITE, 0o644)
        assert dst.ok, f"{tag}: DELETE-open failed {_status_tuple(dst)}"
        _, si = d.stat(force=True)
        sizes[tag] = int(si.size) if si is not None else None
        d.close()
    assert sizes["our"] == sizes["off"] == 0, sizes


def test_makepath_creates_nested_dirs_parity(srv):
    """NEW|MAKEPATH on a deep non-existent path creates intermediate dirs and
    a readable file on both servers (read-back equality)."""
    rel = "scratch_fileops/mp/a/b/c/leaf.bin"
    payload = b"deep-makepath-payload-0123456789"
    back = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, f"{tag}: {_status_tuple(st)}"
        w.write(payload, 0)
        w.sync()
        w.close()
        _, data = _read(url, rel, 0, len(payload))
        back[tag] = data
    assert back["our"] == back["off"] == payload, back


# =========================================================================== #
# 6. lifecycle error parity — double-open / use-after-close                    #
# =========================================================================== #
@pytest.mark.parametrize("tag", ["our", "off"])
def test_double_open_is_invalid_operation(srv, tag):
    """Calling open() twice on the same File yields a client-side 'Invalid
    operation' (code 3) on both servers (XrdCl rejects it before the wire)."""
    url = srv[tag]
    f, st = _open(url, "hello.txt", OpenFlags.READ)
    assert st.ok, (tag, _status_tuple(st))
    st2, _ = f.open(url + "//data.bin", OpenFlags.READ)
    f.close()
    assert not st2.ok and st2.code == 3, \
        f"{tag}: double-open expected code 3, got {_status_tuple(st2)}"


def test_double_open_status_parity(srv):
    """The double-open rejection status fields are identical our-vs-stock."""
    out = {}
    for tag in ("our", "off"):
        url = srv[tag]
        f, st = _open(url, "hello.txt", OpenFlags.READ)
        st2, _ = f.open(url + "//data.bin", OpenFlags.READ)
        f.close()
        out[tag] = _status_tuple(st2)
    assert out["our"] == out["off"], out


@pytest.mark.parametrize("tag", ["our", "off"])
def test_read_after_close_raises(srv, tag):
    """A read() after close() is rejected identically on both servers (the
    proxy/bindings surface raises ValueError on the closed handle)."""
    url = srv[tag]
    f, st = _open(url, "hello.txt", OpenFlags.READ)
    assert st.ok, (tag, _status_tuple(st))
    f.close()
    with pytest.raises((ValueError, IOError, RuntimeError)):
        f.read(0, 10)


@pytest.mark.parametrize("tag", ["our", "off"])
def test_is_open_lifecycle(srv, tag):
    """is_open() flips False after close() on both servers."""
    url = srv[tag]
    f, st = _open(url, "hello.txt", OpenFlags.READ)
    assert st.ok and f.is_open(), (tag, _status_tuple(st))
    f.close()
    assert not f.is_open(), tag


# =========================================================================== #
# 7. sync() and reopen parity                                                  #
# =========================================================================== #

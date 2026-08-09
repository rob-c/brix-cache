from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_truncate_sync_helpers")

@pytest.mark.parametrize("keep", [0, 1, 4096, 100000])
def test_truncate_big_down_prefix(srv, keep):
    src = det_bytes(1 << 20, seed=7)        # mirrors make_rich_tree big1m.bin seed
    our_w = uniq(f"bigtrunc_our_{keep}.bin")
    off_w = uniq(f"bigtrunc_off_{keep}.bin")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "wb") as f:
            f.write(src)
    assert fs(srv["our"], "truncate", our_w, str(keep))[0] == 0, "our shrink"
    assert fs(srv["off"], "truncate", off_w, str(keep))[0] == 0, "off shrink"
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        with open(disk_for(srv, url, w), "rb") as f:
            got = f.read()
        assert got == src[:keep], f"{url} big-shrink kept wrong prefix (keep={keep})"


# =========================================================================== #
# 11. APPEND-STYLE: open(update) existing, write at offset==size -> grows file.
# =========================================================================== #
@pytest.mark.parametrize("base_n,app_n", [(100, 50), (4096, 4096), (1, 9999)])
def test_append_at_eof_grows(srv, base_n, app_n):
    base = det_bytes(base_n, seed=31)
    app = det_bytes(app_n, seed=32)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"append_{who}_{base_n}_{app_n}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_updt)
            st, body = _write(s_sock, fh, base_n, app)
            assert st == kXR_ok, f"{who} append write failed: err={_err(body)}"
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == base_n + app_n, f"{who} append size wrong"
        assert got == base + app, f"{who} append content wrong"


# =========================================================================== #
# 12. READ AFTER TRUNCATE-EXTEND: bytes in [oldsize,newsize) are zero on BOTH.
# =========================================================================== #
@pytest.mark.parametrize("old,new", [(100, 4096), (4096, 8192), (1, 65536)])
def test_read_after_extend_zero_region(srv, old, new):
    base = det_bytes(old, seed=41)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"extread_{who}_{old}_{new}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        assert fs(url, "truncate", wire, str(new))[0] == 0, f"{who} extend"
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_read)
            st, data = _read(s_sock, fh, old, new - old)
            assert st == kXR_ok, f"{who} read extended region failed"
            assert data == b"\x00" * (new - old), \
                f"{who} extended [old,new) region not zero"
            _close(s_sock, fh)
        finally:
            s_sock.close()


# =========================================================================== #
# 13. ZERO-LENGTH WRITE -> no-op; size unchanged; rc ok parity.
# =========================================================================== #
def test_zero_length_write_is_noop(srv):
    base = det_bytes(256, seed=51)
    res = {}
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"zerowrite_{who}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_updt)
            st, body = _write(s_sock, fh, 128, b"")
            res[who] = st
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            assert f.read() == base, f"{who} zero-length write changed content/size"
    assert (res["our"] == kXR_ok) == (res["off"] == kXR_ok), \
        f"zero-length write rc parity differs: {res}"


# =========================================================================== #
# 14. WRITE PAST a truncated-shrunk file then read -> correct (re-grow via write).
# =========================================================================== #
@pytest.mark.parametrize("idx,shrink_to,write_off,wlen", [
    (0, 10, 100, 16),
    (1, 0, 4096, 32),
    (2, 50, 50, 64),
])
def test_write_past_shrunk_file(srv, idx, shrink_to, write_off, wlen):
    base = det_bytes(200, seed=61)
    payload = det_bytes(wlen, seed=62)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"shrinkwrite_{who}_{idx}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        # shrink first (path-based), then write past the new EOF
        assert fs(url, "truncate", wire, str(shrink_to))[0] == 0, f"{who} shrink"
        s_sock = _session(url)
        try:
            fh = _open_handle(s_sock, wire, kXR_open_updt)
            st, body = _write(s_sock, fh, write_off, payload)
            assert st == kXR_ok, f"{who} write past shrunk failed: err={_err(body)}"
            assert _close(s_sock, fh)[0] == kXR_ok
        finally:
            s_sock.close()
        # expected: kept prefix [0,shrink_to), zeros up to write_off, payload
        expected = bytearray(max(shrink_to, write_off + wlen))
        expected[0:shrink_to] = base[:shrink_to]
        expected[write_off:write_off + wlen] = payload
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert got == bytes(expected), f"{who} write-past-shrunk content wrong"


# =========================================================================== #
# 15. EXTEND-then-SHRINK round trip leaves exact prefix (extra coverage).
# =========================================================================== #
@pytest.mark.parametrize("n,up,down", [(100, 5000, 50), (4096, 1 << 20, 4096)])
def test_extend_then_shrink_roundtrip(srv, n, up, down):
    base = det_bytes(n, seed=71)
    for who, url in (("our", srv["our"]), ("off", srv["off"])):
        wire = uniq(f"extshrink_{who}_{n}_{up}_{down}.bin")
        with open(disk_for(srv, url, wire), "wb") as f:
            f.write(base)
        assert fs(url, "truncate", wire, str(up))[0] == 0, f"{who} extend"
        assert os.path.getsize(disk_for(srv, url, wire)) == up
        assert fs(url, "truncate", wire, str(down))[0] == 0, f"{who} shrink"
        with open(disk_for(srv, url, wire), "rb") as f:
            got = f.read()
        assert len(got) == down, f"{who} ext-shrink size wrong"
        assert got == base[:down], f"{who} ext-shrink prefix corrupted"

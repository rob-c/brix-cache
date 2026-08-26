from split_continuation import reexport as _reexport
def _expression_1(size):
    return (
        16 if size > 65536 else 4
    )

def _expression_2(our, plan):
    return (
        _readv_drain(our.sock, [_seg(our.fh, ln, o) for o, ln in plan])
    )

def _expression_3(dst, name, srv):
    return (
        L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//{name}", dst],
                                 timeout=120 if name == "big1m.bin" else 60)
    )


def _check_test_readv_reassembly_equals_xrdcp_1(st, name):
    assert st == kXR_ok, f"raw readv reassembly of {name} failed"

def _check_test_readv_reassembly_equals_xrdcp_2(rc, name, out, err):
    assert rc == 0, f"xrdcp download of {name} from OUR server failed: {out}{err}"


_reexport(globals(), "_test_conf_readv_helpers")

pytestmark = pytest.mark.xdist_group("conf_readv_b")

def test_readv_empty_file(srv):
    name = "empty.txt"
    our, off_h = _open_both(srv, name)
    try:
        _, st_o, _ = _readv(our.sock, [_seg(our.fh, 16, 0)])
        _, st_f, _ = _readv(off_h.sock, [_seg(off_h.fh, 16, 0)])
    finally:
        our.close()
        off_h.close()
    assert st_o == st_f, (
        f"readv of empty.txt diverges: ours={st_o} stock={st_f}")


# ===========================================================================
# RAW interleave on ONE handle: read, readv (multi-seg), read again — all
# correct, and identical to stock.
# ===========================================================================

def test_interleave_read_readv_read(srv):
    name = "sz_65536.bin"
    src = _local(srv, name)
    (s1o, b1o), (s2o, vo, chunks), (s3o, b3o) = _interleave(*srv["our_hp"], name)
    (s1f, b1f), (s2f, vf, _), (s3f, b3f) = _interleave(*srv["off_hp"], name)
    assert s1o == s1f == kXR_ok and s2o == s2f == kXR_ok and s3o == s3f == kXR_ok
    assert b1o == src[0:100], "OUR first read wrong"
    assert b1o == b1f, "first read diverges from stock"
    want_v = b"".join(src[o:o + ln] for o, ln in chunks)
    assert vo == want_v, "OUR interleaved readv wrong"
    assert vo == vf, "interleaved readv diverges from stock"
    assert b3o == src[2048:2048 + 512], "OUR third read wrong"
    assert b3o == b3f, "third read diverges from stock"


# ===========================================================================
# INTEGRITY: full-file readv reassembly == xrdcp download of the same file.
# The raw readv path and the high-level client read path must agree.
# ===========================================================================
@pytest.mark.parametrize("name", ["data.bin", "sz_8192.bin", "sz_65536.bin",
                                  "big1m.bin"])
def test_readv_reassembly_equals_xrdcp(srv, tmp_path, name):
    # 1) full-file via raw readv on OUR server.
    size = len(_local(srv, name))
    n = _expression_1(size)
    plan = _equal_segments(size, n)
    our = _Handle(*srv["our_hp"], name)
    try:
        st, body = _expression_2(our, plan)
    finally:
        our.close()
    _check_test_readv_reassembly_equals_xrdcp_1(st, name)
    via_readv = b"".join(p for (_f, _r, _o, p) in _parse_segments(body))

    # 2) full-file via stock xrdcp download from OUR server.
    dst = str(tmp_path / f"dl_{name}")
    rc, out, err = _expression_3(dst, name, srv)
    _check_test_readv_reassembly_equals_xrdcp_2(rc, name, out, err)
    via_xrdcp = open(dst, "rb").read()

    def _assert_test_readv_reassembly_equals_xrdcp_1():
        assert via_readv == via_xrdcp, (
            f"OUR readv reassembly of {name} differs from the xrdcp download "
            f"(readv={len(via_readv)}B xrdcp={len(via_xrdcp)}B)")
        assert via_readv == _local(srv, name), (
            f"OUR readv reassembly of {name} differs from the local source")

    _assert_test_readv_reassembly_equals_xrdcp_1()


# ===========================================================================
# Oracle: stock xrdcp stock->stock on a page-boundary file, proving the
# tooling itself is sound (a failure here is environmental, not ours).
# ===========================================================================
def test_oracle_stock_to_stock(srv, tmp_path):
    dst = str(tmp_path / "oracle.bin")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['off']}//sz_4097.bin", dst])
    assert rc == 0, f"oracle stock->stock failed (tooling broken): {out}{err}"
    assert open(dst, "rb").read() == _local(srv, "sz_4097.bin")

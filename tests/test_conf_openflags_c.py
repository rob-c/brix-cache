from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_openflags_helpers")

pytestmark = pytest.mark.xdist_group("conf_openflags_c")

@pytest.mark.parametrize("idx", range(3))
def test_open_wrto_existing_bare_handle(srv, idx):
    """open(write-to) of an existing file (no kXR_new) -> ok, 4-byte handle,
    parity (Xeq:1527 SFS_O_WRONLY)."""
    our_w = f"/wrto_our_{idx}.bin"
    off_w = f"/wrto_off_{idx}.bin"
    _seed_pair(srv, our_w, off_w, b"existing")
    so, sf = _both(srv)
    try:
        st_o, b_o = _open(so, our_w, kXR_open_wrto)
        st_f, b_f = _open(sf, off_w, kXR_open_wrto)
        raw = (f"\n  OURS cat={_category(st_o, b_o)} dlen={len(b_o)}"
               f"\n  STOCK cat={_category(st_f, b_f)} dlen={len(b_f)}")
        assert (st_o == kXR_ok) == (st_f == kXR_ok), f"open(wrto) existing differs:{raw}"
        if st_o == kXR_ok:
            assert len(b_o) == 4, f"open(wrto) body not bare handle:{raw}"
            _close(so, b_o[0:4])
            _close(sf, b_f[0:4])
    finally:
        so.close()
        sf.close()

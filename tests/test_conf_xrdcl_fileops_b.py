from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_xrdcl_fileops_helpers")

def test_sync_then_reopen_read_parity(srv):
    """write -> sync -> close -> reopen READ -> read-back: identical on both."""
    rel = _scratch(None, "sync_reopen.bin")
    payload = bytes(range(256)) * 4  # 1024 bytes
    back = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, (tag, _status_tuple(st))
        w.write(payload, 0)
        sst, _ = w.sync()
        assert sst.ok, (tag, _status_tuple(sst))
        w.close()
        # reopen and read back
        _, data = _read(url, rel, 0, len(payload))
        back[tag] = data
    assert back["our"] == back["off"] == payload, "sync/reopen readback diverges"


@pytest.mark.parametrize("off", [0, 512, 1000])
def test_partial_write_then_read_parity(srv, off):
    """Write at a non-zero offset (sparse-ish), read back the written window;
    the written bytes match on both servers."""
    rel = _scratch(None, f"partial_{off}.bin")
    payload = b"PARTIAL-WRITE-CHECK"
    back = {}
    for tag in ("our", "off"):
        url = srv[tag]
        w, st = _open(url, rel, OpenFlags.NEW | OpenFlags.MAKEPATH, 0o644)
        assert st.ok, (tag, _status_tuple(st))
        w.write(payload, off)
        w.sync()
        w.close()
        _, data = _read(url, rel, off, len(payload))
        back[tag] = data
    assert back["our"] == back["off"] == payload, (off, back)

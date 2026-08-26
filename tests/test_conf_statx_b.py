from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_statx_helpers")

pytestmark = pytest.mark.xdist_group("conf_statx_b")

@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sz_4096.bin"])
def test_stat_mtime_present_and_structurals_match(srv, path):
    o, f = _stat_both(srv, path)
    for who, d in (("our", o), ("stock", f)):
        mt = d.get("MTime", "")
        assert mt, f"{who} stat {path} missing MTime: {d}"
        assert any(c.isdigit() for c in mt), \
            f"{who} stat {path} MTime not numeric-ish: {mt!r}"
    # structural fields must agree even though mtimes differ
    assert ("IsDir" in o.get("Flags", "")) == ("IsDir" in f.get("Flags", "")), \
        f"IsDir divergence {path}: ours={o.get('Flags')!r} stock={f.get('Flags')!r}"
    assert o.get("Size") == f.get("Size"), \
        f"Size divergence {path}: ours={o.get('Size')!r} stock={f.get('Size')!r}"


# =========================================================================== #
# stat MTime numeric via RAW WIRE — the 4th StatGen field is a nonzero integer
# on both servers (xrdfs renders MTime as a date; raw wire keeps it numeric).
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sz_4096.bin"])
def test_raw_stat_mtime_field_nonzero(srv, path):
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        of = _stat_fields(_stat_path(o, path)[2])
        ff = _stat_fields(_stat_path(f, path)[2])
        assert len(ff) >= 4 and ff[3].lstrip("-").isdigit(), \
            f"stock raw stat {path} mtime field non-int (oracle): {ff}"
        assert len(of) >= 4 and of[3].lstrip("-").isdigit(), \
            f"our raw stat {path} mtime field non-int: {of}"
        assert int(of[3]) > 0, f"our raw stat {path} mtime not positive: {of[3]}"
        assert int(ff[3]) > 0, f"stock raw stat {path} mtime not positive: {ff[3]}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# stat trailing slash — file with trailing slash vs dir with trailing slash:
# error/ok parity vs stock.
# =========================================================================== #
@pytest.mark.parametrize("path", [
    "/hello.txt/",   # file + trailing slash (should error on both, ENOTDIR-ish)
    "/data.bin/",
    "/sub/",         # dir + trailing slash (should succeed on both)
    "/empty_dir/",
])
def test_stat_trailing_slash_parity(srv, path):
    orc = fs(srv["our"], "stat", path)[0]
    frc = fs(srv["off"], "stat", path)[0]
    assert (orc == 0) == (frc == 0), \
        f"stat trailing-slash success divergence {path!r}: ours_rc={orc} stock_rc={frc}"


# =========================================================================== #
# stat field key-set parity vs stock — the rendered xrdfs key set agrees.
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sub"])
def test_stat_key_set_matches_stock(srv, path):
    o, f = _stat_both(srv, path)
    need = {"Path", "Id", "Size", "Flags"}
    assert need <= set(f), f"stock stat {path} missing keys (oracle): {need - set(f)}"
    assert need <= set(o), f"our stat {path} missing keys {need - set(o)}"

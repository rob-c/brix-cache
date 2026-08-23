# =========================================================================== #
# 1) plain `ls /D` — basename SET equals stock's set (parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path", [
    "/", "/sub", "/empty_dir", "/many", "/deep", "/bigdir", "/special",
    "/mixed", "/nest", "/nest/x/y/z", "/deep/a/b/c",
])
def test_ls_basename_set_matches(srv, path):
    orc, oout, _ = fs(srv["our"], "ls", path)
    frc, fout, _ = fs(srv["off"], "ls", path)
    assert orc == 0, f"our ls {path} failed"
    assert frc == 0, f"stock ls {path} failed"
    assert _ls_set(oout) == _ls_set(fout), \
        f"ls {path} divergence: ours={_ls_set(oout)} stock={_ls_set(fout)}"


# =========================================================================== #
# 2) `ls -l` — per-entry size column matches stock (parametrized incl bigdir)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/", "/many", "/bigdir", "/sub", "/mixed"])
def test_ls_l_sizes_match_stock(srv, path):
    o = _ls_l_sizes(fs(srv["our"], "ls", "-l", path)[1])
    f = _ls_l_sizes(fs(srv["off"], "ls", "-l", path)[1])
    assert set(o) == set(f), \
        f"ls -l {path} name-set divergence: ours={set(o)} stock={set(f)}"
    for name in f:
        assert o.get(name) == f.get(name), \
            f"ls -l {path} size for {name}: ours={o.get(name)} stock={f.get(name)}"


# =========================================================================== #
# 3) `ls -l` — per-entry dir-flag column matches stock (parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/", "/mixed", "/deep", "/nest"])
def test_ls_l_dirflag_matches_stock(srv, path):
    o = _ls_l_rows(fs(srv["our"], "ls", "-l", path)[1])
    f = _ls_l_rows(fs(srv["off"], "ls", "-l", path)[1])
    assert set(o) == set(f), \
        f"ls -l {path} name-set divergence: ours={set(o)} stock={set(f)}"
    for name in f:
        assert o[name][1] == f[name][1], \
            f"ls -l {path} dir-flag for {name}: ours={o[name][1]} stock={f[name][1]}"


# =========================================================================== #
# 4) mixed dir — a subdir appears flagged as a directory in -l on both
# =========================================================================== #
@pytest.mark.parametrize("subdir", ["subA", "subB"])
def test_ls_l_subdir_flagged_dir(srv, subdir):
    o = _ls_l_rows(fs(srv["our"], "ls", "-l", "/mixed")[1])
    f = _ls_l_rows(fs(srv["off"], "ls", "-l", "/mixed")[1])
    assert o.get(subdir, (None, None))[1] is True, \
        f"our ls -l /mixed: {subdir} not flagged dir: {o.get(subdir)}"
    assert f.get(subdir, (None, None))[1] is True, \
        f"stock ls -l /mixed: {subdir} not flagged dir: {f.get(subdir)}"


# =========================================================================== #
# 5) `ls -R /` — full recursive leaf-name set equals stock's
# =========================================================================== #
def test_ls_recursive_leaf_set_matches(srv):
    orc, oout, _ = fs(srv["our"], "ls", "-R", "/")
    frc, fout, _ = fs(srv["off"], "ls", "-R", "/")
    assert orc == 0 and frc == 0, "ls -R should succeed on both"
    assert _ls_set(oout) == _ls_set(fout), \
        f"ls -R / leaf-set divergence: missing-from-ours={_ls_set(fout) - _ls_set(oout)} " \
        f"extra-in-ours={_ls_set(oout) - _ls_set(fout)}"


def test_ls_recursive_bigdir_all_present(srv):
    """ls -R must carry all 200 bigdir entries on both (no truncation)."""
    our = _ls_set(fs(srv["our"], "ls", "-R", "/bigdir")[1])
    off = _ls_set(fs(srv["off"], "ls", "-R", "/bigdir")[1])
    expected = {f"e{i:03d}" for i in range(200)}
    assert our == expected, f"our ls -R /bigdir missing: {expected - our}"
    assert off == expected, f"stock ls -R /bigdir missing: {expected - off}"


# =========================================================================== #
# 6) 200-entry dir — all 200 present, no truncation, compared as a set
# =========================================================================== #
def test_ls_bigdir_200_no_truncation(srv):
    our = _ls_set(fs(srv["our"], "ls", "/bigdir")[1])
    off = _ls_set(fs(srv["off"], "ls", "/bigdir")[1])
    expected = {f"e{i:03d}" for i in range(200)}
    assert len(our) == 200, f"our /bigdir has {len(our)} entries (want 200)"
    assert our == expected, f"our /bigdir set wrong: missing={expected - our}"
    assert our == off, f"/bigdir set divergence vs stock: {our ^ off}"


def test_wire_bigdir_200_no_truncation(srv):
    """Raw-wire plain dirlist over /bigdir returns all 200 (OKSOFAR chunking)."""
    our = _wire_plain_names(OUR_PORT, "/bigdir")
    off = _wire_plain_names(OFF_PORT, "/bigdir")
    expected = {f"e{i:03d}" for i in range(200)}
    assert our == expected, f"our wire /bigdir missing: {expected - our}"
    assert off == expected, f"stock wire /bigdir missing: {expected - off}"


# =========================================================================== #
# 7) special names (spaces / dots / case) — all present and exact on both
# =========================================================================== #
def test_ls_special_names_match(srv):
    our = _ls_set(fs(srv["our"], "ls", "/special")[1])
    off = _ls_set(fs(srv["off"], "ls", "/special")[1])
    expected = set(SPECIAL_NAMES)
    _assert_expected_names(our, expected, "our /special set")
    _assert_expected_names(off, expected, "stock /special set")
    _assert_expected_names(our, off, "/special parity")


@pytest.mark.parametrize("name", SPECIAL_NAMES)
def test_ls_special_name_present_each(srv, name):
    our = _ls_set(fs(srv["our"], "ls", "/special")[1])
    off = _ls_set(fs(srv["off"], "ls", "/special")[1])
    assert name in our, f"our /special lost {name!r}: {our}"
    assert name in off, f"stock /special lost {name!r}: {off}"


def test_wire_special_names_match(srv):
    """Raw-wire plain dirlist preserves spaced/dotted/cased names exactly."""
    our = _wire_plain_names(OUR_PORT, "/special")
    off = _wire_plain_names(OFF_PORT, "/special")
    expected = set(SPECIAL_NAMES)
    assert our == expected, f"our wire /special set wrong: {our ^ expected}"
    assert off == expected, f"stock wire /special set wrong: {off ^ expected}"


# =========================================================================== #
# 8) nested — `ls /nest/x/y/z` -> [bottom.txt]; `/deep/a/b/c` -> [leaf.txt]
# =========================================================================== #
@pytest.mark.parametrize("path,leaf", [
    ("/nest/x/y/z", "bottom.txt"),
    ("/deep/a/b/c", "leaf.txt"),
])
def test_ls_nested_single_leaf(srv, path, leaf):
    our = _ls_set(fs(srv["our"], "ls", path)[1])
    off = _ls_set(fs(srv["off"], "ls", path)[1])
    assert our == {leaf}, f"our ls {path} = {our}, want {{{leaf!r}}}"
    assert off == {leaf}, f"stock ls {path} = {off}, want {{{leaf!r}}}"


# =========================================================================== #
# 9) trailing slash — `ls /D/` == `ls /D`
# =========================================================================== #
@pytest.mark.parametrize("path", ["/sub", "/mixed", "/special", "/bigdir"])
def test_ls_trailing_slash_equiv(srv, path):
    for url, who in ((srv["our"], "our"), (srv["off"], "stock")):
        a = _ls_set(fs(url, "ls", path)[1])
        b = _ls_set(fs(url, "ls", path + "/")[1])
        assert a == b, f"{who} ls {path} vs {path}/ differ: {a ^ b}"
    # and across servers
    assert _ls_set(fs(srv["our"], "ls", path + "/")[1]) == \
        _ls_set(fs(srv["off"], "ls", path + "/")[1]), \
        f"trailing-slash ls {path}/ divergence vs stock"


# =========================================================================== #
# 10) empty dir — empty listing on both (no synthetic '.'/'..'); pin stock
# =========================================================================== #
def test_ls_empty_dir(srv):
    orc, oout, _ = fs(srv["our"], "ls", "/empty_dir")
    frc, fout, _ = fs(srv["off"], "ls", "/empty_dir")
    assert orc == 0 and frc == 0, "ls /empty_dir should succeed on both"
    assert _ls_set(oout) == _ls_set(fout), \
        f"empty-dir divergence: ours={_ls_set(oout)} stock={_ls_set(fout)}"
    # pin stock: whatever stock emits (typically nothing), ours must equal it.
    assert _ls_set(oout) == set(), f"our /empty_dir not empty: {_ls_set(oout)}"


def test_wire_empty_dir(srv):
    """Raw-wire plain dirlist of an empty dir -> empty name set on both."""
    our = _wire_plain_names(OUR_PORT, "/empty_dir")
    off = _wire_plain_names(OFF_PORT, "/empty_dir")
    assert our == off == set(), f"wire empty-dir: ours={our} stock={off}"


# =========================================================================== #
# 11) listing a FILE (not a dir) — error-category parity vs stock
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/special/a-b"])
def test_ls_on_file_error_parity(srv, path):
    orc, oout, oerr = fs(srv["our"], "ls", path)
    frc, fout, ferr = fs(srv["off"], "ls", path)
    # stock pins the category; if stock errors, ours must error with same coarse
    # category. (Some xrdfs builds list a file as a single-entry result.)
    if frc != 0:
        assert orc != 0, f"our ls {path} (a file) succeeded but stock errored: {oout}"
        oc = L.err_code(oerr + oout)
        fc = L.err_code(ferr + fout)
        assert oc == fc, f"ls-on-file error category divergence {path}: ours={oc!r} stock={fc!r}"
    else:
        # stock tolerated it -> ours must agree on the resulting set
        assert _ls_set(oout) == _ls_set(fout), \
            f"ls-on-file {path} divergence vs stock: ours={_ls_set(oout)} stock={_ls_set(fout)}"


# =========================================================================== #
# 12) listing a nonexistent dir — error parity vs stock
# =========================================================================== #
@pytest.mark.parametrize("path", ["/no_such_dir", "/sub/missing", "/bigdir/nope"])
def test_ls_nonexistent_dir_error_parity(srv, path):
    orc, oout, oerr = fs(srv["our"], "ls", path)
    frc, fout, ferr = fs(srv["off"], "ls", path)
    assert orc != 0, f"our ls {path} unexpectedly succeeded: {oout}"
    assert frc != 0, f"stock ls {path} unexpectedly succeeded: {fout}"
    oc = L.err_code(oerr + oout)
    fc = L.err_code(ferr + fout)
    assert oc == fc, f"nonexistent-dir error category divergence {path}: ours={oc!r} stock={fc!r}"


def test_wire_nonexistent_dir_error_parity(srv):
    """Raw-wire dirlist of a nonexistent dir -> kXR_error with same errnum."""
    def probe(port):
        try:
            _wire_plain_names(port, "/no_such_dir")
            return None
        except _DirlistError as e:
            return e.errnum
    our = probe(OUR_PORT)
    off = probe(OFF_PORT)
    assert our is not None, "our wire dirlist of missing dir did not error"
    assert off is not None, "stock wire dirlist of missing dir did not error"
    assert our == off, f"wire dirlist errnum divergence: ours={our} stock={off}"


# =========================================================================== #
# 13) no internal-artifact leak — no name starting with ".nginx-xrootd"
# =========================================================================== #
@pytest.mark.parametrize("path", ["/", "/sub", "/bigdir", "/mixed", "/special"])
def test_no_artifact_leak(srv, path):
    raw = fs(srv["our"], "ls", path)[1]
    leaked = [os.path.basename(l.strip().rstrip("/"))
              for l in raw.splitlines() if l.strip()
              and os.path.basename(l.strip().rstrip("/")).startswith(".nginx-xrootd")]
    assert not leaked, f"our ls {path} leaks internal artifacts: {leaked}"


def test_no_artifact_leak_wire_root(srv):
    """Raw-wire dirlist of '/' must not surface any internal artifact name."""
    s = _session(OUR_PORT)
    try:
        _dirlist_raw(s, "/", options=0)
        body = _drain_dirlist(s)
    finally:
        s.close()
    names = body.replace(b"\x00", b"\n").decode("utf-8", "replace").split("\n")
    leaked = [n for n in names if n.strip().startswith(".nginx-xrootd")]
    assert not leaked, f"wire dirlist '/' leaks internal artifacts: {leaked}"


# =========================================================================== #
# 14) raw-wire PLAIN dirlist — name set equals stock's wire set (parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/", "/sub", "/many", "/mixed", "/nest/x/y/z"])
def test_wire_plain_set_matches_stock(srv, path):
    our = _wire_plain_names(OUR_PORT, path)
    off = _wire_plain_names(OFF_PORT, path)
    assert our == off, f"wire plain dirlist {path} divergence: ours={our} stock={off}"


def test_wire_plain_root_includes_baseline(srv):
    """Sanity anchor: wire '/' carries the known baseline tree on both."""
    our = _wire_plain_names(OUR_PORT, "/")
    off = _wire_plain_names(OFF_PORT, "/")
    baseline = {"hello.txt", "data.bin", "sub", "bigdir", "special", "mixed"}
    _assert_contains_names(our, baseline, "our wire '/'")
    _assert_contains_names(off, baseline, "stock wire '/'")
    _assert_expected_names(our, off, "wire '/' parity")


# =========================================================================== #
# 15) dirlist WITH-STAT (kXR_dstat) — "." lead-in sentinel present on both
# =========================================================================== #
@pytest.mark.parametrize("path", ["/", "/many", "/mixed"])
def test_wire_dstat_sentinel_present(srv, path):
    our_sent, _ = _wire_dstat(OUR_PORT, path)
    off_sent, _ = _wire_dstat(OFF_PORT, path)
    assert off_sent, f"stock dstat {path} lacks the '.' lead-in sentinel"
    assert our_sent, f"our dstat {path} lacks the '.' lead-in sentinel (stock has it)"


# =========================================================================== #
# 16) dirlist WITH-STAT — entry count matches stock (excl sentinel)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/many", "/mixed", "/bigdir", "/sub"])
def test_wire_dstat_entry_count_matches(srv, path):
    _, our_e = _wire_dstat(OUR_PORT, path)
    _, off_e = _wire_dstat(OFF_PORT, path)
    our_names = {n for n, *_ in our_e}
    off_names = {n for n, *_ in off_e}
    assert our_names == off_names, \
        f"dstat {path} name-set divergence: missing-from-ours={off_names - our_names} " \
        f"extra={our_names - off_names}"


# =========================================================================== #
# 17) dirlist WITH-STAT — per-entry size matches the real file size + stock
# =========================================================================== #
def test_wire_dstat_sizes_match(srv):
    """For /many each entry's stat-line size == real on-disk size, and == stock."""
    _, our_e = _wire_dstat(OUR_PORT, "/many")
    _, off_e = _wire_dstat(OFF_PORT, "/many")
    our_sz = {n: sz for n, sz, *_ in our_e}
    off_sz = {n: sz for n, sz, *_ in off_e}
    for name in sorted(our_sz):
        real = os.path.getsize(os.path.join(srv["our_data"], "many", name))
        _assert_dstat_size(name, our_sz[name], off_sz.get(name), real)


@pytest.mark.parametrize("name,size", [
    ("hello.txt", 12), ("data.bin", 4096), ("empty.txt", 0),
    ("cksum.bin", 10000), ("big1m.bin", 1048576),
])
def test_wire_dstat_root_known_sizes(srv, name, size):
    _, our_e = _wire_dstat(OUR_PORT, "/")
    _, off_e = _wire_dstat(OFF_PORT, "/")
    our_sz = {n: sz for n, sz, *_ in our_e}
    off_sz = {n: sz for n, sz, *_ in off_e}
    assert our_sz.get(name) == size, f"our dstat / {name} size={our_sz.get(name)} want {size}"
    assert off_sz.get(name) == size, f"stock dstat / {name} size={off_sz.get(name)} want {size}"


# =========================================================================== #
# 18) dirlist WITH-STAT — directory entries carry the IsDir flag bit on both
# =========================================================================== #
def test_wire_dstat_isdir_flag(srv):
    """In /mixed dstat, subA/subB are flagged IsDir and files are not, on both."""
    _, our_e = _wire_dstat(OUR_PORT, "/mixed")
    _, off_e = _wire_dstat(OFF_PORT, "/mixed")
    our_fl = _flag_map(our_e)
    off_fl = _flag_map(off_e)
    for directory in ("subA", "subB"):
        _assert_directory_flag(directory, our_fl, off_fl)
    for file_name in ("file1.txt", "file2.bin"):
        _assert_regular_file_flag(file_name, our_fl, off_fl)


# =========================================================================== #
# 19) dstat flags presence parity — every entry carries a non-empty stat line
# =========================================================================== #
@pytest.mark.parametrize("path", ["/many", "/mixed"])
def test_wire_dstat_flags_present_each_entry(srv, path):
    for port, who in ((OUR_PORT, "our"), (OFF_PORT, "stock")):
        _, entries = _wire_dstat(port, path)
        assert entries, f"{who} dstat {path} returned no entries"
        for name, size, flags, _ck in entries:
            assert size is not None, f"{who} dstat {path} {name} missing size field"
            assert flags is not None, f"{who} dstat {path} {name} missing flags field"


# =========================================================================== #
# 20) dstat mtime presence parity — the stat line has the 4th (mtime) int field
# =========================================================================== #
def test_wire_dstat_mtime_field_present(srv):
    """The per-entry stat line is 'id size flags mtime' -> >=4 leading ints, on
    both servers (StatGen)."""
    assert _dstat_quad_ok(OFF_PORT, "/many"), \
        "stock dstat stat line lacks 4 leading ints"
    assert _dstat_quad_ok(OUR_PORT, "/many"), \
        "our dstat stat line lacks 4 leading ints (stock has it)"


# =========================================================================== #
# 21) dirlist WITH-CHECKSUM (kXR_dcksm) on /many — each entry carries a token,
#     spot-checked == zlib.adler32 of that file. If stock errors on dcksm (no
#     plugin), pin OUR output against the independent computation + require OUR
#     success.
# =========================================================================== #
def _adler32_hex(path):
    with open(path, "rb") as f:
        return f"{zlib.adler32(f.read()) & 0xffffffff:08x}"


def test_wire_dcksm_tokens_and_value(srv):
    # OUR server: every entry must carry a checksum token, and a spot-checked
    # one must equal the independent adler32 of that file.
    our_e = _required_dcksm_entries(OUR_PORT, "/many", "our server")
    _assert_checksum_tokens(our_e, "our dcksm /many")
    spot = "f00.txt"
    actual = _assert_spot_checksum(srv, _checksum_map(our_e), spot)
    stock = _optional_stock_checksum(spot)
    if stock is not None:
        assert actual == stock, (
            f"dcksm /many {spot} value divergence: ours={actual!r} stock={stock!r}"
        )


def test_wire_dcksm_every_entry_has_token(srv):
    """Across /mixed files, OUR dcksm gives a token per regular file entry."""
    try:
        _, our_e = _wire_dstat(OUR_PORT, "/mixed", with_cksum=True)
    except _DirlistError as e:
        pytest.fail(f"our server errored on kXR_dcksm /mixed (errnum={e.errnum})")
    by = {n: ck for n, _s, _f, ck in our_e}
    for fil in ("file1.txt", "file2.bin"):
        assert by.get(fil), f"our dcksm /mixed {fil} missing checksum token: {by.get(fil)!r}"


# =========================================================================== #
# 22) dcksm implies dstat — the response still has the sentinel + sizes on ours
# =========================================================================== #
def test_wire_dcksm_implies_dstat(srv):
    try:
        sent, entries = _wire_dstat(OUR_PORT, "/many", with_cksum=True)
    except _DirlistError as e:
        pytest.fail(f"our dcksm dirlist errored (errnum={e.errnum})")
    assert sent, "our dcksm dirlist lacks the '.' lead-in sentinel (dcksm implies dstat)"
    sizes = {n: sz for n, sz, _f, _c in entries}
    spot = "f05.txt"
    real = os.path.getsize(os.path.join(srv["our_data"], "many", spot))
    assert sizes.get(spot) == real, \
        f"our dcksm /many {spot} size={sizes.get(spot)} real={real} (dstat info missing)"


# =========================================================================== #
# 23) plain vs dstat name-set agreement on OUR server (internal consistency,
#     each pinned to stock's plain set)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/many", "/mixed", "/sub"])
def test_plain_and_dstat_agree(srv, path):
    plain = _wire_plain_names(OUR_PORT, path)
    _, dstat_e = _wire_dstat(OUR_PORT, path)
    dstat_names = {n for n, *_ in dstat_e}
    assert plain == dstat_names, \
        f"our plain vs dstat name divergence {path}: plain-only={plain - dstat_names} " \
        f"dstat-only={dstat_names - plain}"
    # and both equal stock's plain set
    off_plain = _wire_plain_names(OFF_PORT, path)
    assert plain == off_plain, f"plain {path} divergence vs stock: {plain ^ off_plain}"


# =========================================================================== #
# 24) special-name dir under dstat — spaced/dotted names survive intact + size
# =========================================================================== #
def test_wire_dstat_special_names(srv):
    _, our_e = _wire_dstat(OUR_PORT, "/special")
    _, off_e = _wire_dstat(OFF_PORT, "/special")
    our_names = {n for n, *_ in our_e}
    off_names = {n for n, *_ in off_e}
    expected = set(SPECIAL_NAMES)
    _assert_expected_names(our_names, expected, "our dstat /special names")
    _assert_expected_names(off_names, expected, "stock dstat /special names")
    # a spaced name carries its real size on ours
    our_sz = {n: sz for n, sz, *_ in our_e}
    real = os.path.getsize(os.path.join(srv["our_data"], "special", "with space"))
    _assert_named_size(our_sz, "with space", real, "our dstat /special")

from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_statx_helpers")

pytestmark = pytest.mark.xdist_group("conf_statx")

@pytest.mark.parametrize("path", [
    "/hello.txt", "/data.bin", "/empty.txt", "/cksum.bin", "/big1m.bin",
    "/sz_1.bin", "/sz_4096.bin", "/deep/a/b/c/leaf.txt",
])
def test_statx_single_file_one_byte_not_dir(srv, path):
    (ost, obody), (fst, fbody) = _statx_both(srv, [path])
    assert fst == kXR_ok, f"stock statx {path} status={fst} (oracle broken)"
    assert ost == kXR_ok, f"our statx {path} status={ost} err={_err(obody)}"
    assert len(fbody) == 1, f"stock statx {path}: {len(fbody)} bytes (want 1)"
    assert len(obody) == 1, f"our statx {path}: {len(obody)} bytes (want 1)"
    assert not (obody[0] & kXR_isDir), \
        f"our statx {path} flag 0x{obody[0]:02x} wrongly sets kXR_isDir"
    assert not (fbody[0] & kXR_isDir), \
        f"stock statx {path} flag 0x{fbody[0]:02x} sets kXR_isDir (oracle)"


# =========================================================================== #
# kXR_statx — SINGLE directory path -> ONE flag byte with kXR_isDir set.
# =========================================================================== #
@pytest.mark.parametrize("path", [
    "/sub", "/empty_dir", "/deep", "/deep/a", "/deep/a/b", "/many",
])
def test_statx_single_dir_one_byte_isdir(srv, path):
    (ost, obody), (fst, fbody) = _statx_both(srv, [path])
    assert fst == kXR_ok, f"stock statx {path} status={fst} (oracle broken)"
    assert ost == kXR_ok, f"our statx {path} status={ost} err={_err(obody)}"
    assert len(obody) == 1, f"our statx {path}: {len(obody)} bytes (want 1)"
    assert len(fbody) == 1, f"stock statx {path}: {len(fbody)} bytes (want 1)"
    assert fbody[0] & kXR_isDir, \
        f"stock statx {path} flag 0x{fbody[0]:02x} lacks kXR_isDir (oracle)"
    assert obody[0] & kXR_isDir, \
        f"our statx {path} flag 0x{obody[0]:02x} lacks kXR_isDir"


# =========================================================================== #
# kXR_statx — N paths -> exactly N flag bytes, one per path, correct bit per
# entry (mix of files + dirs). THIS pins the per-path newline framing.
# =========================================================================== #
@pytest.mark.parametrize("paths,dir_idx", [
    (["/hello.txt", "/sub"], {1}),
    (["/sub", "/hello.txt"], {0}),
    (["/data.bin", "/empty.txt"], set()),
    (["/sub", "/empty_dir"], {0, 1}),
    (["/hello.txt", "/sub", "/data.bin"], {1}),
    (["/sub", "/data.bin", "/empty_dir"], {0, 2}),
    (["/deep", "/deep/a", "/deep/a/b"], {0, 1, 2}),
    (["/hello.txt", "/data.bin", "/sub", "/empty.txt", "/many"], {2, 4}),
    (["/sub", "/empty_dir", "/deep", "/data.bin", "/hello.txt"], {0, 1, 2}),
    (["/cksum.bin", "/big1m.bin", "/sub", "/empty.txt", "/deep/a"], {2, 4}),
])
def test_statx_multipath_n_bytes_per_path_bits(srv, paths, dir_idx):
    (ost, obody), (fst, fbody) = _statx_both(srv, paths)
    n = len(paths)
    assert fst == kXR_ok, f"stock statx {paths} status={fst} (oracle)"
    assert ost == kXR_ok, f"our statx {paths} status={ost} err={_err(obody)}"
    assert len(fbody) == n, f"stock statx returned {len(fbody)} bytes for {n} paths"
    assert len(obody) == n, \
        f"our statx returned {len(obody)} flag bytes for {n} paths (want {n}): {obody!r}"
    for i, p in enumerate(paths):
        want_dir = i in dir_idx
        assert bool(fbody[i] & kXR_isDir) == want_dir, \
            f"stock statx {p} (idx {i}) isDir={bool(fbody[i] & kXR_isDir)} want {want_dir}"
        assert bool(obody[i] & kXR_isDir) == want_dir, \
            f"our statx {p} (idx {i}) flag 0x{obody[i]:02x} isDir wrong (want {want_dir})"
    # exact byte-for-byte agreement with the oracle
    assert obody == fbody, \
        f"statx flag-byte divergence for {paths}: ours={obody!r} stock={fbody!r}"


# =========================================================================== #
# kXR_statx — a NONEXISTENT path among valid ones. Reference do_Statx returns
# a single kXR_error on the FIRST failing stat (early return), so the reply is
# NOT N flag bytes. Pin OUR behavior to the stock server's.
# =========================================================================== #
@pytest.mark.parametrize("paths", [
    ["/hello.txt", "/nope_missing.bin"],
    ["/nope_missing.bin", "/hello.txt"],
    ["/sub", "/data.bin", "/also_missing.xyz"],
    ["/missing_a", "/missing_b"],
])
def test_statx_missing_among_valid_matches_stock(srv, paths):
    (ost, obody), (fst, fbody) = _statx_both(srv, paths)
    assert fst == ost, \
        f"statx status divergence for {paths}: ours={ost} stock={fst}"
    # whatever the reference does (it errors), our reply must NOT be a clean
    # full set of N OK flag bytes if the stock server errored.
    if fst == kXR_error:
        assert ost == kXR_error, f"our statx {paths} did not error like stock"
        assert _err(obody) == _err(fbody), \
            f"statx error code divergence {paths}: ours={_err(obody)} stock={_err(fbody)}"


# =========================================================================== #
# kXR_statx — a single nonexistent path -> error parity vs stock.
# =========================================================================== #
@pytest.mark.parametrize("path", [
    "/does_not_exist.bin", "/sub/missing.txt", "/no_such_dir/x",
])
def test_statx_single_missing_error_parity(srv, path):
    (ost, obody), (fst, fbody) = _statx_both(srv, [path])
    assert fst == kXR_error, f"stock statx {path} did not error (oracle): st={fst}"
    assert ost == kXR_error, \
        f"our statx {path} status={ost} (stock errored) body={obody!r}"
    assert _err(obody) == _err(fbody), \
        f"statx missing-path error code divergence {path}: " \
        f"ours={_err(obody)} stock={_err(fbody)}"


# =========================================================================== #
# kXR_statx — determinism: repeating the same probe yields the identical byte.
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/sub", "/data.bin", "/deep"])
def test_statx_determinism_same_byte(srv, path):
    s = _session(srv["our_port"])
    try:
        bytes_seen = []
        for _ in range(4):
            st, body = _statx(s, [path])[1:]
            assert st == kXR_ok, f"our statx {path} status={st}"
            assert len(body) == 1, f"our statx {path}: {len(body)} bytes"
            bytes_seen.append(body[0])
        assert len(set(bytes_seen)) == 1, \
            f"our statx {path} non-deterministic flag bytes: {bytes_seen}"
    finally:
        s.close()


# =========================================================================== #
# stat by PATH vs stat by HANDLE — same Size and same flags from both modes.
# Reference do_Stat: !dlen => fstat on the open handle, else stat the path.
# =========================================================================== #
@pytest.mark.parametrize("path,size", [
    ("/hello.txt", 12),
    ("/data.bin", 4096),
    ("/cksum.bin", 10000),
    ("/sz_1.bin", 1),
    ("/sz_4096.bin", 4096),
    ("/sz_4097.bin", 4097),
    ("/big1m.bin", 1048576),
    ("/empty.txt", 0),
])
def test_stat_handle_matches_path(srv, path, size):
    s = _session(srv["our_port"])
    try:
        pst, pbody = _stat_path(s, path)[1:]
        assert pst == kXR_ok, f"our stat-by-path {path} status={pst}"
        fh = _open_handle(s, path)
        hst, hbody = _stat_handle(s, fh)[1:]
        assert hst == kXR_ok, f"our stat-by-handle {path} status={hst} err={_err(hbody)}"
        pf, hf = _stat_fields(pbody), _stat_fields(hbody)
        assert len(pf) >= 4 and len(hf) >= 4, f"short statinfo path={pf} handle={hf}"
        assert int(pf[1]) == size, f"our path-stat {path} size={pf[1]} want {size}"
        assert int(hf[1]) == size, f"our handle-stat {path} size={hf[1]} want {size}"
        assert pf[1] == hf[1], \
            f"size divergence path vs handle {path}: path={pf[1]} handle={hf[1]}"
        assert pf[2] == hf[2], \
            f"flags divergence path vs handle {path}: path={pf[2]} handle={hf[2]}"
        _close(s, fh)
    finally:
        s.close()


# =========================================================================== #
# stat by HANDLE — differential: our handle-stat flags/size must match the
# STOCK server's handle-stat for the same file.
# =========================================================================== #
@pytest.mark.parametrize("path,size", [
    ("/hello.txt", 12), ("/data.bin", 4096), ("/sz_4096.bin", 4096),
    ("/big1m.bin", 1048576), ("/empty.txt", 0),
])
def test_stat_handle_matches_stock(srv, path, size):
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ofh = _open_handle(o, path)
        ffh = _open_handle(f, path)
        ost, obody = _stat_handle(o, ofh)[1:]
        fst, fbody = _stat_handle(f, ffh)[1:]
        assert fst == kXR_ok, f"stock handle-stat {path} status={fst} (oracle)"
        assert ost == kXR_ok, f"our handle-stat {path} status={ost} err={_err(obody)}"
        of, ff = _stat_fields(obody), _stat_fields(fbody)
        assert int(of[1]) == size, f"our handle-stat {path} size={of[1]} want {size}"
        assert int(ff[1]) == size, f"stock handle-stat {path} size={ff[1]} want {size}"
        assert of[1] == ff[1], \
            f"handle-stat size divergence {path}: ours={of[1]} stock={ff[1]}"
        # flag bits must agree (isDir/readable/writable/etc.)
        assert int(of[2]) == int(ff[2]), \
            f"handle-stat flags divergence {path}: ours={of[2]} stock={ff[2]}"
        _close(o, ofh); _close(f, ffh)
    finally:
        o.close(); f.close()


# =========================================================================== #
# stat by HANDLE after a partial write — fstat the OPEN fd reflects the bytes
# written so far. open(new,updt), write 100 bytes at 0, then stat the handle
# => Size==100. Differential vs the stock server doing the same.
# =========================================================================== #
@pytest.mark.parametrize("nbytes", [1, 100, 4096])
def test_handle_stat_after_partial_write(srv, nbytes):
    name = f"/hs_write_{nbytes}.bin"
    payload = bytes((i * 7 + 1) & 0xff for i in range(nbytes))
    opt = kXR_open_updt | kXR_new | kXR_delete | kXR_mkpath

    def probe(port):
        s = _session(port)
        try:
            fh = _open_handle(s, name, options=opt)
            wst, wbody = _write(s, fh, 0, payload)[1:]
            assert wst == kXR_ok, f"write {name} status={wst} err={_err(wbody)}"
            st, body = _stat_handle(s, fh)[1:]
            assert st == kXR_ok, f"handle-stat {name} status={st} err={_err(body)}"
            fields = _stat_fields(body)
            _close(s, fh)
            return int(fields[1])
        finally:
            s.close()

    our_sz = probe(srv["our_port"])
    off_sz = probe(srv["off_port"])
    assert our_sz == nbytes, \
        f"our handle-stat after writing {nbytes}B reports Size={our_sz}"
    assert off_sz == nbytes, \
        f"stock handle-stat after writing {nbytes}B reports Size={off_sz} (oracle)"
    assert our_sz == off_sz, \
        f"partial-write handle-stat size divergence: ours={our_sz} stock={off_sz}"


# =========================================================================== #
# stat by HANDLE on a stale/closed handle -> kXR_FileNotOpen-class error, and
# our behavior matches stock (both error).
# =========================================================================== #
def test_stat_handle_bad_handle_errors(srv):
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        bogus = b"\xff\xff\xff\xff"
        ost = _stat_handle(o, bogus)[1]
        fst = _stat_handle(f, bogus)[1]
        assert fst == kXR_error, f"stock stat bad-handle did not error (st={fst})"
        assert ost == kXR_error, f"our stat bad-handle did not error (st={ost})"
    finally:
        o.close(); f.close()


# =========================================================================== #
# statvfs (xrdfs) — both yield the reference 6-field RW/staging response.
# =========================================================================== #
def test_statvfs_rw_present_both(srv):
    orc, oout, _ = fs(srv["our"], "statvfs", "/")
    frc, fout, _ = fs(srv["off"], "statvfs", "/")
    assert frc == 0, f"stock statvfs / failed (oracle): {fout}"
    assert orc == 0, f"our statvfs / failed: {oout}"
    assert "Nodes with RW space" in fout, f"stock statvfs not parsed: {fout!r}"
    assert "Nodes with RW space" in oout, f"our statvfs not parsed: {oout!r}"


def test_statvfs_field_keys_match_stock(srv):
    o = _statf(fs(srv["our"], "statvfs", "/")[1])
    f = _statf(fs(srv["off"], "statvfs", "/")[1])
    assert set(o) == set(f), \
        f"statvfs key-set divergence: ours={set(o)} stock={set(f)}"


@pytest.mark.parametrize("subdir", ["/sub", "/deep", "/many"])
def test_statvfs_on_subdir_matches(srv, subdir):
    o = _statf(fs(srv["our"], "statvfs", subdir)[1])
    f = _statf(fs(srv["off"], "statvfs", subdir)[1])
    assert set(o) == set(f), \
        f"statvfs {subdir} key-set divergence: ours={set(o)} stock={set(f)}"


# =========================================================================== #
# raw kXR_vfs bit — kXR_stat with options=kXR_vfs yields the statfs body, NOT a
# 4-field stat line. Reference do_Stat sends the fsctl statfs text.
# =========================================================================== #
def test_raw_vfs_bit_returns_vfs_body(srv):
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _stat_path(o, "/", options=kXR_vfs)[1:]
        fst, fbody = _stat_path(f, "/", options=kXR_vfs)[1:]
        assert fst == kXR_ok, f"stock kXR_vfs status={fst} (oracle) body={fbody!r}"
        assert ost == kXR_ok, f"our kXR_vfs status={ost} err={_err(obody)}"
        # vfs body is the statfs text (rwservers ... staging ...), which is
        # whitespace-tokenized into more than the 4 fields of a stat line, and
        # is NOT a bare 'id size flags mtime' line.
        ofields = _stat_fields(obody)
        ffields = _stat_fields(fbody)
        assert len(ffields) != 4 or len(ofields) != 4 or ofields != ffields, \
            "kXR_vfs body looks like a 4-field stat line, not a statfs body"
        # the two servers' vfs bodies must have the same FIELD COUNT (6-field
        # statfs form: rwNodes rwFree rwUtil stgNodes stgFree stgUtil)
        assert len(ofields) == len(ffields), \
            f"kXR_vfs field-count divergence: ours={len(ofields)} ({ofields}) " \
            f"stock={len(ffields)} ({ffields})"
    finally:
        o.close(); f.close()


def test_raw_vfs_field_count_is_six(srv):
    f = _session(srv["off_port"])
    o = _session(srv["our_port"])
    try:
        fbody = _stat_path(f, "/", options=kXR_vfs)[2]
        obody = _stat_path(o, "/", options=kXR_vfs)[2]
        nf = len(_stat_fields(fbody))
        no = len(_stat_fields(obody))
        assert nf == 6, f"stock kXR_vfs body not 6 fields (oracle): {nf} -> {fbody!r}"
        assert no == 6, f"our kXR_vfs body has {no} fields (want 6): {obody!r}"
    finally:
        f.close(); o.close()


# =========================================================================== #
# stat Size field — exact byte count over the full size matrix, ours==stock.
# =========================================================================== #
@pytest.mark.parametrize("path,size", [
    ("/sz_1.bin", 1),
    ("/sz_255.bin", 255),
    ("/sz_4095.bin", 4095),
    ("/sz_4096.bin", 4096),
    ("/sz_4097.bin", 4097),
    ("/sz_8192.bin", 8192),
    ("/sz_65536.bin", 65536),
    ("/big1m.bin", 1048576),
    ("/empty.txt", 0),
    ("/hello.txt", 12),
    ("/data.bin", 4096),
    ("/cksum.bin", 10000),
])
def test_stat_size_exact_matches_stock(srv, path, size):
    o, f = _stat_both(srv, path)
    assert f.get("Size") == str(size), \
        f"stock stat {path} Size={f.get('Size')!r} want {size} (oracle)"
    assert o.get("Size") == str(size), \
        f"our stat {path} Size={o.get('Size')!r} want {size}"
    assert o.get("Size") == f.get("Size"), \
        f"Size divergence {path}: ours={o.get('Size')!r} stock={f.get('Size')!r}"


# =========================================================================== #
# stat IsDir flag parity vs stock — dirs.
# =========================================================================== #
@pytest.mark.parametrize("path", ["/sub", "/empty_dir", "/deep", "/deep/a/b/c",
                                  "/many"])
def test_stat_isdir_parity_dirs(srv, path):
    o, f = _stat_both(srv, path)
    assert "IsDir" in f.get("Flags", ""), \
        f"stock stat {path} missing IsDir (oracle): {f.get('Flags')!r}"
    assert "IsDir" in o.get("Flags", ""), \
        f"our stat {path} missing IsDir: {o.get('Flags')!r}"


# =========================================================================== #
# stat IsReadable / IsWritable / not-IsDir parity vs stock — files. This pins
# the flags fix (writable + xset now emitted) against the reference.
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sz_4096.bin",
                                  "/cksum.bin"])
def test_stat_file_flag_string_matches_stock(srv, path):
    o, f = _stat_both(srv, path)
    assert "IsDir" not in f.get("Flags", ""), \
        f"stock stat {path} wrongly IsDir (oracle): {f.get('Flags')!r}"
    assert "IsDir" not in o.get("Flags", ""), \
        f"our stat {path} wrongly IsDir: {o.get('Flags')!r}"
    assert o.get("Flags") == f.get("Flags"), \
        f"Flags divergence {path}: ours={o.get('Flags')!r} stock={f.get('Flags')!r}"


# =========================================================================== #
# stat MTime — present, numeric & nonzero on both; IsDir/Size still agree.
# (mtimes are independent between the two trees, so we don't require equality;
# we DO require both to be plausible timestamps and the structural fields equal.)
# =========================================================================== #

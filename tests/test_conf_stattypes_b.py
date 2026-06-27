from _test_conf_stattypes_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

# =========================================================================== #
# BROKEN SYMLINK -> error (or type) parity vs stock. A dangling link's stat()
# fails on both (the target ENOENT propagates). Pin status + error category.
# =========================================================================== #
def test_broken_symlink_error_parity(srv):
    rel = "/types/lnk_broken"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == fst, \
        f"broken-symlink status divergence {rel}: ours={ost} stock={fst}"
    if fst == kXR_error:
        assert _err(of) == _err(ff), \
            f"broken-symlink error code divergence {rel}: ours={_err(of)} stock={_err(ff)}"
    elif fst == kXR_ok:
        # if stock somehow succeeds, our flags must match
        assert _flags_int(of) == _flags_int(ff), \
            f"broken-symlink FLAGS divergence {rel}: ours={of} stock={ff}"


def test_broken_symlink_statx_parity(srv):
    rel = "/types/lnk_broken"
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert ost == fst, \
            f"broken-symlink statx status divergence {rel}: ours={ost} stock={fst}"
        if fst == kXR_error:
            assert _err(obody) == _err(fbody), \
                f"statx error code divergence {rel}: ours={_err(obody)} stock={_err(fbody)}"
        else:
            assert obody == fbody, \
                f"statx broken-symlink byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# SIZE exactness across many sizes (mode fixed) -> ours==stock==expected, and
# the flags integer (0644 -> readable|writable) agrees too.
# =========================================================================== #
@pytest.mark.parametrize("sz", REG_SIZES)
def test_size_exact_and_flags(srv, sz):
    rel = f"/types/sz_{sz}.dat"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost}"
    assert _size_int(ff) == sz, f"stock {rel} size={_size_int(ff)} want {sz} (oracle)"
    assert _size_int(of) == sz, f"our {rel} size={_size_int(of)} want {sz}"
    assert _size_int(of) == _size_int(ff), \
        f"size divergence {rel}: ours={_size_int(of)} stock={_size_int(ff)}"
    assert _flags_int(of) == _flags_int(ff), \
        f"FLAGS divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"


# =========================================================================== #
# MTime — 4th StatGen field numeric & positive on both (trees are independent
# so no equality requirement); the STRUCTURAL fields (isDir/size/flags) agree.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/reg_0644.bin", "/types/dir_0755",
                                 "/types/sz_4096.dat", "/types/exec.sh"])
def test_mtime_numeric_structurals_match(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    for who, fields in (("our", of), ("stock", ff)):
        assert len(fields) >= 4 and fields[3].lstrip("-").isdigit(), \
            f"{who} {rel} mtime field non-int: {fields}"
        assert int(fields[3]) > 0, f"{who} {rel} mtime not positive: {fields[3]}"
    # structural agreement
    assert (_flags_int(of) & kXR_isDir) == (_flags_int(ff) & kXR_isDir), \
        f"isDir divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"
    assert _size_int(of) == _size_int(ff), \
        f"size divergence {rel}: ours={_size_int(of)} stock={_size_int(ff)}"
    assert _flags_int(of) == _flags_int(ff), \
        f"FLAGS divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"


# =========================================================================== #
# statx across the FULL type matrix -> one flag byte per path, correct type bit
# (file / dir / other), byte-identical to stock.
# =========================================================================== #
@pytest.mark.parametrize("rel,kind", [
    ("/types/reg_0644.bin", "file"),
    ("/types/reg_0000.bin", "file"),
    ("/types/reg_0755.bin", "file"),
    ("/types/sz_0.dat", "file"),
    ("/types/sz_65536.dat", "file"),
    ("/types/exec.sh", "file"),
    ("/types/dir_0755", "dir"),
    ("/types/dir_0700", "dir"),
    ("/types/dir_0500", "dir"),
    ("/types/fifo1", "other"),
])
def test_statx_type_bit_matches(srv, rel, kind):
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_ok, f"stock statx {rel} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {rel} status={ost} err={_err(obody)}"
        assert len(fbody) == 1 and len(obody) == 1, "statx must return 1 flag byte"
        # The directory bit is reliably surfaced by stock's do_Statx; the
        # non-regular ("other") classification is NOT (stock emits 0x00 for a
        # fifo in statx even though its do_Stat flags integer sets kXR_other),
        # so we pin "other" purely by the byte-for-byte differential below.
        want_dir = (kind == "dir")
        assert bool(fbody[0] & kXR_isDir) == want_dir, \
            f"stock statx {rel} isDir wrong (oracle): 0x{fbody[0]:02x}"
        assert obody == fbody, \
            f"statx flag-byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# statx MULTI-PATH mixing types -> N flag bytes, byte-identical to stock.
# =========================================================================== #
@pytest.mark.parametrize("paths", [
    ["/types/reg_0644.bin", "/types/dir_0755"],
    ["/types/dir_0700", "/types/reg_0400.bin"],
    ["/types/fifo1", "/types/reg_0644.bin", "/types/dir_0755"],
    ["/types/reg_0755.bin", "/types/exec.sh", "/types/dir_0500"],
    ["/types/sz_0.dat", "/types/sz_4096.dat", "/types/sz_65536.dat"],
    ["/types/dir_0755", "/types/dir_0700", "/types/dir_0500"],
    ["/types/reg_0644.bin", "/types/fifo1", "/types/dir_0755", "/types/exec.sh"],
])
def test_statx_multipath_mixed_types(srv, paths):
    for p in paths:
        _present(srv, p)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, paths)[1:]
        fst, fbody = _statx(f, paths)[1:]
        assert fst == kXR_ok, f"stock statx {paths} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {paths} status={ost} err={_err(obody)}"
        assert len(fbody) == len(paths), \
            f"stock statx returned {len(fbody)} bytes for {len(paths)} paths"
        assert len(obody) == len(paths), \
            f"our statx returned {len(obody)} bytes for {len(paths)} paths"
        assert obody == fbody, \
            f"statx multi byte divergence {paths}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# statx MISSING path -> error parity vs stock (NOT an offline byte). A single
# missing path errors on both; do_Statx early-returns kXR_error.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/no_such_node.bin",
                                 "/types/missing_dir/x",
                                 "/types/reg_0644.bin/nope"])
def test_statx_missing_error_parity(srv, rel):
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_error, f"stock statx {rel} did not error (oracle): st={fst}"
        assert ost == kXR_error, \
            f"our statx {rel} status={ost} (stock errored) body={obody!r}"
        assert _err(obody) == _err(fbody), \
            f"statx missing error code divergence {rel}: ours={_err(obody)} stock={_err(fbody)}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# stat via OPEN HANDLE for a regular file -> matches the path-stat flags+size.
# Reference do_Stat: !dlen => fstat the open fd.
# =========================================================================== #
@pytest.mark.parametrize("rel,sz", [
    ("/types/reg_0644.bin", 64),
    ("/types/reg_0400.bin", 64),
    ("/types/sz_0.dat", 0),
    ("/types/sz_4096.dat", 4096),
    ("/types/sz_65536.dat", 65536),
    ("/types/exec.sh", None),
])
def test_handle_stat_matches_path(srv, rel, sz):
    _present(srv, rel)
    s = _session(srv["our_port"])
    try:
        pst, pbody = _stat_path(s, rel)[1:]
        assert pst == kXR_ok, f"our path-stat {rel} status={pst}"
        fh = _open_handle(s, rel)
        hst, hbody = _stat_handle(s, fh)[1:]
        assert hst == kXR_ok, f"our handle-stat {rel} status={hst} err={_err(hbody)}"
        pf, hf = _stat_fields(pbody), _stat_fields(hbody)
        assert pf[1] == hf[1], \
            f"size path vs handle {rel}: path={pf[1]} handle={hf[1]}"
        assert pf[2] == hf[2], \
            f"flags path vs handle {rel}: path={pf[2]} handle={hf[2]}"
        if sz is not None:
            assert int(pf[1]) == sz, f"our {rel} size={pf[1]} want {sz}"
        _close(s, fh)
    finally:
        s.close()


# =========================================================================== #
# stat with TRAILING SLASH on each type -> ok/error parity vs stock (file with
# trailing slash should ENOTDIR; dir with trailing slash should succeed).
# =========================================================================== #
@pytest.mark.parametrize("rel", [
    "/types/reg_0644.bin/", "/types/exec.sh/",
    "/types/dir_0755/", "/types/dir_0700/",
    "/types/fifo1/",
])
def test_trailing_slash_parity(srv, rel):
    _present(srv, rel.rstrip("/"))
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert (ost == kXR_ok) == (fst == kXR_ok), \
        f"trailing-slash success divergence {rel!r}: ours={ost} stock={fst}"
    if ost == kXR_ok and fst == kXR_ok:
        assert _flags_int(of) == _flags_int(ff), \
            f"trailing-slash FLAGS divergence {rel}: ours={of} stock={ff}"


# =========================================================================== #
# stat the export ROOT "/" -> kXR_isDir + flags parity.
# =========================================================================== #
def test_stat_root_isdir_parity(srv):
    of, ff, ost, fst = _raw_stat(srv, "/")
    assert fst == kXR_ok, f"stock stat / status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat / status={ost}"
    assert _flags_int(ff) & kXR_isDir, f"stock / missing kXR_isDir (oracle)"
    assert _flags_int(of) & kXR_isDir, f"our / missing kXR_isDir"
    assert (_flags_int(of) & kXR_isDir) == (_flags_int(ff) & kXR_isDir), \
        "root isDir divergence"


# =========================================================================== #
# FLAGS determinism — repeating the raw stat yields the identical flags integer.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/reg_0644.bin", "/types/dir_0755",
                                 "/types/exec.sh", "/types/fifo1"])
def test_flags_determinism(srv, rel):
    _present(srv, rel)
    s = _session(srv["our_port"])
    try:
        seen = []
        for _ in range(4):
            st, body = _stat_path(s, rel)[1:]
            assert st == kXR_ok, f"our stat {rel} status={st}"
            seen.append(_flags_int(_stat_fields(body)))
        assert len(set(seen)) == 1, \
            f"our stat {rel} non-deterministic flags: {seen}"
    finally:
        s.close()


# =========================================================================== #
# setuid / setgid files -> the StatGen flags integer (which ignores the s-bits)
# matches stock; type stays regular-file (no isDir/other).
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/setuid", "/types/setgid"])
def test_setuid_setgid_flags_match(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost}"
    on, fn = _flags_int(of), _flags_int(ff)
    assert not (on & kXR_isDir) and not (on & kXR_other), \
        f"our {rel} misclassified: {on}({_decode_flags(on)})"
    assert on == fn, \
        f"FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) stock={fn}({_decode_flags(fn)})"


# =========================================================================== #
# xrdfs (stock client) rendered Flags string parity across the matrix — pins
# the human-facing rendering on top of the raw integer.
# =========================================================================== #
@pytest.mark.parametrize("rel", [
    "/types/reg_0644.bin", "/types/reg_0400.bin", "/types/reg_0000.bin",
    "/types/reg_0755.bin", "/types/exec.sh", "/types/dir_0755",
    "/types/dir_0700",
])
def test_xrdfs_flags_string_parity(srv, rel):
    _present(srv, rel)

    def _statf(out):
        d = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                d[k.strip()] = v.strip()
        return d
    o = _statf(L.run([L.OFF_XRDFS, srv["our"], "stat", rel])[1])
    f = _statf(L.run([L.OFF_XRDFS, srv["off"], "stat", rel])[1])
    assert "Flags" in f, f"stock xrdfs stat {rel} produced no Flags (oracle): {f}"
    assert "Flags" in o, f"our xrdfs stat {rel} produced no Flags: {o}"
    assert o.get("Flags") == f.get("Flags"), \
        f"xrdfs Flags string divergence {rel}: ours={o.get('Flags')!r} stock={f.get('Flags')!r}"
    assert o.get("Size") == f.get("Size"), \
        f"xrdfs Size divergence {rel}: ours={o.get('Size')!r} stock={f.get('Size')!r}"

from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_dirlist_helpers")

@pytest.mark.parametrize("path", [
    pytest.param(WROOT, id="wroot"), "/sub", "/empty_dir", "/many", "/deep",
    "/bigdir", "/special", "/mixed", "/nest", "/nest/x/y/z", "/deep/a/b/c",
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
@pytest.mark.parametrize("path", [pytest.param(WROOT, id="wroot"), "/many",
                                  "/bigdir", "/sub", "/mixed"])
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
@pytest.mark.parametrize("path", [pytest.param(WROOT, id="wroot"), "/mixed",
                                  "/deep", "/nest"])
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
    orc, oout, _ = fs(srv["our"], "ls", "-R", WROOT)
    frc, fout, _ = fs(srv["off"], "ls", "-R", WROOT)
    assert orc == 0 and frc == 0, "ls -R should succeed on both"
    assert _ls_set(oout) == _ls_set(fout), \
        f"ls -R {WROOT} leaf-set divergence: missing-from-ours={_ls_set(fout) - _ls_set(oout)} " \
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
    assert our == expected, f"our /special set wrong: missing={expected - our} extra={our - expected}"
    assert off == expected, f"stock /special set wrong: {off ^ expected}"
    assert our == off, f"/special divergence vs stock: {our ^ off}"


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
@pytest.mark.parametrize("path", [pytest.param(WROOT, id="wroot"), "/sub",
                                  "/many", "/mixed", "/nest/x/y/z"])
def test_wire_plain_set_matches_stock(srv, path):
    our = _wire_plain_names(OUR_PORT, path)
    off = _wire_plain_names(OFF_PORT, path)
    assert our == off, f"wire plain dirlist {path} divergence: ours={our} stock={off}"


def test_wire_plain_root_includes_baseline(srv):
    """Sanity anchor: the wire dirlist carries the known baseline tree on both,
    and the full set agrees. Uses the per-worker pseudo-root (WROOT) so a
    concurrent worker's files under the shared '/' can't perturb the equality."""
    our = _wire_plain_names(OUR_PORT, WROOT)
    off = _wire_plain_names(OFF_PORT, WROOT)
    assert WROOT_BASELINE <= our, f"our wire {WROOT} missing baseline: {WROOT_BASELINE - our}"
    assert WROOT_BASELINE <= off, f"stock wire {WROOT} missing baseline: {WROOT_BASELINE - off}"
    assert our == off, f"wire {WROOT} set divergence: {our ^ off}"


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
        assert our_sz[name] == real, \
            f"our dstat /many {name} size={our_sz[name]} real={real}"
        assert our_sz[name] == off_sz.get(name), \
            f"dstat /many {name} size divergence: ours={our_sz[name]} stock={off_sz.get(name)}"


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
    our_fl = {n: fl for n, _sz, fl, _ck in our_e}
    off_fl = {n: fl for n, _sz, fl, _ck in off_e}
    for d in ("subA", "subB"):
        assert our_fl.get(d) is not None and our_fl[d] & kXR_isDir, \
            f"our dstat /mixed {d} not flagged IsDir: flags={our_fl.get(d)}"
        assert off_fl.get(d) is not None and off_fl[d] & kXR_isDir, \
            f"stock dstat /mixed {d} not flagged IsDir: flags={off_fl.get(d)}"
    for fil in ("file1.txt", "file2.bin"):
        assert not (our_fl.get(fil, 0) & kXR_isDir), \
            f"our dstat /mixed {fil} wrongly flagged IsDir: {our_fl.get(fil)}"
        assert not (off_fl.get(fil, 0) & kXR_isDir), \
            f"stock dstat /mixed {fil} wrongly flagged IsDir: {off_fl.get(fil)}"


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


# =========================================================================== #
# 21) kXR_locate '*'-prefix (create-locate) — the fix that unblocks `xrdfs ls`
#
# `xrdfs ls <dir>` (and every read/write) issues a kXR_locate FIRST, and XrdCl
# PREFIXES the path with a star ("locate a server for a possibly-new file").
# brix used to treat only a BARE "*" as the wildcard, so a star-prefixed path
# ("*/wroot") was stat'd literally, missed, and returned [3011] — aborting the
# whole listing. The handler now strips the star and, for a missing target,
# still answers with this data server (reference create-locate semantics).
# =========================================================================== #
def test_wire_locate_star_prefix_existing_dir_ok(srv):
    """SUCCESS: a star-prefixed locate of an EXISTING path resolves to this data
    server (kXR_ok + 'S<access>host:port' token). This is the exact locate every
    `xrdfs ls` sends before the dirlist."""
    st, body = _wire_locate(OUR_PORT, "*" + WROOT)
    assert st == kXR_ok, \
        f"star-locate of existing {WROOT}: status={st} body={body!r}"
    assert body[:1] == "S", f"locate reply is not a server token: {body!r}"


def test_wire_locate_star_prefix_missing_still_serves(srv):
    """SUCCESS (create-locate): a star-prefixed locate of a NONEXISTENT path
    still answers with this server — the client is about to create it — instead
    of kXR_NotFound. Mirrors the reference server; also what lets `ls` proceed."""
    st, body = _wire_locate(OUR_PORT, "*" + WROOT + "/nope_" + L.worker_tag())
    assert st == kXR_ok, \
        f"star-locate of a missing path should still serve: status={st} body={body!r}"
    assert body[:1] == "S", f"locate reply is not a server token: {body!r}"


def test_wire_locate_plain_missing_notfound(srv):
    """ERROR: a PLAIN (no-star) locate of a nonexistent path must still return a
    kXR_error — the tolerate-missing behavior is gated on the star marker and
    must not leak to ordinary locates (no existence oracle change)."""
    st, body = _wire_locate(OUR_PORT, WROOT + "/nope_" + L.worker_tag())
    assert st == kXR_error, \
        f"plain locate of a missing path should error: status={st} body={body!r}"


def test_wire_locate_star_prefix_traversal_rejected(srv):
    """SECURITY-NEG: stripping the star must NOT open a traversal hole — a
    star-prefixed '..' path is still rejected as an invalid path and never
    resolves a location outside the export root."""
    st, body = _wire_locate(OUR_PORT, "*/../../../../etc/passwd")
    assert st == kXR_error, \
        f"star-locate traversal must be rejected: status={st} body={body!r}"
    assert "root:" not in body, f"traversal locate leaked file contents: {body!r}"

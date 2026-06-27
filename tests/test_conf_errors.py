from _test_conf_errors_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_qcksum_nonexistent(srv):
    """query checksum of a nonexistent file -> OUR rejects (NotFound); STOCK may
    say 'not supported' (no checksum configured), in which case only require
    OUR to reject."""
    _assert_both_fail_cksum(srv, "query", "checksum", "/nonexistent")


@pytest.mark.parametrize("args", NONEXISTENT_OPS)
def test_nonexistent_path_category_parity(srv, args):
    """A nonexistent target must be rejected with the same coarse error category
    (kXR_NotFound / ENOENT) on OUR and the STOCK server."""
    _assert_both_fail_same_cat(srv, *args)


def test_rmdir_nonexistent_parity(srv):
    """rmdir of a nonexistent path: stock is idempotent (success), OUR returns a
    clean NotFound. Accept either; OUR's stricter NotFound is conformant."""
    _assert_rmdir_missing_ok(srv, "rmdir", "/nonexistent_dir")


def test_locate_nonexistent_parity(srv):
    """locate of a nonexistent path: some builds return a 'no replicas' success.
    Pin OUR behavior to STOCK rather than assuming failure."""
    _assert_parity(srv, "locate", "/no_such_locate_target")


@pytest.mark.parametrize("args", INSIDE_MISSING_DIR_OPS)
def test_inside_missing_dir_category_parity(srv, args):
    """An op targeting a file inside a nonexistent directory must be rejected
    with the same error category on both servers."""
    _assert_both_fail_same_cat(srv, *args)


def test_qcksum_in_missing_dir(srv):
    """query checksum of a file inside a nonexistent dir: OUR rejects; pin only
    if STOCK actually rejects with a comparable (supported) error."""
    _assert_both_fail_cksum(srv, "query", "checksum", MISSING_DIR)


def test_mv_src_inside_missing_dir_parity(srv):
    _assert_both_fail_same_cat(srv, "mv", MISSING_DIR, "/dst_x")


def test_mkdir_inside_missing_dir_parity(srv):
    """mkdir (no -p) whose parent does not exist: pin to STOCK (failure)."""
    _assert_parity(srv, "mkdir", "/no/such/parent/newdir")


def test_rmdir_inside_missing_dir_parity(srv):
    """rmdir of a dir inside a missing parent: stock idempotent-success, OUR
    clean NotFound. Accept either."""
    _assert_rmdir_missing_ok(srv, "rmdir", "/no/such/dir/sub")


def test_rm_directory_parity(srv):
    """rm (unlink) of a NON-EMPTY directory: pin to STOCK. Uses freshly-seeded
    unique non-empty dirs per server so the result is order-independent (the
    shared /sub must not be mutated by a differential)."""
    _seed_nonempty(srv, "/rm_dir_our", "/rm_dir_off")
    (rc_o, cat_o, _), (rc_f, cat_f, _), raw = _diff_fail_split(
        srv, ("rm", "/rm_dir_our"), ("rm", "/rm_dir_off"))
    assert (rc_o == 0) == (rc_f == 0), f"rm-directory rc-class differs:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"rm-directory category differs:{raw}"


def test_rmdir_file_parity(srv):
    """rmdir of a regular file (ENOTDIR / kXR_NotFile-ish): both must reject with
    a matching category."""
    _assert_both_fail_same_cat(srv, "rmdir", "/hello.txt")


def test_cat_directory_parity(srv):
    """cat of a directory: open-for-read of a dir must be rejected
    (kXR_isDirectory) with a matching category on both."""
    _assert_both_fail_same_cat(srv, "cat", "/sub")


def test_ls_file_parity(srv):
    """dirlist of a regular file: pin to STOCK. Some builds list the single file
    (success), others reject ENOTDIR; pin OUR behavior to the oracle."""
    _assert_parity(srv, "ls", "/hello.txt")


def test_truncate_directory_parity(srv):
    """truncate of a directory (EISDIR): both must reject with a matching
    category."""
    _assert_both_fail_same_cat(srv, "truncate", "/sub", "0")


def test_chmod_directory_parity(srv):
    """chmod of a directory should SUCCEED identically on both (a directory is a
    valid chmod target); pin the success-class to STOCK."""
    _assert_parity(srv, "chmod", "/empty_dir", "rwxr-xr-x")


def test_mkdir_over_existing_file_parity(srv):
    """mkdir whose target name is an existing regular file: both must reject."""
    _assert_both_fail_same_cat(srv, "mkdir", "/hello.txt")


def test_cat_empty_dir_parity(srv):
    """cat of an (empty) directory is still a directory-read reject on both."""
    _assert_both_fail_same_cat(srv, "cat", "/empty_dir")


def test_rm_twice_second_notfound(srv):
    """rm a freshly-created file twice: the 2nd rm must fail NotFound on BOTH.

    Parallel unique paths so neither tree pollutes the other."""
    our_p = "/dbl_rm_our.txt"
    off_p = "/dbl_rm_off.txt"
    with open(os.path.join(srv["our_data"], our_p.lstrip("/")), "w") as f:
        f.write("x")
    with open(os.path.join(srv["off_data"], off_p.lstrip("/")), "w") as f:
        f.write("x")
    assert fs(srv["our"], "rm", our_p)[0] == 0, "first rm (our) must succeed"
    assert fs(srv["off"], "rm", off_p)[0] == 0, "first rm (stock) must succeed"
    rc_o, o_o, e_o = fs(srv["our"], "rm", our_p)
    rc_f, o_f, e_f = fs(srv["off"], "rm", off_p)
    assert rc_o != 0 and rc_f != 0, \
        f"2nd rm must fail: our_rc={rc_o} stock_rc={rc_f}"
    assert _category(o_o + e_o) == _category(o_f + e_f), \
        f"2nd-rm category differs: our={_category(o_o + e_o)} stock={_category(o_f + e_f)}"


def test_rmdir_twice_parity(srv):
    """rmdir an empty dir twice: 1st succeeds, pin the 2nd's rc-class+category to
    STOCK (which is lenient for a now-missing dir)."""
    our_p = "/dbl_rmdir_our"
    off_p = "/dbl_rmdir_off"
    assert fs(srv["our"], "mkdir", our_p)[0] == 0
    assert fs(srv["off"], "mkdir", off_p)[0] == 0
    assert fs(srv["our"], "rmdir", our_p)[0] == 0
    assert fs(srv["off"], "rmdir", off_p)[0] == 0
    rc_o, o_o, e_o = fs(srv["our"], "rmdir", our_p)
    rc_f, o_f, e_f = fs(srv["off"], "rmdir", off_p)
    assert (rc_o == 0) == (rc_f == 0), \
        f"2nd-rmdir rc-class differs: our={rc_o} stock={rc_f}"
    if rc_o != 0:
        assert _category(o_o + e_o) == _category(o_f + e_f), \
            f"2nd-rmdir category differs"


def test_mkdir_same_dir_twice_itexists(srv):
    """mkdir the SAME pre-existing on-disk dir twice (no -p) -> kXR_ItExists on
    both. Pin to the stable on-disk-dir contract using /sub (present on disk on
    both servers), where stock returns [3018] 'file exists'."""
    _assert_both_fail_same_cat(srv, "mkdir", "/sub")


def test_mkdir_fresh_then_again_parity(srv):
    """mkdir a fresh dir, then mkdir it again (no -p).

    NOTE: stock xrootd is idempotent (rc=0) ONLY for a directory it created
    earlier in the SAME process (its oss namespace cache remembers it) — a quirk
    that does not generalize. OUR server returns the POSIX-correct kXR_ItExists.
    Both are conformant; accept either, but if OUR fails it must be ItExists/
    exists, not some unrelated error."""
    our_p = "/mk_twice_our"
    off_p = "/mk_twice_off"
    assert fs(srv["our"], "mkdir", our_p)[0] == 0
    assert fs(srv["off"], "mkdir", off_p)[0] == 0
    rc_o, o_o, e_o = fs(srv["our"], "mkdir", our_p)
    if rc_o != 0:
        assert _category(o_o + e_o) == "exists", (
            f"OUR mkdir-again failed with non-exists category "
            f"{_category(o_o + e_o)!r}: {(o_o + e_o).strip()!r}")
    # the dir must still exist on disk either way
    assert os.path.isdir(os.path.join(srv["our_data"], "mk_twice_our"))


def test_mv_onto_existing_dest_parity(srv):
    """mv onto an existing destination file: pin overwrite-vs-error to STOCK on
    parallel unique trees."""
    for data, sfx in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        with open(os.path.join(data, f"mv_ovw_src_{sfx}.txt"), "w") as f:
            f.write("src")
        with open(os.path.join(data, f"mv_ovw_dst_{sfx}.txt"), "w") as f:
            f.write("dst")
    rc_o, o_o, e_o = fs(srv["our"], "mv", "/mv_ovw_src_our.txt", "/mv_ovw_dst_our.txt")
    rc_f, o_f, e_f = fs(srv["off"], "mv", "/mv_ovw_src_off.txt", "/mv_ovw_dst_off.txt")
    raw = (f"\n  OURS  rc={rc_o} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} :: {(o_f + e_f).strip()!r}")
    assert (rc_o == 0) == (rc_f == 0), f"mv-onto-existing rc-class differs:{raw}"
    if rc_o != 0:
        assert _category(o_o + e_o) == _category(o_f + e_f), \
            f"mv-onto-existing category differs:{raw}"


def test_mv_dir_onto_file_parity(srv):
    """mv a directory onto an existing regular file: both must reject."""
    for data, sfx in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        os.makedirs(os.path.join(data, f"mv_dof_dir_{sfx}"), exist_ok=True)
        with open(os.path.join(data, f"mv_dof_file_{sfx}.txt"), "w") as f:
            f.write("f")
    rc_o, o_o, e_o = fs(srv["our"], "mv", "/mv_dof_dir_our", "/mv_dof_file_our.txt")
    rc_f, o_f, e_f = fs(srv["off"], "mv", "/mv_dof_dir_off", "/mv_dof_file_off.txt")
    raw = (f"\n  OURS  rc={rc_o} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} :: {(o_f + e_f).strip()!r}")
    assert rc_o != 0 and rc_f != 0, f"mv-dir-onto-file must fail:{raw}"
    assert _category(o_o + e_o) == _category(o_f + e_f), \
        f"mv-dir-onto-file category differs:{raw}"


def test_mv_nonexistent_source_category(srv):
    """mv with a nonexistent source -> NotFound on both."""
    _assert_both_fail_same_cat(srv, "mv", "/mv_no_src.txt", "/mv_any_dst.txt")


def test_mv_dest_into_missing_dir_parity(srv):
    """mv whose destination directory does not exist: pin to STOCK."""
    for data, sfx in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        with open(os.path.join(data, f"mv_bd_src_{sfx}.txt"), "w") as f:
            f.write("x")
    rc_o, o_o, e_o = fs(srv["our"], "mv", "/mv_bd_src_our.txt", "/no_dst_dir/x.txt")
    rc_f, o_f, e_f = fs(srv["off"], "mv", "/mv_bd_src_off.txt", "/no_dst_dir/x.txt")
    raw = (f"\n  OURS  rc={rc_o} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} :: {(o_f + e_f).strip()!r}")
    assert (rc_o == 0) == (rc_f == 0), f"mv-bad-dest rc-class differs:{raw}"
    if rc_o != 0:
        assert _category(o_o + e_o) == _category(o_f + e_f), \
            f"mv-bad-dest category differs:{raw}"


def test_rmdir_nonempty_parity(srv):
    """rmdir of a non-empty dir (ENOTEMPTY -> kXR_ItExists): /sub holds
    nested.txt on both servers, so both must reject with a matching category."""
    _assert_both_fail_same_cat(srv, "rmdir", "/sub")


def test_rmdir_nonempty_fresh_parity(srv):
    """A freshly-populated non-empty dir on parallel trees must reject on both."""
    for data, sfx in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        d = os.path.join(data, f"rmd_full_{sfx}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "child.txt"), "w") as f:
            f.write("x")
    rc_o, o_o, e_o = fs(srv["our"], "rmdir", "/rmd_full_our")
    rc_f, o_f, e_f = fs(srv["off"], "rmdir", "/rmd_full_off")
    assert rc_o != 0 and rc_f != 0, \
        f"rmdir-nonempty must fail: our={rc_o} stock={rc_f}"
    assert _category(o_o + e_o) == _category(o_f + e_f), \
        f"rmdir-nonempty category differs: our={_category(o_o + e_o)} stock={_category(o_f + e_f)}"


def test_chmod_missing_explicit_category(srv):
    _assert_both_fail_same_cat(srv, "chmod", "/chmod_missing_x.txt", "rw-r--r--")


def test_truncate_missing_explicit_category(srv):
    _assert_both_fail_same_cat(srv, "truncate", "/trunc_missing_x.bin", "7")


def test_query_unknown_subcmd_parity(srv):
    """An unsupported `query` selector must agree on success/failure class (and,
    if failing, category) between OUR and STOCK."""
    rc_o, o_o, e_o = fs(srv["our"], "query", "bogusquerycode", "/")
    rc_f, o_f, e_f = fs(srv["off"], "query", "bogusquerycode", "/")
    assert (rc_o == 0) == (rc_f == 0), (
        f"unknown query subcmd rc-class differs: "
        f"our_ok={rc_o == 0}({o_o}{e_o!r}) stock_ok={rc_f == 0}({o_f}{e_f!r})")
    if rc_o != 0:
        assert _category(o_o + e_o) == _category(o_f + e_f), \
            "unknown query subcmd category differs"


def test_query_checksum_directory_parity(srv):
    """query checksum of a DIRECTORY (not a file): OUR must reject; pin category
    to STOCK only when STOCK supports checksums."""
    _assert_both_fail_cksum(srv, "query", "checksum", "/sub")

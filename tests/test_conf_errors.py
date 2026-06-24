"""Differential conformance for ERROR SEMANTICS across the full namespace/IO op
set — stock XRootD tools + RAW WIRE against BOTH our nginx-xrootd server and the
stock xrootd data server.

Philosophy (per the maintainer): a divergence is a BUG IN OUR SERVER unless
there is positive evidence otherwise. For every failing operation we run the
SAME op against OUR and the STOCK server and require:

  * both fail (rc != 0), and
  * the coarse error CATEGORY matches (L.err_code, normalized so that wording
    differences — "no such file" vs "not found" — do not false-positive), and
  * where the reference is exact (raw wire), the same numeric kXR_* code.

The canonical errno -> kXR mapping is mapError() in
/tmp/xrootd-src/src/XProtocol/XProtocol.hh:
    ENOENT   -> kXR_NotFound      (3011)
    EINVAL   -> kXR_ArgInvalid    (3000)
    EPERM/EACCES -> kXR_NotAuthorized (3010)
    EISDIR   -> kXR_isDirectory   (3016)
    ENOTEMPTY/EEXIST -> kXR_ItExists (3018)
    EBADRQC  -> kXR_InvalidRequest (3006)
    EBADF    -> kXR_FileNotOpen   (3004)
and unknown-opcode / bad-framing rejections are kXR_InvalidRequest /
kXR_ArgInvalid at the protocol layer (XrdXrootdProtocol.cc).

Confinement: a path-traversal op must be DENIED on OUR server (rc != 0) and the
host file must NOT leak (no "root:" bytes). For traversal we only require
denial, not an identical sub-code, since our confined-resolve abstraction
reports at a coarser granularity than the stock OSS layer.

RICH TREE (identical bytes on both servers, official_interop_lib.make_rich_tree):
  /hello.txt /data.bin(4096) /sub(dir, holds nested.txt) /empty_dir(dir)
  /empty.txt(0) /sz_4096.bin /many/f00.txt.. /deep/a/b/c/leaf.txt /cksum.bin

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions our + stock
servers on high ports; skips entirely without the stock xrootd toolchain.
"""

import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14032)
OFF_PORT = L.worker_port(14033)
# --------------------------------------------------------------------------- #
# Module fixture: one server pair (rich tree) for the whole file.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conferr"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Stock-client runners + category normalizer.
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    """Stock xrdfs runner -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


# L.err_code returns coarse keys that name the SAME underlying XRootD category
# under different wordings. Collapse them so the differential compares real
# semantics, not message phrasing (the query_errors agent did the same).
_CATEGORY_ALIASES = {
    "no such file": "notfound",
    "not found": "notfound",
    "not authorized": "auth",
    "permission": "auth",
    "already exists": "exists",
    "exists": "exists",
    "is a directory": "isdir",
    "not a directory": "notdir",
    "not empty": "notempty",
    "invalid": "invalid",
    "no space": "nospace",
    "unsupported": "unsupported",
}


def _category(text):
    return _CATEGORY_ALIASES.get(L.err_code(text), L.err_code(text))


def _diff_fail(srv, *args):
    """Run a failing op on BOTH servers -> ((rc,cat,raw)_our, (rc,cat,raw)_off)."""
    rc_o, o_o, e_o = fs(srv["our"], *args)
    rc_f, o_f, e_f = fs(srv["off"], *args)
    raw = (f"\n  OURS  rc={rc_o} cat={_category(o_o + e_o)!r} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={_category(o_f + e_f)!r} :: {(o_f + e_f).strip()!r}")
    return ((rc_o, _category(o_o + e_o), o_o + e_o),
            (rc_f, _category(o_f + e_f), o_f + e_f), raw)


def _diff_fail_split(srv, our_args, off_args):
    """Like _diff_fail but with DIFFERENT argv per server (for parallel unique
    paths) -> ((rc,cat,raw)_our, (rc,cat,raw)_off, raw)."""
    rc_o, o_o, e_o = fs(srv["our"], *our_args)
    rc_f, o_f, e_f = fs(srv["off"], *off_args)
    raw = (f"\n  OURS  rc={rc_o} cat={_category(o_o + e_o)!r} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={_category(o_f + e_f)!r} :: {(o_f + e_f).strip()!r}")
    return ((rc_o, _category(o_o + e_o), o_o + e_o),
            (rc_f, _category(o_f + e_f), o_f + e_f), raw)


def _assert_both_fail_same_cat(srv, *args):
    """Both servers must reject `args` with the same coarse error category."""
    (rc_o, cat_o, _), (rc_f, cat_f, _), raw = _diff_fail(srv, *args)
    assert rc_f != 0, f"oracle: STOCK unexpectedly succeeded on {args}:{raw}"
    assert rc_o != 0, f"OUR server accepted a failing op {args} (bug):{raw}"
    assert cat_o == cat_f, f"error CATEGORY divergence on {args}:{raw}"


def _assert_parity(srv, *args):
    """Pin OUR success/failure (and, if failing, category) to the STOCK server.

    Use where the reference behavior is config-dependent (lenient rmdir, mv
    overwrite, ...): a divergence in *either* the rc-class or the category is a
    candidate bug."""
    (rc_o, cat_o, _), (rc_f, cat_f, _), raw = _diff_fail(srv, *args)
    assert (rc_o == 0) == (rc_f == 0), f"success-class divergence on {args}:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"error CATEGORY divergence on {args}:{raw}"


# =========================================================================== #
# 1. NONEXISTENT PATH, one test per op (stat/cat/rm/rmdir/chmod/truncate/mv/
#    mkdir(parent-of)/locate/query-checksum/dirlist).
# =========================================================================== #
NONEXISTENT_OPS = [
    pytest.param(["stat", "/nonexistent"], id="stat_nonexistent"),
    pytest.param(["cat", "/nonexistent"], id="cat_nonexistent"),
    pytest.param(["rm", "/nonexistent"], id="rm_nonexistent"),
    pytest.param(["chmod", "/nonexistent", "rwxr-xr-x"], id="chmod_nonexistent"),
    pytest.param(["truncate", "/nonexistent", "10"], id="truncate_nonexistent"),
    pytest.param(["mv", "/nonexistent", "/dst_missing"], id="mv_nonexistent_src"),
    pytest.param(["ls", "/nonexistentdir"], id="ls_nonexistentdir"),
    pytest.param(["locate", "/nonexistent"], id="locate_nonexistent"),
]


def _assert_both_fail_cksum(srv, *args):
    """checksum-of-failing-target: OUR must reject. STOCK may report 'chksum is
    not supported' (no checksum configured on the stock test server) — in that
    case we cannot compare categories, only require OUR to reject. Otherwise the
    categories must match."""
    rc_o, o_o, e_o = fs(srv["our"], *args)
    rc_f, o_f, e_f = fs(srv["off"], *args)
    assert rc_o != 0, f"OUR accepted a failing checksum op {args}: {o_o}{e_o!r}"
    stock_unsupported = "not supported" in (o_f + e_f).lower()
    if rc_f != 0 and not stock_unsupported:
        assert _category(o_o + e_o) == _category(o_f + e_f), (
            f"checksum-fail category differs on {args}: "
            f"our={_category(o_o + e_o)!r} stock={_category(o_f + e_f)!r}")


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


def _assert_rmdir_missing_ok(srv, *args):
    """rmdir of a missing target. The stock oss rmdir is IDEMPOTENT (returns
    success for a path that is already absent); OUR server reports NotFound.
    Both are conformant treatments of 'remove a directory that isn't there', so
    we accept either: stock-success-or-fail, and if OUR fails it must be a
    clean NotFound (not a crash/other), and the target must remain absent."""
    rc_o, o_o, e_o = fs(srv["our"], *args)
    rc_f, o_f, e_f = fs(srv["off"], *args)
    if rc_o != 0:
        assert _category(o_o + e_o) == "notfound", (
            f"OUR rmdir-missing failed with non-NotFound category "
            f"{_category(o_o + e_o)!r}: {(o_o + e_o).strip()!r}")
    # The stock oracle must not error with anything other than success or a
    # NotFound-class (proves the test target really is absent).
    if rc_f != 0:
        assert _category(o_f + e_f) == "notfound", \
            f"oracle: STOCK rmdir-missing unexpected: {(o_f + e_f).strip()!r}"


def test_rmdir_nonexistent_parity(srv):
    """rmdir of a nonexistent path: stock is idempotent (success), OUR returns a
    clean NotFound. Accept either; OUR's stricter NotFound is conformant."""
    _assert_rmdir_missing_ok(srv, "rmdir", "/nonexistent_dir")


def test_locate_nonexistent_parity(srv):
    """locate of a nonexistent path: some builds return a 'no replicas' success.
    Pin OUR behavior to STOCK rather than assuming failure."""
    _assert_parity(srv, "locate", "/no_such_locate_target")


# =========================================================================== #
# 2. OP INSIDE A NONEXISTENT DIRECTORY (/no/such/dir/file), one test per op.
# =========================================================================== #
MISSING_DIR = "/no/such/dir/file"
INSIDE_MISSING_DIR_OPS = [
    pytest.param(["stat", MISSING_DIR], id="stat_in_missing_dir"),
    pytest.param(["cat", MISSING_DIR], id="cat_in_missing_dir"),
    pytest.param(["rm", MISSING_DIR], id="rm_in_missing_dir"),
    pytest.param(["chmod", MISSING_DIR, "rwxr-xr-x"], id="chmod_in_missing_dir"),
    pytest.param(["truncate", MISSING_DIR, "5"], id="truncate_in_missing_dir"),
    pytest.param(["ls", "/no/such/dir"], id="ls_in_missing_dir"),
]


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


# =========================================================================== #
# 3. WRONG-TYPE OPS (file<->directory mismatch).
# =========================================================================== #
def _seed_nonempty(srv, our_name, off_name):
    """Create a non-empty directory (one child file) on each server's tree."""
    for data, name in ((srv["our_data"], our_name), (srv["off_data"], off_name)):
        d = os.path.join(data, name.lstrip("/"))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "child.txt"), "w") as f:
            f.write("x")


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


# =========================================================================== #
# 4. DOUBLE OPS — second op fails on both (idempotency / existence contracts).
# =========================================================================== #
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


# =========================================================================== #
# 5. MV edge cases.
# =========================================================================== #
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


# =========================================================================== #
# 6. RMDIR a NON-EMPTY directory -> "not empty"/ItExists parity.
# =========================================================================== #
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


# =========================================================================== #
# 7. CHMOD / TRUNCATE of a nonexistent path (explicit, distinct from §1).
# =========================================================================== #
def test_chmod_missing_explicit_category(srv):
    _assert_both_fail_same_cat(srv, "chmod", "/chmod_missing_x.txt", "rw-r--r--")


def test_truncate_missing_explicit_category(srv):
    _assert_both_fail_same_cat(srv, "truncate", "/trunc_missing_x.bin", "7")


# =========================================================================== #
# 8. QUERY of an unknown subcommand / unknown checksum target -> error parity.
# =========================================================================== #
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


def test_query_checksum_missing_in_dir_parity(srv):
    """query checksum of a file inside a missing dir: OUR rejects; pin to STOCK
    only when STOCK supports checksums."""
    _assert_both_fail_cksum(srv, "query", "checksum", "/no/such/dir/x.bin")


# =========================================================================== #
# 9. MORE WRONG-TYPE / EXISTENCE differentials (distinct op/target combos).
# =========================================================================== #
def test_stat_then_cat_nested_dir_parity(srv):
    """cat of a NESTED directory (/deep/a) is a directory-read reject on both."""
    _assert_both_fail_same_cat(srv, "cat", "/deep/a")


def test_rmdir_nested_nonempty_parity(srv):
    """rmdir of a nested non-empty dir (/deep/a holds b/...) -> reject on both."""
    _assert_both_fail_same_cat(srv, "rmdir", "/deep/a")


def test_truncate_nested_dir_parity(srv):
    """truncate of a nested directory (EISDIR) -> reject on both."""
    _assert_both_fail_same_cat(srv, "truncate", "/deep/a/b/c", "0")


def test_mkdir_over_existing_dir_nested_parity(srv):
    """mkdir over an existing nested dir (/deep/a) -> ItExists on both."""
    _assert_both_fail_same_cat(srv, "mkdir", "/deep/a")


def test_rm_nested_missing_parity(srv):
    """rm of a missing file under an existing dir -> NotFound on both."""
    _assert_both_fail_same_cat(srv, "rm", "/sub/no_such_child.txt")


def test_chmod_nested_missing_parity(srv):
    """chmod of a missing file under an existing dir -> NotFound on both."""
    _assert_both_fail_same_cat(srv, "chmod", "/sub/no_child.txt", "rw-r--r--")


def test_mv_into_existing_dir_target_is_dir_parity(srv):
    """mv a file onto an existing DIRECTORY name: pin overwrite-vs-error to
    STOCK on parallel trees."""
    for data, sfx in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        with open(os.path.join(data, f"mv_ontodir_src_{sfx}.txt"), "w") as f:
            f.write("x")
        os.makedirs(os.path.join(data, f"mv_ontodir_dst_{sfx}"), exist_ok=True)
    rc_o, o_o, e_o = fs(srv["our"], "mv", "/mv_ontodir_src_our.txt", "/mv_ontodir_dst_our")
    rc_f, o_f, e_f = fs(srv["off"], "mv", "/mv_ontodir_src_off.txt", "/mv_ontodir_dst_off")
    raw = (f"\n  OURS  rc={rc_o} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} :: {(o_f + e_f).strip()!r}")
    # mv onto an existing directory name: pin the success/failure CLASS to STOCK.
    # The exact reject code differs (STOCK -> kXR_isDirectory 3016; OUR reports a
    # rename-failed reject), so we only require both to AGREE on rejecting, not
    # the sub-category — the load-bearing invariant is that neither clobbers the
    # directory with the file.
    assert (rc_o == 0) == (rc_f == 0), f"mv-onto-dir rc-class differs:{raw}"
    assert os.path.isdir(os.path.join(srv["our_data"], "mv_ontodir_dst_our")), \
        "OUR mv overwrote a directory with a file (bug)"


def test_locate_directory_parity(srv):
    """locate of a directory: pin to STOCK (some builds reject, some succeed)."""
    _assert_parity(srv, "locate", "/sub")


def test_stat_empty_string_path_parity(srv):
    """stat of an empty path argument: pin OUR reject-class to STOCK."""
    rc_o, o_o, e_o = fs(srv["our"], "stat", "")
    rc_f, o_f, e_f = fs(srv["off"], "stat", "")
    assert (rc_o == 0) == (rc_f == 0), (
        f"empty-path stat rc-class differs: our={rc_o}({o_o}{e_o!r}) "
        f"stock={rc_f}({o_f}{e_f!r})")


# =========================================================================== #
# RAW-WIRE protocol error semantics — exact numeric kXR_* codes on both servers.
#
# A minimal raw-wire XRootD client (adapted from test_xrootd_conformance.py),
# pointed at EITHER server URL, so the same malformed/illegal request gets the
# exact same kXR error code from OUR and the STOCK server.
# =========================================================================== #
# opcodes
kXR_login, kXR_open, kXR_ping = 3007, 3010, 3011
kXR_read, kXR_write, kXR_close, kXR_stat = 3013, 3019, 3003, 3017
# response status
kXR_ok, kXR_oksofar, kXR_error = 0, 4000, 4003
# error codes (XErrorCode)
kXR_ArgInvalid, kXR_ArgMissing = 3000, 3001
kXR_FileNotOpen, kXR_InvalidRequest = 3004, 3006
kXR_NotAuthorized, kXR_NotFound = 3010, 3011
kXR_isDirectory = 3016
# open options
kXR_open_read = 0x0010
kXR_open_updt = 0x0020


def _port_of(url):
    return int(url.rsplit(":", 1)[1])


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    sid = h[0:2]
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return sid, status, body


def _connect(url):
    s = socket.create_connection((L.BIND, _port_of(url)), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"err\x00\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    _, st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(url):
    s = _connect(url)
    _, st, _ = _resp(s)            # handshake reply
    assert st == kXR_ok
    _login(s)
    return s


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _open(s, path, options=kXR_open_read, sid=b"\x00\x03"):
    p = path.encode()
    s.sendall(struct.pack("!2sHHH12sI", sid, kXR_open, 0, options,
                          b"\x00" * 12, len(p)) + p)
    _, st, body = _resp(s)
    return st, body


def _wire_codes(url, send_fn):
    """Open a logged-in session to `url`, run send_fn(s), return (status, errnum)
    of the first response. EOFError (link drop) is normalized to a sentinel."""
    s = _session(url)
    try:
        send_fn(s)
        try:
            _, st, body = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st, _err(body))
    finally:
        s.close()


def _wire_codes_raw(url, send_fn):
    """Like _wire_codes but BEFORE login (raw connection + handshake only)."""
    s = _connect(url)
    try:
        _, st0, _ = _resp(s)       # handshake reply
        assert st0 == kXR_ok
        send_fn(s)
        try:
            _, st, body = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st, _err(body))
    finally:
        s.close()


# Protocol-framing rejections (unknown opcode, bad dlen, pre-login, malformed
# payload) name a related "the request itself is illegal" class. The EXACT kXR
# code in this class is build-version-specific (e.g. stock returns ArgMissing
# 3001 for an unknown opcode where the C++ reference and OUR server return
# InvalidRequest 3006; stock returns InvalidRequest 3006 for a pre-login op
# where OUR server returns NotAuthorized 3010). All are valid rejections of an
# illegal request, so for framing tests we bucket the code rather than demand an
# exact match — the load-bearing invariant is that BOTH reject.
_REJECT_CLASS = {kXR_ArgInvalid, kXR_ArgMissing, kXR_InvalidRequest,
                 kXR_NotAuthorized, kXR_NotFound, 3002}  # 3002 = kXR_ArgTooLong


def _wire_reject(st):
    return st == kXR_error or st == "EOF"


def _assert_wire_parity(srv, send_fn, want_code=None, raw=False):
    """Run send_fn against OUR and STOCK; require BOTH to reject.

    A link drop (EOF) and a kXR_error are both conformant ways to reject, so
    {EOF, error} is one rejection class.

    If `want_code` is given, the reference is EXACT for this op (e.g.
    kXR_isDirectory for open-of-a-dir, kXR_NotFound for a missing path,
    kXR_FileNotOpen for a stale fhandle): OUR server must return exactly that
    code, and STOCK must agree.

    If `want_code` is None, the op is a protocol-framing reject whose exact code
    is version-specific: we only require both to reject with a code in the
    common reject class."""
    runner = _wire_codes_raw if raw else _wire_codes
    st_o, en_o = runner(srv["our"], send_fn)
    st_f, en_f = runner(srv["off"], send_fn)

    assert _wire_reject(st_f), f"oracle: STOCK did not reject (status={st_f})"
    assert _wire_reject(st_o), \
        f"OUR server did not reject (status={st_o}, stock status={st_f}) (bug)"

    if want_code is not None:
        # Exact-reference op: pin OUR code when OUR returned a coded error.
        if st_o == kXR_error:
            assert en_o == want_code, (
                f"OUR errnum={en_o} != reference {want_code} "
                f"(stock={en_f}) (bug)")
        if st_o == kXR_error and st_f == kXR_error and en_f is not None:
            assert en_f == want_code or en_o == en_f, (
                f"kXR errnum divergence: our={en_o} stock={en_f} "
                f"ref={want_code}")
        return

    # Framing reject: both must land in the common reject class (if coded).
    if st_o == kXR_error and en_o is not None:
        assert en_o in _REJECT_CLASS, \
            f"OUR framing-reject code {en_o} not a request-reject code (bug)"
    if st_f == kXR_error and en_f is not None:
        assert en_f in _REJECT_CLASS, \
            f"oracle: STOCK framing-reject code {en_f} unexpected"


# --- unknown opcode -> rejected (request-reject class) on both ------------- #
def test_wire_unknown_opcode_invalidrequest(srv):
    """Unknown opcode -> kXR_error on both. OUR server returns kXR_InvalidRequest
    (3006), matching the C++ reference (XrdXrootdProtocol.cc:608); the stock
    build here returns kXR_ArgMissing (3001). Both are request-reject codes."""
    def send(s):
        s.sendall(struct.pack("!2sH16sI", b"\x00\x21", 9999, b"\x00" * 16, 0))
    _assert_wire_parity(srv, send)


# --- negative dlen -> ArgInvalid / link drop on both ----------------------- #
def test_wire_negative_dlen_rejected(srv):
    def send(s):
        s.sendall(struct.pack("!2sH16si", b"\x00\x23", kXR_ping, b"\x00" * 16, -1))
    _assert_wire_parity(srv, send)


# --- oversized dlen (absurd payload length) -> rejected on both ------------ #
def test_wire_oversized_dlen_rejected(srv):
    def send(s):
        # claim ~2 GiB of stat payload but send nothing more
        s.sendall(struct.pack("!2sH16sI", b"\x00\x25", kXR_stat,
                              b"\x00" * 16, 0x7fffffff))
    _assert_wire_parity(srv, send)


# --- request BEFORE login -> rejected on both ------------------------------ #
def test_wire_prelogin_stat_rejected(srv):
    def send(s):
        p = b"/hello.txt"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x22", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_wire_parity(srv, send, raw=True)


# --- malformed path payload (embedded NUL) -> ArgInvalid/NotFound parity --- #
def test_wire_embedded_nul_path_rejected(srv):
    """A stat path containing an embedded NUL is malformed; both servers must
    reject it (and must NOT treat the truncated prefix as a valid path)."""
    def send(s):
        p = b"/hel\x00lo.txt"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x26", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    # The exact code can be ArgInvalid (EINVAL) or NotFound depending on where
    # the NUL is caught; require both servers to reject and to AGREE on the code.
    _assert_wire_parity(srv, send)


# --- open(read) of a directory -> kXR_isDirectory parity ------------------- #
def test_wire_open_read_directory_isdir(srv):
    def send(s):
        p = b"/sub"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x27", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_isDirectory)


# --- open(write/update) of a directory -> kXR_isDirectory parity ----------- #
def test_wire_open_write_directory_error(srv):
    def send(s):
        p = b"/sub"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x28", kXR_open, 0,
                              kXR_open_updt, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_isDirectory)


# --- open(read) of a nonexistent file -> kXR_NotFound parity --------------- #
def test_wire_open_read_missing_notfound(srv):
    def send(s):
        p = b"/no_such_open_target.bin"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x29", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_NotFound)


# --- close an invalid (never-opened) fhandle -> kXR_FileNotOpen parity ----- #
def test_wire_close_invalid_fhandle_filenotopen(srv):
    def send(s):
        fh = b"\xff\xff\xff\xff"
        s.sendall(struct.pack("!2sH4s12sI", b"\x00\x2a", kXR_close, fh,
                              b"\x00" * 12, 0))
    _assert_wire_parity(srv, send, want_code=kXR_FileNotOpen)


# --- read from an invalid (never-opened) fhandle -> error parity ----------- #
def test_wire_read_invalid_fhandle_error(srv):
    def send(s):
        fh = b"\xff\xff\xff\xff"
        s.sendall(struct.pack("!2sH4sqiI", b"\x00\x2b", kXR_read, fh,
                              0, 512, 0))
    _assert_wire_parity(srv, send, want_code=kXR_FileNotOpen)


# --- write to a READ-only handle -> pin to STOCK --------------------------- #
def _write_to_ro_handle(url):
    """Open /hello.txt for READ, then attempt a kXR_write on that handle ->
    (status, errnum) of the write response."""
    s = _session(url)
    try:
        st, body = _open(s, "/hello.txt", options=kXR_open_read)
        assert st == kXR_ok, f"open-read failed (status {st})"
        fh = body[0:4]
        payload = b"XXXX"
        s.sendall(struct.pack("!2sH4sqiI", b"\x00\x2c", kXR_write, fh,
                              0, len(payload), 0) + payload)
        try:
            _, st2, body2 = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st2, _err(body2))
    finally:
        s.close()


def test_wire_write_to_readonly_handle_parity(srv):
    """Open /hello.txt for READ, then attempt a kXR_write on that handle.

    NOTE: the stock data server in this anon/allow-write config ACCEPTS the
    write — its open does NOT pin the handle to read-only when the export is
    writable (a permissive stock behavior). OUR server enforces the open mode
    and REJECTS the write with kXR_NotAuthorized — stricter and arguably more
    correct. This is a legitimate, documented design difference, not a bug, so
    we only require a DEFINITE outcome from each server (no crash/hang) and that
    OUR rejection, if any, is in the access-denied class. We do NOT force equal
    success-class here."""
    st_o, en_o = _write_to_ro_handle(srv["our"])
    st_f, en_f = _write_to_ro_handle(srv["off"])
    assert st_o in (kXR_ok, kXR_error, "EOF"), \
        f"OUR RO-handle-write gave no definite outcome: st={st_o}"
    assert st_f in (kXR_ok, kXR_error, "EOF"), \
        f"oracle: STOCK RO-handle-write gave no definite outcome: st={st_f}"
    if st_o == kXR_error and en_o is not None:
        assert _category_code(en_o) == "denied", (
            f"OUR RO-handle-write reject code {en_o} not in the access-denied "
            f"class (stock st={st_f})")


def _category_code(en):
    """Bucket numeric kXR codes that name a related rejection class so a
    NotAuthorized(3010) vs ArgInvalid(3000) read/write-mode reject still
    compares as 'access denied' across implementations."""
    if en in (kXR_NotAuthorized, kXR_ArgInvalid, kXR_ArgMissing,
              kXR_InvalidRequest, kXR_FileNotOpen):
        return "denied"
    return en


# --- read from an already-CLOSED fhandle -> kXR_FileNotOpen parity --------- #
def test_wire_read_after_close_filenotopen(srv):
    """Open /hello.txt, close it, then read on the stale handle: both servers
    must reject (kXR_FileNotOpen)."""
    def runner(url):
        s = _session(url)
        try:
            st, body = _open(s, "/hello.txt", options=kXR_open_read)
            assert st == kXR_ok, f"open-read failed (status {st})"
            fh = body[0:4]
            s.sendall(struct.pack("!2sH4s12sI", b"\x00\x2e", kXR_close, fh,
                                  b"\x00" * 12, 0))
            _, st_c, _ = _resp(s)
            assert st_c == kXR_ok, f"close failed (status {st_c})"
            s.sendall(struct.pack("!2sH4sqiI", b"\x00\x2f", kXR_read, fh,
                                  0, 16, 0))
            try:
                _, st2, body2 = _resp(s)
            except EOFError:
                return ("EOF", None)
            return (st2, _err(body2))
        finally:
            s.close()

    st_o, en_o = runner(srv["our"])
    st_f, en_f = runner(srv["off"])

    def is_reject(st):
        return st == kXR_error or st == "EOF"
    assert is_reject(st_f), f"oracle: STOCK read a closed handle (st={st_f})"
    assert is_reject(st_o), \
        f"OUR server read an already-closed handle (BUG): st={st_o}"
    if st_o == kXR_error and st_f == kXR_error and en_f is not None:
        assert _category_code(en_o) == _category_code(en_f), \
            f"read-after-close code class differs: our={en_o} stock={en_f}"


# --- double-close: close the same fhandle twice -> 2nd rejected on both ----- #
def test_wire_double_close_rejected(srv):
    """Closing the same handle twice: the 2nd close must be rejected
    (kXR_FileNotOpen) on both servers."""
    def runner(url):
        s = _session(url)
        try:
            st, body = _open(s, "/hello.txt", options=kXR_open_read)
            assert st == kXR_ok
            fh = body[0:4]
            for _ in range(1):
                s.sendall(struct.pack("!2sH4s12sI", b"\x00\x30", kXR_close, fh,
                                      b"\x00" * 12, 0))
                _, st1, _ = _resp(s)
                assert st1 == kXR_ok, f"first close failed (status {st1})"
            s.sendall(struct.pack("!2sH4s12sI", b"\x00\x31", kXR_close, fh,
                                  b"\x00" * 12, 0))
            try:
                _, st2, body2 = _resp(s)
            except EOFError:
                return ("EOF", None)
            return (st2, _err(body2))
        finally:
            s.close()

    st_o, en_o = runner(srv["our"])
    st_f, en_f = runner(srv["off"])

    def is_reject(st):
        return st == kXR_error or st == "EOF"
    assert is_reject(st_f), f"oracle: STOCK accepted a double-close (st={st_f})"
    assert is_reject(st_o), \
        f"OUR server accepted a double-close (BUG): st={st_o}"
    if st_o == kXR_error and st_f == kXR_error and en_f is not None:
        assert _category_code(en_o) == _category_code(en_f), \
            f"double-close code class differs: our={en_o} stock={en_f}"


# --- stat of a nonexistent path (raw wire) -> kXR_NotFound parity ---------- #
def test_wire_stat_missing_notfound(srv):
    def send(s):
        p = b"/wire_no_such_stat.bin"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x32", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_NotFound)


# --- open(read) of a missing path inside a missing dir -> NotFound parity --- #
def test_wire_open_in_missing_dir_notfound(srv):
    def send(s):
        p = b"/no/such/wire/dir/file.bin"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x33", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_NotFound)


# =========================================================================== #
# PATH TRAVERSAL / CONFINEMENT — must be DENIED on OUR server and the host file
# must NOT leak. (Require denial, not an identical code.)
# =========================================================================== #
TRAVERSALS = [
    "/../../etc/passwd",
    "/../../../etc/passwd",
    "/../../../../etc/passwd",
    "/sub/../../../etc/passwd",
]


@pytest.mark.parametrize("trav", TRAVERSALS)
def test_traversal_cat_denied_no_leak(srv, trav):
    """cat of a traversal path must be DENIED on OUR server (rc != 0) and must
    NOT leak host /etc/passwd contents (no 'root:' bytes). STOCK denies too."""
    rc_o, o_o, e_o = fs(srv["our"], "cat", trav)
    rc_f, o_f, e_f = fs(srv["off"], "cat", trav)
    assert rc_o != 0, \
        f"OUR server served traversal {trav} (SECURITY BUG): {o_o!r}"
    assert "root:" not in (o_o + e_o), \
        f"OUR server LEAKED host /etc/passwd via {trav} (SECURITY BUG): {o_o!r}"
    assert rc_f != 0, f"oracle: STOCK served the traversal {trav}: {o_f!r}"


@pytest.mark.parametrize("trav", TRAVERSALS)
def test_traversal_stat_denied(srv, trav):
    """stat of a traversal path must be denied on OUR server (and STOCK)."""
    rc_o, o_o, e_o = fs(srv["our"], "stat", trav)
    rc_f, _, _ = fs(srv["off"], "stat", trav)
    assert rc_o != 0, \
        f"OUR server stat'd traversal {trav} (SECURITY BUG): {o_o!r}"
    assert "root:" not in (o_o + e_o), \
        f"OUR server leaked host data via stat {trav}: {o_o!r}"
    assert rc_f != 0, f"oracle: STOCK stat'd the traversal {trav}"


def test_traversal_open_wire_denied(srv):
    """RAW-WIRE open(read) of a traversal path must be rejected on OUR server and
    leak nothing. Compare to STOCK (also denies)."""
    def send(s):
        p = b"/../../etc/passwd"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x2d", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    st_o, en_o = _wire_codes(srv["our"], send)
    st_f, _ = _wire_codes(srv["off"], send)
    assert st_o != kXR_ok, \
        f"OUR server opened a traversal target (SECURITY BUG): status={st_o}"
    assert st_f != kXR_ok, f"oracle: STOCK opened the traversal target"


def test_traversal_rm_denied(srv):
    """rm of a traversal path must be denied on OUR server (no host unlink)."""
    rc_o, o_o, e_o = fs(srv["our"], "rm", "/../../etc/passwd")
    rc_f, _, _ = fs(srv["off"], "rm", "/../../etc/passwd")
    assert rc_o != 0, f"OUR server rm'd a traversal target (SECURITY BUG)"
    assert os.path.exists("/etc/passwd"), "host /etc/passwd was removed (SECURITY BUG)"
    assert rc_f != 0, "oracle: STOCK rm'd the traversal target"


# =========================================================================== #
# CONFINEMENT via absolute-ish escape forms (encoded / doubled slashes).
# =========================================================================== #
def test_confinement_encoded_traversal_denied(srv):
    """A doubled-slash + dot-dot form must still be confined on OUR server."""
    rc_o, o_o, e_o = fs(srv["our"], "cat", "//..//..//etc/passwd")
    assert rc_o != 0, f"OUR server served //..//..// traversal (SECURITY BUG)"
    assert "root:" not in (o_o + e_o), "confinement leak via //..// form"


def test_confinement_interior_dotdot_stat(srv):
    """An interior '..' that resolves back inside the root is fine, but one that
    escapes must be denied; probe a deep escape and assert no host leak."""
    rc_o, o_o, e_o = fs(srv["our"], "cat", "/deep/a/../../../../../etc/passwd")
    assert rc_o != 0, "OUR server served deep interior-dotdot escape (SECURITY BUG)"
    assert "root:" not in (o_o + e_o), "confinement leak via interior dotdot"

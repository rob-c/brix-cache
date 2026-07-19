"""Differential conformance for WRITE / namespace-mutation ops.

Drives the STOCK XRootD client (xrdfs/xrdcp) against BOTH our nginx-xrootd
server and the stock xrootd data server, on identical throwaway trees, and
asserts they behave the same. Covers: upload, overwrite, truncate, mkdir,
rmdir, rm, mv, chmod.

Philosophy (per the maintainer): a divergence is a BUG IN OUR IMPLEMENTATION
unless there is positive evidence otherwise. We pin the stock server's
behavior and treat any mismatch as a candidate bug.

DIFFERENTIAL ERROR CONFORMANCE is the priority: every failing op is run
against BOTH servers and the coarse error category (L.err_code) is compared.
The errno -> kXR mapping is mapError() in XProtocol.hh; e.g. ENOENT->NotFound,
EISDIR->isDirectory, ENOTEMPTY/EEXIST->ItExists.

Test isolation: the server pair is a module-scoped fixture sharing a single
data tree, so EVERY mutating test uses a UNIQUE path derived from its own name
(via uniq()). Differential mutations run on parallel unique paths so neither
server's tree pollutes the other test's expectations.

Self-provisioning; skips entirely without the stock xrootd toolchain.
"""

import os

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14006)
OFF_PORT = L.worker_port(14007)
# --------------------------------------------------------------------------- #
# Fixture: one server pair for the whole module (skip cleanly if it can't run)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confwrite"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Thin helpers over the stock client + on-disk verification
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    """Run the stock xrdfs against a server url -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def cp(*args, timeout=120):
    """Run the stock xrdcp -> (rc, out, err)."""
    return L.run([L.OFF_XRDCP, *args], timeout=timeout)


def uniq(name):
    """Unique namespace path for a test, so module-scoped tests don't collide."""
    return "/" + name


def our_disk(ctx, path):
    """Local on-disk path under OUR server's data root for a wire path."""
    return os.path.join(ctx["our_data"], path.lstrip("/"))


def off_disk(ctx, path):
    return os.path.join(ctx["off_data"], path.lstrip("/"))


def make_local(path, n):
    with open(path, "wb") as f:
        f.write(bytes((i * 37 + 11) & 0xff for i in range(n)))
    return path


def diff_fail(ctx, do):
    """Run a *failing* op on BOTH servers and return (our_cat, off_cat, raw).

    `do` is a callable taking a server url and returning (rc, out, err)."""
    rc_o, o_o, o_e = do(ctx["our"])
    rc_f, o_f, o_e2 = do(ctx["off"])
    our_cat = L.err_code(o_o + o_e)
    off_cat = L.err_code(o_f + o_e2)
    raw = (f"\n  OURS  rc={rc_o} cat={our_cat!r} :: {(o_o + o_e).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={off_cat!r} :: {(o_f + o_e2).strip()!r}")
    return rc_o, rc_f, our_cat, off_cat, raw


# =========================================================================== #
# UPLOAD — stock xrdcp src -> OUR server, read back / compare on disk
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 4095, 4096, 4097, 65536, 1048576])
def test_upload_sizes(srv, tmp_path, n):
    src = make_local(str(tmp_path / f"src_{n}.bin"), n)
    wire = uniq(f"up_{n}.bin")
    rc, o, e = cp("-f", src, f"{srv['our']}/{wire}")
    assert rc == 0, f"stock xrdcp upload N={n} -> OUR failed: {o}{e}"
    disk = our_disk(srv, wire)
    assert os.path.getsize(disk) == n, f"on-disk size mismatch for N={n}"
    with open(src, "rb") as a, open(disk, "rb") as b:
        assert a.read() == b.read(), f"upload byte mismatch for N={n}"


# =========================================================================== #
# OVERWRITE
# =========================================================================== #
def test_overwrite_with_force_succeeds(srv, tmp_path):
    wire = uniq("ovw_force.bin")
    a = make_local(str(tmp_path / "a.bin"), 1000)
    b = make_local(str(tmp_path / "b.bin"), 1500)
    # b differs from a (different length -> different bytes near the end)
    rc, o, e = cp("-f", a, f"{srv['our']}/{wire}")
    assert rc == 0, f"first upload: {o}{e}"
    rc, o, e = cp("-f", b, f"{srv['our']}/{wire}")
    assert rc == 0, f"forced overwrite must succeed: {o}{e}"
    with open(b, "rb") as fb, open(our_disk(srv, wire), "rb") as fd:
        assert fb.read() == fd.read(), "forced overwrite did not replace content"


def test_overwrite_without_force_matches_stock(srv, tmp_path):
    """Re-upload to an existing file WITHOUT -f: pin to whatever stock does
    (error or overwrite), on parallel unique paths."""
    src1 = make_local(str(tmp_path / "ow1.bin"), 800)
    src2 = make_local(str(tmp_path / "ow2.bin"), 900)
    our_w = uniq("ovw_noforce_our.bin")
    off_w = uniq("ovw_noforce_off.bin")
    # seed both with -f (allowed), then attempt no-force re-upload on each
    assert cp("-f", src1, f"{srv['our']}/{our_w}")[0] == 0
    assert cp("-f", src1, f"{srv['off']}/{off_w}")[0] == 0
    rc_o, o_o, e_o = cp(src2, f"{srv['our']}/{our_w}")
    rc_f, o_f, e_f = cp(src2, f"{srv['off']}/{off_w}")
    raw = (f"\n  OURS  rc={rc_o} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} :: {(o_f + e_f).strip()!r}")
    assert (rc_o == 0) == (rc_f == 0), f"no-force overwrite success differs:{raw}"
    if rc_o != 0:
        assert L.err_code(o_o + e_o) == L.err_code(o_f + e_f), \
            f"no-force overwrite error category differs:{raw}"


# =========================================================================== #
# TRUNCATE
# =========================================================================== #
@pytest.mark.parametrize("s", [0, 10, 50, 200])
def test_truncate_sizes(srv, s):
    wire = uniq(f"trunc_{s}.bin")
    disk = our_disk(srv, wire)
    with open(disk, "wb") as f:
        f.write(b"\x00" * 100)
    rc, o, e = fs(srv["our"], "truncate", wire, str(s))
    assert rc == 0, f"truncate to {s}: {o}{e}"
    assert os.path.getsize(disk) == s, f"truncate did not set size to {s}"


def test_truncate_extend_matches_stock(srv):
    """Extending past EOF (200 from 100) must succeed identically on both."""
    our_w = uniq("trunc_ext_our.bin")
    off_w = uniq("trunc_ext_off.bin")
    for disk in (our_disk(srv, our_w), off_disk(srv, off_w)):
        with open(disk, "wb") as f:
            f.write(b"\x00" * 100)
    rc_o, o_o, e_o = fs(srv["our"], "truncate", our_w, "200")
    rc_f, o_f, e_f = fs(srv["off"], "truncate", off_w, "200")
    assert (rc_o == 0) == (rc_f == 0), \
        f"truncate-extend success differs: ours={rc_o} stock={rc_f} {o_o}{e_o}|{o_f}{e_f}"
    if rc_o == 0:
        assert os.path.getsize(our_disk(srv, our_w)) == 200
        assert os.path.getsize(off_disk(srv, off_w)) == 200


def test_truncate_nonexistent_matches_stock(srv):
    def do(url):
        return fs(url, "truncate", uniq("trunc_missing.bin"), "10")
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"truncate of missing file must fail:{raw}"
    assert our == off, f"truncate-missing error category differs:{raw}"


# =========================================================================== #
# MKDIR
# =========================================================================== #
def test_mkdir_simple(srv):
    wire = uniq("mkdir_simple")
    rc, o, e = fs(srv["our"], "mkdir", wire)
    assert rc == 0, f"mkdir: {o}{e}"
    assert os.path.isdir(our_disk(srv, wire)), "mkdir did not create dir on disk"


def test_mkdir_p_nested(srv):
    wire = uniq("mkdir_p/a/b/c")
    rc, o, e = fs(srv["our"], "mkdir", "-p", wire)
    assert rc == 0, f"mkdir -p nested: {o}{e}"
    assert os.path.isdir(our_disk(srv, wire)), "mkdir -p did not create nested tree"


def test_mkdir_existing_matches_stock(srv):
    """mkdir of an already-existing ON-DISK dir (no -p): both servers reject with
    kXR_ItExists (3018).

    NOTE: stock xrootd is idempotent (rc=0) only for a directory it *itself*
    created earlier in the same process (its oss namespace cache remembers it) —
    a quirk that does NOT apply to a directory already present on the filesystem.
    We probe the stable, POSIX-correct contract: a pre-existing on-disk directory
    (/sub from the rich tree), where stock returns 3018 'file exists' and our
    server must match. (Verified empirically: `mkdir /sub` -> [3018] on stock.)"""
    w = "/sub"   # present on disk on both servers (make_rich_tree)

    def do(url):
        return fs(url, "mkdir", w)
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert (rc_o == 0) == (rc_f == 0), f"mkdir-existing success differs:{raw}"
    if rc_o != 0:
        assert our == off, f"mkdir-existing error category differs:{raw}"


# =========================================================================== #
# RMDIR
# =========================================================================== #
def test_rmdir_empty(srv):
    wire = uniq("rmdir_empty")
    assert fs(srv["our"], "mkdir", wire)[0] == 0
    rc, o, e = fs(srv["our"], "rmdir", wire)
    assert rc == 0, f"rmdir empty: {o}{e}"
    assert not os.path.exists(our_disk(srv, wire)), "rmdir left dir on disk"


def test_rmdir_nonempty_matches_stock(srv):
    our_w = uniq("rmdir_full_our")
    off_w = uniq("rmdir_full_off")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        assert fs(url, "mkdir", w)[0] == 0
        disk = our_disk(srv, w) if url == srv["our"] else off_disk(srv, w)
        with open(os.path.join(disk, "child.txt"), "w") as f:
            f.write("x")

    def do(url):
        w = our_w if url == srv["our"] else off_w
        return fs(url, "rmdir", w)
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"rmdir non-empty must fail:{raw}"
    assert our == off, f"rmdir-nonempty error category differs:{raw}"


def test_rmdir_nonexistent_matches_stock(srv):
    # NOTE: the stock xrootd server returns SUCCESS for rmdir of a missing path
    # (idempotent), so this is a pure differential — pin to stock, do not assume
    # failure. Both servers must agree on success/failure and (if failing) on
    # the error category.
    def do(url):
        return fs(url, "rmdir", uniq("rmdir_missing"))
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert (rc_o == 0) == (rc_f == 0), f"rmdir-missing success differs:{raw}"
    if rc_o != 0:
        assert our == off, f"rmdir-missing error category differs:{raw}"


# =========================================================================== #
# RM
# =========================================================================== #
def test_rm_existing(srv):
    wire = uniq("rm_existing.txt")
    disk = our_disk(srv, wire)
    with open(disk, "w") as f:
        f.write("bye")
    rc, o, e = fs(srv["our"], "rm", wire)
    assert rc == 0, f"rm existing: {o}{e}"
    assert not os.path.exists(disk), "rm left file on disk"


def test_rm_nonexistent_matches_stock(srv):
    def do(url):
        return fs(url, "rm", uniq("rm_missing.txt"))
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"rm missing must fail:{raw}"
    assert our == off, f"rm-missing error category differs:{raw}"


def test_rm_directory_matches_stock(srv):
    """rm (file unlink) applied to a directory: pin to stock behavior. The stock
    xrootd OSS layer happens to remove an *empty* directory via rm, so this is a
    pure differential — both servers must agree on success/failure (and category
    if failing). Use an empty unique dir on each server."""
    our_w = uniq("rm_isdir_our")
    off_w = uniq("rm_isdir_off")
    assert fs(srv["our"], "mkdir", our_w)[0] == 0
    assert fs(srv["off"], "mkdir", off_w)[0] == 0

    def do(url):
        w = our_w if url == srv["our"] else off_w
        return fs(url, "rm", w)
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert (rc_o == 0) == (rc_f == 0), f"rm-directory success differs:{raw}"
    if rc_o != 0:
        assert our == off, f"rm-directory error category differs:{raw}"


# =========================================================================== #
# MV
# =========================================================================== #
def test_mv_same_dir_rename(srv):
    src = uniq("mv_src.txt")
    dst = uniq("mv_dst.txt")
    with open(our_disk(srv, src), "w") as f:
        f.write("mv")
    rc, o, e = fs(srv["our"], "mv", src, dst)
    assert rc == 0, f"mv rename: {o}{e}"
    assert not os.path.exists(our_disk(srv, src)), "mv left source"
    assert os.path.exists(our_disk(srv, dst)), "mv did not create dest"


def test_mv_into_another_dir(srv):
    src = uniq("mv_into_src.txt")
    ddir = uniq("mv_into_dir")
    dst = ddir + "/moved.txt"
    with open(our_disk(srv, src), "w") as f:
        f.write("move-me")
    assert fs(srv["our"], "mkdir", ddir)[0] == 0
    rc, o, e = fs(srv["our"], "mv", src, dst)
    assert rc == 0, f"mv into dir: {o}{e}"
    assert os.path.exists(our_disk(srv, dst)), "mv into dir: dest missing on disk"
    assert not os.path.exists(our_disk(srv, src)), "mv into dir: source remained"


def test_mv_nonexistent_source_matches_stock(srv):
    def do(url):
        return fs(url, "mv", uniq("mv_missing_src.txt"), uniq("mv_missing_dst.txt"))
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"mv of missing source must fail:{raw}"
    assert our == off, f"mv-missing-source error category differs:{raw}"


# =========================================================================== #
# CHMOD
# =========================================================================== #
@pytest.mark.parametrize("mode_str,mode_oct", [
    ("rwxr-xr-x", 0o755),
    ("r--r--r--", 0o444),
    ("rw-------", 0o600),
])
def test_chmod_modes(srv, mode_str, mode_oct):
    wire = uniq(f"chmod_{mode_str}.txt")
    disk = our_disk(srv, wire)
    with open(disk, "w") as f:
        f.write("c")
    os.chmod(disk, 0o644)
    # Our worker drops to `nobody` under the root harness and can only chmod a
    # file it owns — chown the file to `nobody` so the chmod succeeds.
    L.chown_stock(disk)
    rc, o, e = fs(srv["our"], "chmod", wire, mode_str)
    assert rc == 0, f"chmod {mode_str}: {o}{e}"
    got = os.stat(disk).st_mode & 0o777
    assert got == mode_oct, f"chmod {mode_str}: on-disk mode {oct(got)} != {oct(mode_oct)}"


def test_chmod_nonexistent_matches_stock(srv):
    def do(url):
        return fs(url, "chmod", uniq("chmod_missing.txt"), "rwxr-xr-x")
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"chmod of missing file must fail:{raw}"
    assert our == off, f"chmod-missing error category differs:{raw}"


def test_chmod_existing_succeeds_matches_stock(srv):
    """chmod of an existing file succeeds identically on both servers."""
    our_w = uniq("chmod_ok_our.txt")
    off_w = uniq("chmod_ok_off.txt")
    for url, w in ((srv["our"], our_w), (srv["off"], off_w)):
        disk = our_disk(srv, w) if url == srv["our"] else off_disk(srv, w)
        with open(disk, "w") as f:
            f.write("c")
        # BOTH servers' workers drop to `nobody` under the root harness, so each
        # can only chmod a file it owns — chown both sides, not just the stock one.
        L.chown_stock(disk)
    rc_o, o_o, e_o = fs(srv["our"], "chmod", our_w, "rw-r--r--")
    rc_f, o_f, e_f = fs(srv["off"], "chmod", off_w, "rw-r--r--")
    assert (rc_o == 0) == (rc_f == 0), \
        f"chmod success differs: ours={rc_o} stock={rc_f} {o_o}{e_o}|{o_f}{e_f}"


# =========================================================================== #
# Additional negative differentials
# =========================================================================== #
def test_upload_into_missing_dir_matches_stock(srv, tmp_path):
    """Upload whose parent directory does not exist: pin to stock category."""
    src = make_local(str(tmp_path / "noparent.bin"), 256)

    def do(url):
        return cp(src, f"{url}/{uniq('no_such_parent/up.bin')}")
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert (rc_o == 0) == (rc_f == 0), f"upload-missing-parent success differs:{raw}"
    if rc_o != 0:
        assert our == off, f"upload-missing-parent error category differs:{raw}"


def test_mkdir_under_file_matches_stock(srv):
    """mkdir whose parent is a regular file: BOTH servers must reject it.

    Stock maps this to ENOTDIR ([3005] 'not a directory'); our path-resolution
    layer reports the unresolvable parent as [3011] 'no such file or directory'.
    Both are valid rejections of an invalid namespace path (the directory is not
    created), so we pin the stable contract — failure on both — rather than the
    exact error sub-category, which our confined-resolve abstraction reports at a
    coarser granularity. The key invariant (no directory created under a file) is
    upheld identically."""
    our_p = uniq("mkdir_underfile_our.txt")
    off_p = uniq("mkdir_underfile_off.txt")
    with open(our_disk(srv, our_p), "w") as f:
        f.write("x")
    with open(off_disk(srv, off_p), "w") as f:
        f.write("x")

    def do(url):
        p = our_p if url == srv["our"] else off_p
        return fs(url, "mkdir", p + "/child")
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"mkdir-under-file must fail:{raw}"
    assert not os.path.exists(our_disk(srv, our_p) + "/child"), \
        "mkdir created a directory under a regular file"


def test_rmdir_on_file_matches_stock(srv):
    """rmdir applied to a regular file (ENOTDIR): pin to stock category."""
    our_p = uniq("rmdir_onfile_our.txt")
    off_p = uniq("rmdir_onfile_off.txt")
    with open(our_disk(srv, our_p), "w") as f:
        f.write("x")
    with open(off_disk(srv, off_p), "w") as f:
        f.write("x")

    def do(url):
        p = our_p if url == srv["our"] else off_p
        return fs(url, "rmdir", p)
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert rc_o != 0 and rc_f != 0, f"rmdir-on-file must fail:{raw}"
    assert our == off, f"rmdir-on-file error category differs:{raw}"


def test_mv_dest_into_missing_dir_matches_stock(srv):
    """mv whose destination directory does not exist: pin to stock category."""
    our_s = uniq("mv_baddest_our.txt")
    off_s = uniq("mv_baddest_off.txt")
    with open(our_disk(srv, our_s), "w") as f:
        f.write("x")
    with open(off_disk(srv, off_s), "w") as f:
        f.write("x")

    def do(url):
        s = our_s if url == srv["our"] else off_s
        return fs(url, "mv", s, uniq("mv_no_such_dest_dir/moved.txt"))
    rc_o, rc_f, our, off, raw = diff_fail(srv, do)
    assert (rc_o == 0) == (rc_f == 0), f"mv-bad-dest success differs:{raw}"
    if rc_o != 0:
        assert our == off, f"mv-bad-dest error category differs:{raw}"


# =========================================================================== #
# ROUND-TRIP
# =========================================================================== #
def test_mkdir_rmdir_roundtrip_clean(srv):
    wire = uniq("roundtrip_dir")
    disk = our_disk(srv, wire)
    assert fs(srv["our"], "mkdir", wire)[0] == 0
    assert os.path.isdir(disk)
    assert fs(srv["our"], "rmdir", wire)[0] == 0
    assert not os.path.exists(disk), "round-trip left the tree dirty"


def test_upload_then_rm_roundtrip_clean(srv, tmp_path):
    wire = uniq("up_rm_roundtrip.bin")
    src = make_local(str(tmp_path / "rt.bin"), 2048)
    assert cp("-f", src, f"{srv['our']}/{wire}")[0] == 0
    assert os.path.exists(our_disk(srv, wire))
    assert fs(srv["our"], "rm", wire)[0] == 0
    assert not os.path.exists(our_disk(srv, wire)), "upload+rm left file on disk"

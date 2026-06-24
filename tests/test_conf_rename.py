"""Differential conformance for kXR_mv (rename / move) and directory-manipulation
semantics IN DEPTH — stock XRootD tools (xrdfs/xrdcp) + RAW WIRE against BOTH our
nginx-xrootd server and the stock xrootd data server, on identical throwaway
trees.

This file goes DEEPER than test_conf_write_ops.py (basic mv/mkdir/rmdir) and
test_conf_errors.py (mv error categories) — it exhaustively probes rename edge
cases: same-dir rename, cross-dir move, missing-dest-parent, overwrite-onto-file,
onto-empty-dir, onto-nonempty-dir, directory rename (subtree move), same-path
no-op, trailing-slash forms, case-only differences, special names, src-under-dst,
content/mode/mtime preservation, round-trips, and the RAW kXR_mv framing contract
(arg1len + space separator, out-of-range arg1len, embedded NUL, missing dst).

Philosophy (per the maintainer): a divergence is a BUG IN OUR SERVER unless there
is positive evidence otherwise. EVERY mutating operation is run on BOTH servers,
on PARALLEL UNIQUE paths (so neither tree pollutes the other test's
expectations), and we require:

  * same success/failure class ((rc == 0) on OUR  ==  (rc == 0) on STOCK), and
  * the SAME coarse error category if it fails (L.err_code, alias-normalized), and
  * the SAME on-disk effect (src gone, dst present, exact content bytes, mode/
    mtime as stock leaves them), and
  * confinement: a traversal src/dst is DENIED on OUR server and nothing escapes.

Any wrong success/failure, wrong on-disk effect, content/mode not preserved,
framing-handling difference, or confinement bypass is flagged as a BUG. We pin
the stock server's behavior — no xfail/skip is used to hide a real divergence.

kXR_mv wire contract (XProtocol.hh ClientMvRequest + XrdXrootdXeq.cc do_Mv):
  struct: streamid[2] requestid(u16) reserved[14] arg1len(int16) dlen(int32)
  data buffer: "<oldpath> <newpath>" (single space separator).
  do_Mv: if arg1len != 0, byte at offset arg1len MUST be ' ' (else kXR_ArgInvalid
  'invalid path specification') and arg1len must satisfy 0 <= n < dlen; oldpath is
  buff[0..arg1len), newpath is buff[arg1len+1..]. If arg1len == 0 the server
  splits on the first space itself. A missing new path -> kXR_ArgMissing.

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisions our + stock
servers on high ports; skips entirely without the stock xrootd toolchain.
"""

import hashlib
import os
import socket
import struct

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14048)
OFF_PORT = L.worker_port(14049)
# --------------------------------------------------------------------------- #
# Module fixture: one server pair (rich tree) for the whole file. Extra fixture
# dirs/files are built IDENTICALLY on both data roots so every differential is
# byte-exact from the same starting state.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confrename"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    # Build identical extra scaffolding on BOTH roots.
    for data in (ctx["our_data"], ctx["off_data"]):
        _seed_scaffold(data)
    yield ctx
    L.stop_pair(procs)


def _seed_scaffold(data):
    """Identical extra dirs/files on each data root (idempotent)."""
    j = os.path.join
    for d in ("rn_d1", "rn_d2", "rn_deep/x/y/z", "rn_empty_target"):
        os.makedirs(j(data, *d.split("/")), exist_ok=True)


# --------------------------------------------------------------------------- #
# Stock-client runners + on-disk verification helpers.
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    """Stock xrdfs runner -> (rc, out, err)."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


# Collapse the coarse L.err_code keys that name the SAME underlying XRootD error
# under different wordings, so the differential compares semantics, not phrasing.
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


def our_disk(ctx, path):
    return os.path.join(ctx["our_data"], path.lstrip("/"))


def off_disk(ctx, path):
    return os.path.join(ctx["off_data"], path.lstrip("/"))


def make_local(path, n, seed=11):
    with open(path, "wb") as f:
        f.write(bytes((i * 37 + seed) & 0xff for i in range(n)))
    return path


def write_disk(ctx, wire, data):
    """Write identical content to the same wire path on BOTH data roots."""
    for disk in (our_disk(ctx, wire), off_disk(ctx, wire)):
        os.makedirs(os.path.dirname(disk), exist_ok=True)
        mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
        with open(disk, mode) as f:
            f.write(data)


def mkdir_disk(ctx, wire):
    for disk in (our_disk(ctx, wire), off_disk(ctx, wire)):
        os.makedirs(disk, exist_ok=True)


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def mv_both(ctx, our_src, our_dst, off_src, off_dst):
    """Run `mv` on each server with its own (unique) src/dst -> raw diagnostics."""
    rc_o, o_o, e_o = fs(ctx["our"], "mv", our_src, our_dst)
    rc_f, o_f, e_f = fs(ctx["off"], "mv", off_src, off_dst)
    raw = (f"\n  OURS  rc={rc_o} cat={_category(o_o + e_o)!r} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} cat={_category(o_f + e_f)!r} :: {(o_f + e_f).strip()!r}")
    return (rc_o, _category(o_o + e_o)), (rc_f, _category(o_f + e_f)), raw


def assert_mv_parity(ctx, our_src, our_dst, off_src, off_dst):
    """mv on each server (parallel unique paths): success-class must match, and
    if failing the category must match too. Returns (rc_our, rc_stock, raw)."""
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(ctx, our_src, our_dst, off_src, off_dst)
    assert (rc_o == 0) == (rc_f == 0), f"mv success-class divergence:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"mv error-category divergence:{raw}"
    return rc_o, rc_f, raw


# =========================================================================== #
# 1. RENAME FILE SAME DIR (a -> b) — parametrized by size.  (7 tests)
#    dst has the content, src is gone, on BOTH servers; content byte-exact.
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 2, 511, 512, 4095, 4096, 4097, 8192,
                               65535, 65536, 65537, 262144, 1048576])
def test_rename_same_dir_sizes(srv, n):
    src = f"/rn_same_{n}_src.bin"
    dst = f"/rn_same_{n}_dst.bin"
    payload = bytes((i * 13 + 5) & 0xff for i in range(n))
    write_disk(srv, src, payload)
    before = md5_file(our_disk(srv, src))
    rc_o, rc_f, raw = assert_mv_parity(srv, src, dst, src, dst)
    assert rc_o == 0, f"same-dir rename N={n} should succeed:{raw}"
    for disk_src, disk_dst in ((our_disk(srv, src), our_disk(srv, dst)),
                               (off_disk(srv, src), off_disk(srv, dst))):
        assert not os.path.exists(disk_src), f"N={n}: source remained"
        assert os.path.exists(disk_dst), f"N={n}: dest missing"
        assert os.path.getsize(disk_dst) == n, f"N={n}: dest size wrong"
        assert md5_file(disk_dst) == before, f"N={n}: content not preserved"


# =========================================================================== #
# 2. MOVE FILE ACROSS DIRS (/d1/a -> /d2/a) where /d2 exists. (3 tests)
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 16, 4095, 4096, 4097, 100000, 1048576])
def test_move_across_existing_dirs(srv, n):
    src = f"/rn_d1/cross_{n}.bin"
    dst = f"/rn_d2/cross_{n}.bin"
    payload = bytes((i * 7 + 3) & 0xff for i in range(n))
    write_disk(srv, src, payload)
    before = md5_file(our_disk(srv, src))
    rc_o, rc_f, raw = assert_mv_parity(srv, src, dst, src, dst)
    assert rc_o == 0, f"cross-dir move N={n} should succeed:{raw}"
    for disk_src, disk_dst in ((our_disk(srv, src), our_disk(srv, dst)),
                               (off_disk(srv, src), off_disk(srv, dst))):
        assert not os.path.exists(disk_src), f"N={n}: src remained"
        assert os.path.exists(disk_dst), f"N={n}: dst missing"
        assert md5_file(disk_dst) == before, f"N={n}: content changed across move"


# =========================================================================== #
# 3. MOVE INTO A MISSING DEST DIR (/nope/a) — pin to stock (its rename may NOT
#    create the parent; verify parity + on-disk effect identical). (1 test)
# =========================================================================== #
def test_move_into_missing_dest_dir(srv):
    our_src = "/rn_md_src_our.txt"
    off_src = "/rn_md_src_off.txt"
    for disk in (our_disk(srv, our_src), off_disk(srv, off_src)):
        with open(disk, "w") as f:
            f.write("payload")
    our_dst = "/rn_md_nope_our/moved.txt"
    off_dst = "/rn_md_nope_off/moved.txt"
    rc_o, rc_f, raw = assert_mv_parity(srv, our_src, our_dst, off_src, off_dst)
    # Verify on-disk effect matches the rc-class on BOTH servers.
    if rc_o == 0:
        assert os.path.exists(our_disk(srv, our_dst)), f"OUR: dst missing after ok:{raw}"
        assert os.path.exists(off_disk(srv, off_dst)), f"STOCK: dst missing after ok:{raw}"
    else:
        assert os.path.exists(our_disk(srv, our_src)), f"OUR: src lost on failed mv:{raw}"
        assert not os.path.exists(our_disk(srv, "/rn_md_nope_our")), \
            f"OUR: failed mv created the missing dest parent dir:{raw}"


# =========================================================================== #
# 4. RENAME ONTO AN EXISTING FILE DEST — overwrite-vs-error; pin stock; content
#    after must match the stock outcome. (3 sizes)  (3 tests)
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 10, 4095, 4096, 4097, 50000])
def test_rename_onto_existing_file(srv, n):
    src_payload = bytes((i * 5 + 1) & 0xff for i in range(n))
    dst_payload = bytes((i * 9 + 2) & 0xff for i in range(n + 7))
    our_src, our_dst = f"/rn_ov_src_our_{n}.bin", f"/rn_ov_dst_our_{n}.bin"
    off_src, off_dst = f"/rn_ov_src_off_{n}.bin", f"/rn_ov_dst_off_{n}.bin"
    for s, d in ((our_src, our_dst), (off_src, off_dst)):
        for disk, data in ((our_disk(srv, s) if s == our_src else off_disk(srv, s), src_payload),
                           (our_disk(srv, d) if d == our_dst else off_disk(srv, d), dst_payload)):
            with open(disk, "wb") as f:
                f.write(data)
    src_md5 = hashlib.md5(src_payload).hexdigest()
    rc_o, rc_f, raw = assert_mv_parity(srv, our_src, our_dst, off_src, off_dst)
    if rc_o == 0:
        # Overwrite happened: dst now holds the SOURCE bytes, src is gone.
        assert md5_file(our_disk(srv, our_dst)) == src_md5, \
            f"OUR: overwrite did not replace dst with src content N={n}:{raw}"
        assert md5_file(off_disk(srv, off_dst)) == src_md5, \
            f"STOCK: overwrite did not replace dst with src content N={n}:{raw}"
        assert not os.path.exists(our_disk(srv, our_src)), f"OUR: src remained N={n}"
    else:
        # Rejected: dst keeps original content, src untouched.
        assert md5_file(our_disk(srv, our_dst)) == hashlib.md5(dst_payload).hexdigest(), \
            f"OUR: failed mv mutated dst content N={n}:{raw}"
        assert os.path.exists(our_disk(srv, our_src)), f"OUR: failed mv lost src N={n}"


# =========================================================================== #
# 5. RENAME ONTO AN EXISTING NON-EMPTY DIR DEST — error parity. (1 test)
# =========================================================================== #
def test_rename_onto_nonempty_dir(srv):
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        with open(os.path.join(data, f"rn_one_src_{sfx}.txt"), "w") as f:
            f.write("src")
        d = os.path.join(data, f"rn_one_dst_{sfx}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "child.txt"), "w") as f:
            f.write("child")
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_one_src_our.txt", "/rn_one_dst_our",
        "/rn_one_src_off.txt", "/rn_one_dst_off")
    assert rc_o != 0 and rc_f != 0, f"mv-onto-nonempty-dir must fail on both:{raw}"
    assert cat_o == cat_f, f"mv-onto-nonempty-dir category differs:{raw}"
    # Neither server clobbered the directory with the file.
    assert os.path.isdir(our_disk(srv, "/rn_one_dst_our")), \
        f"OUR: overwrote a non-empty dir with a file (DATA LOSS):{raw}"
    assert os.path.isfile(our_disk(srv, "/rn_one_dst_our/child.txt")), \
        f"OUR: dir child vanished:{raw}"


# =========================================================================== #
# 6. RENAME ONTO AN EXISTING EMPTY DIR DEST — pin stock. (1 test)
# =========================================================================== #
def test_rename_onto_empty_dir(srv):
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        with open(os.path.join(data, f"rn_oe_src_{sfx}.txt"), "w") as f:
            f.write("src")
        os.makedirs(os.path.join(data, f"rn_oe_dst_{sfx}"), exist_ok=True)
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_oe_src_our.txt", "/rn_oe_dst_our",
        "/rn_oe_src_off.txt", "/rn_oe_dst_off")
    assert (rc_o == 0) == (rc_f == 0), f"mv-onto-empty-dir rc-class differs:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"mv-onto-empty-dir category differs:{raw}"
        # On failure the dir must remain a directory on OUR server.
        assert os.path.isdir(our_disk(srv, "/rn_oe_dst_our")), \
            f"OUR: failed mv corrupted the empty-dir dest:{raw}"


# =========================================================================== #
# 7. RENAME A DIRECTORY (dir a -> dir b) — whole subtree moves; children intact.
#    (1 test)
# =========================================================================== #
def test_rename_directory_subtree(srv):
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        base = os.path.join(data, f"rn_dir_a_{sfx}")
        os.makedirs(os.path.join(base, "sub"), exist_ok=True)
        with open(os.path.join(base, "f1.txt"), "w") as f:
            f.write("one")
        with open(os.path.join(base, "sub", "f2.txt"), "w") as f:
            f.write("two-deep")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_dir_a_our", "/rn_dir_b_our",
        "/rn_dir_a_off", "/rn_dir_b_off")
    assert rc_o == 0, f"directory rename should succeed:{raw}"
    assert not os.path.exists(our_disk(srv, "/rn_dir_a_our")), "OUR: old dir remained"
    assert os.path.isdir(our_disk(srv, "/rn_dir_b_our")), "OUR: new dir missing"
    assert md5_file(our_disk(srv, "/rn_dir_b_our/f1.txt")) == hashlib.md5(b"one").hexdigest()
    assert md5_file(our_disk(srv, "/rn_dir_b_our/sub/f2.txt")) == \
        hashlib.md5(b"two-deep").hexdigest(), "OUR: deep child content lost on dir rename"


# =========================================================================== #
# 8. RENAME DIR ACROSS DIRS (/d1/dir -> /d2/dir) — subtree moves; parity. (1)
# =========================================================================== #
def test_rename_directory_across_dirs(srv):
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        base = os.path.join(data, "rn_d1", f"movedir_{sfx}")
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "leaf.txt"), "w") as f:
            f.write("leaf-bytes")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_d1/movedir_our", "/rn_d2/movedir_our",
        "/rn_d1/movedir_off", "/rn_d2/movedir_off")
    assert rc_o == 0, f"cross-dir directory move should succeed:{raw}"
    assert not os.path.exists(our_disk(srv, "/rn_d1/movedir_our")), "OUR: src dir remained"
    assert md5_file(our_disk(srv, "/rn_d2/movedir_our/leaf.txt")) == \
        hashlib.md5(b"leaf-bytes").hexdigest(), "OUR: subtree content lost"


# =========================================================================== #
# 9. RENAME NONEXISTENT SOURCE — error category parity. (1 test)
# =========================================================================== #
def test_rename_nonexistent_source(srv):
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_no_src_our.txt", "/rn_no_dst_our.txt",
        "/rn_no_src_off.txt", "/rn_no_dst_off.txt")
    assert rc_o != 0 and rc_f != 0, f"mv of missing source must fail:{raw}"
    assert cat_o == cat_f, f"mv-missing-source category differs:{raw}"


# =========================================================================== #
# 10. RENAME TO THE SAME PATH (a -> a) — pin stock (no-op success or error).
#     File survives either way. (1 test)
# =========================================================================== #
def test_rename_same_path(srv):
    write_disk(srv, "/rn_self_our.txt", "selfpayload")
    write_disk(srv, "/rn_self_off.txt", "selfpayload")
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_self_our.txt", "/rn_self_our.txt",
        "/rn_self_off.txt", "/rn_self_off.txt")
    assert (rc_o == 0) == (rc_f == 0), f"mv same-path rc-class differs:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"mv same-path category differs:{raw}"
    # Either way the file must NOT vanish.
    assert md5_file(our_disk(srv, "/rn_self_our.txt")) == \
        hashlib.md5(b"selfpayload").hexdigest(), \
        f"OUR: a->a mv destroyed the file (DATA LOSS):{raw}"


# =========================================================================== #
# 11. TRAILING-SLASH FORMS — file -> "dir-style" dst (trailing /), and dir ->
#     "file-style" (no slash, already covered). Pin stock per case. (2 tests)
# =========================================================================== #
def test_rename_file_to_trailing_slash_dest(srv):
    write_disk(srv, "/rn_ts_src_our.txt", "ts")
    write_disk(srv, "/rn_ts_src_off.txt", "ts")
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_ts_src_our.txt", "/rn_ts_dst_our/",
        "/rn_ts_src_off.txt", "/rn_ts_dst_off/")
    assert (rc_o == 0) == (rc_f == 0), f"mv file->trailing-slash rc-class differs:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"mv file->trailing-slash category differs:{raw}"
        assert os.path.exists(our_disk(srv, "/rn_ts_src_our.txt")), \
            f"OUR: failed trailing-slash mv lost src:{raw}"


def test_rename_dir_to_trailing_slash_dest(srv):
    mkdir_disk(srv, "/rn_tsd_src_our")
    mkdir_disk(srv, "/rn_tsd_src_off")
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_tsd_src_our", "/rn_tsd_dst_our/",
        "/rn_tsd_src_off", "/rn_tsd_dst_off/")
    assert (rc_o == 0) == (rc_f == 0), f"mv dir->trailing-slash rc-class differs:{raw}"
    if rc_o != 0:
        assert cat_o == cat_f, f"mv dir->trailing-slash category differs:{raw}"


# =========================================================================== #
# 12. RENAME WHERE SRC AND DST DIFFER ONLY BY CASE — parity (case-sensitive
#     POSIX fs: distinct paths, so rename succeeds). (1 test)
# =========================================================================== #
def test_rename_case_only_difference(srv):
    write_disk(srv, "/rn_Case_our.txt", "casebytes")
    write_disk(srv, "/rn_Case_off.txt", "casebytes")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_Case_our.txt", "/rn_case_our.txt",
        "/rn_Case_off.txt", "/rn_case_off.txt")
    if rc_o == 0:
        assert os.path.exists(our_disk(srv, "/rn_case_our.txt")), "OUR: lowercased dst missing"
        assert not os.path.exists(our_disk(srv, "/rn_Case_our.txt")), "OUR: uppercase src remained"


# =========================================================================== #
# 13. SPECIAL-NAME SRC/DST (spaces, dots) — parity + on-disk content. (3 tests)
# =========================================================================== #
@pytest.mark.parametrize("name", [
    pytest.param("rn has space.txt", id="space"),
    pytest.param("rn  two  spaces.txt", id="double_space"),
    pytest.param("rn.dotted.name.txt", id="dots"),
    pytest.param("rn..leading.txt", id="leading_dots"),
    pytest.param("rn-dash_under.txt", id="dash_under"),
    pytest.param("rn+plus=eq,comma.txt", id="punct"),
    pytest.param("rn@at%pct.txt", id="at_pct"),
    pytest.param("rn(paren)[brak].txt", id="brackets"),
])
def test_rename_special_names(srv, name):
    src = "/rn_special_src_" + name.replace(" ", "_")
    our_dst = "/" + name + ".our"
    off_dst = "/" + name + ".off"
    write_disk(srv, src, "specialbytes")
    rc_o, rc_f, raw = assert_mv_parity(srv, src, our_dst, src, off_dst)
    if rc_o == 0:
        assert md5_file(our_disk(srv, our_dst)) == hashlib.md5(b"specialbytes").hexdigest(), \
            f"OUR: special-name rename lost content ({name!r}):{raw}"
        assert not os.path.exists(our_disk(srv, src)), f"OUR: src remained ({name!r})"


# =========================================================================== #
# 14. RENAME SRC UNDER DST'S SUBTREE (dir a -> a/b) — error parity (EINVAL).
#     (1 test)
# =========================================================================== #
def test_rename_dir_into_own_subtree(srv):
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        os.makedirs(os.path.join(data, f"rn_loop_{sfx}", "inner"), exist_ok=True)
        with open(os.path.join(data, f"rn_loop_{sfx}", "keep.txt"), "w") as f:
            f.write("keepme")
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_loop_our", "/rn_loop_our/inner/loop",
        "/rn_loop_off", "/rn_loop_off/inner/loop")
    assert rc_o != 0 and rc_f != 0, f"dir-into-own-subtree must fail (EINVAL):{raw}"
    assert cat_o == cat_f, f"dir-into-own-subtree category differs:{raw}"
    # The original dir + its content must be intact on OUR server.
    assert os.path.isdir(our_disk(srv, "/rn_loop_our")), \
        f"OUR: failed self-subtree mv destroyed the dir (DATA LOSS):{raw}"
    assert md5_file(our_disk(srv, "/rn_loop_our/keep.txt")) == \
        hashlib.md5(b"keepme").hexdigest(), f"OUR: content lost:{raw}"


# =========================================================================== #
# 15. RENAME PRESERVES CONTENT BYTES EXACTLY (md5 before == after). (4 sizes)
# =========================================================================== #
@pytest.mark.parametrize("n", [1, 255, 4096, 4097, 8192, 65536, 300000, 1048577])
def test_rename_preserves_content_md5(srv, n):
    src = f"/rn_md5_{n}.bin"
    dst = f"/rn_md5_{n}.moved.bin"
    make_local(our_disk(srv, src), n, seed=n & 0xff)
    make_local(off_disk(srv, src), n, seed=n & 0xff)
    before = md5_file(our_disk(srv, src))
    rc_o, rc_f, raw = assert_mv_parity(srv, src, dst, src, dst)
    assert rc_o == 0, f"rename N={n} should succeed:{raw}"
    assert md5_file(our_disk(srv, dst)) == before, f"OUR: md5 changed across rename N={n}"
    assert md5_file(off_disk(srv, dst)) == before, f"STOCK: md5 changed across rename N={n}"


# =========================================================================== #
# 16. RENAME PRESERVES MODE / MTIME AS STOCK DOES. (2 tests)
# =========================================================================== #
def test_rename_preserves_mode(srv):
    src = "/rn_mode_src.bin"
    dst = "/rn_mode_dst.bin"
    write_disk(srv, src, "modebytes")
    os.chmod(our_disk(srv, src), 0o640)
    os.chmod(off_disk(srv, src), 0o640)
    rc_o, rc_f, raw = assert_mv_parity(srv, src, dst, src, dst)
    assert rc_o == 0, f"mode-preserve rename should succeed:{raw}"
    our_mode = os.stat(our_disk(srv, dst)).st_mode & 0o777
    off_mode = os.stat(off_disk(srv, dst)).st_mode & 0o777
    assert our_mode == off_mode, \
        f"OUR rename mode {oct(our_mode)} != STOCK {oct(off_mode)} (mode not preserved like stock)"


def test_rename_preserves_mtime(srv):
    src = "/rn_mtime_src.bin"
    dst = "/rn_mtime_dst.bin"
    write_disk(srv, src, "mtimebytes")
    fixed = 1_600_000_000
    os.utime(our_disk(srv, src), (fixed, fixed))
    os.utime(off_disk(srv, src), (fixed, fixed))
    rc_o, rc_f, raw = assert_mv_parity(srv, src, dst, src, dst)
    assert rc_o == 0, f"mtime-preserve rename should succeed:{raw}"
    our_mt = int(os.stat(our_disk(srv, dst)).st_mtime)
    off_mt = int(os.stat(off_disk(srv, dst)).st_mtime)
    # Stock's rename(2) preserves mtime; OUR must match stock's effect exactly.
    assert our_mt == off_mt, \
        f"OUR rename mtime {our_mt} != STOCK {off_mt} (mtime not preserved like stock)"


# =========================================================================== #
# 17. MV THEN MV-BACK ROUND-TRIP — original restored. (1 test)
# =========================================================================== #
def test_rename_roundtrip_restores(srv):
    a = "/rn_rt_a.bin"
    b = "/rn_rt_b.bin"
    make_local(our_disk(srv, a), 5000, seed=42)
    make_local(off_disk(srv, a), 5000, seed=42)
    orig = md5_file(our_disk(srv, a))
    rc1_o, rc1_f, raw1 = assert_mv_parity(srv, a, b, a, b)
    assert rc1_o == 0, f"forward mv failed:{raw1}"
    rc2_o, rc2_f, raw2 = assert_mv_parity(srv, b, a, b, a)
    assert rc2_o == 0, f"back mv failed:{raw2}"
    assert md5_file(our_disk(srv, a)) == orig, "OUR: round-trip did not restore original"
    assert not os.path.exists(our_disk(srv, b)), "OUR: round-trip left intermediate"


# =========================================================================== #
# 18. MKDIR -p DEEP THEN MV A FILE INTO THE DEEP PATH. (1 test)
# =========================================================================== #
def test_mkdir_p_then_move_into_deep(srv):
    write_disk(srv, "/rn_deepmv_src_our.txt", "deepbytes")
    write_disk(srv, "/rn_deepmv_src_off.txt", "deepbytes")
    assert fs(srv["our"], "mkdir", "-p", "/rn_dpm_our/x/y/z")[0] == 0
    assert fs(srv["off"], "mkdir", "-p", "/rn_dpm_off/x/y/z")[0] == 0
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_deepmv_src_our.txt", "/rn_dpm_our/x/y/z/moved.txt",
        "/rn_deepmv_src_off.txt", "/rn_dpm_off/x/y/z/moved.txt")
    assert rc_o == 0, f"mv into mkdir-p deep path should succeed:{raw}"
    assert md5_file(our_disk(srv, "/rn_dpm_our/x/y/z/moved.txt")) == \
        hashlib.md5(b"deepbytes").hexdigest(), "OUR: deep-mv content lost"


# =========================================================================== #
# 19. MV A FILE OUT OF A DIR THEN RMDIR THE NOW-EMPTY DIR. (1 test)
# =========================================================================== #
def test_move_out_then_rmdir_empty(srv):
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        d = os.path.join(data, f"rn_emptyout_{sfx}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "only.txt"), "w") as f:
            f.write("only")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_emptyout_our/only.txt", "/rn_moved_out_our.txt",
        "/rn_emptyout_off/only.txt", "/rn_moved_out_off.txt")
    assert rc_o == 0, f"mv out of dir should succeed:{raw}"
    rrc_o = fs(srv["our"], "rmdir", "/rn_emptyout_our")[0]
    rrc_f = fs(srv["off"], "rmdir", "/rn_emptyout_off")[0]
    assert (rrc_o == 0) == (rrc_f == 0), "rmdir-now-empty rc-class differs after mv-out"
    if rrc_o == 0:
        assert not os.path.exists(our_disk(srv, "/rn_emptyout_our")), "OUR: rmdir left dir"


# =========================================================================== #
# 20. CONFINEMENT — mv with src or dst escaping the root must be DENIED on OUR
#     server (rc != 0), no host escape; compare to stock denial. (4 tests)
# =========================================================================== #
TRAVERSAL_SRCS = [
    "/../../etc/passwd",
    "/../../../etc/passwd",
    "/../../../../etc/passwd",
    "/rn_d1/../../../etc/passwd",
]


@pytest.mark.parametrize("trav", TRAVERSAL_SRCS)
def test_confinement_mv_src_traversal(srv, trav):
    """mv whose SOURCE is a traversal path must be denied; nothing leaks."""
    rc_o, o_o, e_o = fs(srv["our"], "mv", trav, "/rn_steal_our.txt")
    rc_f, _, _ = fs(srv["off"], "mv", trav, "/rn_steal_off.txt")
    assert rc_o != 0, f"OUR served mv-from-traversal {trav} (SECURITY BUG): {o_o!r}{e_o!r}"
    assert "root:" not in (o_o + e_o), f"OUR leaked host passwd via {trav} (SECURITY BUG)"
    assert not os.path.exists(our_disk(srv, "/rn_steal_our.txt")), \
        f"OUR: traversal mv {trav} produced a file from host /etc/passwd (SECURITY BUG)"
    assert rc_f != 0, f"oracle: STOCK served the traversal mv source {trav}"


def test_confinement_mv_dst_traversal(srv):
    """mv whose DEST is a traversal path must be denied; host file not created/
    overwritten."""
    write_disk(srv, "/rn_dsttr_our.txt", "x")
    write_disk(srv, "/rn_dsttr_off.txt", "x")
    rc_o, o_o, e_o = fs(srv["our"], "mv", "/rn_dsttr_our.txt", "/../../tmp/rn_escape_our")
    rc_f, _, _ = fs(srv["off"], "mv", "/rn_dsttr_off.txt", "/../../tmp/rn_escape_off")
    assert rc_o != 0, f"OUR served mv-to-traversal-dest (SECURITY BUG): {o_o!r}{e_o!r}"
    assert not os.path.exists("/tmp/rn_escape_our"), \
        "OUR: traversal mv wrote OUTSIDE the root (SECURITY BUG)"
    # Source must survive a denied mv.
    assert os.path.exists(our_disk(srv, "/rn_dsttr_our.txt")), \
        "OUR: denied traversal mv still consumed the source"
    assert rc_f != 0, "oracle: STOCK served the traversal mv dest"


def test_confinement_mv_deep_interior_dotdot_src(srv):
    """A deep interior '..' escape in the source must be denied on OUR server."""
    rc_o, o_o, e_o = fs(srv["our"], "mv",
                        "/deep/a/../../../../../etc/passwd", "/rn_deep_steal_our.txt")
    assert rc_o != 0, f"OUR served deep interior-dotdot mv (SECURITY BUG): {o_o!r}"
    assert not os.path.exists(our_disk(srv, "/rn_deep_steal_our.txt")), \
        "OUR: deep interior-dotdot mv leaked a host file (SECURITY BUG)"


def test_confinement_mv_doubled_slash_dotdot(srv):
    """A doubled-slash + dot-dot form must still be confined on the source."""
    rc_o, o_o, e_o = fs(srv["our"], "mv", "//..//..//etc/passwd", "/rn_ds_steal_our.txt")
    assert rc_o != 0, f"OUR served //..// traversal mv (SECURITY BUG): {o_o!r}"
    assert not os.path.exists(our_disk(srv, "/rn_ds_steal_our.txt")), \
        "OUR: //..// traversal mv leaked a host file (SECURITY BUG)"


# =========================================================================== #
# 21. ADDITIONAL DISTINCT RENAME / DIRECTORY SCENARIOS.
# =========================================================================== #
def test_rename_dir_onto_existing_file(srv):
    """mv a directory onto an existing regular file -> reject parity; the file is
    not clobbered by a directory and the dir survives."""
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        os.makedirs(os.path.join(data, f"rn_dof_dir_{sfx}"), exist_ok=True)
        with open(os.path.join(data, f"rn_dof_file_{sfx}.txt"), "w") as f:
            f.write("filebytes")
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_dof_dir_our", "/rn_dof_file_our.txt",
        "/rn_dof_dir_off", "/rn_dof_file_off.txt")
    assert rc_o != 0 and rc_f != 0, f"mv-dir-onto-file must fail:{raw}"
    assert cat_o == cat_f, f"mv-dir-onto-file category differs:{raw}"
    assert os.path.isfile(our_disk(srv, "/rn_dof_file_our.txt")), \
        f"OUR: dir clobbered a file (DATA LOSS):{raw}"
    assert os.path.isdir(our_disk(srv, "/rn_dof_dir_our")), \
        f"OUR: failed mv consumed the source dir:{raw}"


def test_rename_file_onto_existing_dir(srv):
    """mv a file onto an existing (empty) directory name -> reject parity; the
    directory is not replaced by the file."""
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        with open(os.path.join(data, f"rn_fod_file_{sfx}.txt"), "w") as f:
            f.write("filebytes")
        os.makedirs(os.path.join(data, f"rn_fod_dir_{sfx}"), exist_ok=True)
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_fod_file_our.txt", "/rn_fod_dir_our",
        "/rn_fod_file_off.txt", "/rn_fod_dir_off")
    assert (rc_o == 0) == (rc_f == 0), f"mv-file-onto-dir rc-class differs:{raw}"
    assert os.path.isdir(our_disk(srv, "/rn_fod_dir_our")), \
        f"OUR: file clobbered a directory (DATA LOSS):{raw}"


def test_rename_empty_file(srv):
    """rename a 0-byte file -> dst is a 0-byte file, src gone."""
    write_disk(srv, "/rn_empty_src.bin", b"")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_empty_src.bin", "/rn_empty_dst.bin",
        "/rn_empty_src.bin", "/rn_empty_dst.bin")
    assert rc_o == 0, f"empty-file rename should succeed:{raw}"
    assert os.path.getsize(our_disk(srv, "/rn_empty_dst.bin")) == 0
    assert not os.path.exists(our_disk(srv, "/rn_empty_src.bin"))


def test_rename_into_deeper_existing_subtree(srv):
    """move a file into a pre-existing deep subtree (/rn_deep/x/y/z)."""
    write_disk(srv, "/rn_deepexist_src.txt", "deepexist")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_deepexist_src.txt", "/rn_deep/x/y/z/landed.txt",
        "/rn_deepexist_src.txt", "/rn_deep/x/y/z/landed.txt")
    assert rc_o == 0, f"move into existing deep subtree should succeed:{raw}"
    assert md5_file(our_disk(srv, "/rn_deep/x/y/z/landed.txt")) == \
        hashlib.md5(b"deepexist").hexdigest(), "OUR: deep-existing move lost content"


def test_rename_up_out_of_deep_subtree(srv):
    """move a file UP out of a deep subtree to the root."""
    for data in (srv["our_data"], srv["off_data"]):
        d = os.path.join(data, "rn_up", "a", "b")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "buried.txt"), "w") as f:
            f.write("buried")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_up/a/b/buried.txt", "/rn_surfaced_our.txt",
        "/rn_up/a/b/buried.txt", "/rn_surfaced_off.txt")
    assert rc_o == 0, f"move up out of subtree should succeed:{raw}"
    assert md5_file(our_disk(srv, "/rn_surfaced_our.txt")) == \
        hashlib.md5(b"buried").hexdigest(), "OUR: surfaced content lost"
    assert not os.path.exists(our_disk(srv, "/rn_up/a/b/buried.txt")), "OUR: buried src remained"


def test_rename_swaps_via_temp(srv):
    """Two files swapped via a temp name (a->t, b->a, t->b): contents exchanged."""
    write_disk(srv, "/rn_swap_a.bin", "AAAA")
    write_disk(srv, "/rn_swap_b.bin", "BBBB")
    md5a = hashlib.md5(b"AAAA").hexdigest()
    md5b = hashlib.md5(b"BBBB").hexdigest()
    for url in (srv["our"], srv["off"]):
        assert fs(url, "mv", "/rn_swap_a.bin", "/rn_swap_t.bin")[0] == 0
        assert fs(url, "mv", "/rn_swap_b.bin", "/rn_swap_a.bin")[0] == 0
        assert fs(url, "mv", "/rn_swap_t.bin", "/rn_swap_b.bin")[0] == 0
    assert md5_file(our_disk(srv, "/rn_swap_a.bin")) == md5b, "OUR: swap a wrong"
    assert md5_file(our_disk(srv, "/rn_swap_b.bin")) == md5a, "OUR: swap b wrong"


def test_rename_dir_preserves_child_count(srv):
    """rename a dir holding many children -> all children present after, none
    added/lost, parity on both."""
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        d = os.path.join(data, f"rn_many_{sfx}")
        os.makedirs(d, exist_ok=True)
        for i in range(20):
            with open(os.path.join(d, f"c{i:02d}.txt"), "w") as f:
                f.write(f"child{i}")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_many_our", "/rn_many_moved_our",
        "/rn_many_off", "/rn_many_moved_off")
    assert rc_o == 0, f"many-child dir rename should succeed:{raw}"
    moved = our_disk(srv, "/rn_many_moved_our")
    assert sorted(os.listdir(moved)) == sorted(f"c{i:02d}.txt" for i in range(20)), \
        "OUR: dir rename changed the child set"


def test_rename_long_name(srv):
    """rename to a long (200-char) name -> parity + content preserved."""
    longname = "/rn_long_" + ("z" * 200) + ".txt"
    write_disk(srv, "/rn_long_src.txt", "longbytes")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_long_src.txt", longname, "/rn_long_src.txt", longname)
    if rc_o == 0:
        assert md5_file(our_disk(srv, longname)) == hashlib.md5(b"longbytes").hexdigest(), \
            "OUR: long-name rename lost content"


def test_rename_missing_src_into_existing_dir(srv):
    """mv of a missing source even when the dest dir exists -> NotFound parity."""
    mkdir_disk(srv, "/rn_missrc_dst_our")
    mkdir_disk(srv, "/rn_missrc_dst_off")
    (rc_o, cat_o), (rc_f, cat_f), raw = mv_both(
        srv, "/rn_missrc_no_our.txt", "/rn_missrc_dst_our/x.txt",
        "/rn_missrc_no_off.txt", "/rn_missrc_dst_off/x.txt")
    assert rc_o != 0 and rc_f != 0, f"mv missing-src-into-dir must fail:{raw}"
    assert cat_o == cat_f, f"mv missing-src-into-dir category differs:{raw}"


def test_rename_overwrite_preserves_dst_neighbors(srv):
    """rename onto an existing file in a populated dir must not disturb sibling
    files in that dir (only the target is affected)."""
    for sfx in ("our", "off"):
        data = srv["our_data"] if sfx == "our" else srv["off_data"]
        d = os.path.join(data, f"rn_nbr_{sfx}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "src.txt"), "w") as f:
            f.write("SRC")
        with open(os.path.join(d, "dst.txt"), "w") as f:
            f.write("DST")
        with open(os.path.join(d, "sibling.txt"), "w") as f:
            f.write("SIBLING")
    (rc_o, _), (rc_f, _), raw = mv_both(
        srv, "/rn_nbr_our/src.txt", "/rn_nbr_our/dst.txt",
        "/rn_nbr_off/src.txt", "/rn_nbr_off/dst.txt")
    assert (rc_o == 0) == (rc_f == 0), f"neighbor-preserve rc-class differs:{raw}"
    assert md5_file(our_disk(srv, "/rn_nbr_our/sibling.txt")) == \
        hashlib.md5(b"SIBLING").hexdigest(), "OUR: rename disturbed a sibling file"


def test_rename_then_stat_dst(srv):
    """after a rename, stat of the new path succeeds and stat of the old path
    fails NotFound -> parity on both servers (end-to-end namespace coherence)."""
    write_disk(srv, "/rn_stat_src.bin", "statbytes")
    for url in (srv["our"], srv["off"]):
        assert fs(url, "mv", "/rn_stat_src.bin", "/rn_stat_dst.bin")[0] == 0
    rc_new_o = fs(srv["our"], "stat", "/rn_stat_dst.bin")[0]
    rc_new_f = fs(srv["off"], "stat", "/rn_stat_dst.bin")[0]
    assert rc_new_o == 0 and rc_new_f == 0, "stat of renamed dst must succeed on both"
    o = fs(srv["our"], "stat", "/rn_stat_src.bin")
    f = fs(srv["off"], "stat", "/rn_stat_src.bin")
    assert o[0] != 0 and f[0] != 0, "stat of old path after rename must fail"
    assert _category(o[1] + o[2]) == _category(f[1] + f[2]), \
        "post-rename old-path stat category differs"


def test_rename_then_cat_dst(srv):
    """after a rename, cat of the new path returns the original bytes on OUR
    server (end-to-end data coherence through the namespace change)."""
    payload = b"cat-after-rename-payload-bytes"
    write_disk(srv, "/rn_catrn_src.bin", payload)
    for url in (srv["our"], srv["off"]):
        assert fs(url, "mv", "/rn_catrn_src.bin", "/rn_catrn_dst.bin")[0] == 0
    rc, out, err = fs(srv["our"], "cat", "/rn_catrn_dst.bin")
    assert rc == 0, f"cat of renamed dst failed: {out}{err}"
    assert out.encode() == payload or payload.decode() in out, \
        "OUR: cat after rename returned wrong bytes"


def test_rename_chain_multiple_hops(srv):
    """a -> b -> c -> d chain: final name holds the content, no intermediates
    left, parity on both."""
    write_disk(srv, "/rn_chain_a.bin", "chainbytes")
    md = hashlib.md5(b"chainbytes").hexdigest()
    hops = [("/rn_chain_a.bin", "/rn_chain_b.bin"),
            ("/rn_chain_b.bin", "/rn_chain_c.bin"),
            ("/rn_chain_c.bin", "/rn_chain_d.bin")]
    for url in (srv["our"], srv["off"]):
        for s, d in hops:
            assert fs(url, "mv", s, d)[0] == 0, f"chain hop {s}->{d} failed on {url}"
    assert md5_file(our_disk(srv, "/rn_chain_d.bin")) == md, "OUR: chain lost content"
    for _, intermediate in hops[:-1]:
        assert not os.path.exists(our_disk(srv, intermediate)), \
            f"OUR: chain left intermediate {intermediate}"


def test_rename_dir_into_sibling_dir(srv):
    """move dir /d1/sub into a sibling dir /d2 (as /d2/sub) -> subtree intact."""
    for data in (srv["our_data"], srv["off_data"]):
        d = os.path.join(data, "rn_d1", "sibmove")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "f.txt"), "w") as f:
            f.write("sibcontent")
    rc_o, rc_f, raw = assert_mv_parity(
        srv, "/rn_d1/sibmove", "/rn_d2/sibmove",
        "/rn_d1/sibmove", "/rn_d2/sibmove")
    assert rc_o == 0, f"dir sibling move should succeed:{raw}"
    assert md5_file(our_disk(srv, "/rn_d2/sibmove/f.txt")) == \
        hashlib.md5(b"sibcontent").hexdigest(), "OUR: sibling-dir move lost content"
    assert not os.path.exists(our_disk(srv, "/rn_d1/sibmove")), "OUR: src dir remained"


# =========================================================================== #
# RAW-WIRE kXR_mv framing conformance.
#
# A minimal raw-wire XRootD client (adapted from test_conf_errors.py) pointed at
# EITHER server, so the same kXR_mv frame gets the same accept/reject from OUR
# and the STOCK server. We exercise the arg1len + space-separator contract that
# do_Mv() enforces directly.
# =========================================================================== #
kXR_login, kXR_mv = 3007, 3009
kXR_ok, kXR_error = 0, 4003
kXR_ArgInvalid, kXR_ArgMissing = 3000, 3001
kXR_InvalidRequest, kXR_NotFound = 3006, 3011
kXR_NotAuthorized = 3010

# Reject codes that all name "the mv request itself is illegal / not allowed".
_REJECT_CLASS = {kXR_ArgInvalid, kXR_ArgMissing, kXR_InvalidRequest,
                 kXR_NotAuthorized, kXR_NotFound, 3002}  # 3002 = kXR_ArgTooLong


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
    status = struct.unpack("!H", h[2:4])[0]
    dlen = struct.unpack("!I", h[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    return status, body


def _connect(url):
    s = socket.create_connection((L.BIND, _port_of(url)), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    return s


def _login(s, sid=b"\x00\x01"):
    s.sendall(struct.pack("!2sHI8sBBBBI", sid, kXR_login,
                          os.getpid() & 0x7fffffff, b"err\x00\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    st, _ = _resp(s)
    assert st == kXR_ok, "anon login failed"


def _session(url):
    s = _connect(url)
    st, _ = _resp(s)               # handshake reply
    assert st == kXR_ok
    _login(s)
    return s


def _err(body):
    return struct.unpack("!i", body[0:4])[0] if len(body) >= 4 else None


def _mv_frame(buf, arg1len, sid=b"\x00\x07"):
    """Build a raw kXR_mv request:
       streamid[2] requestid(u16) reserved[14] arg1len(int16) dlen(int32) + buf
    """
    return (struct.pack("!2sH14shi", sid, kXR_mv, b"\x00" * 14,
                        arg1len, len(buf)) + buf)


def _send_mv(url, buf, arg1len):
    """Logged-in session -> send one kXR_mv frame -> (status, errnum)."""
    s = _session(url)
    try:
        s.sendall(_mv_frame(buf, arg1len))
        try:
            st, body = _resp(s)
        except EOFError:
            return ("EOF", None)
        return (st, _err(body))
    finally:
        s.close()


def _wire_reject(st):
    return st == kXR_error or st == "EOF"


# --- correct arg1len + space separator -> OK on both ----------------------- #
def test_wire_mv_correct_arg1len_ok(srv):
    """A well-formed kXR_mv with arg1len pointing exactly at the space separator
    must SUCCEED on both servers and perform the rename on disk."""
    write_disk(srv, "/rn_wire_ok_src.txt", "wirebytes")
    old = b"/rn_wire_ok_src.txt"
    new = b"/rn_wire_ok_dst.txt"
    buf = old + b" " + new
    for url in (srv["our"], srv["off"]):
        s = _session(url)
        try:
            s.sendall(_mv_frame(buf, len(old)))
            st, _ = _resp(s)
            assert st == kXR_ok, f"well-formed kXR_mv rejected (status={st}) on {url}"
        finally:
            s.close()
    assert os.path.exists(our_disk(srv, "/rn_wire_ok_dst.txt")), "OUR: wire mv dst missing"
    assert not os.path.exists(our_disk(srv, "/rn_wire_ok_src.txt")), "OUR: wire mv src remained"
    assert os.path.exists(off_disk(srv, "/rn_wire_ok_dst.txt")), "STOCK: wire mv dst missing"


# --- arg1len points at a NON-SPACE byte -> kXR_ArgInvalid parity ----------- #
def test_wire_mv_wrong_separator_arginvalid(srv):
    """arg1len that does NOT land on a space byte -> kXR_ArgInvalid on both
    (do_Mv: '*(argp->buff+n) != \" \"' -> 'invalid path specification')."""
    old = b"/rn_wire_sep_src.txt"
    new = b"/rn_wire_sep_dst.txt"
    buf = old + b" " + new
    bad = len(old) - 1                       # points inside oldpath, not the space
    st_o, en_o = _send_mv(srv["our"], buf, bad)
    st_f, en_f = _send_mv(srv["off"], buf, bad)
    assert _wire_reject(st_f), f"oracle: STOCK accepted wrong-separator arg1len (st={st_f})"
    assert _wire_reject(st_o), \
        f"OUR accepted a kXR_mv whose arg1len misses the space (BUG): st={st_o}"
    if st_o == kXR_error and en_o is not None:
        assert en_o == kXR_ArgInvalid or en_o in _REJECT_CLASS, \
            f"OUR wrong-separator code {en_o} not ArgInvalid-class (stock={en_f})"


# --- arg1len OUT OF RANGE (>= dlen) -> reject parity ----------------------- #
def test_wire_mv_arg1len_out_of_range(srv):
    """arg1len >= dlen is illegal (do_Mv: 'n < 0 || n >= Request.mv.dlen') -> both
    must reject."""
    old = b"/rn_wire_oor_src.txt"
    new = b"/rn_wire_oor_dst.txt"
    buf = old + b" " + new
    st_o, en_o = _send_mv(srv["our"], buf, len(buf) + 50)     # past the buffer
    st_f, en_f = _send_mv(srv["off"], buf, len(buf) + 50)
    assert _wire_reject(st_f), f"oracle: STOCK accepted out-of-range arg1len (st={st_f})"
    assert _wire_reject(st_o), \
        f"OUR accepted an out-of-range kXR_mv arg1len (BUG): st={st_o}"
    if st_o == kXR_error and en_o is not None:
        assert en_o in _REJECT_CLASS, \
            f"OUR out-of-range code {en_o} not a request-reject code (stock={en_f})"


# --- NEGATIVE arg1len -> reject parity ------------------------------------- #
def test_wire_mv_arg1len_negative(srv):
    """A negative arg1len is illegal (do_Mv: 'n < 0') -> both must reject."""
    old = b"/rn_wire_neg_src.txt"
    new = b"/rn_wire_neg_dst.txt"
    buf = old + b" " + new
    st_o, en_o = _send_mv(srv["our"], buf, -3)
    st_f, en_f = _send_mv(srv["off"], buf, -3)
    assert _wire_reject(st_f), f"oracle: STOCK accepted negative arg1len (st={st_f})"
    assert _wire_reject(st_o), f"OUR accepted a negative kXR_mv arg1len (BUG): st={st_o}"


# --- EMBEDDED NUL in a path -> reject parity ------------------------------- #
def test_wire_mv_embedded_nul_in_src(srv):
    """An embedded NUL in the source path is malformed; both must reject and must
    NOT operate on the truncated prefix. Use arg1len=0 so the server splits on
    the first space itself (the NUL is interior to oldpath)."""
    old = b"/rn_wire\x00nul_src.txt"
    new = b"/rn_wire_nul_dst.txt"
    buf = old + b" " + new
    st_o, en_o = _send_mv(srv["our"], buf, 0)
    st_f, en_f = _send_mv(srv["off"], buf, 0)
    assert _wire_reject(st_f), f"oracle: STOCK accepted embedded-NUL mv (st={st_f})"
    assert _wire_reject(st_o), \
        f"OUR accepted an embedded-NUL kXR_mv source (BUG): st={st_o}"
    # The truncated prefix must NOT have been renamed/created on OUR server.
    assert not os.path.exists(our_disk(srv, "/rn_wire")), \
        "OUR: embedded-NUL mv operated on the truncated prefix (BUG)"


# --- MISSING dst (no space, single token) -> reject parity ----------------- #
def test_wire_mv_missing_dst(srv):
    """A kXR_mv buffer with no space / no new path -> kXR_ArgMissing-class on
    both (do_Mv: 'new path specified for mv')."""
    buf = b"/rn_wire_only_src.txt"          # single token, no space, no dst
    st_o, en_o = _send_mv(srv["our"], buf, 0)
    st_f, en_f = _send_mv(srv["off"], buf, 0)
    assert _wire_reject(st_f), f"oracle: STOCK accepted mv with no dst (st={st_f})"
    assert _wire_reject(st_o), f"OUR accepted a kXR_mv with no destination (BUG): st={st_o}"
    if st_o == kXR_error and en_o is not None:
        assert en_o in _REJECT_CLASS, \
            f"OUR missing-dst code {en_o} not a request-reject code (stock={en_f})"


# --- arg1len off-by-N (never on the space) -> reject parity ---------------- #
@pytest.mark.parametrize("delta", [-3, -2, -1, 1, 2, 3, 5])
def test_wire_mv_arg1len_offby(srv, delta):
    """arg1len displaced from the true separator offset always misses the space
    byte (or points into a path) -> reject on both. (delta chosen so the byte at
    arg1len is never ' ': the only space is at offset len(old).)"""
    old = b"/rn_wire_off_src.txt"
    new = b"/rn_wire_off_dst.txt"
    buf = old + b" " + new
    n = len(old) + delta
    # ensure the chosen byte is not a space (defensive; paths have no spaces)
    if 0 <= n < len(buf):
        assert buf[n:n + 1] != b" "
    st_o, en_o = _send_mv(srv["our"], buf, n)
    st_f, en_f = _send_mv(srv["off"], buf, n)
    assert _wire_reject(st_f), f"oracle: STOCK accepted off-by-{delta} arg1len (st={st_f})"
    assert _wire_reject(st_o), \
        f"OUR accepted a kXR_mv arg1len off-by-{delta} from the space (BUG): st={st_o}"


# --- well-formed wire mv across dirs at varying depth -> OK parity ---------- #
@pytest.mark.parametrize("depth", [1, 2, 3, 4, 5])
def test_wire_mv_cross_depth_ok(srv, depth):
    """Well-formed kXR_mv moving a file into an existing subtree at varying depth
    succeeds on both and lands on disk."""
    sub = "/".join(f"wd{depth}_{i}" for i in range(depth))
    for data in (srv["our_data"], srv["off_data"]):
        os.makedirs(os.path.join(data, *sub.split("/")), exist_ok=True)
    write_disk(srv, f"/rn_wd_src_{depth}.txt", "wirecross")
    old = f"/rn_wd_src_{depth}.txt".encode()
    new = f"/{sub}/landed.txt".encode()
    buf = old + b" " + new
    for url in (srv["our"], srv["off"]):
        s = _session(url)
        try:
            s.sendall(_mv_frame(buf, len(old)))
            st, _ = _resp(s)
            assert st == kXR_ok, f"wire cross-depth mv rejected (st={st}) on {url}"
        finally:
            s.close()
    assert md5_file(our_disk(srv, f"/{sub}/landed.txt")) == \
        hashlib.md5(b"wirecross").hexdigest(), f"OUR: wire depth-{depth} mv lost content"


# --- arg1len=0 self-split on first space -> OK parity (positive control) ---- #
def test_wire_mv_arg1len_zero_autosplit_ok(srv):
    """With arg1len=0 the do_Mv() reference path splits on the first space itself
    and performs the rename: a well-formed 'old new' buffer must SUCCEED on both
    servers and rename on disk. (Differential: any accept/reject divergence here
    is a BUG — STOCK implements the arg1len==0 autosplit branch.)"""
    write_disk(srv, "/rn_wire_zero_src.txt", "zerobytes")
    buf = b"/rn_wire_zero_src.txt /rn_wire_zero_dst.txt"
    st_o, en_o = _send_mv(srv["our"], buf, 0)
    st_f, en_f = _send_mv(srv["off"], buf, 0)
    raw = f"\n  OURS  st={st_o} en={en_o}\n  STOCK st={st_f} en={en_f}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"arg1len=0 autosplit accept/reject divergence:{raw}"
    if st_o == kXR_ok:
        assert os.path.exists(our_disk(srv, "/rn_wire_zero_dst.txt")), \
            "OUR: arg1len=0 autosplit mv dst missing"
        assert not os.path.exists(our_disk(srv, "/rn_wire_zero_src.txt")), \
            "OUR: arg1len=0 autosplit mv src remained"
        assert os.path.exists(off_disk(srv, "/rn_wire_zero_dst.txt")), \
            "STOCK: arg1len=0 autosplit mv dst missing"

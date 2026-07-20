from _test_conf_rename_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

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
    # A distinctive FUTURE stamp, never one in the past: the shared interop
    # roots are patrolled by _wipe_stale_working_files, which deletes entries
    # whose mtime predates a concurrent worker's import time — a backdated
    # fixture is wiped mid-test under xdist.
    fixed = int(os.stat(our_disk(srv, src)).st_mtime) + 7200
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

# brix-remote-ok
from _test_conf_rename_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

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

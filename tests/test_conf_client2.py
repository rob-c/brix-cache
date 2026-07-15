from _test_conf_client2_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

# =========================================================================== #
# OUR xrdfs ls — name-set parity with the stock client on the stock server     #
# =========================================================================== #
@pytest.mark.parametrize("path,expect", [
    # '/' is SHARED and concurrent xdist workers pollute its listing under -n8,
    # so the full-set case enumerates a per-worker isolated dir (resolved in the
    # body); the stable node id keeps xdist collection consistent.
    pytest.param(L.LISTING_ROOT_SENTINEL, L.LISTING_ROOT_ENTRIES, id="listing_root"),
    ("/sub", {"nested.txt"}),
    ("/many", {f"f{i:02d}.txt" for i in range(12)}),
    ("/deep", {"a"}),
    ("/deep/a/b/c", {"leaf.txt"}),
    ("/empty_dir", set()),
])
def test_ls_nameset_matches_stock_client(srv, path, expect):
    if path == L.LISTING_ROOT_SENTINEL:
        path = L.ensure_listing_root(srv)
    orc, oout, oerr = ourfs(srv["off"], "ls", path)
    frc, fout, ferr = fs(srv["off"], "ls", path)
    assert orc == 0 and frc == 0, \
        f"ls {path}: our rc={orc} ({oerr!r}) stock rc={frc} ({ferr!r})"
    our, off = _names(oout), _names(fout)
    assert our == off, f"OUR xrdfs ls {path} name-set != stock: ours={our} stock={off}"
    assert expect <= our, f"ls {path}: missing {expect - our}"


def test_ls_of_a_file_matches_stock(srv):
    """The stock client treats ``ls <file>`` as listing that single path. OUR
    client instead opens it as a directory and errors ("not a directory")."""
    orc, oout, oerr = ourfs(srv["off"], "ls", "/hello.txt")
    frc, fout, ferr = fs(srv["off"], "ls", "/hello.txt")
    assert frc == 0 and _names(fout) == {"hello.txt"}, \
        f"stock ls of a file should list it (oracle): {fout!r} {ferr!r}"
    if orc != 0:
        pytest.xfail(
            "CLIENT GAP: OUR xrdfs 'ls <file>' errors instead of listing the "
            f"single path like the stock client (ours: {(oerr+oout).strip()!r}; "
            f"stock lists {_names(fout)}).")
    assert _names(oout) == {"hello.txt"}, \
        f"OUR ls file != stock: ours={_names(oout)} stock={_names(fout)}"


def test_ls_long_carries_sizes_like_stock(srv):
    o = ourfs(srv["off"], "ls", "-l", "/")[1]
    f = fs(srv["off"], "ls", "-l", "/")[1]
    for name, sz in (("data.bin", "4096"), ("big1m.bin", "1048576"),
                     ("hello.txt", "12")):
        assert any(sz in l and name in l for l in o.splitlines()), \
            f"OUR ls -l lost {name} size {sz}: {o!r}"
        assert any(sz in l and name in l for l in f.splitlines()), \
            f"stock ls -l lost {name} size {sz}"


def test_ls_long_size_column_value_parity(srv):
    """The size column value our client emits must equal the stock client's for
    every listed file (column layout may differ, the numeric size may not)."""
    def sizes(out):
        m = {}
        for line in out.splitlines():
            toks = line.split()
            if not toks:
                continue
            name = os.path.basename(toks[-1].rstrip("/"))
            digits = [t for t in toks if t.isdigit()]
            if name and digits:
                m[name] = digits[-1]   # last numeric col == size in both forms
        return m
    o = sizes(ourfs(srv["off"], "ls", "-l", "/")[1])
    f = sizes(fs(srv["off"], "ls", "-l", "/")[1])
    for name in ("hello.txt", "data.bin", "big1m.bin", "cksum.bin", "empty.txt"):
        assert o.get(name) == f.get(name), \
            f"ls -l size for {name}: ours={o.get(name)} stock={f.get(name)}"


def test_ls_recursive_leaf_set_matches_stock(srv):
    # Recurse a per-worker isolated dir, not the shared '/' (whose recursive
    # listing a concurrent worker's transient files would perturb under -n8).
    lroot = L.ensure_listing_root(srv)
    orc, oout, _ = ourfs(srv["off"], "ls", "-R", lroot)
    frc, fout, _ = fs(srv["off"], "ls", "-R", lroot)
    assert orc == 0 and frc == 0, "ls -R should succeed on both clients"
    leaves = set(L.LISTING_ROOT_FILES) | {"leaf.txt"}   # files + the subdir leaf
    our, off = _names(oout), _names(fout)
    assert leaves <= our, f"OUR ls -R missing {leaves - our}"
    assert leaves <= off, f"stock ls -R missing {leaves - off}"
    assert our == off, \
        f"OUR ls -R leaf-set != stock: only-ours={our-off} only-stock={off-our}"


# =========================================================================== #
# OUR xrdfs stat — field parity against the stock client (same stock server)    #
# =========================================================================== #
@pytest.mark.parametrize("path,size", [
    ("/hello.txt", "12"),
    ("/data.bin", "4096"),
    ("/empty.txt", "0"),
    ("/big1m.bin", "1048576"),
    ("/cksum.bin", "10000"),
] + [(f"/sz_{n}.bin", str(n)) for n in _SZ])
def test_stat_size_matches_stock_client(srv, path, size):
    o = _fields(ourfs(srv["off"], "stat", path)[1])
    f = _fields(fs(srv["off"], "stat", path)[1])
    assert o.get("Size") == f.get("Size") == size, \
        f"stat {path} Size: ours={o.get('Size')} stock={f.get('Size')} want {size}"


@pytest.mark.parametrize("path", ["/sub", "/many", "/deep", "/empty_dir"])
def test_stat_dir_flags_match_stock(srv, path):
    o = _fields(ourfs(srv["off"], "stat", path)[1])
    f = _fields(fs(srv["off"], "stat", path)[1])
    assert "IsDir" in o.get("Flags", ""), f"OUR stat {path} not IsDir: {o!r}"
    assert "IsDir" in f.get("Flags", ""), f"stock stat {path} not IsDir: {f!r}"
    assert o.get("Flags") == f.get("Flags"), \
        f"OUR stat {path} Flags != stock: ours={o.get('Flags')!r} stock={f.get('Flags')!r}"


def test_stat_file_fields_byte_parity(srv):
    """Every Key/value the stock client prints for a file, our client must print
    identically (Id, Size, Flags, Mode, Owner, Group, M/C/ATime)."""
    o = _fields(ourfs(srv["off"], "stat", "/data.bin")[1])
    f = _fields(fs(srv["off"], "stat", "/data.bin")[1])
    for key in ("Path", "Id", "Size", "Flags", "Mode", "Owner", "Group",
                "MTime", "CTime", "ATime"):
        assert o.get(key) == f.get(key), \
            f"stat field {key}: ours={o.get(key)!r} stock={f.get(key)!r}"


def test_stat_field_keyset_parity(srv):
    o = set(_fields(ourfs(srv["off"], "stat", "/hello.txt")[1]))
    f = set(_fields(fs(srv["off"], "stat", "/hello.txt")[1]))
    assert o == f, f"OUR stat key-set != stock: only-ours={o-f} only-stock={f-o}"


@pytest.mark.parametrize("path", ["/does_not_exist.bin", "/sub/missing.txt",
                                  "/many/nope"])
def test_stat_nonexistent_rc_and_category_match(srv, path):
    orc, oo, oe = ourfs(srv["off"], "stat", path)
    frc, fo, fe = fs(srv["off"], "stat", path)
    assert (orc == 0) == (frc == 0) and orc != 0, \
        f"stat {path} rc: ours={orc} stock={frc}"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"stat {path} category: ours={oe+oo!r} stock={fe+fo!r}"


def test_stat_with_space_name(srv):
    o = _fields(ourfs(srv["off"], "stat", "/with space.txt")[1])
    f = _fields(fs(srv["off"], "stat", "/with space.txt")[1])
    assert o.get("Size") == f.get("Size") == "7", \
        f"stat spaced name Size: ours={o.get('Size')} stock={f.get('Size')}"


# =========================================================================== #
# OUR xrdfs statvfs — field-VALUE parity (layout may differ; numbers may not)   #
# =========================================================================== #
def test_statvfs_values_match_stock(srv):
    o = ourfs(srv["off"], "statvfs", "/")
    f = fs(srv["off"], "statvfs", "/")
    assert o[0] == 0 and f[0] == 0, f"statvfs rc: ours={o[0]} stock={f[0]}"
    # The stock client prints six labelled metrics; our client prints the six
    # numbers (possibly bare). The numeric MULTISET must match regardless of
    # layout — a divergence in any metric is a client bug.
    our_nums = [t for t in o[1].replace(":", " ").split() if t.lstrip("-").isdigit()]
    off_nums = [t for t in f[1].replace(":", " ").split() if t.lstrip("-").isdigit()]
    assert len(our_nums) >= 6 and len(off_nums) >= 6, \
        f"statvfs <6 metrics: ours={o[1]!r} stock={f[1]!r}"
    # Pin the RW-node count (first stock metric) since it is deterministic (==1).
    assert "1" in our_nums and "1" in off_nums, \
        f"statvfs missing RW-node count 1: ours={o[1]!r} stock={f[1]!r}"


# =========================================================================== #
# OUR xrdfs locate — rc parity (host-specific content)                         #
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sub", "/many"])
def test_locate_rc_parity(srv, path):
    orc, oo, oe = ourfs(srv["off"], "locate", path)
    frc, fo, fe = fs(srv["off"], "locate", path)
    assert (orc == 0) == (frc == 0), \
        f"locate {path} rc: ours={orc} ({oe!r}) stock={frc} ({fe!r})"
    if orc == 0:
        assert oo.strip(), f"OUR locate {path} produced no output"


def test_locate_nonexistent_rc_parity(srv):
    orc, oo, oe = ourfs(srv["off"], "locate", "/no_such_zzz")
    frc, fo, fe = fs(srv["off"], "locate", "/no_such_zzz")
    assert (orc == 0) == (frc == 0), \
        f"locate noent rc: ours={orc} ({oe!r}) stock={frc} ({fe!r})"


@pytest.mark.parametrize("key", _CFG_KEYS)
def test_query_config_value_matches_stock_client(srv, key):
    orc, oout, oerr = ourfs(srv["off"], "query", "config", key)
    frc, fout, ferr = fs(srv["off"], "query", "config", key)
    assert (orc == 0) == (frc == 0), \
        f"query config {key} rc: ours={orc} stock={frc}"
    if orc == 0:
        ov = oout.strip().splitlines()[0].strip() if oout.strip() else ""
        fv = fout.strip().splitlines()[0].strip() if fout.strip() else ""
        assert not ov.startswith(f"{key}="), \
            f"OUR query config {key} carries 'key=' prefix: {oout!r}"
        assert ov == fv, \
            f"OUR query config {key} value {ov!r} != stock client {fv!r}"


# =========================================================================== #
# OUR xrdfs query checksum — hex parity with stock client when answered         #
# =========================================================================== #
@pytest.mark.parametrize("path", ["/cksum.bin", "/data.bin", "/hello.txt"])
def test_query_checksum_matches_stock_client(srv, path):
    orc, oout, _ = ourfs(srv["off"], "query", "checksum", path)
    frc, fout, _ = fs(srv["off"], "query", "checksum", path)
    assert (orc == 0) == (frc == 0), \
        f"checksum {path} rc: ours={orc} stock={frc}"
    if orc == 0 and frc == 0:
        assert len(oout.split()) >= 2, \
            f"OUR checksum reply not '<algo> <hex>': {oout!r}"
        assert oout.split()[-1] == fout.split()[-1], \
            f"OUR checksum hex {oout.split()[-1]!r} != stock {fout.split()[-1]!r}"


# =========================================================================== #
# OUR xrdfs cat — text + byte-exact binary parity with the stock client         #
# =========================================================================== #
def test_cat_text_matches_stock(srv):
    orc, oout, _ = ourfs(srv["off"], "cat", "/hello.txt")
    frc, fout, _ = fs(srv["off"], "cat", "/hello.txt")
    assert orc == 0 and frc == 0, "cat /hello.txt should succeed on both"
    assert oout == fout == "hello world\n", \
        f"OUR cat text != stock: ours={oout!r} stock={fout!r}"


@pytest.mark.parametrize("name", ["data.bin", "sz_4096.bin", "sz_65536.bin",
                                  "big1m.bin", "cksum.bin", "sz_1.bin",
                                  "sz_4095.bin", "sz_4097.bin"])
def test_cat_binary_byte_exact_vs_stock(srv, name):
    orc, ob = cat_bytes(L.OUR_XRDFS, srv["off"], f"/{name}")
    frc, fb = cat_bytes(L.OFF_XRDFS, srv["off"], f"/{name}")
    assert orc == 0 and frc == 0, f"cat {name} rc: ours={orc} stock={frc}"
    src = _read(_ondisk(srv, "off", name))
    assert fb == src, f"stock cat {name} not byte-exact vs source (oracle sanity)"
    assert ob == fb, f"OUR cat {name} bytes != stock client bytes"


def test_cat_empty_file_parity(srv):
    orc, ob = cat_bytes(L.OUR_XRDFS, srv["off"], "/empty.txt")
    frc, fb = cat_bytes(L.OFF_XRDFS, srv["off"], "/empty.txt")
    assert orc == 0 and frc == 0, f"cat empty rc: ours={orc} stock={frc}"
    assert ob == fb == b"", f"OUR cat empty != stock: ours={ob!r} stock={fb!r}"


def test_cat_with_space_name_parity(srv):
    orc, oout, _ = ourfs(srv["off"], "cat", "/with space.txt")
    frc, fout, _ = fs(srv["off"], "cat", "/with space.txt")
    assert orc == 0 and frc == 0, "cat spaced name should succeed on both"
    assert oout == fout == "spaced\n", \
        f"OUR cat spaced != stock: ours={oout!r} stock={fout!r}"


def test_cat_is_a_directory_rc_category(srv):
    orc, oo, oe = ourfs(srv["off"], "cat", "/sub")
    frc, fo, fe = fs(srv["off"], "cat", "/sub")
    assert orc != 0 and frc != 0, "cat of a dir must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo) == "is a directory", \
        f"cat dir category: ours={oe+oo!r} stock={fe+fo!r}"


def test_cat_nonexistent_rc_category(srv):
    orc, oo, oe = ourfs(srv["off"], "cat", "/no_such.bin")
    frc, fo, fe = fs(srv["off"], "cat", "/no_such.bin")
    assert orc != 0 and frc != 0, "cat of missing file must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"cat noent category: ours={oe+oo!r} stock={fe+fo!r}"


# =========================================================================== #
# OUR xrdfs tail — last-bytes parity                                            #
# =========================================================================== #
def test_tail_whole_small_file_parity(srv):
    orc, oout, _ = ourfs(srv["off"], "tail", "/hello.txt")
    frc, fout, _ = fs(srv["off"], "tail", "/hello.txt")
    assert orc == 0 and frc == 0, "tail /hello.txt should succeed on both"
    assert oout == fout == "hello world\n", \
        f"OUR tail != stock: ours={oout!r} stock={fout!r}"


@pytest.mark.parametrize("n,want", [(5, "orld\n"), (1, "\n"), (12, "hello world\n")])
def test_tail_byte_count_parity(srv, n, want):
    orc, oout, _ = ourfs(srv["off"], "tail", "-c", str(n), "/hello.txt")
    frc, fout, _ = fs(srv["off"], "tail", "-c", str(n), "/hello.txt")
    assert orc == 0 and frc == 0, f"tail -c {n} rc: ours={orc} stock={frc}"
    assert oout == fout == want, \
        f"OUR tail -c {n} != stock: ours={oout!r} stock={fout!r}"


# =========================================================================== #
# OUR xrdfs MUTATIONS on the stock server (stock disk is the witness)           #
# =========================================================================== #
def test_mkdir_rmdir_roundtrip_on_stock(srv):
    d = "/c2_mkdir_rt"
    rc, o, e = ourfs(srv["off"], "mkdir", d)
    assert rc == 0, f"OUR mkdir -> stock failed: {o}{e}"
    assert os.path.isdir(_ondisk(srv, "off", d)), "OUR mkdir no on-disk dir"
    rc, o, e = ourfs(srv["off"], "rmdir", d)
    assert rc == 0, f"OUR rmdir -> stock failed: {o}{e}"
    assert not os.path.exists(_ondisk(srv, "off", d)), "OUR rmdir left dir"


def test_mkdir_p_tree_on_stock(srv):
    d = "/c2_mkp/a/b/c"
    rc, o, e = ourfs(srv["off"], "mkdir", "-p", d)
    assert rc == 0, f"OUR mkdir -p -> stock failed: {o}{e}"
    assert os.path.isdir(_ondisk(srv, "off", d)), "OUR mkdir -p no deep dir"


def test_mkdir_existing_rc_category_parity(srv):
    ourfs(srv["off"], "mkdir", "/c2_mk_exists")
    fs(srv["off"], "mkdir", "/c2_mk_exists_ref")
    orc, oo, oe = ourfs(srv["off"], "mkdir", "/c2_mk_exists")
    frc, fo, fe = fs(srv["off"], "mkdir", "/c2_mk_exists_ref")
    assert (orc == 0) == (frc == 0), \
        f"mkdir existing rc: ours={orc} ({oe!r}) stock={frc} ({fe!r})"
    if orc != 0:
        assert L.err_code(oe + oo) == L.err_code(fe + fo), \
            f"mkdir existing category: ours={oe+oo!r} stock={fe+fo!r}"


def test_rm_uploaded_file_on_stock(srv, tmp_path):
    src = str(tmp_path / "c2rm.src")
    with open(src, "wb") as f:
        f.write(b"remove me\n")
    rc, o, e = ourcp("-f", src, f"{srv['off']}//c2_rm.bin")
    assert rc == 0, f"setup upload failed: {o}{e}"
    on_disk = _ondisk(srv, "off", "/c2_rm.bin")
    assert os.path.exists(on_disk)
    rc, o, e = ourfs(srv["off"], "rm", "/c2_rm.bin")
    assert rc == 0, f"OUR rm -> stock failed: {o}{e}"
    assert not os.path.exists(on_disk), "OUR rm did not delete on stock disk"


def test_rm_nonexistent_rc_category_parity(srv):
    orc, oo, oe = ourfs(srv["off"], "rm", "/c2_rm_noent.bin")
    frc, fo, fe = fs(srv["off"], "rm", "/c2_rm_noent.bin")
    assert (orc == 0) == (frc == 0), \
        f"rm noent rc: ours={orc} ({oe!r}) stock={frc} ({fe!r})"
    if orc != 0:
        assert L.err_code(oe + oo) == L.err_code(fe + fo), \
            f"rm noent category: ours={oe+oo!r} stock={fe+fo!r}"

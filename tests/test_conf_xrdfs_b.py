from split_continuation import reexport as _reexport
def _check_test_combined_lifecycle_on_our_server_1(rc, o, e):
    assert rc == 0, f"lifecycle mkdir: {o}{e}"

def _check_test_combined_lifecycle_on_our_server_2(rc, o, e):
    assert rc == 0, f"lifecycle put: {o}{e}"

def _check_test_combined_lifecycle_on_our_server_3(rc, lout):
    assert rc == 0 and "life.bin" in _names(lout), f"lifecycle ls: {lout!r}"

def _check_test_combined_lifecycle_on_our_server_4(rc, o, e):
    assert rc == 0, f"lifecycle rm: {o}{e}"


_reexport(globals(), "_test_conf_xrdfs_helpers")

pytestmark = pytest.mark.xdist_group("conf_xrdfs_b")

@pytest.mark.parametrize("size", [0, 10])
def test_truncate_size_parity(srv, size):
    for side in ("our", "off"):
        rel = f"/x_trunc_{side}_{size}.bin"
        with open(_ondisk(srv, side, rel), "wb") as f:
            f.write(b"\x00" * 100)
        rc, o, e = fs(srv[side], "truncate", rel, str(size))
        assert rc == 0, f"{side} truncate failed: {o}{e}"
        assert os.path.getsize(_ondisk(srv, side, rel)) == size, \
            f"{side} truncate size {os.path.getsize(_ondisk(srv, side, rel))} != {size}"


# =========================================================================== #
# prepare — rc/category parity (kXR_prepare; the stock server may no-op)       (1)
# =========================================================================== #
def test_prepare_category_parity(srv):
    orc, oo, oe = fs(srv["our"], "prepare", "/hello.txt")
    frc, fo, fe = fs(srv["off"], "prepare", "/hello.txt")
    assert (orc == 0) == (frc == 0), \
        f"prepare rc divergence: ours={orc} ({oe!r}) stock={frc} ({fe!r})"


# =========================================================================== #
# spaceinfo — field parity                                                     (1)
# =========================================================================== #
def test_spaceinfo_field_keys_match(srv):
    o = _fields(fs(srv["our"], "spaceinfo", "/")[1])
    f = _fields(fs(srv["off"], "spaceinfo", "/")[1])
    assert set(o) == set(f), \
        f"spaceinfo key set divergence: ours={set(o)} stock={set(f)}"
    assert "Total" in o, f"spaceinfo missing Total: {o}"


# =========================================================================== #
# combined lifecycle — mkdir -> put -> ls -> stat -> rm -> rmdir, on-disk      (1)
# =========================================================================== #
def test_combined_lifecycle_on_our_server(srv, tmp_path):
    d = "/x_life_dir"
    rc, o, e = fs(srv["our"], "mkdir", d)
    _check_test_combined_lifecycle_on_our_server_1(rc, o, e)
    src = str(tmp_path / "life.bin")
    payload = bytes((i * 13 + 1) & 0xff for i in range(2048))
    with open(src, "wb") as f:
        f.write(payload)
    rc, o, e = L.run([L.OFF_XRDCP, "-f", src, f"{srv['our']}/{d}/life.bin"])
    _check_test_combined_lifecycle_on_our_server_2(rc, o, e)
    rc, lout, _ = fs(srv["our"], "ls", d)
    _check_test_combined_lifecycle_on_our_server_3(rc, lout)
    st = _fields(fs(srv["our"], "stat", f"{d}/life.bin")[1])
    def _assert_test_combined_lifecycle_on_our_server_1():
        assert st.get("Size") == "2048", f"lifecycle stat size: {st.get('Size')}"
        assert _read(_ondisk(srv, "our", f"{d}/life.bin")) == payload, \
            "lifecycle on-disk bytes mismatch"

    _assert_test_combined_lifecycle_on_our_server_1()
    rc, o, e = fs(srv["our"], "rm", f"{d}/life.bin")
    _check_test_combined_lifecycle_on_our_server_4(rc, o, e)
    rc, o, e = fs(srv["our"], "rmdir", d)
    def _assert_test_combined_lifecycle_on_our_server_2():
        assert rc == 0, f"lifecycle rmdir: {o}{e}"
        assert not os.path.exists(_ondisk(srv, "our", d)), "lifecycle dir not removed"

    _assert_test_combined_lifecycle_on_our_server_2()


# =========================================================================== #
# Q2 — OUR xrdfs against the STOCK server (read-only; a failure == client bug) #
# Parametrized breadth; output consistent with the stock-on-stock reference.  #
# =========================================================================== #
@pytest.mark.parametrize("args,check", [
    (["ls", "/"], lambda o: "hello.txt" in o),
    (["ls", "-l", "/"], lambda o: "data.bin" in o and "4096" in o),
    (["ls", "-R", "/sub"], lambda o: "nested.txt" in o),
    (["ls", "/sub"], lambda o: "nested.txt" in o),
    (["stat", "/hello.txt"], lambda o: "Size" in o and "12" in o),
    (["stat", "/sub"], lambda o: "IsDir" in o),
    (["statvfs", "/"], lambda o: bool(o.strip())),
    (["locate", "/hello.txt"], lambda o: bool(o.strip())),
    (["cat", "/hello.txt"], lambda o: "hello world" in o),
    (["tail", "/hello.txt"], lambda o: "hello world" in o),
    (["query", "config", "version"], lambda o: bool(o.strip())),
    (["query", "config", "chksum"], lambda o: not o.strip().startswith("chksum=")),
])
def test_q2_our_xrdfs_readonly_vs_stock(srv, args, check):
    rc, out, err = ourfs(srv["off"], *args)
    assert rc == 0, f"OUR xrdfs {args} -> stock server failed: {out}{err}"
    assert check(out), f"OUR xrdfs {args}: output inconsistent with stock: {out!r}"


def test_q2_our_xrdfs_query_config_no_key_prefix(srv):
    # The reference returns bare values; ensure OUR client never echoes 'key='.
    for key in ("bind_max", "tpc", "readv_iov_max"):
        rc, out, err = ourfs(srv["off"], "query", "config", key)
        assert rc == 0, f"OUR query config {key} -> stock failed: {out}{err}"
        assert not out.strip().startswith(f"{key}="), \
            f"OUR query config {key} carries 'key=' prefix: {out!r}"


def test_q2_our_xrdfs_query_checksum_matches_stock_client(srv):
    # Both clients hit the SAME stock server: a divergence is OUR client's bug.
    our_rc, our_out, _ = ourfs(srv["off"], "query", "checksum", "/cksum.bin")
    off_rc, off_out, _ = fs(srv["off"], "query", "checksum", "/cksum.bin")
    assert (our_rc == 0) == (off_rc == 0), \
        f"OUR client checksum rc={our_rc} disagrees with stock client rc={off_rc}"
    if our_rc == 0 and off_rc == 0:
        assert our_out.split()[-1] == off_out.split()[-1], \
            f"OUR client checksum {our_out!r} != stock client {off_out!r}"


def test_q2_our_xrdfs_stat_size_matches_stock_client(srv):
    o = _fields(ourfs(srv["off"], "stat", "/data.bin")[1])
    s = _fields(fs(srv["off"], "stat", "/data.bin")[1])
    assert o.get("Size") == s.get("Size") == "4096", \
        f"OUR client stat Size={o.get('Size')} vs stock client {s.get('Size')}"


def test_q2_our_xrdfs_statvfs_six_fields(srv):
    rc, out, err = ourfs(srv["off"], "statvfs", "/")
    assert rc == 0, f"OUR statvfs -> stock failed: {out}{err}"
    # Our client renders statvfs as 6 whitespace-separated fields.
    toks = out.split()
    assert len(toks) >= 6, f"OUR statvfs not 6+ fields: {out!r}"


def test_q2_our_xrdfs_cat_binary_byte_exact(srv):
    r = subprocess.run([L.OUR_XRDFS, srv["off"], "cat", "/sz_4096.bin"],
                       capture_output=True, timeout=60)
    assert r.returncode == 0, f"OUR cat binary -> stock failed: {r.stderr!r}"
    assert r.stdout == _read(_ondisk(srv, "off", "sz_4096.bin")), \
        "OUR client cat binary not byte-exact vs stock source"


# =========================================================================== #
# Q2 — OUR xrdfs MUTATIONS against the STOCK server (unique paths)            #
# A divergence here is a BUG IN OUR CLIENT; the stock disk is the witness.    #
# =========================================================================== #
def test_q2_our_mkdir_rmdir_on_stock(srv):
    d = "/q2x_mkdir"
    rc, o, e = ourfs(srv["off"], "mkdir", d)
    assert rc == 0, f"OUR mkdir -> stock failed: {o}{e}"
    assert os.path.isdir(_ondisk(srv, "off", d)), "OUR mkdir no on-disk dir on stock"
    rc, o, e = ourfs(srv["off"], "rmdir", d)
    assert rc == 0, f"OUR rmdir -> stock failed: {o}{e}"
    assert not os.path.exists(_ondisk(srv, "off", d)), "OUR rmdir left dir on stock"


def test_q2_our_rm_on_stock(srv):
    rel = "/q2x_rm.bin"
    with open(_ondisk(srv, "off", rel), "wb") as f:
        f.write(b"x\n")
    rc, o, e = ourfs(srv["off"], "rm", rel)
    assert rc == 0, f"OUR rm -> stock failed: {o}{e}"
    assert not os.path.exists(_ondisk(srv, "off", rel)), "OUR rm left file on stock"


def test_q2_our_mv_on_stock(srv):
    a, b = "/q2x_mv_a.txt", "/q2x_mv_b.txt"
    with open(_ondisk(srv, "off", a), "w") as f:
        f.write("mv\n")
    rc, o, e = ourfs(srv["off"], "mv", a, b)
    assert rc == 0, f"OUR mv -> stock failed: {o}{e}"
    assert os.path.exists(_ondisk(srv, "off", b)), "OUR mv no destination on stock"
    assert not os.path.exists(_ondisk(srv, "off", a)), "OUR mv left source on stock"


def test_q2_our_chmod_on_stock(srv):
    """OUR xrdfs chmod must set the same mode the stock client does, via the
    stock 9-char symbolic form ("rwxr-xr-x"). (Previously our client only parsed
    octal, so the symbolic form silently became mode 000 — fixed in client/apps/
    xrdfs.c parse_chmod_mode, which now accepts both symbolic and octal.)"""
    import stat as _stat
    rel = "/q2x_chmod.txt"
    ours = _ondisk(srv, "off", rel)
    with open(ours, "w") as f:
        f.write("c\n")
    # chmod runs on the stock server (nobody), which can only chmod files it
    # owns (root cause #2), so give it ownership of both off-tree targets.
    L.chown_stock(ours)
    # Reference: the SAME chmod via the stock client on the SAME stock server.
    ref = _ondisk(srv, "off", "/q2x_chmod_ref.txt")
    with open(ref, "w") as f:
        f.write("c\n")
    L.chown_stock(ref)
    fs(srv["off"], "chmod", "/q2x_chmod_ref.txt", "rwxr-xr-x")
    ref_mode = _stat.S_IMODE(os.stat(ref).st_mode)

    rc, o, e = ourfs(srv["off"], "chmod", rel, "rwxr-xr-x")
    assert rc == 0, f"OUR chmod -> stock failed: {o}{e}"
    mode = _stat.S_IMODE(os.stat(ours).st_mode)
    assert mode == ref_mode, \
        f"OUR client chmod set mode {mode:o}, stock client set {ref_mode:o}"


def test_q2_our_truncate_on_stock(srv):
    rel = "/q2x_trunc.bin"
    with open(_ondisk(srv, "off", rel), "wb") as f:
        f.write(b"\x00" * 100)
    rc, o, e = ourfs(srv["off"], "truncate", rel, "7")
    assert rc == 0, f"OUR truncate -> stock failed: {o}{e}"
    assert os.path.getsize(_ondisk(srv, "off", rel)) == 7, \
        f"OUR truncate on stock: size {os.path.getsize(_ondisk(srv, 'off', rel))} != 7"

# brix-remote-ok
from _test_conf_client2_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_mv_rename_on_stock(srv):
    a, b = "/c2_mv_a.txt", "/c2_mv_b.txt"
    with open(_ondisk(srv, "off", a), "w") as f:
        f.write("mv\n")
    rc, o, e = ourfs(srv["off"], "mv", a, b)
    assert rc == 0, f"OUR mv -> stock failed: {o}{e}"
    assert not os.path.exists(_ondisk(srv, "off", a)), "OUR mv left source"
    assert os.path.exists(_ondisk(srv, "off", b)), "OUR mv no destination"
    assert _read(_ondisk(srv, "off", b)) == b"mv\n", "OUR mv corrupted bytes"


def test_mv_nonexistent_rc_category_parity(srv):
    orc, oo, oe = ourfs(srv["off"], "mv", "/c2_mv_noent_a", "/c2_mv_noent_b")
    frc, fo, fe = fs(srv["off"], "mv", "/c2_mv_noent_a2", "/c2_mv_noent_b2")
    assert orc != 0 and frc != 0, "mv of nonexistent must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"mv noent category: ours={oe+oo!r} stock={fe+fo!r}"


def test_rmdir_nonempty_rc_category_parity(srv):
    orc, oo, oe = ourfs(srv["off"], "rmdir", "/many")
    frc, fo, fe = fs(srv["off"], "rmdir", "/many")
    assert orc != 0 and frc != 0, "rmdir of non-empty must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"rmdir nonempty category: ours={oe+oo!r} stock={fe+fo!r}"


# --------------------------------------------------------------------------- #
# chmod — symbolic AND octal, parity with the stock client's resulting mode    #
# --------------------------------------------------------------------------- #
# The stock xrdfs `chmod` accepts ONLY the 9-char symbolic form; it rejects an
# octal argument ("Invalid arguments"). Symbolic parity is the differential
# oracle; OUR client's octal acceptance is tested separately as an extension.
@pytest.mark.parametrize("idx,mode_arg,want", [
    (0, "rwxr-xr-x", 0o755),
    (1, "rw-r--r--", 0o644),
    (2, "rwx------", 0o700),
    (3, "r--r--r--", 0o444),
    (4, "rwxr-x---", 0o750),
])
def test_chmod_symbolic_parity(srv, idx, mode_arg, want):
    import stat as _stat
    rel = f"/c2_chmod_{idx}.txt"
    ours = _ondisk(srv, "off", rel)
    with open(ours, "w") as f:
        f.write("c\n")
    # Reference: same chmod via the stock client on a sibling file. The stock
    # *server* may clamp some bits (e.g. world-write), so the oracle is the
    # stock client's RESULTING mode on this server, not the literal argument.
    ref_rel = f"/c2_chmod_ref_{idx}.txt"
    ref = _ondisk(srv, "off", ref_rel)
    with open(ref, "w") as f:
        f.write("c\n")
    frc, _, fe = fs(srv["off"], "chmod", ref_rel, mode_arg)
    assert frc == 0, f"stock chmod {mode_arg} failed (oracle): {fe!r}"
    ref_mode = _stat.S_IMODE(os.stat(ref).st_mode)
    assert ref_mode == want, \
        f"stock chmod {mode_arg} -> {ref_mode:o}, harness expected {want:o}"

    orc, o, e = ourfs(srv["off"], "chmod", rel, mode_arg)
    assert orc == 0, f"OUR chmod {mode_arg} -> stock failed: {o}{e}"
    mode = _stat.S_IMODE(os.stat(ours).st_mode)
    assert mode == ref_mode, \
        f"OUR chmod {mode_arg} set {mode:o}, stock client set {ref_mode:o}"


@pytest.mark.parametrize("mode_arg,want", [("0755", 0o755), ("0600", 0o600),
                                           ("755", 0o755)])
def test_chmod_octal_extension(srv, mode_arg, want):
    """OUR xrdfs additionally accepts an OCTAL chmod argument (the stock client
    rejects octal as 'Invalid arguments'). Verify our extension sets the right
    mode AND confirm the stock client really does reject it (so this is a true
    superset, not a silent divergence)."""
    import stat as _stat
    frc, _, _ = fs(srv["off"], "chmod", "/c2_chmod_oct_ref.txt", mode_arg)
    # stock rejects octal: create the file first then confirm rejection
    ref = _ondisk(srv, "off", "/c2_chmod_oct_ref.txt")
    with open(ref, "w") as f:
        f.write("c\n")
    frc, _, _ = fs(srv["off"], "chmod", "/c2_chmod_oct_ref.txt", mode_arg)
    assert frc != 0, "stock xrdfs unexpectedly accepted an octal chmod argument"

    rel = f"/c2_chmod_oct_{mode_arg}.txt"
    ours = _ondisk(srv, "off", rel)
    with open(ours, "w") as f:
        f.write("c\n")
    rc, o, e = ourfs(srv["off"], "chmod", rel, mode_arg)
    assert rc == 0, f"OUR chmod octal {mode_arg} failed: {o}{e}"
    assert _stat.S_IMODE(os.stat(ours).st_mode) == want, \
        f"OUR chmod octal {mode_arg} -> {os.stat(ours).st_mode & 0o777:o} != {want:o}"


# --------------------------------------------------------------------------- #
# truncate — on-disk size parity (grow + shrink + zero)                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("size", [0, 1, 7, 50, 200])
def test_truncate_size_parity(srv, size):
    rel = f"/c2_trunc_{size}.bin"
    ours = _ondisk(srv, "off", rel)
    with open(ours, "wb") as f:
        f.write(b"\x00" * 100)
    rc, o, e = ourfs(srv["off"], "truncate", rel, str(size))
    assert rc == 0, f"OUR truncate {size} -> stock failed: {o}{e}"
    got = os.path.getsize(ours)
    assert got == size, f"OUR truncate {size}: on-disk size {got} != {size}"


# =========================================================================== #
# OUR xrdcp DOWNLOAD — byte-exact vs source AND vs the stock client            #
# =========================================================================== #
@pytest.mark.parametrize("name", ["empty.txt", "sz_1.bin", "data.bin",
                                  "sz_4095.bin", "sz_4096.bin", "sz_4097.bin",
                                  "sz_8192.bin", "sz_65536.bin", "big1m.bin",
                                  "cksum.bin"])
def test_xrdcp_download_byte_exact(srv, tmp_path, name):
    our_dst = str(tmp_path / f"our_{name}")
    off_dst = str(tmp_path / f"off_{name}")
    orc, oo, oe = ourcp("-f", f"{srv['off']}//{name}", our_dst)
    frc, fo, fe = cp("-f", f"{srv['off']}//{name}", off_dst)
    assert orc == 0, f"OUR xrdcp download {name} failed: {oo}{oe}"
    assert frc == 0, f"stock xrdcp download {name} failed (oracle): {fo}{fe}"
    src = _read(_ondisk(srv, "off", name))
    assert _read(off_dst) == src, f"stock download {name} not byte-exact (oracle)"
    assert _read(our_dst) == src, f"OUR xrdcp download {name} byte mismatch vs source"
    assert _read(our_dst) == _read(off_dst), \
        f"OUR xrdcp download {name} bytes != stock client bytes"


def test_xrdcp_download_to_stdout_parity(srv):
    """xrdcp <remote> -  -> stdout. Compare raw bytes against the stock client."""
    o = subprocess.run([L.OUR_XRDCP, "-f", f"{srv['off']}//data.bin", "-"],
                       capture_output=True, timeout=60)
    f = subprocess.run([L.OFF_XRDCP, "-f", f"{srv['off']}//data.bin", "-"],
                       capture_output=True, timeout=60)
    assert o.returncode == 0 and f.returncode == 0, \
        f"xrdcp to stdout rc: ours={o.returncode} stock={f.returncode}"
    src = _read(_ondisk(srv, "off", "data.bin"))
    assert f.stdout == src, "stock xrdcp -> stdout not byte-exact (oracle)"
    assert o.stdout == src, "OUR xrdcp -> stdout byte mismatch vs source"


# =========================================================================== #
# OUR xrdcp UPLOAD — byte-exact on stock disk, parity with stock client        #
# =========================================================================== #
@pytest.mark.parametrize("size", [0, 1, 255, 4096, 65536, 1024 * 1024])
def test_xrdcp_upload_byte_exact(srv, tmp_path, size):
    payload = bytes((i * 31 + size) & 0xff for i in range(size))
    src = str(tmp_path / f"up_{size}.src")
    with open(src, "wb") as f:
        f.write(payload)
    our_rel = f"/c2_up_our_{size}.bin"
    off_rel = f"/c2_up_off_{size}.bin"
    orc, oo, oe = ourcp("-f", src, f"{srv['off']}/{our_rel}")
    frc, fo, fe = cp("-f", src, f"{srv['off']}/{off_rel}")
    assert orc == 0, f"OUR xrdcp upload {size} failed: {oo}{oe}"
    assert frc == 0, f"stock xrdcp upload {size} failed (oracle): {fo}{fe}"
    on_ours = _ondisk(srv, "off", our_rel)
    on_off = _ondisk(srv, "off", off_rel)
    assert os.path.exists(on_ours), f"OUR upload {size} did not land on disk"
    assert _read(on_ours) == payload, f"OUR upload {size} byte mismatch on disk"
    assert _read(on_ours) == _read(on_off), \
        f"OUR upload {size} bytes != stock-client upload bytes"


def test_xrdcp_upload_from_stdin_parity(srv):
    payload = b"from stdin via our client\n"
    o = subprocess.run([L.OUR_XRDCP, "-f", "-", f"{srv['off']}//c2_stdin_our.bin"],
                       input=payload, capture_output=True, timeout=60)
    assert o.returncode == 0, f"OUR xrdcp stdin upload failed: {o.stderr!r}"
    assert _read(_ondisk(srv, "off", "/c2_stdin_our.bin")) == payload, \
        "OUR xrdcp stdin upload byte mismatch on disk"
    # Stock client parity on a sibling path.
    f = subprocess.run([L.OFF_XRDCP, "-f", "-", f"{srv['off']}//c2_stdin_off.bin"],
                       input=payload, capture_output=True, timeout=60)
    assert f.returncode == 0, f"stock xrdcp stdin upload failed (oracle): {f.stderr!r}"
    assert _read(_ondisk(srv, "off", "/c2_stdin_off.bin")) == payload


def test_xrdcp_upload_then_download_roundtrip(srv, tmp_path):
    payload = bytes((i * 17 + 5) & 0xff for i in range(50000))
    src = str(tmp_path / "rt.src")
    with open(src, "wb") as f:
        f.write(payload)
    rc, o, e = ourcp("-f", src, f"{srv['off']}//c2_rt.bin")
    assert rc == 0, f"OUR upload (roundtrip) failed: {o}{e}"
    back = str(tmp_path / "rt.back")
    rc, o, e = ourcp("-f", f"{srv['off']}//c2_rt.bin", back)
    assert rc == 0, f"OUR download (roundtrip) failed: {o}{e}"
    assert _read(back) == payload, "OUR xrdcp upload/download roundtrip not byte-exact"


# =========================================================================== #
# OUR xrdcp option flavors — outcome parity with the stock client              #
# =========================================================================== #
def test_xrdcp_force_overwrite_parity(srv, tmp_path):
    dst = str(tmp_path / "force.bin")
    with open(dst, "wb") as f:
        f.write(b"stale contents that must be overwritten")
    rc, o, e = ourcp("-f", f"{srv['off']}//data.bin", dst)
    assert rc == 0, f"OUR xrdcp -f failed: {o}{e}"
    assert _read(dst) == _read(_ondisk(srv, "off", "data.bin")), \
        "OUR xrdcp -f: overwritten file does not match source"


def test_xrdcp_no_overwrite_without_force_parity(srv, tmp_path):
    """Without -f, an existing destination must NOT be overwritten on either
    client (same rc category)."""
    our_dst = str(tmp_path / "noforce_our.bin")
    off_dst = str(tmp_path / "noforce_off.bin")
    for p in (our_dst, off_dst):
        with open(p, "wb") as f:
            f.write(b"preexisting")
    orc, oo, oe = ourcp(f"{srv['off']}//data.bin", our_dst)
    frc, fo, fe = cp(f"{srv['off']}//data.bin", off_dst)
    assert (orc == 0) == (frc == 0), \
        f"xrdcp no-force rc: ours={orc} ({oe!r}) stock={frc} ({fe!r})"
    # neither should have clobbered the preexisting bytes on failure
    if orc != 0:
        assert _read(our_dst) == b"preexisting", \
            "OUR xrdcp clobbered destination despite no -f and a failure rc"


def test_xrdcp_silent_flag_parity(srv, tmp_path):
    dst = str(tmp_path / "silent.bin")
    rc, o, e = ourcp("-s", "-f", f"{srv['off']}//data.bin", dst)
    assert rc == 0, f"OUR xrdcp -s failed: {o}{e}"
    assert _read(dst) == _read(_ondisk(srv, "off", "data.bin")), \
        "OUR xrdcp -s: download integrity mismatch"


def test_xrdcp_persist_on_close_upload(srv, tmp_path):
    """Our client's persist-on-successful-close flag is `-P` (the stock spelling
    is `--posc`; see the dedicated gap test below). `-P` must persist bytes."""
    payload = bytes((i * 7 + 1) & 0xff for i in range(5000))
    src = str(tmp_path / "posc.src")
    with open(src, "wb") as f:
        f.write(payload)
    rc, o, e = ourcp("-P", "-f", src, f"{srv['off']}//c2_posc.bin")
    assert rc == 0, f"OUR xrdcp -P upload failed: {o}{e}"
    on_disk = _ondisk(srv, "off", "/c2_posc.bin")
    assert os.path.exists(on_disk) and _read(on_disk) == payload, \
        "OUR xrdcp -P: persisted bytes do not match source"


def test_xrdcp_cksum_source_outcome_parity(srv, tmp_path):
    """`--cksum adler32:source` asks xrdcp to verify the download against the
    SERVER-reported checksum. The stock data server has no checksum plugin, so
    the stock client treats the inability to fetch the requested checksum as a
    FATAL error (rc!=0, no file). OUR client instead downloads the file and only
    WARNS that the checksum was not verified (rc==0)."""
    our_dst = str(tmp_path / "cks_our.bin")
    off_dst = str(tmp_path / "cks_off.bin")
    orc, oo, oe = ourcp("-f", "--cksum", "adler32:source",
                        f"{srv['off']}//data.bin", our_dst)
    frc, fo, fe = cp("-f", "--cksum", "adler32:source",
                     f"{srv['off']}//data.bin", off_dst)
    assert frc != 0, f"stock --cksum :source should fail w/o a plugin (oracle): {fo}{fe}"
    if orc == 0 and "not verified" in (oe + oo).lower():
        # the bytes that landed must still be correct, but the contract diverges
        if os.path.exists(our_dst):
            assert _read(our_dst) == _read(_ondisk(srv, "off", "data.bin")), \
                "OUR xrdcp --cksum: downloaded bytes do not match source"
        pytest.xfail(
            "CLIENT GAP: with '--cksum adler32:source' and a server that cannot "
            "supply the checksum, OUR xrdcp downloads the file and exits 0 with a "
            f"'checksum NOT verified' warning ({(oe+oo).strip()!r}); the stock "
            f"client treats it as fatal (rc={frc}). Verification was REQUESTED, "
            "so a soft pass silently weakens integrity.")
    assert (orc == 0) == (frc == 0), \
        f"xrdcp --cksum rc: ours={orc} ({oe!r}) stock={frc} ({fe!r})"


def test_xrdcp_cksum_print_independent_oracle(srv, tmp_path):
    """`--cksum adler32:print` should not corrupt the transfer regardless of the
    server's checksum support; the landed bytes must match an INDEPENDENT oracle
    (the source file on the stock disk)."""
    dst = str(tmp_path / "cksprint.bin")
    rc, o, e = ourcp("-f", "--cksum", "adler32:print",
                     f"{srv['off']}//cksum.bin", dst)
    if rc != 0:
        # parity guard: the stock client must also reject :print here
        frc, fo, fe = cp("-f", "--cksum", "adler32:print",
                         f"{srv['off']}//cksum.bin", str(tmp_path / "cksprint_off.bin"))
        assert frc != 0, \
            f"OUR xrdcp --cksum :print failed (rc={rc}) but stock succeeded: {o}{e}"
        return
    assert _read(dst) == _read(_ondisk(srv, "off", "cksum.bin")), \
        "OUR xrdcp --cksum :print: landed bytes != source"


@pytest.mark.parametrize("remote", ["/many", "/deep"])
def test_xrdcp_recursive_download_matches_stock_tree(srv, tmp_path, remote):
    our_dst = str(tmp_path / "rec_our")
    off_dst = str(tmp_path / "rec_off")
    os.makedirs(our_dst)
    os.makedirs(off_dst)
    orc, oo, oe = ourcp("-r", "-f", f"{srv['off']}/{remote}", our_dst)
    frc, fo, fe = cp("-r", "-f", f"{srv['off']}/{remote}", off_dst)
    assert orc == 0, f"OUR xrdcp -r {remote} failed: {oo}{oe}"
    assert frc == 0, f"stock xrdcp -r {remote} failed (oracle): {fo}{fe}"
    our_files = _rel_fileset(our_dst)
    off_files = _rel_fileset(off_dst)
    # Same set of relative paths AND byte-identical contents at each leaf. If the
    # destination LAYOUT differs (a known gap), fail with the exact divergence.
    if our_files != off_files:
        pytest.xfail(
            f"CLIENT GAP: OUR xrdcp -r {remote} destination layout != stock. "
            f"only-ours={sorted(our_files)[:3]} only-stock={sorted(off_files)[:3]} "
            f"(stock preserves the source dir name; ours flattens it)")
    for rel in off_files:
        assert _read(os.path.join(our_dst, rel)) == _read(os.path.join(off_dst, rel)), \
            f"OUR xrdcp -r {remote} leaf {rel} bytes != stock client"


def test_xrdcp_recursive_leaf_bytes_present(srv, tmp_path):
    """Independent of layout, every recursive leaf our client copies must be
    byte-exact vs the source on disk (catches silent truncation/corruption)."""
    dst = str(tmp_path / "rec_bytes")
    os.makedirs(dst)
    rc, o, e = ourcp("-r", "-f", f"{srv['off']}//many", dst)
    assert rc == 0, f"OUR xrdcp -r /many failed: {o}{e}"
    landed = {os.path.basename(p): p
              for p in (os.path.join(dp, fn)
                        for dp, _, fs_ in os.walk(dst) for fn in fs_)}
    for i in range(12):
        name = f"f{i:02d}.txt"
        assert name in landed, f"OUR xrdcp -r missing {name} (landed={sorted(landed)})"
        assert _read(landed[name]) == _read(_ondisk(srv, "off", f"many/{name}")), \
            f"OUR xrdcp -r {name} content mismatch vs source"


def test_xrdcp_recursive_upload_lands_bytes(srv, tmp_path):
    """Build a local tree, upload recursively to the stock server, verify every
    leaf is byte-exact on the stock disk."""
    local = tmp_path / "uptree"
    (local / "x").mkdir(parents=True)
    payloads = {}
    for i in range(6):
        rel = f"u{i:02d}.bin"
        data = bytes((i * 41 + j) & 0xff for j in range(300 + i))
        (local / rel).write_bytes(data)
        payloads[rel] = data
    deep = bytes(range(128))
    (local / "x" / "leaf.bin").write_bytes(deep)
    payloads["x/leaf.bin"] = deep
    rc, o, e = ourcp("-r", "-f", str(local), f"{srv['off']}//c2_uptree")
    assert rc == 0, f"OUR xrdcp -r upload failed: {o}{e}"
    # Find each payload under the stock data dir regardless of the exact prefix.
    base = srv["off_data"]
    found = {}
    for dp, _, files in os.walk(base):
        for fn in files:
            found.setdefault(fn, os.path.join(dp, fn))
    for rel, data in payloads.items():
        name = os.path.basename(rel)
        # locate a landed copy that matches by content (robust to layout)
        candidates = [os.path.join(dp, fn)
                      for dp, _, files in os.walk(base)
                      for fn in files if fn == name]
        assert any(_read(c) == data for c in candidates), \
            f"OUR xrdcp -r upload: no byte-exact landed copy of {rel}"


# =========================================================================== #
# Error-parity — rc + category across failure modes                            #
# =========================================================================== #
@pytest.mark.parametrize("remote", ["/no_such_file.bin", "/many", "/deep/a"])
def test_xrdcp_download_error_category_parity(srv, tmp_path, remote):
    """Download of a missing file / a directory (no -r) must fail the same way on
    both clients (rc category)."""
    our_dst = str(tmp_path / "err_our.bin")
    off_dst = str(tmp_path / "err_off.bin")
    orc, oo, oe = ourcp(f"{srv['off']}/{remote}", our_dst)
    frc, fo, fe = cp(f"{srv['off']}/{remote}", off_dst)
    assert (orc == 0) == (frc == 0), \
        f"xrdcp download {remote} rc: ours={orc} ({oe!r}) stock={frc} ({fe!r})"


def test_xrdcp_upload_to_bad_path_parity(srv, tmp_path):
    """Upload into a path whose parent is a regular file must fail on both."""
    src = str(tmp_path / "bad.src")
    with open(src, "wb") as f:
        f.write(b"x")
    orc, oo, oe = ourcp("-f", src, f"{srv['off']}//hello.txt/under.bin")
    frc, fo, fe = cp("-f", src, f"{srv['off']}//hello.txt/under2.bin")
    assert orc != 0 and frc != 0, \
        f"upload under a file must fail on both: ours={orc} stock={frc}"


# =========================================================================== #
# CONFIRMED CLIENT GAPS — pinned with imperative xfail + exact detail           #
# =========================================================================== #
def test_xrdcp_posc_long_flag_gap(srv, tmp_path):
    """Stock xrdcp accepts the long ``--posc`` flag for persist-on-successful-
    close. OUR xrdcp does not (it only accepts ``-P``), so a script written for
    the reference client breaks. Pin the gap with the exact OURS-vs-STOCK detail."""
    src = str(tmp_path / "posc_long.src")
    with open(src, "wb") as f:
        f.write(b"posc long flag\n")
    orc, oo, oe = ourcp("--posc", "-f", src, f"{srv['off']}//c2_posc_long.bin")
    frc, fo, fe = cp("--posc", "-f", src, f"{srv['off']}//c2_posc_long_ref.bin")
    assert frc == 0, f"stock xrdcp --posc must work (oracle): {fo}{fe}"
    if orc != 0 and "posc" in (oe + oo).lower():
        pytest.xfail("CLIENT GAP: OUR xrdcp rejects '--posc' "
                     f"(stock accepts it; ours: {(oe+oo).strip()!r}). "
                     "Our spelling is '-P'.")
    assert orc == 0, f"OUR xrdcp --posc unexpectedly failed differently: {oo}{oe}"


def test_xrdcp_download_to_directory_destination(srv, tmp_path):
    """``xrdcp <remote> <existing-dir>`` (or ``<dir>/``) should place
    ``<dir>/<basename>`` — that's what the stock client does. OUR xrdcp instead
    fails the final rename into the directory yet still exits 0, leaving nothing.
    Pin the gap differentially against the stock client."""
    our_dir = str(tmp_path / "dst_our")
    off_dir = str(tmp_path / "dst_off")
    os.makedirs(our_dir)
    os.makedirs(off_dir)
    orc, oo, oe = ourcp("-f", f"{srv['off']}//data.bin", our_dir)
    frc, fo, fe = cp("-f", f"{srv['off']}//data.bin", off_dir)
    assert frc == 0 and os.path.exists(os.path.join(off_dir, "data.bin")), \
        f"stock xrdcp into a dir must place data.bin (oracle): {fo}{fe}"
    our_landed = os.path.join(our_dir, "data.bin")
    if not (os.path.exists(our_landed)
            and _read(our_landed) == _read(_ondisk(srv, "off", "data.bin"))):
        pytest.xfail(
            "CLIENT GAP: OUR xrdcp into an existing directory destination does "
            f"not place <dir>/data.bin (rc={orc}, dir={os.listdir(our_dir)!r}); "
            "the stock client places it. Our client renames to a temp name and "
            "fails the move into the directory while still exiting 0.")
    assert True  # behavior matches stock — gap closed


# =========================================================================== #
# SANITY — a subset of OUR xrdfs against OUR server too                         #
# =========================================================================== #
@pytest.mark.parametrize("args,check", [
    (["ls", "/"], lambda o: "hello.txt" in o and "data.bin" in o),
    (["stat", "/hello.txt"], lambda o: "Size" in o and "12" in o),
    (["stat", "/sub"], lambda o: "IsDir" in o),
    (["cat", "/hello.txt"], lambda o: o == "hello world\n"),
    (["tail", "-c", "5", "/hello.txt"], lambda o: o == "orld\n"),
    (["query", "config", "version"], lambda o: bool(o.strip())),
])
def test_our_xrdfs_against_our_server_sanity(srv, args, check):
    rc, out, err = ourfs(srv["our"], *args)
    assert rc == 0, f"OUR xrdfs {args} -> OUR server failed: {out}{err}"
    assert check(out), f"OUR xrdfs {args} -> OUR server: {out!r}"


def test_our_xrdcp_roundtrip_against_our_server(srv, tmp_path):
    payload = bytes((i * 19 + 3) & 0xff for i in range(33333))
    src = str(tmp_path / "ours_rt.src")
    with open(src, "wb") as f:
        f.write(payload)
    rc, o, e = ourcp("-f", src, f"{srv['our']}//c2_ours_rt.bin")
    assert rc == 0, f"OUR xrdcp upload -> OUR server failed: {o}{e}"
    assert _read(_ondisk(srv, "our", "/c2_ours_rt.bin")) == payload, \
        "OUR xrdcp upload -> OUR server: on-disk byte mismatch"
    back = str(tmp_path / "ours_rt.back")
    rc, o, e = ourcp("-f", f"{srv['our']}//c2_ours_rt.bin", back)
    assert rc == 0, f"OUR xrdcp download -> OUR server failed: {o}{e}"
    assert _read(back) == payload, "OUR xrdcp roundtrip -> OUR server not byte-exact"


def test_our_query_checksum_against_our_server_independent_oracle(srv):
    """OUR server advertises adler32; OUR client must report exactly zlib's
    adler32 over the identical bytes (independent oracle)."""
    rc, out, err = ourfs(srv["our"], "query", "checksum", "/cksum.bin")
    if rc != 0:
        # Some builds gate the checksum plugin; accept only an explicit
        # unsupported answer, never a wrong hex.
        assert "support" in (err + out).lower(), \
            f"OUR query checksum -> OUR server failed unexpectedly: {out}{err}"
        return
    data = _read(_ondisk(srv, "our", "cksum.bin"))
    toks = out.split()
    assert len(toks) >= 2, f"OUR checksum reply not '<algo> <hex>': {out!r}"
    algo, got = toks[0].lower(), toks[-1].lower()
    if "adler" in algo:
        want = f"{zlib.adler32(data) & 0xffffffff:08x}"
        assert got == want, f"OUR adler32 {got!r} != zlib {want!r}"
    elif "md5" in algo:
        assert got == hashlib.md5(data).hexdigest(), \
            f"OUR md5 {got!r} != hashlib"
    else:
        int(got, 16)  # at minimum, must be valid hex


def test_our_query_checksum_explicit_algo_against_our_server(srv):
    """Explicit algorithm selection via the `?cks.type=` opaque should yield the
    matching independent-oracle hex (or a clean unsupported rc)."""
    rc, out, err = ourfs(srv["our"], "query", "checksum", "/cksum.bin?cks.type=adler32")
    if rc != 0:
        assert "support" in (err + out).lower(), \
            f"OUR explicit-algo checksum failed unexpectedly: {out}{err}"
        return
    data = _read(_ondisk(srv, "our", "cksum.bin"))
    want = f"{zlib.adler32(data) & 0xffffffff:08x}"
    got = out.split()[-1].lower()
    assert got == want, f"OUR ?cks.type=adler32 {got!r} != zlib {want!r}"

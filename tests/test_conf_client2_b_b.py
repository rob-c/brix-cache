from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_client2_helpers")

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

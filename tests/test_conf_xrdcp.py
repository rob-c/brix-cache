from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_xrdcp_helpers")

pytestmark = pytest.mark.xdist_group("conf_xrdcp")

@pytest.mark.parametrize("name", ["data.bin", "sz_4096.bin", "hello.txt"])
def test_force_overwrite_download(srv, tmp_path, name):
    dst = str(tmp_path / f"force_{name}")
    with open(dst, "wb") as f:
        f.write(b"STALE pre-existing junk that must be replaced")
    want = _src_bytes(srv, name)
    for attempt in (1, 2):  # second pass overwrites the freshly-correct file
        rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst, "-f")
        assert rc == 0, (f"xrdcp -f (pass {attempt}) {name} <- OUR server "
                         f"failed: {out}{err}")
        assert _read(dst) == want, (
            f"xrdcp -f (pass {attempt}) {name}: overwritten bytes != source")


def test_force_required_for_existing_target(srv, tmp_path):
    """Without -f to an existing local target, xrdcp must refuse (it does not
    silently clobber). Pin that our server's download obeys the same rule the
    stock server does — same rc class for both."""
    dst = str(tmp_path / "noforce.bin")
    open(dst, "wb").write(b"already here")
    rc_our, o1, e1 = _download(L.OFF_XRDCP, srv["our"], "data.bin", dst)
    rc_off, o2, e2 = _download(L.OFF_XRDCP, srv["off"], "data.bin", dst)
    assert (rc_our == 0) == (rc_off == 0), (
        f"no-force-to-existing diverges: OUR rc={rc_our} STOCK rc={rc_off} "
        f"(our={o1}{e1} stock={o2}{e2})")
    # whatever the rc, the original local file must be intact (no partial clobber)
    assert _read(dst) == b"already here", "no-force download clobbered the target"


# =========================================================================== #
# OPTION: -N / -s / default(progress) — output-mode flags must never affect    #
# the bytes delivered. Parametrize across files and modes; integrity is exact. #
# =========================================================================== #
@pytest.mark.parametrize("mode", ["-N", "-s", "--nopbar", "--silent", "default"])
@pytest.mark.parametrize("name", ["data.bin", "sz_65536.bin", "hello.txt"])
def test_output_mode_integrity(srv, tmp_path, mode, name):
    dst = str(tmp_path / f"mode_{mode.strip('-')}_{name}")
    opts = ["-f"] if mode == "default" else [mode, "-f"]
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst, *opts,
                             timeout=_timeout_for(name))
    assert rc == 0, f"xrdcp {mode} {name} <- OUR server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, name), (
        f"xrdcp {mode} {name}: output-mode flag altered the bytes")


# =========================================================================== #
# OPTION: -f upload — local -> server, byte-exact on disk; and no-force        #
# upload-to-existing parity vs stock.                                          #
# =========================================================================== #
def test_force_overwrite_upload(srv, tmp_path):
    src = str(tmp_path / "up_force.src")
    payload = bytes((i * 53 + 3) & 0xff for i in range(4321))
    open(src, "wb").write(payload)
    remote = "/up_force.bin"
    on_disk = os.path.join(srv["our_data"], "up_force.bin")
    # seed a different prior object so -f must truly overwrite
    open(on_disk, "wb").write(b"prior server-side contents")
    rc, out, err = _cp(L.OFF_XRDCP, "-f", src, f"{srv['our']}/{remote}")
    assert rc == 0, f"xrdcp -f upload to OUR server failed: {out}{err}"
    assert _read(on_disk) == payload, "xrdcp -f upload: server bytes != source"


def test_noforce_upload_to_existing_parity(srv, tmp_path):
    """Upload (no -f) onto a pre-existing remote object: our server and the
    stock server must give the same rc class; neither silently corrupts."""
    src = str(tmp_path / "up_noforce.src")
    payload = bytes((i * 7 + 9) & 0xff for i in range(1500))
    open(src, "wb").write(payload)
    # pre-create the destination on BOTH servers
    for data_dir, ext in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        open(os.path.join(data_dir, "noforce_up.bin"), "wb").write(b"existing\n")
    rc_our, o1, e1 = _cp(L.OFF_XRDCP, src, f"{srv['our']}//noforce_up.bin")
    rc_off, o2, e2 = _cp(L.OFF_XRDCP, src, f"{srv['off']}//noforce_up.bin")
    assert (rc_our == 0) == (rc_off == 0), (
        f"no-force upload-to-existing diverges: OUR rc={rc_our} "
        f"STOCK rc={rc_off} (our={o1}{e1} stock={o2}{e2})")


# =========================================================================== #
# OPTION: missing-parent creation — uploading to a path whose parent dir does  #
# not exist. The reference server auto-creates the path (verified in sibling   #
# tests); ours must too, with and without an explicit -p/--path (MakeDir).     #
# =========================================================================== #
@pytest.mark.parametrize("flag", ["none", "-p", "--path"])
def test_upload_missing_parent_creates_path(srv, tmp_path, flag):
    src, payload, sub, remote, opts = _missing_parent_case(tmp_path, flag)
    rc, out, err = _cp(L.OFF_XRDCP, "-f", *opts, src, f"{srv['our']}/{remote}",
                       timeout=90)
    _assert_missing_parent_upload(rc, out, err, flag)
    on_disk = os.path.join(srv["our_data"], sub, "a", "b", "file.bin")
    _assert_missing_parent_file(on_disk, payload, flag)


def _missing_parent_case(tmp_path, flag):
    suffix = flag.strip("-") or "none"
    source = str(tmp_path / f"mkpath_{suffix}.src")
    payload = bytes((index * 11 + 2) & 0xff for index in range(900))
    open(source, "wb").write(payload)
    subdirectory = f"mkparent_{suffix}"
    remote = f"/{subdirectory}/a/b/file.bin"
    options = [] if flag == "none" else [flag]
    return source, payload, subdirectory, remote, options


def _assert_missing_parent_upload(rc, output, error, flag):
    assert rc == 0, (f"xrdcp upload (flag={flag}) to a missing parent on OUR "
                     f"server failed: {output}{error}")


def _assert_missing_parent_file(path, payload, flag):
    assert os.path.exists(path), (
        f"xrdcp upload (flag={flag}): missing-parent path was not created")
    _assert_file_payload(path, payload, flag)


def _assert_file_payload(path, payload, flag):
    assert _read(path) == payload, (
        f"xrdcp upload (flag={flag}): bytes under created path != source")


def test_upload_missing_parent_parity_stock(srv, tmp_path):
    """Differential: the SAME missing-parent upload must land on both servers
    (the stock server is the oracle for auto-mkpath)."""
    src = str(tmp_path / "mkpath_diff.src")
    payload = bytes((i * 19 + 4) & 0xff for i in range(640))
    open(src, "wb").write(payload)
    results = {}
    for url, ext, data_dir in ((srv["our"], "our", srv["our_data"]),
                               (srv["off"], "off", srv["off_data"])):
        rc, out, err = _cp(L.OFF_XRDCP, "-f", src,
                           f"{url}//mkdiff/deep/here.bin")
        landed = os.path.join(data_dir, "mkdiff", "deep", "here.bin")
        results[ext] = (rc, os.path.exists(landed) and _read(landed) == payload)
    assert results["our"] == results["off"], (
        f"missing-parent upload diverges OUR={results['our']} "
        f"STOCK={results['off']}")


# =========================================================================== #
# OPTION: --posc (Persist-On-Successful-Close) — a successful upload must       #
# persist the object exactly.                                                  #
# =========================================================================== #
def test_posc_upload_persists(srv, tmp_path):
    src = str(tmp_path / "posc.src")
    payload = bytes((i * 7 + 1) & 0xff for i in range(5000))
    open(src, "wb").write(payload)
    rc, out, err = _cp(L.OFF_XRDCP, "--posc", "-f", src,
                       f"{srv['our']}//posc_ok.bin")
    assert rc == 0, f"xrdcp --posc upload to OUR server failed: {out}{err}"
    on_disk = os.path.join(srv["our_data"], "posc_ok.bin")
    assert os.path.exists(on_disk), "xrdcp --posc: object not persisted"
    assert _read(on_disk) == payload, "xrdcp --posc: persisted bytes != source"


def test_posc_upload_parity_stock(srv, tmp_path):
    """--posc on a clean transfer must succeed on our server exactly as on the
    stock server (differential rc + landed bytes)."""
    src = str(tmp_path / "posc_diff.src")
    payload = bytes((i * 23 + 6) & 0xff for i in range(3333))
    open(src, "wb").write(payload)
    out = {}
    for url, ext, data_dir in ((srv["our"], "our", srv["our_data"]),
                               (srv["off"], "off", srv["off_data"])):
        rc, o, e = _cp(L.OFF_XRDCP, "--posc", "-f", src,
                       f"{url}//posc_diff.bin")
        landed = os.path.join(data_dir, "posc_diff.bin")
        out[ext] = (rc, os.path.exists(landed) and _read(landed) == payload)
    assert out["our"] == out["off"], (
        f"--posc upload diverges OUR={out['our']} STOCK={out['off']}")


# =========================================================================== #
# OPTION: --cksum adler32:source — the client re-checksums received bytes and  #
# compares to the server's advertised checksum. SUCCESS or a clean unsupported #
# build is fine; a checksum MISMATCH is never tolerated (it means corruption). #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin", "sz_4096.bin",
                                  "hello.txt"])
def test_cksum_source_verify(srv, tmp_path, name):
    dst = str(tmp_path / f"cksum_src_{name}")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst,
                             "-f", "--cksum", "adler32:source")
    blob = (out + err).lower()
    assert "mismatch" not in blob, (
        f"xrdcp --cksum adler32:source {name} <- OUR server reported a "
        f"checksum MISMATCH (read corruption): {out}{err}")
    if rc == 0:
        assert _read(dst) == _src_bytes(srv, name), (
            f"--cksum transfer of {name} reported rc=0 but bytes differ")
    else:
        # Not a mismatch, so this is an unsupported-checksum build: surface it.
        assert _unsupported(out, err) or "checksum" in blob, (
            f"--cksum {name} failed for a non-checksum reason: {out}{err}")


@pytest.mark.parametrize("name", ["data.bin", "cksum.bin"])
def test_cksum_source_diff_our_vs_stock(srv, tmp_path, name):
    """The same --cksum-verified download from OUR vs the STOCK server must
    yield identical bytes (when both succeed)."""
    a = str(tmp_path / f"cks_our_{name}")
    b = str(tmp_path / f"cks_off_{name}")
    rc_a, oa, ea = _download(L.OFF_XRDCP, srv["our"], name, a, "-f",
                             "--cksum", "adler32:source")
    rc_b, ob, eb = _download(L.OFF_XRDCP, srv["off"], name, b, "-f",
                             "--cksum", "adler32:source")
    assert "mismatch" not in (oa + ea).lower(), (
        f"--cksum {name} mismatch from OUR server: {oa}{ea}")
    if rc_a == 0 and rc_b == 0:
        assert _read(a) == _read(b), (
            f"--cksum {name}: OUR and STOCK downloads differ in bytes")


# =========================================================================== #
# OPTION: --cksum adler32:print — print a locally-computed checksum. The value #
# must equal zlib.adler32 over the source bytes.                               #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin", "hello.txt"])
def test_cksum_print_value(srv, tmp_path, name):
    dst = str(tmp_path / f"cksum_print_{name}")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst,
                             "-f", "--cksum", "adler32:print")
    blob = (out + err)
    if rc != 0:
        assert "mismatch" not in blob.lower(), (
            f"--cksum print {name}: checksum mismatch reported: {blob}")
        assert _unsupported(out, err) or "checksum" in blob.lower(), (
            f"--cksum adler32:print {name} failed unexpectedly: {blob}")
        return
    want = _adler_hex(_src_bytes(srv, name))
    assert want in blob.lower(), (
        f"--cksum adler32:print {name}: expected adler32 {want} not in "
        f"output: {blob!r}")
    # the downloaded bytes must still be exact
    assert _read(dst) == _src_bytes(srv, name), (
        f"--cksum print {name}: downloaded bytes != source")


# =========================================================================== #
# OPTION: -r / --recursive — DOWNLOAD a directory tree, all leaves byte-exact. #
# =========================================================================== #
def test_recursive_download_many(srv, tmp_path):
    dst = str(tmp_path / "rec_many")
    os.makedirs(dst)
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "many", dst, "-r", "-f",
                             timeout=120)
    assert rc == 0, f"xrdcp -r /many <- OUR server failed: {out}{err}"
    landed = os.path.join(dst, "many")
    for i in range(12):
        fp = os.path.join(landed, f"f{i:02d}.txt")
        assert os.path.exists(fp), f"recursive /many missing f{i:02d}.txt"
        assert _read(fp) == _src_bytes(srv, os.path.join("many", f"f{i:02d}.txt")), (
            f"recursive /many: f{i:02d}.txt content mismatch")


def test_recursive_download_deep_relpath(srv, tmp_path):
    dst = str(tmp_path / "rec_deep")
    os.makedirs(dst)
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "deep", dst, "-r", "-f",
                             timeout=120)
    assert rc == 0, f"xrdcp -r /deep <- OUR server failed: {out}{err}"
    leaf = os.path.join(dst, "deep", "a", "b", "c", "leaf.txt")
    assert os.path.exists(leaf), (
        f"recursive /deep: leaf not at the right relative path: {out}{err}")
    assert _read(leaf) == _src_bytes(
        srv, os.path.join("deep", "a", "b", "c", "leaf.txt")), (
        "recursive /deep: leaf content mismatch")


def test_recursive_download_whole_tree(srv, tmp_path):
    """`-r` of the whole namespace: every known leaf must land byte-exact.

    The reference selects the export root with a "." path component
    (root://host//.); the bare root://host// form is rejected by xrdcp itself
    on BOTH servers (confirmed: same "Invalid arguments"), so we use the form
    the stock toolchain accepts.
    """
    expected = _whole_tree_leaves()
    found, diagnostic = _download_whole_tree(srv, tmp_path, expected)
    _assert_whole_tree_present(found, expected, diagnostic)
    _assert_whole_tree_digests(srv, found)


def _whole_tree_leaves():
    leaves = ["hello.txt", "data.bin", "cksum.bin", "empty.txt",
              os.path.join("sub", "nested.txt"),
              os.path.join("deep", "a", "b", "c", "leaf.txt")]
    leaves.extend(os.path.join("many", f"f{i:02d}.txt") for i in range(12))
    return leaves


def _download_whole_tree(srv, tmp_path, expected):
    found, diagnostic = {}, "not attempted"
    for attempt in (1, 2):
        L.reset_to_seeded_tree(srv["our_data"], srv["off_data"])
        destination = str(tmp_path / f"rec_root{attempt}")
        os.makedirs(destination)
        rc, out, err = _download(L.OFF_XRDCP, srv["our"], ".", destination,
                                 "-r", "-f", timeout=180)
        found = _files_by_basename(destination)
        diagnostic = f"rc={rc}: {out}{err}"
        if _all_leaves_present(found, expected):
            break
    return found, diagnostic


def _files_by_basename(root):
    found = {}
    for root_dir, _dirs, files in os.walk(root):
        for filename in files:
            path = os.path.join(root_dir, filename)
            found.setdefault(filename, []).append(path)
    return found


def _all_leaves_present(found, expected):
    return all(os.path.basename(relative) in found for relative in expected)


def _assert_whole_tree_present(found, expected, diagnostic):
    missing = [relative for relative in expected
               if os.path.basename(relative) not in found]
    assert not missing, (
        f"whole-tree recursive copy missing {missing} after 2 attempts ({diagnostic})")


def _assert_whole_tree_digests(srv, found):
    representatives = ["data.bin", "cksum.bin",
                       os.path.join("deep", "a", "b", "c", "leaf.txt")]
    for relative in representatives:
        _assert_leaf_digest(srv, found, relative)


def _assert_leaf_digest(srv, found, relative):
    expected = _md5(_src_bytes(srv, relative))
    actual = {_md5(_read(path)) for path in found[os.path.basename(relative)]}
    assert expected in actual, (
        f"whole-tree recursive copy: {relative} md5 {expected} not among {actual}")


# =========================================================================== #
# OPTION: -r recursive UPLOAD of a local tree to the server, byte-exact.       #
# =========================================================================== #
def test_recursive_upload_tree(srv, tmp_path):
    local = str(tmp_path / "uptree")
    os.makedirs(local)
    files = _make_local_tree(local)
    remote_dir = "rec_up"
    # Recursive multi-source upload requires an EXISTING directory target —
    # stock xrdcp stats the destination and refuses "Multiple sources were
    # given but target is not a directory" on a fresh path even with the
    # trailing slash (measured against the reference server too), so create
    # it first exactly as an operator must.
    rc, out, err = _cp(L.OFF_XRDFS, srv["our"], "mkdir", f"/{remote_dir}",
                       timeout=60)
    assert rc == 0 or "exists" in (out + err).lower(), \
        f"mkdir /{remote_dir} failed: {out}{err}"
    rc, out, err = _cp(L.OFF_XRDCP, "-r", "-f", local,
                       f"{srv['our']}//{remote_dir}/", timeout=120)
    assert rc == 0, f"xrdcp -r upload to OUR server failed: {out}{err}"
    # xrdcp places the source dir's basename under the destination
    landed_root = os.path.join(srv["our_data"], remote_dir, os.path.basename(local))
    for rel, data in files.items():
        fp = os.path.join(landed_root, rel)
        assert os.path.exists(fp), f"recursive upload missing {rel} (at {fp})"
        assert _read(fp) == data, f"recursive upload {rel}: bytes != source"


# =========================================================================== #
# OPTION: -S / --streams N — multi-stream download. The byte payload must be   #
# exact regardless of stream count. If the build rejects the option, assert it #
# did NOT corrupt data (any bytes produced are exact) and report it.           #
# =========================================================================== #
@pytest.mark.parametrize("flag", ["-S", "--streams"])
@pytest.mark.parametrize("n", [2, 4])
def test_multistream_download(srv, tmp_path, flag, n):
    name = "big1m.bin"
    dst = str(tmp_path / f"ms_{flag.strip('-')}_{n}.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst, "-f",
                             flag, str(n), timeout=180)
    want = _src_bytes(srv, name)
    if rc == 0:
        assert _read(dst) == want, (
            f"multi-stream {flag} {n} {name}: byte mismatch (corruption)")
    else:
        # Option not honoured by this build: never tolerate corruption.
        if os.path.exists(dst) and os.path.getsize(dst) > 0:
            assert _read(dst) == want, (
                f"multi-stream {flag} {n}: nonzero rc AND wrong bytes "
                f"= data corruption: {out}{err}")
        assert _unsupported(out, err) or "stream" in (out + err).lower(), (
            f"multi-stream {flag} {n} failed for a non-stream reason: {out}{err}")


def test_multistream_diff_our_vs_stock(srv, tmp_path):
    """Same -S 4 download from OUR vs STOCK server: when both succeed, bytes
    must be identical."""
    a = str(tmp_path / "ms_our.bin")
    b = str(tmp_path / "ms_off.bin")
    rc_a, oa, ea = _download(L.OFF_XRDCP, srv["our"], "big1m.bin", a, "-f",
                             "-S", "4", timeout=180)
    rc_b, ob, eb = _download(L.OFF_XRDCP, srv["off"], "big1m.bin", b, "-f",
                             "-S", "4", timeout=180)
    if rc_a == 0 and rc_b == 0:
        assert _read(a) == _read(b), (
            "multi-stream -S 4: OUR and STOCK downloads differ in bytes")


# =========================================================================== #
# OPTION: download to stdout ("-").                                            #
# =========================================================================== #
def test_download_to_stdout(srv):
    rc, out, err = _cp(L.OFF_XRDCP, "-f", f"{srv['our']}//hello.txt", "-")
    assert rc == 0, f"xrdcp -> stdout from OUR server failed: {err}"
    assert "hello world" in out, f"stdout payload wrong: {out!r}"

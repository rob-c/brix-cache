from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_xrdcp_helpers")

pytestmark = pytest.mark.xdist_group("conf_xrdcp_b")

def test_download_to_stdout_binary_exact(srv):
    """A binary file delivered to stdout must be byte-exact (capture raw)."""
    r = subprocess.run([L.OFF_XRDCP, "-f", f"{srv['our']}//sz_4096.bin", "-"],
                       capture_output=True, timeout=90)
    assert r.returncode == 0, f"xrdcp binary -> stdout failed: {r.stderr!r}"
    assert r.stdout == _src_bytes(srv, "sz_4096.bin"), (
        "xrdcp binary -> stdout: byte mismatch vs source")


# =========================================================================== #
# OPTION: upload from stdin ("-" source). xrdcp DISALLOWS stdin as a source    #
# (XrdCpConfig.cc: "Using stdin as a source is disallowed."). Pin that our     #
# server's behaviour matches the stock server's for this input.               #
# =========================================================================== #
def test_upload_from_stdin_parity(srv):
    payload = b"piped-in-content\n"
    res = {}
    for url, ext in ((srv["our"], "our"), (srv["off"], "off")):
        r = subprocess.run([L.OFF_XRDCP, "-f", "-", f"{url}//stdin_up.bin"],
                           input=payload, capture_output=True, timeout=90)
        res[ext] = r.returncode
    # xrdcp rejects stdin sources outright; both servers see the same outcome.
    assert (res["our"] == 0) == (res["off"] == 0), (
        f"stdin-source upload diverges: OUR rc={res['our']} STOCK rc={res['off']}")


# =========================================================================== #
# Empty file — 0-byte up/download must succeed and produce a 0-byte object.    #
# =========================================================================== #
def test_empty_file_download(srv, tmp_path):
    dst = str(tmp_path / "empty_dl.txt")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "empty.txt", dst, "-f")
    assert rc == 0, f"xrdcp empty.txt download <- OUR server failed: {out}{err}"
    assert os.path.getsize(dst) == 0, (
        f"empty download produced {os.path.getsize(dst)} bytes, want 0")


def test_empty_file_upload(srv, tmp_path):
    src = str(tmp_path / "empty_up.src")
    open(src, "wb").close()
    rc, out, err = _cp(L.OFF_XRDCP, "-f", src, f"{srv['our']}//empty_up.bin")
    assert rc == 0, f"xrdcp empty upload to OUR server failed: {out}{err}"
    on_disk = os.path.join(srv["our_data"], "empty_up.bin")
    assert os.path.exists(on_disk) and os.path.getsize(on_disk) == 0, (
        "empty upload did not land as a 0-byte object")


# =========================================================================== #
# Round-trip — 1 MiB upload then download; md5 stable across the round trip.   #
# =========================================================================== #
def test_big_roundtrip_md5_stable(srv, tmp_path):
    big = bytes((i * 2654435761) & 0xff for i in range(1024 * 1024))
    src = str(tmp_path / "rt_big.src")
    open(src, "wb").write(big)
    up_md5 = _md5(big)
    rc, o, e = _cp(L.OFF_XRDCP, "-f", src, f"{srv['our']}//rt_big.bin",
                   timeout=180)
    assert rc == 0, f"round-trip upload to OUR server failed: {o}{e}"
    dl = str(tmp_path / "rt_big.dl")
    rc, o, e = _download(L.OFF_XRDCP, srv["our"], "rt_big.bin", dl, "-f",
                         timeout=180)
    assert rc == 0, f"round-trip download from OUR server failed: {o}{e}"
    assert _md5(_read(dl)) == up_md5, (
        "1 MiB round-trip md5 changed across upload+download")


# =========================================================================== #
# OPTION: --retry N on a healthy transfer — still rc==0 and byte-exact.        #
# =========================================================================== #
@pytest.mark.parametrize("n", ["1", "3"])
def test_retry_on_good_transfer(srv, tmp_path, n):
    dst = str(tmp_path / f"retry_{n}.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "data.bin", dst, "-f",
                             "--retry", n)
    if rc != 0 and _unsupported(out, err):
        pytest.skip(f"--retry unsupported by this xrdcp build: {err.strip()}")
    assert rc == 0, f"xrdcp --retry {n} <- OUR server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, "data.bin"), (
        f"xrdcp --retry {n}: byte mismatch")


# =========================================================================== #
# DIFFERENTIAL — same flags, same file, OUR vs STOCK server -> identical bytes.#
# =========================================================================== #
@pytest.mark.parametrize("name,flags", [
    ("data.bin", ["-f"]),
    ("sz_65536.bin", ["-f", "-N"]),
    ("cksum.bin", ["-f", "-s"]),
    ("hello.txt", ["-f"]),
    ("big1m.bin", ["-f"]),
    ("empty.txt", ["-f"]),
    ("sz_4097.bin", ["-f", "--nopbar"]),
])
def test_diff_download_same_bytes(srv, tmp_path, name, flags):
    a = str(tmp_path / f"diff_our_{name}")
    b = str(tmp_path / f"diff_off_{name}")
    t = _timeout_for(name)
    rc_a, oa, ea = _download(L.OFF_XRDCP, srv["our"], name, a, *flags, timeout=t)
    rc_b, ob, eb = _download(L.OFF_XRDCP, srv["off"], name, b, *flags, timeout=t)
    assert rc_a == 0, f"download {name} {flags} from OUR server failed: {oa}{ea}"
    assert rc_b == 0, f"download {name} {flags} from STOCK server failed: {ob}{eb}"
    assert _read(a) == _read(b), (
        f"xrdcp {flags} got different bytes for {name} from the two servers")


# =========================================================================== #
# Q2 — OUR xrdcp client against the STOCK server: option breadth + integrity.  #
# A divergence here is a BUG IN OUR CLIENT; the stock server is the oracle.    #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "sz_65536.bin", "hello.txt",
                                  "big1m.bin"])
def test_q2_our_client_download(srv, tmp_path, name):
    _require_our_client()
    dst = str(tmp_path / f"q2dl_{name}")
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], name, dst, "-f",
                             timeout=_timeout_for(name))
    assert rc == 0, f"OUR xrdcp {name} <- stock server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, name), (
        f"OUR xrdcp download {name}: byte mismatch vs stock source")


@pytest.mark.parametrize("mode", ["-N", "-s"])
def test_q2_our_client_output_modes(srv, tmp_path, mode):
    _require_our_client()
    dst = str(tmp_path / f"q2mode_{mode.strip('-')}.bin")
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], "data.bin", dst, mode, "-f")
    _skip_unsupported(rc, out, err, f"OUR xrdcp lacks {mode}: {err.strip()}")
    assert rc == 0, f"OUR xrdcp {mode} <- stock server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, "data.bin"), (
        f"OUR xrdcp {mode}: output-mode flag altered the bytes")


@pytest.mark.parametrize("size", [0, 1, 4096, 65537])
def test_q2_our_client_upload(srv, tmp_path, size):
    _require_our_client()
    payload = bytes((i * 31 + size) & 0xff for i in range(size))
    src = str(tmp_path / f"q2up_{size}.src")
    open(src, "wb").write(payload)
    remote = f"/q2up_{size}.bin"
    rc, out, err = _cp(L.OUR_XRDCP, "-f", src, f"{srv['off']}/{remote}",
                       timeout=120)
    assert rc == 0, f"OUR xrdcp upload size={size} -> stock failed: {out}{err}"
    on_disk = os.path.join(srv["off_data"], remote.lstrip("/"))
    assert os.path.exists(on_disk), f"OUR upload size={size} did not land on stock"
    assert _read(on_disk) == payload, (
        f"OUR xrdcp upload size={size}: byte mismatch on stock disk")


def test_q2_our_client_recursive_download(srv, tmp_path):
    _require_our_client()
    dst = str(tmp_path / "q2_rec_many")
    os.makedirs(dst)
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], "many", dst, "-r", "-f",
                             timeout=120)
    _skip_unsupported(rc, out, err,
                      f"OUR xrdcp lacks recursive copy: {err.strip()}")
    assert rc == 0, f"OUR xrdcp -r /many <- stock server failed: {out}{err}"
    # find every f??.txt that landed, anywhere under dst, and verify it
    found = _recursive_files(dst)
    for i in range(12):
        fn = f"f{i:02d}.txt"
        _assert_recursive_file(srv, found, fn, out, err)


def test_q2_our_client_stdout(srv):
    _require_our_client()
    rc, out, err = _cp(L.OUR_XRDCP, "-f", f"{srv['off']}//hello.txt", "-")
    _skip_unsupported(rc, out, err,
                      f"OUR xrdcp lacks stdout sink: {err.strip()}")
    assert rc == 0, f"OUR xrdcp -> stdout from stock server failed: {err}"
    assert "hello world" in out, f"OUR stdout payload wrong: {out!r}"


def _require_our_client():
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")


def _skip_unsupported(returncode, stdout, stderr, message):
    if returncode != 0 and _unsupported(stdout, stderr):
        pytest.skip(message)


def _recursive_files(directory):
    found = {}
    for root_dir, _directories, files in os.walk(directory):
        for filename in files:
            found[filename] = os.path.join(root_dir, filename)
    return found


def _assert_recursive_file(srv, found, filename, stdout, stderr):
    assert filename in found, (
        f"OUR recursive /many missing {filename}: {stdout}{stderr}")
    expected = _src_bytes(srv, os.path.join("many", filename))
    assert _read(found[filename]) == expected, (
        f"OUR recursive /many: {filename} content mismatch")


# =========================================================================== #
# Oracle — stock client against stock server (proves the tooling is sound; a   #
# failure here is environmental, not ours).                                    #
# =========================================================================== #
def test_oracle_stock_to_stock(srv, tmp_path):
    dst = str(tmp_path / "oracle.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["off"], "data.bin", dst, "-f")
    assert rc == 0, f"oracle stock->stock failed (tooling broken): {out}{err}"
    assert _read(dst) == _src_bytes(srv, "data.bin")


def test_oracle_stock_recursive(srv, tmp_path):
    dst = str(tmp_path / "oracle_rec")
    os.makedirs(dst)
    rc, out, err = _download(L.OFF_XRDCP, srv["off"], "many", dst, "-r", "-f",
                             timeout=120)
    assert rc == 0, f"oracle stock recursive failed (tooling broken): {out}{err}"
    assert os.path.exists(os.path.join(dst, "many", "f00.txt"))

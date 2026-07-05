"""Conformance: OUR native client vs the STOCK xrootd server (Q2), plus STOCK
xrdcp option variations against OUR server (Q3 breadth).

Philosophy (per the maintainer): a divergence is a bug in THIS implementation
unless there is positive evidence otherwise.

  * Q2  — OUR xrdfs/xrdcp (client/bin/) against the STOCK xrootd data server.
           A failure here is a BUG IN OUR CLIENT — these tests pin the correct
           behavior the reference server demands.
  * Q3  — STOCK xrdcp option flavors (-f/-N/-s/--posc/-r) against OUR server.
           A failure here is a BUG IN OUR SERVER — the reference client's
           transfer options must all work end to end.

Where possible the assertion is DIFFERENTIAL: our client's result is compared
against the stock client's result on the same stock server, so the oracle is
the reference toolchain itself rather than a hard-coded expectation.

Both servers run on identical rich data trees (see official_interop_lib):
  /hello.txt /data.bin(4096) /sub/nested.txt /empty.txt(0) /many/f00..f11
  /deep/a/b/c/leaf.txt /sz_4096.bin /sz_65536.bin /big1m.bin(1MB)
  "/with space.txt" /cksum.bin(10000)

Self-provisioning on high ports; skips entirely without the stock toolchain.
"""

import os

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Module fixture: our server + stock server on identical rich trees.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confclient"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14012), off_port=L.worker_port(14013))
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def ourfs(url, *args, timeout=60):
    return L.run([L.OUR_XRDFS, url, *args], timeout=timeout)


def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def _names(out):
    return {os.path.basename(l.strip()) for l in out.splitlines() if l.strip()}


def _stat_fields(out):
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def _read(p):
    with open(p, "rb") as f:
        return f.read()


# =========================================================================== #
# Q2 — OUR xrdfs LISTING against the STOCK server
# =========================================================================== #
@pytest.mark.parametrize("path,expect", [
    ("/", {"hello.txt", "data.bin", "sub", "many", "deep", "cksum.bin"}),
    ("/sub", {"nested.txt"}),
    ("/many", {f"f{i:02d}.txt" for i in range(12)}),
    ("/deep", {"a"}),
])
def test_q2_our_ls(srv, path, expect):
    rc, out, err = ourfs(srv["off"], "ls", path)
    assert rc == 0, f"OUR xrdfs ls {path} -> stock server failed: {out}{err}"
    got = _names(out)
    assert expect <= got, f"OUR ls {path}: missing {expect - got} (got {got})"


def test_q2_our_ls_long_has_sizes(srv):
    rc, out, err = ourfs(srv["off"], "ls", "-l", "/")
    assert rc == 0, f"OUR xrdfs ls -l failed: {out}{err}"
    assert any("4096" in l and "data.bin" in l for l in out.splitlines()), \
        f"OUR ls -l did not carry data.bin's 4096 size: {out!r}"
    assert any("1048576" in l and "big1m.bin" in l for l in out.splitlines()), \
        f"OUR ls -l did not carry big1m.bin's 1 MiB size: {out!r}"


# =========================================================================== #
# Q2 — OUR xrdfs STAT against the STOCK server (sizes must be exact)
# =========================================================================== #
@pytest.mark.parametrize("path,size", [
    ("/hello.txt", 12),
    ("/data.bin", 4096),
    ("/empty.txt", 0),
    ("/sz_65536.bin", 65536),
    ("/big1m.bin", 1024 * 1024),
    ("/cksum.bin", 10000),
])
def test_q2_our_stat_file_size(srv, path, size):
    rc, out, err = ourfs(srv["off"], "stat", path)
    assert rc == 0, f"OUR xrdfs stat {path} -> stock server failed: {out}{err}"
    fields = _stat_fields(out)
    assert fields.get("Size") == str(size), \
        f"OUR stat {path}: Size {fields.get('Size')!r} != {size}"


@pytest.mark.parametrize("path", ["/sub", "/many", "/deep"])
def test_q2_our_stat_dir_is_isdir(srv, path):
    rc, out, err = ourfs(srv["off"], "stat", path)
    assert rc == 0, f"OUR xrdfs stat {path} -> stock server failed: {out}{err}"
    fields = _stat_fields(out)
    assert "IsDir" in fields.get("Flags", ""), \
        f"OUR stat {path}: dir not flagged IsDir (Flags={fields.get('Flags')!r})"


def test_q2_our_statvfs(srv):
    rc, out, err = ourfs(srv["off"], "statvfs", "/")
    assert rc == 0, f"OUR xrdfs statvfs / -> stock server failed: {out}{err}"
    assert out.strip(), "OUR statvfs produced no output"


def test_q2_our_locate(srv):
    rc, out, err = ourfs(srv["off"], "locate", "/hello.txt")
    assert rc == 0, f"OUR xrdfs locate -> stock server failed: {out}{err}"
    assert out.strip(), "OUR locate produced no output"


# =========================================================================== #
# Q2 — OUR xrdfs CAT against the STOCK server
# =========================================================================== #
def test_q2_our_cat_text(srv):
    rc, out, err = ourfs(srv["off"], "cat", "/hello.txt")
    assert rc == 0, f"OUR xrdfs cat -> stock server failed: {out}{err}"
    assert "hello world" in out, f"OUR cat /hello.txt: {out!r}"


def test_q2_our_cat_binary_rc(srv):
    # Binary payload on stdout: capture as raw bytes (text mode would choke on
    # non-UTF-8). rc==0 + exact bytes vs the stock source pins correct behavior.
    import subprocess
    r = subprocess.run([L.OUR_XRDFS, srv["off"], "cat", "/sz_4096.bin"],
                       capture_output=True, timeout=60)
    assert r.returncode == 0, \
        f"OUR xrdfs cat /sz_4096.bin -> stock server failed: {r.stderr!r}"
    assert r.stdout == _read(os.path.join(srv["off_data"], "sz_4096.bin")), \
        "OUR xrdfs cat /sz_4096.bin: byte mismatch vs stock source"


# =========================================================================== #
# Q2 — OUR xrdfs QUERY CONFIG against the STOCK server
# =========================================================================== #
@pytest.mark.parametrize("key", ["bind_max", "readv_iov_max", "chksum", "tpc"])
def test_q2_our_query_config(srv, key):
    rc, out, err = ourfs(srv["off"], "query", "config", key)
    assert rc == 0, f"OUR xrdfs query config {key} -> stock server failed: {out}{err}"


# =========================================================================== #
# Q2 — checksum, DIFFERENTIAL against the stock client on the stock server.
# The stock server may or may not advertise a checksum; whatever it answers,
# OUR client must agree with the reference client (same rc; same hex if any).
# =========================================================================== #
def test_q2_our_query_checksum_matches_stock_client(srv):
    our_rc, our_out, _ = ourfs(srv["off"], "query", "checksum", "/cksum.bin")
    off_rc, off_out, _ = fs(srv["off"], "query", "checksum", "/cksum.bin")
    # both query the SAME stock server: divergence == bug in our client.
    assert (our_rc == 0) == (off_rc == 0), \
        f"OUR client checksum rc={our_rc} disagrees with stock client rc={off_rc}"
    if our_rc == 0 and off_rc == 0:
        our_hex = our_out.split()[-1] if our_out.split() else ""
        off_hex = off_out.split()[-1] if off_out.split() else ""
        assert len(our_out.split()) >= 2, \
            f"OUR checksum reply not '<algo> <hex>': {our_out!r}"
        assert our_hex == off_hex, \
            f"OUR client checksum hex {our_hex!r} != stock client {off_hex!r}"


# =========================================================================== #
# Q2 — OUR xrdcp DOWNLOAD from the STOCK server (byte-identical to source)
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "sz_65536.bin", "big1m.bin"])
def test_q2_our_xrdcp_download(srv, tmp_path, name):
    dst = str(tmp_path / f"dl_{name}")
    rc, out, err = L.run([L.OUR_XRDCP, "-f", f"{srv['off']}//{name}", dst],
                         timeout=120)
    assert rc == 0, f"OUR xrdcp download {name} from stock failed: {out}{err}"
    assert _read(dst) == _read(os.path.join(srv["off_data"], name)), \
        f"OUR xrdcp download {name}: byte mismatch vs stock source"


# =========================================================================== #
# Q2 — OUR xrdcp UPLOAD to the STOCK server (verify bytes on the stock disk)
# =========================================================================== #
@pytest.mark.parametrize("size", [0, 1, 4096, 65536])
def test_q2_our_xrdcp_upload(srv, tmp_path, size):
    payload = bytes((i * 31 + size) & 0xff for i in range(size))
    src = str(tmp_path / f"up_{size}.src")
    with open(src, "wb") as f:
        f.write(payload)
    remote = f"/q2_up_{size}.bin"  # unique per case
    rc, out, err = L.run([L.OUR_XRDCP, "-f", src, f"{srv['off']}/{remote}"],
                         timeout=120)
    assert rc == 0, f"OUR xrdcp upload size={size} to stock failed: {out}{err}"
    on_disk = os.path.join(srv["off_data"], remote.lstrip("/"))
    assert os.path.exists(on_disk), f"upload size={size} did not land on stock disk"
    assert _read(on_disk) == payload, \
        f"OUR xrdcp upload size={size}: byte mismatch on stock disk"


# =========================================================================== #
# Q2 — OUR xrdfs MUTATING ops on the STOCK server
# =========================================================================== #
def test_q2_our_mkdir_rmdir_roundtrip(srv):
    d = "/q2_mkdir_rt"
    rc, out, err = ourfs(srv["off"], "mkdir", d)
    assert rc == 0, f"OUR mkdir -> stock failed: {out}{err}"
    assert os.path.isdir(os.path.join(srv["off_data"], "q2_mkdir_rt")), \
        "OUR mkdir did not create the dir on the stock disk"
    rc, out, err = ourfs(srv["off"], "rmdir", d)
    assert rc == 0, f"OUR rmdir -> stock failed: {out}{err}"
    assert not os.path.exists(os.path.join(srv["off_data"], "q2_mkdir_rt")), \
        "OUR rmdir did not remove the dir on the stock disk"


def test_q2_our_rm_uploaded_file(srv, tmp_path):
    src = str(tmp_path / "q2rm.src")
    with open(src, "wb") as f:
        f.write(b"remove me\n")
    rc, out, err = L.run([L.OUR_XRDCP, "-f", src, f"{srv['off']}//q2_rm.bin"])
    assert rc == 0, f"setup upload failed: {out}{err}"
    on_disk = os.path.join(srv["off_data"], "q2_rm.bin")
    assert os.path.exists(on_disk)
    rc, out, err = ourfs(srv["off"], "rm", "/q2_rm.bin")
    assert rc == 0, f"OUR rm -> stock failed: {out}{err}"
    assert not os.path.exists(on_disk), "OUR rm did not delete on the stock disk"


# =========================================================================== #
# Q2 DIFFERENTIAL — OUR stat fields vs STOCK client stat fields (stock server)
# =========================================================================== #
def test_q2_diff_stat_fields_match(srv):
    o = _stat_fields(ourfs(srv["off"], "stat", "/data.bin")[1])
    s = _stat_fields(fs(srv["off"], "stat", "/data.bin")[1])
    assert o.get("Size") == s.get("Size") == "4096", \
        f"Size diverges: ours={o.get('Size')} stock={s.get('Size')}"
    # neither should flag a plain file as a directory
    assert "IsDir" not in o.get("Flags", ""), \
        f"OUR stat flags a file as IsDir: {o.get('Flags')!r}"
    assert "IsDir" not in s.get("Flags", "")


def test_q2_diff_stat_dir_both_isdir(srv):
    o = _stat_fields(ourfs(srv["off"], "stat", "/sub")[1])
    s = _stat_fields(fs(srv["off"], "stat", "/sub")[1])
    assert "IsDir" in o.get("Flags", ""), \
        f"OUR stat dir not IsDir: {o.get('Flags')!r}"
    assert "IsDir" in s.get("Flags", ""), \
        f"stock stat dir not IsDir: {s.get('Flags')!r}"


# =========================================================================== #
# Q3 — STOCK xrdcp OPTION VARIATIONS against OUR server (option must work E2E)
# =========================================================================== #
def test_q3_stock_xrdcp_force_overwrite(srv, tmp_path):
    dst = str(tmp_path / "q3_force.bin")
    with open(dst, "wb") as f:
        f.write(b"stale pre-existing contents")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//data.bin", dst])
    assert rc == 0, f"stock xrdcp -f re-download against OUR server failed: {out}{err}"
    assert _read(dst) == _read(os.path.join(srv["our_data"], "data.bin")), \
        "stock xrdcp -f: overwritten file does not match source"


def test_q3_stock_xrdcp_no_progress_bar(srv, tmp_path):
    dst = str(tmp_path / "q3_nopbar.bin")
    rc, out, err = L.run([L.OFF_XRDCP, "-N", "-f",
                          f"{srv['our']}//sz_65536.bin", dst])
    assert rc == 0, f"stock xrdcp -N against OUR server failed: {out}{err}"
    assert _read(dst) == _read(os.path.join(srv["our_data"], "sz_65536.bin")), \
        "stock xrdcp -N: download integrity mismatch"


def test_q3_stock_xrdcp_silent(srv, tmp_path):
    dst = str(tmp_path / "q3_silent.bin")
    rc, out, err = L.run([L.OFF_XRDCP, "-s", "-f",
                          f"{srv['our']}//data.bin", dst])
    assert rc == 0, f"stock xrdcp -s against OUR server failed: {out}{err}"
    assert _read(dst) == _read(os.path.join(srv["our_data"], "data.bin")), \
        "stock xrdcp -s: download integrity mismatch"


def test_q3_stock_xrdcp_posc_upload(srv, tmp_path):
    src = str(tmp_path / "q3_posc.src")
    payload = bytes((i * 7 + 1) & 0xff for i in range(5000))
    with open(src, "wb") as f:
        f.write(payload)
    rc, out, err = L.run([L.OFF_XRDCP, "--posc", "-f", src,
                          f"{srv['our']}//q3_posc.bin"])
    assert rc == 0, f"stock xrdcp --posc upload to OUR server failed: {out}{err}"
    on_disk = os.path.join(srv["our_data"], "q3_posc.bin")
    assert os.path.exists(on_disk), "stock xrdcp --posc: file not persisted"
    assert _read(on_disk) == payload, \
        "stock xrdcp --posc: persisted bytes do not match source"


def test_q3_stock_xrdcp_recursive_many(srv, tmp_path):
    dst = str(tmp_path / "q3_rec_many")
    os.makedirs(dst)
    rc, out, err = L.run([L.OFF_XRDCP, "-r", "-f",
                          f"{srv['our']}//many", dst], timeout=120)
    assert rc == 0, f"stock xrdcp -r /many against OUR server failed: {out}{err}"
    landed = os.path.join(dst, "many")
    for i in range(12):
        fp = os.path.join(landed, f"f{i:02d}.txt")
        assert os.path.exists(fp), f"recursive copy missing f{i:02d}.txt"
        assert _read(fp) == _read(
            os.path.join(srv["our_data"], "many", f"f{i:02d}.txt")), \
            f"recursive copy f{i:02d}.txt content mismatch"


def test_q3_stock_xrdcp_recursive_deep(srv, tmp_path):
    dst = str(tmp_path / "q3_rec_deep")
    os.makedirs(dst)
    rc, out, err = L.run([L.OFF_XRDCP, "-r", "-f",
                          f"{srv['our']}//deep", dst], timeout=120)
    assert rc == 0, f"stock xrdcp -r /deep against OUR server failed: {out}{err}"
    leaf = os.path.join(dst, "deep", "a", "b", "c", "leaf.txt")
    assert os.path.exists(leaf), f"recursive deep copy missing leaf: {out}{err}"
    assert _read(leaf) == _read(
        os.path.join(srv["our_data"], "deep", "a", "b", "c", "leaf.txt")), \
        "recursive deep copy leaf content mismatch"

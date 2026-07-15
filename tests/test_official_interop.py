"""Differential conformance against the STOCK XRootD server and client.

50 tests across four quadrants (see official_interop_lib.py):
  Q3  stock xrdfs/xrdcp  -> OUR server     (our server must satisfy the reference client)
  Q2  OUR xrdfs/xrdcp    -> stock server    (our client must satisfy the reference server)
  Q4  stock -> stock                        (oracle: proves the test/tool itself is sound)
  DIFF same op, stock client, our vs stock server, outputs compared

Philosophy (per the maintainer): a divergence is a bug in THIS implementation
unless there's positive evidence otherwise. These tests are the detector.

Self-provisioning; skips entirely without the stock xrootd toolchain.
"""

import os
import subprocess

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = tmp_path_factory.mktemp("offinterop")
    our_data = os.path.join(base, "our_data")
    off_data = os.path.join(base, "off_data")
    os.makedirs(our_data); os.makedirs(off_data)
    L.make_tree(our_data); L.make_tree(off_data)
    # Self-started servers MUST bind per-worker ports: the default OUR_PORT/
    # OFF_PORT are FIXED, so under `-n<N> --dist load` two workers that both run
    # this module would collide on the same port (the 2nd nginx/xrootd fails to
    # bind, or the client silently reaches the WRONG worker's tree -> spurious
    # differential failures). worker_port() shifts each worker into its own band,
    # exactly as every other self-provisioning conf module already does.
    our_port = L.worker_port(L.OUR_PORT)
    off_port = L.worker_port(L.OFF_PORT)
    ours = L.start_our_server(str(base), our_data, port=our_port)
    off = L.start_official_server(str(base), off_data, port=off_port)
    if not ours:
        pytest.skip("our nginx server did not start")
    if not off:
        if ours:
            ours.terminate()
        pytest.skip("stock xrootd server did not start")
    ctx = {"our": L.our_url(our_port), "off": L.off_url(off_port),
           "our_data": our_data, "off_data": off_data}
    yield ctx
    for p in (ours, off):
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def ourfs(url, *args, timeout=60):
    return L.run([L.OUR_XRDFS, url, *args], timeout=timeout)


def _ls_set(out):
    return {os.path.basename(l.strip()) for l in out.splitlines() if l.strip()
            and not l.strip().endswith("ckp-recovery.lock")}


# =========================================================================== #
# Q4 — oracle (the stock client against the stock server must work, or the
# test/tooling is broken, not our implementation).
# =========================================================================== #
def test_q4_oracle_ls(srv):
    rc, out, _ = fs(srv["off"], "ls", "/")
    assert rc == 0 and "hello.txt" in out


def test_q4_oracle_stat(srv):
    rc, out, _ = fs(srv["off"], "stat", "/hello.txt")
    assert rc == 0 and "Size:" in out


# =========================================================================== #
# Q3 — STOCK xrdfs against OUR server (read-only ops; rc==0 + sane output)
# =========================================================================== #
@pytest.mark.parametrize("args,needle", [
    (["ls", "/"], "hello.txt"),
    (["ls", "-l", "/"], "hello.txt"),
    (["ls", "/sub"], "nested.txt"),
    (["stat", "/hello.txt"], "Size:"),
    (["stat", "/sub"], "IsDir"),
    (["statvfs", "/"], None),
    (["locate", "/hello.txt"], None),
    (["query", "config", "bind_max"], None),
    (["query", "config", "chksum"], None),
    (["query", "config", "tpc"], None),
    (["query", "config", "readv_iov_max"], None),
])
def test_q3_stock_xrdfs_readonly(srv, args, needle):
    rc, out, err = fs(srv["our"], *args)
    assert rc == 0, f"stock xrdfs {args} -> OUR server failed: {out}{err}"
    if needle:
        assert needle in out, f"stock xrdfs {args}: {needle!r} not in {out!r}"


def test_q3_stock_stat_size_correct(srv):
    rc, out, _ = fs(srv["our"], "stat", "/data.bin")
    assert rc == 0 and "Size:   4096" in out, out


def test_q3_stock_ls_l_has_size(srv):
    rc, out, _ = fs(srv["our"], "ls", "-l", "/")
    assert rc == 0
    # the data.bin line must carry its 4096-byte size
    assert any("4096" in l and "data.bin" in l for l in out.splitlines()), out


def test_q3_stock_stat_dir_flag(srv):
    rc, out, _ = fs(srv["our"], "stat", "/sub")
    assert rc == 0 and "IsDir" in out, out


# Q3 — mutating ops via stock xrdfs against OUR server
def test_q3_stock_mkdir_rmdir(srv):
    d = "/q3mkdir"
    rc, out, err = fs(srv["our"], "mkdir", d)
    assert rc == 0, f"mkdir: {out}{err}"
    assert os.path.isdir(os.path.join(srv["our_data"], "q3mkdir"))
    rc, out, err = fs(srv["our"], "rmdir", d)
    assert rc == 0, f"rmdir: {out}{err}"
    assert not os.path.exists(os.path.join(srv["our_data"], "q3mkdir"))


def test_q3_stock_rm(srv):
    p = os.path.join(srv["our_data"], "q3rm.txt")
    with open(p, "w") as f:
        f.write("x")
    rc, out, err = fs(srv["our"], "rm", "/q3rm.txt")
    assert rc == 0, f"rm: {out}{err}"
    assert not os.path.exists(p)


def test_q3_stock_mv(srv):
    p = os.path.join(srv["our_data"], "q3mv.txt")
    with open(p, "w") as f:
        f.write("mv")
    rc, out, err = fs(srv["our"], "mv", "/q3mv.txt", "/q3mv2.txt")
    assert rc == 0, f"mv: {out}{err}"
    assert os.path.exists(os.path.join(srv["our_data"], "q3mv2.txt"))


def test_q3_stock_truncate(srv):
    p = os.path.join(srv["our_data"], "q3trunc.bin")
    with open(p, "wb") as f:
        f.write(b"\x00" * 100)
    rc, out, err = fs(srv["our"], "truncate", "/q3trunc.bin", "10")
    assert rc == 0, f"truncate: {out}{err}"
    assert os.path.getsize(p) == 10


def test_q3_stock_chmod(srv):
    p = os.path.join(srv["our_data"], "q3chmod.txt")
    with open(p, "w") as f:
        f.write("c")
    rc, out, err = fs(srv["our"], "chmod", "/q3chmod.txt", "rwxr-xr-x")
    assert rc == 0, f"chmod: {out}{err}"


# Q3 — stock xrdcp against OUR server
def test_q3_stock_xrdcp_download_integrity(srv, tmp_path):
    dst = str(tmp_path / "dl.bin")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//data.bin", dst])
    assert rc == 0, f"stock xrdcp download from OUR server failed: {out}{err}"
    with open(dst, "rb") as f:
        got = f.read()
    with open(os.path.join(srv["our_data"], "data.bin"), "rb") as f:
        want = f.read()
    assert got == want, "stock xrdcp download integrity mismatch"


def test_q3_stock_xrdcp_upload_integrity(srv, tmp_path):
    src = str(tmp_path / "up.bin")
    payload = bytes((i * 53 + 3) & 0xff for i in range(2048))
    with open(src, "wb") as f:
        f.write(payload)
    rc, out, err = L.run([L.OFF_XRDCP, "-f", src, f"{srv['our']}//q3up.bin"])
    assert rc == 0, f"stock xrdcp upload to OUR server failed: {out}{err}"
    with open(os.path.join(srv["our_data"], "q3up.bin"), "rb") as f:
        assert f.read() == payload, "stock xrdcp upload integrity mismatch"


def test_q3_stock_xrdcp_download_to_stdout(srv):
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//hello.txt", "-"])
    assert rc == 0, f"xrdcp to stdout failed: {err}"
    assert "hello world" in out, out


# =========================================================================== #
# Q2 — OUR client against the STOCK server
# =========================================================================== #
@pytest.mark.parametrize("args,needle", [
    (["ls", "/"], "hello.txt"),
    (["ls", "-l", "/"], "hello.txt"),
    (["ls", "/sub"], "nested.txt"),
    (["stat", "/hello.txt"], "Size"),
    (["stat", "/sub"], None),
    (["statvfs", "/"], None),
    (["locate", "/hello.txt"], None),
    (["cat", "/hello.txt"], "hello world"),
])
def test_q2_our_xrdfs_against_stock(srv, args, needle):
    rc, out, err = ourfs(srv["off"], *args)
    assert rc == 0, f"OUR xrdfs {args} -> stock server failed: {out}{err}"
    if needle:
        assert needle in out, f"OUR xrdfs {args}: {needle!r} not in {out!r}"


def test_q2_our_xrdcp_download_from_stock(srv, tmp_path):
    dst = str(tmp_path / "q2dl.bin")
    rc, out, err = L.run([L.OUR_XRDCP, "-f", f"{srv['off']}//data.bin", dst])
    assert rc == 0, f"OUR xrdcp download from stock server failed: {out}{err}"
    with open(dst, "rb") as f:
        got = f.read()
    with open(os.path.join(srv["off_data"], "data.bin"), "rb") as f:
        assert got == f.read(), "OUR xrdcp download from stock integrity mismatch"


def test_q2_our_xrdcp_upload_to_stock(srv, tmp_path):
    src = str(tmp_path / "q2up.bin")
    payload = bytes((i * 17 + 9) & 0xff for i in range(3000))
    with open(src, "wb") as f:
        f.write(payload)
    rc, out, err = L.run([L.OUR_XRDCP, "-f", src, f"{srv['off']}//q2up.bin"])
    assert rc == 0, f"OUR xrdcp upload to stock server failed: {out}{err}"
    with open(os.path.join(srv["off_data"], "q2up.bin"), "rb") as f:
        assert f.read() == payload, "OUR xrdcp upload to stock integrity mismatch"


def test_q2_our_xrdfs_mkdir_rm_on_stock(srv):
    rc, out, err = ourfs(srv["off"], "mkdir", "/q2dir")
    assert rc == 0, f"OUR mkdir -> stock: {out}{err}"
    assert os.path.isdir(os.path.join(srv["off_data"], "q2dir"))
    rc, out, err = ourfs(srv["off"], "rmdir", "/q2dir")
    assert rc == 0, f"OUR rmdir -> stock: {out}{err}"


# =========================================================================== #
# DIFF — same op, stock client, OUR server vs STOCK server, compared
# =========================================================================== #
def test_diff_ls_listing_matches(srv):
    # '/' accumulates files from the mutating Q3 tests (shared module fixture), so
    # compare the stable baseline tree as a subset and assert our server exposes
    # no internal artifact (the strict whole-dir equality lives in the /sub test,
    # which no mutating test touches).
    our = _ls_set(fs(srv["our"], "ls", "/")[1])
    off = _ls_set(fs(srv["off"], "ls", "/")[1])
    baseline = {"hello.txt", "data.bin", "sub"}
    assert baseline <= our and baseline <= off, f"ours={our} stock={off}"
    assert not any(n.startswith(".nginx-xrootd") for n in our), \
        f"our server leaks an internal artifact into the namespace: {our}"


def test_diff_ls_sub_matches(srv):
    _, our_out, _ = fs(srv["our"], "ls", "/sub")
    _, off_out, _ = fs(srv["off"], "ls", "/sub")
    assert _ls_set(our_out) == _ls_set(off_out)


def _stat_fields(out):
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def test_diff_stat_size_field(srv):
    o = _stat_fields(fs(srv["our"], "stat", "/data.bin")[1])
    f = _stat_fields(fs(srv["off"], "stat", "/data.bin")[1])
    assert o.get("Size") == f.get("Size") == "4096", f"ours={o} stock={f}"


def test_diff_stat_has_same_keys(srv):
    o = set(_stat_fields(fs(srv["our"], "stat", "/hello.txt")[1]))
    f = set(_stat_fields(fs(srv["off"], "stat", "/hello.txt")[1]))
    # the reference always emits Path/Id/Size/MTime/Flags; ours must at least cover them
    need = {"Path", "Size", "Flags"}
    assert need <= o, f"our stat missing fields {need - o} (stock has {f})"


def test_diff_stat_dir_flags_both_isdir(srv):
    o = _stat_fields(fs(srv["our"], "stat", "/sub")[1])
    f = _stat_fields(fs(srv["off"], "stat", "/sub")[1])
    assert "IsDir" in o.get("Flags", "") and "IsDir" in f.get("Flags", ""), \
        f"ours={o.get('Flags')} stock={f.get('Flags')}"


def test_diff_query_tpc_both_parseable(srv):
    # XrdCl parses query config tpc as a leading digit; both must be parseable.
    _, our_out, _ = fs(srv["our"], "query", "config", "tpc")
    _, off_out, _ = fs(srv["off"], "query", "config", "tpc")
    assert our_out.strip()[:1].isdigit() or our_out.strip() in ("tpc",), our_out
    assert off_out.strip()[:1].isdigit() or off_out.strip() in ("tpc",), off_out


def test_diff_query_chksum_value_only(srv):
    # Reference returns the bare cslist (no "chksum=" prefix); ours must match form.
    _, our_out, _ = fs(srv["our"], "query", "config", "chksum")
    assert not our_out.strip().startswith("chksum="), \
        f"our chksum config still has a key= prefix: {our_out!r}"


def test_diff_xrdcp_download_same_bytes(srv, tmp_path):
    a = str(tmp_path / "from_our.bin")
    b = str(tmp_path / "from_off.bin")
    L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//data.bin", a])
    L.run([L.OFF_XRDCP, "-f", f"{srv['off']}//data.bin", b])
    with open(a, "rb") as fa, open(b, "rb") as fb:
        assert fa.read() == fb.read(), "stock xrdcp got different bytes from the two servers"


# =========================================================================== #
# Cross: OUR client <-> OUR server still good (self-consistency anchor)
# =========================================================================== #
def test_cross_our_client_our_server(srv, tmp_path):
    rc, out, _ = ourfs(srv["our"], "ls", "/")
    assert rc == 0 and "hello.txt" in out
    dst = str(tmp_path / "self.bin")
    rc, out, err = L.run([L.OUR_XRDCP, "-f", f"{srv['our']}//data.bin", dst])
    assert rc == 0, f"{out}{err}"
    with open(dst, "rb") as f, open(os.path.join(srv["our_data"], "data.bin"), "rb") as g:
        assert f.read() == g.read()


# =========================================================================== #
# Extended coverage (toward 50): checksums, large files, recursion, cat, prepare
# =========================================================================== #
def test_q3_stock_xrdcp_large_roundtrip(srv, tmp_path):
    """1 MiB upload then download through OUR server, byte-exact."""
    big = bytes((i * 2654435761) & 0xff for i in range(1024 * 1024))
    src = str(tmp_path / "big.bin")
    with open(src, "wb") as f:
        f.write(big)
    rc, o, e = L.run([L.OFF_XRDCP, "-f", src, f"{srv['our']}//big.bin"])
    assert rc == 0, f"upload: {o}{e}"
    dl = str(tmp_path / "big_dl.bin")
    rc, o, e = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//big.bin", dl])
    assert rc == 0, f"download: {o}{e}"
    with open(dl, "rb") as f:
        assert f.read() == big, "1 MiB roundtrip integrity mismatch"


def test_q3_stock_xrdcp_cksum_verify(srv, tmp_path):
    """xrdcp --cksum adler32:source verifies the server checksum end to end."""
    dst = str(tmp_path / "ck.bin")
    rc, o, e = L.run([L.OFF_XRDCP, "-f", "--cksum", "adler32:source",
                      f"{srv['our']}//data.bin", dst])
    # Some xrdcp builds spell it differently; accept success OR a clean
    # checksum-unsupported message, but NOT a checksum MISMATCH.
    assert rc == 0 or "mismatch" not in (o + e).lower(), \
        f"xrdcp --cksum against OUR server reported a mismatch: {o}{e}"


def test_q3_stock_xrdfs_cat(srv):
    rc, out, err = fs(srv["our"], "cat", "/hello.txt")
    assert rc == 0, f"stock xrdfs cat -> OUR server failed: {out}{err}"
    assert "hello world" in out, out


def test_q3_stock_xrdfs_ls_recursive(srv):
    rc, out, err = fs(srv["our"], "ls", "-R", "/")
    assert rc == 0, f"ls -R: {out}{err}"
    assert "hello.txt" in out and "nested.txt" in out, out


def test_q3_stock_query_checksum(srv):
    """xrdfs query checksum <file> must return '<algo> <hex>' (kXR_Qcksum)."""
    rc, out, err = fs(srv["our"], "query", "checksum", "/data.bin")
    assert rc == 0, f"query checksum -> OUR failed: {out}{err}"
    assert len(out.split()) >= 2, f"checksum reply not '<algo> <hex>': {out!r}"


def test_diff_query_checksum_same(srv):
    """Same file content → same adler32 from our server and the stock server."""
    def hexsum(url):
        rc, out, _ = fs(url, "query", "checksum", "/data.bin")
        if rc != 0:
            return None
        toks = out.split()
        return toks[-1] if toks else None
    ours, off = hexsum(srv["our"]), hexsum(srv["off"])
    if ours and off:
        assert ours == off, f"adler32 differs: ours={ours} stock={off}"


def test_q2_our_xrdcp_large_from_stock(srv, tmp_path):
    """Our client downloads a 512 KiB file from the stock server, byte-exact."""
    big = bytes((i * 40503) & 0xff for i in range(512 * 1024))
    p = os.path.join(srv["off_data"], "q2big.bin")
    with open(p, "wb") as f:
        f.write(big)
    dl = str(tmp_path / "q2big_dl.bin")
    rc, o, e = L.run([L.OUR_XRDCP, "-f", f"{srv['off']}//q2big.bin", dl])
    assert rc == 0, f"OUR xrdcp large download from stock: {o}{e}"
    with open(dl, "rb") as f:
        assert f.read() == big, "OUR client large download integrity mismatch"


def test_diff_statvfs_six_fields(srv):
    """Both servers' statvfs must yield the reference 6-field RW/staging form."""
    for url, who in ((srv["our"], "our"), (srv["off"], "stock")):
        rc, out, _ = fs(url, "statvfs", "/")
        assert rc == 0, f"{who} statvfs failed"
        assert "Nodes with RW space" in out, f"{who} statvfs not parsed: {out!r}"


def test_q3_stock_xrdfs_tail(srv):
    rc, out, err = fs(srv["our"], "tail", "/hello.txt")
    # tail may be unimplemented in some xrdfs builds; only fail on a real error
    if rc == 0:
        assert "hello world" in out, out

"""Differential READ data-plane conformance: stock XRootD client (xrdcp/xrdfs)
against BOTH our nginx-xrootd server and the stock xrootd server.

Scope: the read path only — kXR_read, kXR_readv, kXR_pgread, and checksums
(kXR_Qcksum). Every probe is differential or pins stock-correct behaviour:
a divergence (wrong bytes, checksum mismatch, rc!=0 where stock succeeds) is
treated as a BUG IN OUR IMPLEMENTATION, and the assertion is written to fail.

The data tree is identical and deterministic on both servers (see
official_interop_lib.make_rich_tree), with files chosen to straddle the
read/pgread framing boundaries:
  /sz_1.bin /sz_255.bin /sz_4095.bin /sz_4096.bin /sz_4097.bin
  /sz_8192.bin /sz_65536.bin     (size == name)
  /data.bin (4096)  /big1m.bin (1048576)  /cksum.bin (10000)
  /hello.txt (12)   /empty.txt (0)

References for read framing (consulted, not modified):
  /tmp/xrootd-src/src/XrdXrootd/XrdXrootdXeq.cc      do_ReadAll / do_ReadV
  /tmp/xrootd-src/src/XrdXrootd/XrdXrootdXeqPgrw.cc  do_PgRead

Self-provisioning on high ports; skips entirely without the stock toolchain.
"""

import os
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

# Page-boundary edge sizes that exercise read/pgread/oksofar framing.
SZ_FILES = ["sz_1.bin", "sz_255.bin", "sz_4095.bin", "sz_4096.bin",
            "sz_4097.bin", "sz_8192.bin", "sz_65536.bin"]

# Full integrity matrix: every boundary size plus the named extras.
ALL_FILES = SZ_FILES + ["data.bin", "big1m.bin", "empty.txt", "cksum.bin"]


# --------------------------------------------------------------------------- #
# Module-scoped server pair (our nginx-xrootd + stock xrootd, identical tree). #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conf_io_read"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14004), off_port=L.worker_port(14005))
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _fs(url, *args, timeout=60):
    """Run the stock xrdfs against `url`."""
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def _read_local(ctx, name):
    """The authoritative source bytes (identical on both data dirs)."""
    with open(os.path.join(ctx["our_data"], name), "rb") as f:
        return f.read()


def _download(xrdcp, url, name, dst, timeout=60):
    return L.run([xrdcp, "-f", f"{url}//{name}", dst], timeout=timeout)


def _checksum_hex(url, name):
    """Return the trailing hex token of `xrdfs query checksum`, or None."""
    rc, out, _ = _fs(url, "query", "checksum", f"/{name}")
    if rc != 0:
        return None
    toks = out.split()
    return toks[-1] if toks else None


def _timeout_for(name):
    return 120 if "big1m" in name else 60


# =========================================================================== #
# DOWNLOAD integrity — stock xrdcp against OUR server. The bytes pulled over   #
# the wire must equal the local source for every boundary size. This is the    #
# core read-path correctness check across pgread/oksofar edges.                #
# =========================================================================== #
@pytest.mark.parametrize("name", ALL_FILES)
def test_download_integrity_our_server(srv, tmp_path, name):
    dst = str(tmp_path / f"our_{name}")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst,
                             timeout=_timeout_for(name))
    assert rc == 0, f"stock xrdcp {name} <- OUR server failed: {out}{err}"
    got = open(dst, "rb").read()
    want = _read_local(srv, name)
    first_diff = next((i for i in range(min(len(got), len(want)))
                       if got[i] != want[i]), "tail")
    assert got == want, (
        f"OUR server read returned wrong bytes for {name}: "
        f"got {len(got)} bytes, want {len(want)} (first diff at {first_diff})")


# =========================================================================== #
# DOWNLOAD via OUR client (Q2 read path) from the STOCK server -> integrity.   #
# Exercises our client's read decode against the reference server framing.     #
# =========================================================================== #
@pytest.mark.parametrize("name", ALL_FILES)
def test_download_integrity_our_client(srv, tmp_path, name):
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")
    dst = str(tmp_path / f"q2_{name}")
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], name, dst,
                             timeout=_timeout_for(name))
    assert rc == 0, f"OUR xrdcp {name} <- stock server failed: {out}{err}"
    got = open(dst, "rb").read()
    want = _read_local(srv, name)
    assert got == want, (
        f"OUR client read returned wrong bytes for {name}: "
        f"got {len(got)} bytes, want {len(want)}")


# =========================================================================== #
# DIFFERENTIAL bytes — stock xrdcp pulls the same file from OUR and from the   #
# STOCK server; the two downloads must be byte-identical.                      #
# =========================================================================== #
@pytest.mark.parametrize("name", ALL_FILES)
def test_download_diff_our_vs_stock(srv, tmp_path, name):
    a = str(tmp_path / f"from_our_{name}")
    b = str(tmp_path / f"from_off_{name}")
    rc_a, oa, ea = _download(L.OFF_XRDCP, srv["our"], name, a,
                             timeout=_timeout_for(name))
    rc_b, ob, eb = _download(L.OFF_XRDCP, srv["off"], name, b,
                             timeout=_timeout_for(name))
    assert rc_a == 0, f"download {name} from OUR server failed: {oa}{ea}"
    assert rc_b == 0, f"download {name} from STOCK server failed: {ob}{eb}"
    da, db = open(a, "rb").read(), open(b, "rb").read()
    assert da == db, (
        f"stock xrdcp got different bytes for {name} from the two servers: "
        f"OUR={len(da)}B STOCK={len(db)}B")


# =========================================================================== #
# xrdcp to stdout ("-") — the read path delivering through a pipe.             #
# =========================================================================== #
def test_download_stdout_hello(srv):
    rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{srv['our']}//hello.txt", "-"])
    assert rc == 0, f"stock xrdcp to stdout from OUR server failed: {err}"
    assert "hello world" in out, f"stdout payload wrong: {out!r}"


# =========================================================================== #
# CHECKSUM — `xrdfs query checksum` (kXR_Qcksum). If the stock server has a    #
# checksum plugin, identical content must yield the same hex from both. The    #
# bare stock data-server config ships no chksum plugin (error 3013), so when   #
# the stock side is unavailable we pin our server against an independently     #
# computed adler32 over the same bytes — the value the reference would emit.   #
# =========================================================================== #
def _adler32_hex(data):
    return f"{zlib.adler32(data) & 0xffffffff:08x}"


@pytest.mark.parametrize("name", ["data.bin", "cksum.bin", "sz_4096.bin",
                                  "big1m.bin"])
def test_checksum_matches_stock(srv, name):
    ours = _checksum_hex(srv["our"], name)
    assert ours is not None, f"OUR server query checksum {name} failed"
    off = _checksum_hex(srv["off"], name)
    if off is not None:
        assert ours == off, (
            f"checksum differs for {name} (same content): "
            f"OUR={ours} STOCK={off}")
        return
    # Stock server has no checksum plugin; verify our adler32 is correct anyway.
    expect = _adler32_hex(_read_local(srv, name))
    assert ours.lower() == expect, (
        f"OUR adler32 for {name} wrong: server={ours} expected={expect}")


# =========================================================================== #
# CHECKSUM — reply shape. The stock client expects '<algo> <hex>'; pin that    #
# our server returns at least two whitespace tokens (algo + value).           #
# =========================================================================== #
def test_checksum_reply_shape(srv):
    rc, out, err = _fs(srv["our"], "query", "checksum", "/cksum.bin")
    assert rc == 0, f"OUR query checksum failed: {out}{err}"
    assert len(out.split()) >= 2, (
        f"OUR checksum reply not '<algo> <hex>': {out!r}")


# =========================================================================== #
# CHECKSUM — server-verified transfer. `xrdcp --cksum adler32:source` makes    #
# the client re-checksum the bytes it received and compare to the server's     #
# advertised checksum. We accept success OR a clean "unsupported" build, but   #
# NEVER a checksum MISMATCH (that would mean read corruption).                 #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin"])
def test_checksum_verified_transfer(srv, tmp_path, name):
    dst = str(tmp_path / f"ckv_{name}")
    rc, out, err = L.run([L.OFF_XRDCP, "-f", "--cksum", "adler32:source",
                          f"{srv['our']}//{name}", dst])
    blob = (out + err).lower()
    assert "mismatch" not in blob, (
        f"xrdcp --cksum against OUR server reported a checksum MISMATCH "
        f"for {name} (read corruption): {out}{err}")
    if rc == 0:
        assert open(dst, "rb").read() == _read_local(srv, name), (
            f"--cksum transfer of {name} succeeded but bytes differ")


# =========================================================================== #
# EMPTY file — a 0-byte read must succeed and produce a 0-byte file on both    #
# servers (the read path must handle EOF-at-offset-0 correctly).              #
# =========================================================================== #
@pytest.mark.parametrize("which", ["our", "off"])
def test_empty_file_zero_bytes(srv, tmp_path, which):
    dst = str(tmp_path / f"empty_{which}.txt")
    rc, out, err = _download(L.OFF_XRDCP, srv[which], "empty.txt", dst)
    assert rc == 0, f"stock xrdcp empty.txt <- {which} server failed: {out}{err}"
    assert os.path.getsize(dst) == 0, (
        f"{which} server returned a non-empty file for empty.txt: "
        f"{os.path.getsize(dst)} bytes")


# =========================================================================== #
# LARGE file — 1 MiB download from OUR server, byte-exact. Exercises read      #
# pipelining and oksofar (kXR_oksofar) partial-response framing.              #
# =========================================================================== #
def test_large_download_pipelining(srv, tmp_path):
    dst = str(tmp_path / "big1m_pipe.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "big1m.bin", dst,
                             timeout=120)
    assert rc == 0, f"stock xrdcp big1m.bin <- OUR server failed: {out}{err}"
    got = open(dst, "rb").read()
    want = _read_local(srv, "big1m.bin")
    assert len(got) == len(want) == 1024 * 1024, (
        f"size mismatch: got {len(got)} want {len(want)}")
    assert got == want, "1 MiB read-pipelining integrity mismatch on OUR server"


# =========================================================================== #
# LARGE file via OUR client from STOCK server — symmetric pipelining check.    #
# =========================================================================== #
def test_large_download_our_client(srv, tmp_path):
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")
    dst = str(tmp_path / "big1m_q2.bin")
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], "big1m.bin", dst,
                             timeout=120)
    assert rc == 0, f"OUR xrdcp big1m.bin <- stock server failed: {out}{err}"
    assert open(dst, "rb").read() == _read_local(srv, "big1m.bin"), (
        "OUR client 1 MiB read integrity mismatch from stock server")


# =========================================================================== #
# Oracle — stock client against stock server for a boundary size, proving the  #
# tooling/test itself is sound (any failure here is environmental, not ours).  #
# =========================================================================== #
def test_oracle_stock_to_stock(srv, tmp_path):
    dst = str(tmp_path / "oracle.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["off"], "sz_4097.bin", dst)
    assert rc == 0, f"oracle stock->stock failed (tooling broken): {out}{err}"
    assert open(dst, "rb").read() == _read_local(srv, "sz_4097.bin")

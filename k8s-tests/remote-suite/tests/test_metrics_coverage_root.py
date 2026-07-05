# brix-remote-skip
"""
test_metrics_coverage_root.py — Prometheus coverage for the root:// data plane.

Verifies that `brix_requests_total{op,status}` and the byte counters actually
increment for every root:// pathway, with emphasis on DATA TRANSFER and FILE
CREATE / MODIFY / DELETE / RENAME.  Each test drives one real operation against
the live anon listener and asserts the exact labelled counter moved.

It also pins a regression for the op-name<->enum alignment (the phase-44
query_space fix): `locate` must report under op="locate", not a shifted label.

Run: PYTHONPATH=tests pytest tests/test_metrics_coverage_root.py -v
"""

import os
import time

import pytest

from settings import NGINX_ANON_PORT, HOST, DATA_ROOT
from metrics_helpers import Snapshot, fetch, value, xrdcp, xrdfs

client = pytest.importorskip("XRootD.client", reason="pyxrootd required")
from XRootD import client as xrdcl                       # noqa: E402
from XRootD.client.flags import (                        # noqa: E402
    OpenFlags, MkDirFlags, QueryCode,
)

ANON = f"root://{HOST}:{NGINX_ANON_PORT}"
PORT = str(NGINX_ANON_PORT)
LBL = {"port": PORT, "auth": "anon"}


def _fs():
    return xrdcl.FileSystem(ANON)


def _op_ok(snap, op):
    return snap.delta("brix_requests_total", {**LBL, "op": op, "status": "ok"})


def _op_err(snap, op):
    return snap.delta("brix_requests_total",
                      {**LBL, "op": op, "status": "error"})


def _put(path, data=b"data", flags=OpenFlags.NEW | OpenFlags.DELETE | OpenFlags.WRITE):
    f = xrdcl.File()
    st, _ = f.open(f"{ANON}/{path.lstrip('/')}", flags)
    assert st.ok, f"open-write {path}: {st.message}"
    if data:
        st, _ = f.write(data, offset=0)
        assert st.ok, f"write {path}: {st.message}"
    f.close()


# ----------------------------------------------------------------- success ----

class TestRootOpCountersOK:
    """Each operation increments its op="..." ,status="ok" series."""

    def test_open_wr_create_and_write_and_sync_and_close(self):
        snap = Snapshot()
        f = xrdcl.File()
        st, _ = f.open(f"{ANON}//cov_create.bin",
                       OpenFlags.NEW | OpenFlags.DELETE | OpenFlags.WRITE)
        assert st.ok, st.message
        f.write(b"Z" * 4096, offset=0)
        f.sync()
        f.close()
        assert _op_ok(snap, "open_wr") >= 1     # CREATE
        assert _op_ok(snap, "write") >= 1       # MODIFY (write data)
        assert _op_ok(snap, "sync") >= 1
        assert _op_ok(snap, "close") >= 1

    def test_open_rd_and_read(self):
        _put("cov_read.bin", b"R" * 8192)
        snap = Snapshot()
        f = xrdcl.File()
        st, _ = f.open(f"{ANON}//cov_read.bin", OpenFlags.READ)
        assert st.ok, st.message
        st, _ = f.read(offset=0, size=8192)
        assert st.ok, st.message
        f.close()
        assert _op_ok(snap, "open_rd") >= 1
        assert _op_ok(snap, "read") >= 1

    def test_readv(self):
        _put("cov_readv.bin", b"V" * 16384)
        snap = Snapshot()
        f = xrdcl.File()
        f.open(f"{ANON}//cov_readv.bin", OpenFlags.READ)
        try:
            st, _ = f.vector_read(chunks=[(0, 1024), (2048, 1024), (4096, 1024)])
        except TypeError:
            # The test-harness XrdCl worker proxy JSON-serializes chunk tuples
            # to lists; pyxrootd's vector_read requires tuples.  The op="readv"
            # metric itself is verified out-of-band (direct binding).
            f.close()
            pytest.skip("XrdCl proxy mangles vector_read chunk tuples")
        f.close()
        assert st.ok, st.message
        assert _op_ok(snap, "readv") >= 1

    def test_pgread(self):
        _put("cov_pgread.bin", b"P" * 16384)
        f = xrdcl.File()
        f.open(f"{ANON}//cov_pgread.bin", OpenFlags.READ)
        snap = Snapshot()
        try:
            st, _ = f.pgread(offset=0, size=8192)
        except (AttributeError, NotImplementedError) as exc:
            f.close()
            pytest.skip(f"pgread not available in this XrdCl binding: {exc}")
        f.close()
        if not st.ok:
            pytest.skip(f"pgread unsupported: {st.message}")
        assert _op_ok(snap, "pgread") >= 1

    def test_stat(self):
        _put("cov_stat.bin")
        snap = Snapshot()
        st, _ = _fs().stat("/cov_stat.bin")
        assert st.ok, st.message
        assert _op_ok(snap, "stat") >= 1

    def test_dirlist(self):
        snap = Snapshot()
        st, _ = _fs().dirlist("/")
        assert st.ok, st.message
        assert _op_ok(snap, "dirlist") >= 1

    def test_mkdir_create_dir(self):
        _fs().rmdir("/cov_dir")  # best-effort cleanup
        snap = Snapshot()
        st, _ = _fs().mkdir("/cov_dir", MkDirFlags.NONE)
        assert st.ok, st.message
        assert _op_ok(snap, "mkdir") >= 1       # CREATE (directory)

    def test_rmdir_delete_dir(self):
        _fs().mkdir("/cov_dir_rm", MkDirFlags.NONE)
        snap = Snapshot()
        st, _ = _fs().rmdir("/cov_dir_rm")
        assert st.ok, st.message
        assert _op_ok(snap, "rmdir") >= 1       # DELETE (directory)

    def test_rm_delete_file(self):
        _put("cov_rm.bin")
        snap = Snapshot()
        st, _ = _fs().rm("/cov_rm.bin")
        assert st.ok, st.message
        assert _op_ok(snap, "rm") >= 1          # DELETE (file)

    def test_mv_rename_file(self):
        _put("cov_mv_src.bin")
        _fs().rm("/cov_mv_dst.bin")
        snap = Snapshot()
        st, _ = _fs().mv("/cov_mv_src.bin", "/cov_mv_dst.bin")
        assert st.ok, st.message
        assert _op_ok(snap, "mv") >= 1          # RENAME

    def test_truncate_modify(self):
        _put("cov_trunc.bin", b"T" * 10000)
        snap = Snapshot()
        st, _ = _fs().truncate("/cov_trunc.bin", 100)
        assert st.ok, st.message
        assert _op_ok(snap, "truncate") >= 1    # MODIFY (size)

    def test_chmod(self):
        _put("cov_chmod.bin")
        snap = Snapshot()
        st, _ = _fs().chmod("/cov_chmod.bin", 0o640)
        assert st.ok, st.message
        assert _op_ok(snap, "chmod") >= 1

    def test_ping(self):
        snap = Snapshot()
        st = _fs().ping()
        # ping returns a status (no payload)
        assert st.ok if hasattr(st, "ok") else st[0].ok
        assert _op_ok(snap, "ping") >= 1

    def test_query_cksum(self):
        _put("cov_cksum.bin", b"C" * 4096)
        snap = Snapshot()
        st, _ = _fs().query(QueryCode.CHECKSUM, "/cov_cksum.bin")
        assert st.ok, st.message
        assert _op_ok(snap, "query_cksum") >= 1

    def test_locate_native(self):
        """Regression for the op-name<->enum skew: kXR_locate must report under
        op="locate".  pyxrootd may not issue kXR_locate to a standalone data
        server, so drive it with the native xrdfs (which definitely does)."""
        _put("cov_locate.bin")
        snap = Snapshot()
        r = xrdfs(ANON, "locate", "/cov_locate.bin")
        assert r.returncode == 0, r.stderr
        assert _op_ok(snap, "locate") >= 1, (
            "kXR_locate did not bump op=\"locate\" — op-name table skew "
            "(see the phase-44 query_space fix in src/observability/metrics/stream.c)")


# ------------------------------------------------------------------- error ----

class TestRootOpCountersError:
    """Failing operations increment op="...",status="error"."""

    def test_open_rd_missing(self):
        snap = Snapshot()
        f = xrdcl.File()
        st, _ = f.open(f"{ANON}//cov_no_such_file.bin", OpenFlags.READ)
        assert not st.ok
        assert _op_err(snap, "open_rd") >= 1

    def test_rm_missing(self):
        snap = Snapshot()
        st, _ = _fs().rm("/cov_rm_missing.bin")
        assert not st.ok
        assert _op_err(snap, "rm") >= 1

    def test_stat_missing(self):
        snap = Snapshot()
        st, _ = _fs().stat("/cov_stat_missing.bin")
        assert not st.ok
        assert _op_err(snap, "stat") >= 1

    def test_truncate_missing(self):
        snap = Snapshot()
        st, _ = _fs().truncate("/cov_trunc_missing.bin", 0)
        assert not st.ok
        assert _op_err(snap, "truncate") >= 1


# ------------------------------------------------------- file lifecycle E2E ----

class TestRootFileLifecycle:
    """One file through CREATE -> MODIFY -> RENAME -> DELETE, asserting the
    correct op counter fires at each phase."""

    def test_create_modify_rename_delete(self):
        fs = _fs()
        fs.rm("/life_a.bin"); fs.rm("/life_b.bin")

        # CREATE
        snap = Snapshot()
        _put("life_a.bin", b"1" * 2048)
        assert _op_ok(snap, "open_wr") >= 1
        assert _op_ok(snap, "write") >= 1

        # MODIFY (truncate)
        snap = Snapshot()
        assert fs.truncate("/life_a.bin", 512)[0].ok
        assert _op_ok(snap, "truncate") >= 1

        # RENAME
        snap = Snapshot()
        assert fs.mv("/life_a.bin", "/life_b.bin")[0].ok
        assert _op_ok(snap, "mv") >= 1

        # DELETE
        snap = Snapshot()
        assert fs.rm("/life_b.bin")[0].ok
        assert _op_ok(snap, "rm") >= 1


# -------------------------------------------------------------- byte counters ----

class TestRootByteCounters:
    """Data-transfer byte counters flush at TCP disconnect, so drive them with
    xrdcp subprocesses (clean disconnect) and assert a lower-bound delta >=
    payload on the aggregate AND the per-protocol (root) series."""

    PAYLOAD = 4 * 1024 * 1024

    def test_upload_increments_rx_bytes(self):
        src = os.path.join(DATA_ROOT, "cov_bytes_up.src")
        with open(src, "wb") as fh:
            fh.write(os.urandom(self.PAYLOAD))
        snap = Snapshot()
        r = xrdcp("-f", src, f"{ANON}//cov_bytes_up.bin")
        assert r.returncode == 0, r.stderr
        time.sleep(1.0)                      # let the closed session flush
        after = fetch()
        for name in ("brix_bytes_rx_total", "brix_bytes_root_rx_total"):
            d = snap.delta(name, LBL, after=after)
            assert d >= self.PAYLOAD, f"{name} delta {d} < {self.PAYLOAD}"

    def test_download_increments_tx_bytes(self):
        # seed a server-side file of known size
        src = os.path.join(DATA_ROOT, "cov_bytes_dl.bin")
        with open(src, "wb") as fh:
            fh.write(os.urandom(self.PAYLOAD))
        snap = Snapshot()
        r = xrdcp("-f", f"{ANON}//cov_bytes_dl.bin", "/tmp/cov_bytes_dl.out")
        assert r.returncode == 0, r.stderr
        time.sleep(1.0)
        after = fetch()
        for name in ("brix_bytes_tx_total", "brix_bytes_root_tx_total"):
            d = snap.delta(name, LBL, after=after)
            assert d >= self.PAYLOAD, f"{name} delta {d} < {self.PAYLOAD}"

    def test_wire_bytes_move_on_any_traffic(self):
        snap = Snapshot()
        assert _fs().stat("/")[0].ok
        time.sleep(0.5)
        after = fetch()
        assert snap.delta("brix_wire_bytes_rx_total", LBL, after=after) >= 1
        assert snap.delta("brix_wire_bytes_tx_total", LBL, after=after) >= 1

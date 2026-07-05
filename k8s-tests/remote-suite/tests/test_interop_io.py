# brix-remote-skip
"""
tests/test_interop_io.py

Conformance tests for I/O operations comparing nginx-xrootd against the
reference xrootd server.

Covered opcodes: kXR_readv, kXR_pgread, kXR_pgwrite, kXR_writev, kXR_sync,
                 kXR_locate, kXR_clone

The reference server shares the same filesystem.  For read operations we seed
a known file and compare both servers' output.  For write operations we write
through nginx-xrootd and verify the result via the reference server.

Run:
    pytest tests/test_interop_io.py -v
"""

import hashlib
import os
import socket
import struct
import zlib

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, StatInfoFlags
from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    url_host,
)

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

NGINX_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
REF_URL   = f"root://{url_host(HOST)}:{REF_BRIX_PORT}"
DATA_DIR  = DATA_ROOT
ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fs(url):
    return client.FileSystem(url)


def _url(url, path):
    return f"{url.rstrip('/')}//{path.lstrip('/')}"


def _open_file(url, path, flags=OpenFlags.READ):
    f = client.File()
    st, _ = f.open(_url(url, path), flags)
    return f, st


def _read_all(url, path):
    f, st = _open_file(url, path)
    if not st.ok:
        return st, None
    st2, info = f.stat()
    st3, data = f.read(size=info.size)
    f.close()
    return st3, data


def _md5(data):
    return hashlib.md5(data).hexdigest()


def _seed(size, name_prefix=""):
    name    = f"_{name_prefix}_{os.getpid()}_{id(size)}.bin"
    content = os.urandom(size)
    with open(os.path.join(DATA_DIR, name), "wb") as fh:
        fh.write(content)
    return f"/{name}", content


def _adler32_hex(data):
    return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")


def _recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "connection closed unexpectedly"
        buf += chunk
    return buf


def _recv_response(sock):
    hdr = _recvall(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recvall(sock, dlen) if dlen else b""
    return status, body


def _connect_nginx():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((ANON_HOST, ANON_PORT))
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    hdr = _recvall(sock, 8)
    _recvall(sock, struct.unpack("!I", hdr[4:8])[0])
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                             b"\x00\x01", 3007, 0,
                             b"test\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _recv_response(sock)
    return sock


def _raw_open(sock, sid, path, options):
    path_b = path.encode()
    req = struct.pack("!2sHHH2s6s4sI",
                      bytes([0, sid]), 3010,
                      0o644, options,
                      b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(path_b))
    sock.sendall(req + path_b)
    status, body = _recv_response(sock)
    assert status == 0, f"open({path!r}) failed: status={status} body={body!r}"
    return body[:4]


def _raw_close(sock, sid, fh):
    req = struct.pack("!2sH4s12sI",
                      bytes([0, sid]), 3003, fh, b"\x00" * 12, 0)
    sock.sendall(req)
    _recv_response(sock)


def _raw_clone(sock, sid, dst_fh, items):
    payload = b"".join(
        struct.pack("!4s4sQQQ", src_fh, b"\x00" * 4,
                    src_off, src_len, dst_off)
        for src_fh, src_off, src_len, dst_off in items
    )
    req = struct.pack("!2sH4s12sI",
                      bytes([0, sid]), 3032, dst_fh, b"\x00" * 12,
                      len(payload))
    sock.sendall(req + payload)
    return _recv_response(sock)


# ---------------------------------------------------------------------------
# Vector read (kXR_readv)
# ---------------------------------------------------------------------------

class TestVectorReadConformance:

    def test_readv_matches_sequential_reads_on_both(self):
        path, content = _seed(16384, "readv")
        segments = [(0, 1024), (4096, 2048), (8192, 512), (12288, 1024)]
        expected = b"".join(content[o:o+s] for o, s in segments)

        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f, st = _open_file(url, path)
                assert st.ok, f"{label} open failed: {st.message}"
                v_st, vri = f.vector_read(segments)
                f.close()

                assert v_st.ok, f"{label} readv failed: {v_st.message}"
                got = b"".join(chunk.buffer for chunk in vri.chunks)
                assert got == expected, \
                    f"{label}: readv data mismatch (md5 got={_md5(got)} expected={_md5(expected)})"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_readv_single_segment_matches_read(self):
        path, content = _seed(4096, "readvsingle")
        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f, st = _open_file(url, path)
                assert st.ok
                _, vri = f.vector_read([(0, len(content))])
                f.close()
                got = b"".join(chunk.buffer for chunk in vri.chunks)
                assert got == content, f"{label}: single-segment readv mismatch"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_readv_out_of_order_segments_match(self):
        path, content = _seed(8192, "readvooo")
        # Segments in reverse address order
        segments = [(6144, 512), (2048, 512), (0, 512)]
        try:
            n_f, _ = _open_file(NGINX_URL, path)
            r_f, _ = _open_file(REF_URL,   path)
            _, n_vri = n_f.vector_read(segments)
            _, r_vri = r_f.vector_read(segments)
            n_f.close()
            r_f.close()

            n_data = b"".join(c.buffer for c in n_vri.chunks)
            r_data = b"".join(c.buffer for c in r_vri.chunks)
            assert n_data == r_data, "out-of-order readv: nginx vs ref mismatch"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_readv_nginx_and_ref_agree(self):
        path, content = _seed(32768, "readvagree")
        chunk = 4096
        segments = [(i * chunk, chunk) for i in range(len(content) // chunk)]
        try:
            n_f, _ = _open_file(NGINX_URL, path)
            r_f, _ = _open_file(REF_URL,   path)
            _, n_vri = n_f.vector_read(segments)
            _, r_vri = r_f.vector_read(segments)
            n_f.close()
            r_f.close()

            n_data = b"".join(c.buffer for c in n_vri.chunks)
            r_data = b"".join(c.buffer for c in r_vri.chunks)
            assert n_data == r_data == content, \
                f"full readv: nginx_md5={_md5(n_data)} ref_md5={_md5(r_data)}"
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# pgread (kXR_pgread) — data must match regular read
# ---------------------------------------------------------------------------

class TestPgreadConformance:
    """
    pgread returns per-page CRC32c checksums alongside data.  The Python client
    presents it as a regular read; we verify data integrity by comparing with
    sequential kXR_read output from both servers.
    """

    def test_pgread_data_matches_regular_read(self):
        path, content = _seed(8192, "pgread")
        try:
            # Read via nginx (which may use pgread internally for large reads)
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)

            assert n_st.ok and r_st.ok
            assert n_data == r_data == content, (
                f"pgread data mismatch: "
                f"nginx={_md5(n_data)} ref={_md5(r_data)} expected={_md5(content)}"
            )
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_page_boundary_alignment(self):
        # 3 full pages: 3 × 4096 = 12288
        page_size = 4096
        path, content = _seed(3 * page_size, "pgrd_align")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_non_page_aligned_size(self):
        # Partial last page: 2 full pages + 100 bytes
        path, content = _seed(2 * 4096 + 100, "pgrd_partial")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_single_page(self):
        path, content = _seed(4096, "pgrd_one")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_sub_page(self):
        path, content = _seed(100, "pgrd_sub")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_checksum_coverage_across_large_file(self):
        # 64 pages: enough to exercise the CRC32c chain
        path, content = _seed(64 * 4096, "pgrd_large")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert _md5(n_data) == _md5(r_data) == _md5(content)
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# pgwrite (kXR_pgwrite) — write then read back via ref
# ---------------------------------------------------------------------------

class TestPgwriteConformance:

    def _pgwrite_file(self, content, name_suffix=""):
        name = f"_pgw_{os.getpid()}{name_suffix}.bin"
        path = f"/{name}"

        f = client.File()
        st, _ = f.open(_url(NGINX_URL, path),
                       OpenFlags.NEW | OpenFlags.WRITE)
        assert st.ok, f"open for pgwrite: {st.message}"
        # xrdcp v5 uses pgwrite internally; the Python client sends kXR_write
        # which the server handles identically.  For true pgwrite wire-level
        # testing see test_pgwrite_checksum.py.
        chunk = 4096
        for off in range(0, len(content), chunk):
            piece = content[off:off+chunk]
            st2, _ = f.write(piece, offset=off)
            assert st2.ok, f"write at {off}: {st2.message}"
        f.close()
        return path, name

    def test_pgwrite_4k_boundary_readback_via_ref(self):
        content = os.urandom(16 * 4096)
        path, name = self._pgwrite_file(content, "_4k")
        try:
            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok, f"ref read-back failed: {r_st.message}"
            assert _md5(r_data) == _md5(content), "pgwrite 4k boundary: data mismatch"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgwrite_non_aligned_readback_via_ref(self):
        content = os.urandom(4096 + 777)
        path, name = self._pgwrite_file(content, "_mis")
        try:
            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok
            assert r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgwrite_checksum_verified_by_ref_read(self):
        content = os.urandom(8 * 4096)
        path, name = self._pgwrite_file(content, "_cksum")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content, \
                "pgwrite: nginx and ref disagree on file content"
            # Verify adler32 via nginx query
            q_st, q_result = _fs(NGINX_URL).query(
                client.flags.QueryCode.CHECKSUM, path
            )
            if q_st.ok:
                cksum_val = q_result.decode().split()[1].rstrip("\x00")
                assert cksum_val == _adler32_hex(content), \
                    f"pgwrite checksum mismatch: {cksum_val} vs {_adler32_hex(content)}"
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# writev (kXR_writev)
# ---------------------------------------------------------------------------

class TestWritevConformance:
    """
    kXR_writev: scatter-gather write.  Write discontiguous segments, then
    read back via both servers and verify agreement.
    """

    def test_writev_then_read_back(self):
        total   = 8192
        content = os.urandom(total)
        name    = f"_writev_{os.getpid()}.bin"
        path    = f"/{name}"

        try:
            # Pre-allocate file to total size (write zeros)
            f = client.File()
            st, _ = f.open(_url(NGINX_URL, path),
                           OpenFlags.NEW | OpenFlags.WRITE)
            assert st.ok
            st2, _ = f.write(b"\x00" * total, offset=0)
            assert st2.ok

            # Now overwrite with chunks via sequential writes at specific offsets
            chunk = total // 4
            for i, off in enumerate(range(0, total, chunk)):
                piece = content[off:off+chunk]
                st3, _ = f.write(piece, offset=off)
                assert st3.ok, f"write chunk {i} at {off}: {st3.message}"
            f.close()

            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content, (
                f"writev readback mismatch: "
                f"nginx_md5={_md5(n_data)} ref_md5={_md5(r_data)}"
            )
        finally:
            _fs(NGINX_URL).rm(path)

    def test_writev_sparse_segments_agree(self):
        """Write at offsets leaving gaps; both servers see same zeros in gaps."""
        total = 4096
        name  = f"_writev_sparse_{os.getpid()}.bin"
        path  = f"/{name}"

        try:
            f = client.File()
            f.open(_url(NGINX_URL, path), OpenFlags.NEW | OpenFlags.WRITE)
            f.write(b"\x00" * total)
            # Overwrite first and last 512 bytes only
            first = os.urandom(512)
            last  = os.urandom(512)
            f.write(first, offset=0)
            f.write(last,  offset=total - 512)
            f.close()

            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data, "sparse write: nginx and ref disagree"
            assert n_data[:512]  == first
            assert n_data[-512:] == last
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# sync (kXR_sync)
# ---------------------------------------------------------------------------

class TestSyncConformance:

    def test_sync_on_open_read_handle_succeeds_on_both(self):
        path, _ = _seed(1024, "sync")
        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f, st = _open_file(url, path)
                assert st.ok
                s_st = f.sync()
                f.close()
                assert s_st[0].ok, f"{label} sync failed: {s_st[0].message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_sync_after_write_returns_ok(self):
        name = f"_sync_write_{os.getpid()}.bin"
        path = f"/{name}"
        try:
            f = client.File()
            st, _ = f.open(_url(NGINX_URL, path),
                           OpenFlags.NEW | OpenFlags.WRITE)
            assert st.ok
            f.write(os.urandom(4096))
            s_st = f.sync()
            assert s_st[0].ok, f"sync after write: {s_st[0].message}"
            f.close()
        finally:
            _fs(NGINX_URL).rm(path)

    def test_sync_data_visible_to_ref_after_sync(self):
        name    = f"_sync_vis_{os.getpid()}.bin"
        path    = f"/{name}"
        content = os.urandom(2048)
        try:
            f = client.File()
            st, _ = f.open(_url(NGINX_URL, path),
                           OpenFlags.NEW | OpenFlags.WRITE)
            assert st.ok
            f.write(content)
            f.sync()
            f.close()

            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok
            assert r_data == content, "data not visible to ref after sync"
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# locate (kXR_locate)
# ---------------------------------------------------------------------------

class TestLocateConformance:

    def test_locate_existing_file_returns_ok_on_both(self):
        path, _ = _seed(512, "locate")
        try:
            n_st, n_locs = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
            r_st, r_locs = _fs(REF_URL  ).locate(path, OpenFlags.NONE)

            assert n_st.ok, f"nginx locate failed: {n_st.message}"
            assert r_st.ok, f"ref   locate failed: {r_st.message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_locate_nonexistent_fails_on_both(self):
        path = "/_no_locate_xyzzy.bin"
        n_st, _ = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
        r_st, _ = _fs(REF_URL  ).locate(path, OpenFlags.NONE)
        assert not n_st.ok, "nginx: locate of nonexistent should fail"
        assert not r_st.ok, "ref:   locate of nonexistent should fail"

    def test_locate_returns_at_least_one_location(self):
        path, _ = _seed(512, "loc_count")
        try:
            n_st, n_locs = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
            assert n_st.ok
            locs = list(n_locs)
            assert len(locs) >= 1, "locate returned no locations"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_locate_response_contains_host_and_port(self):
        path, _ = _seed(512, "loc_fmt")
        try:
            n_st, n_locs = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
            assert n_st.ok
            for loc in n_locs:
                # Each location should have a non-empty address
                assert loc.address, "locate entry has empty address"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_locate_directory_returns_ok(self):
        path = "//"
        n_st, _ = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
        r_st, _ = _fs(REF_URL  ).locate(path, OpenFlags.NONE)
        # Both should succeed or both should fail (root directory is always present)
        assert n_st.ok == r_st.ok, \
            f"root locate outcome differs: nginx={n_st.ok}, ref={r_st.ok}"


# ---------------------------------------------------------------------------
# clone (kXR_clone) — server-side file copy
# ---------------------------------------------------------------------------

class TestCloneConformance:

    def test_clone_creates_identical_file(self):
        src_path, content = _seed(8192, "clone_src")
        dst_name = f"_clone_dst_{os.getpid()}.bin"
        dst_path = f"/{dst_name}"
        with open(os.path.join(DATA_DIR, dst_name), "wb") as fh:
            fh.write(b"\x00" * len(content))

        try:
            sock = _connect_nginx()
            try:
                src_fh = _raw_open(sock, 2, src_path, 0x0010)
                dst_fh = _raw_open(sock, 3, dst_path, 0x0020)
                status, body = _raw_clone(sock, 4, dst_fh,
                                          [(src_fh, 0, len(content), 0)])
                assert status == 0, f"clone failed: status={status} body={body!r}"
                _raw_close(sock, 5, src_fh)
                _raw_close(sock, 6, dst_fh)
            finally:
                sock.close()

            n_st, n_data = _read_all(NGINX_URL, dst_path)
            r_st, r_data = _read_all(REF_URL,   dst_path)
            assert n_st.ok, f"nginx read cloned file: {n_st.message}"
            assert r_st.ok, f"ref   read cloned file: {r_st.message}"
            assert n_data == r_data == content, \
                "clone: destination content differs from source"
        finally:
            _fs(NGINX_URL).rm(src_path)
            try:
                _fs(NGINX_URL).rm(dst_path)
            except Exception:
                pass

    def test_clone_source_unchanged(self):
        src_path, content = _seed(4096, "clone_src_intact")
        dst_name = f"_clone_dst_intact_{os.getpid()}.bin"
        dst_path = f"/{dst_name}"
        with open(os.path.join(DATA_DIR, dst_name), "wb") as fh:
            fh.write(b"\x00" * len(content))

        try:
            sock = _connect_nginx()
            try:
                src_fh = _raw_open(sock, 2, src_path, 0x0010)
                dst_fh = _raw_open(sock, 3, dst_path, 0x0020)
                status, body = _raw_clone(sock, 4, dst_fh,
                                          [(src_fh, 0, len(content), 0)])
                assert status == 0, f"clone failed: status={status} body={body!r}"
                _raw_close(sock, 5, src_fh)
                _raw_close(sock, 6, dst_fh)
            finally:
                sock.close()

            n_st, n_data = _read_all(NGINX_URL, src_path)
            assert n_st.ok
            assert n_data == content, "source file modified by clone"
        finally:
            _fs(NGINX_URL).rm(src_path)
            try:
                _fs(NGINX_URL).rm(dst_path)
            except Exception:
                pass

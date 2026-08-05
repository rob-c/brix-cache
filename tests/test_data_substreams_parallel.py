"""
Data sub-streams (kXR_bind) as a PARALLEL DATA-TRANSFER mechanism.

`test_session_bind.py` proves the mechanics of a single bound secondary (pathid
assignment, one bound read, slot-hint cache, revocation).  This suite proves the
property the *client* relies on when it uses sub-streams for a transfer: several
bound secondary connections can read DISJOINT regions of one primary-published
handle in parallel and the concatenation reassembles the whole object byte-exact
— including under genuinely concurrent (threaded) in-flight reads.

The server default is `brix_data_substreams on`, so the shared anonymous endpoint
already accepts binds; no special server config is needed (that default is itself
asserted by `test_server_default_accepts_bind`).

Run:
    PYTHONPATH=tests pytest tests/test_data_substreams_parallel.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import zlib

import pytest

from settings import DATA_ROOT

# The directory the target anon endpoint exports.  In the standard fleet the
# anonymous main-nginx exports DATA_ROOT, so that is the default and keeps this
# suite CI-correct.  A bespoke BriX endpoint (e.g. a hand-launched substreams-ON
# server on another port) can redirect writes here via BRIX_SUBS_EXPORT_DIR so
# the suite can be validated against it without touching the fleet.
EXPORT_DIR = os.environ.get("BRIX_SUBS_EXPORT_DIR", DATA_ROOT)

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------
kXR_ok        = 0
kXR_oksofar   = 4000
kXR_error     = 4003
kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_read      = 3013
kXR_bind      = 3024
kXR_close     = 3003
kXR_write     = 3019
kXR_open_read = 0x0010
kXR_open_updt = 0x0020  # open for update/write
kXR_new       = 0x0008  # create new
kXR_delete    = 0x0002  # delete/overwrite


# ---------------------------------------------------------------------------
# Raw-socket helpers (self-contained; host/port passed explicitly)
# ---------------------------------------------------------------------------
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_req(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00")
    hdr += struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    rsp_hdr = _recv_exact(sock, 8)
    assert rsp_hdr is not None, "no response header"
    status = struct.unpack(">H", rsp_hdr[2:4])[0]
    dlen = struct.unpack(">I", rsp_hdr[4:8])[0]
    data = _recv_exact(sock, dlen) if dlen else b""
    return status, data


def _handshake(sock):
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)  # 8B hdr + 8B body


def _establish_primary(host, port):
    sock = socket.create_connection((host, port))
    _handshake(sock)
    status, _ = _send_req(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok, "protocol"
    status, sessid_body = _send_req(sock, b"\x00\x01", kXR_login,
                                    payload=b"anonymous\x00")
    assert status == kXR_ok and len(sessid_body) >= 16, "login"
    return sock, sessid_body[:16]


def _bind_secondary(host, port, sessid, streamid):
    sock = socket.create_connection((host, port))
    _handshake(sock)
    status, pathid_body = _send_req(sock, streamid, kXR_bind, body=sessid)
    assert status == kXR_ok, f"bind failed: status={status}"
    assert len(pathid_body) == 1, "pathid body must be 1 byte"
    return sock, pathid_body[0]


def _open_read(sock, streamid, path):
    open_body = struct.pack(">HH", 0o644, kXR_open_read) + b"\x00" * 12
    status, body = _send_req(sock, streamid, kXR_open, body=open_body,
                             payload=path.encode() + b"\x00")
    assert status == kXR_ok and len(body) >= 4, f"open failed: status={status}"
    return body[:4]


def _read_range(sock, streamid, fhandle, offset, length):
    """Read exactly `length` bytes from `offset`, looping over kXR_oksofar /
    server-side chunking.  Returns the assembled bytes (may be short only if the
    server signals EOF)."""
    out = b""
    pos = offset
    remaining = length
    while remaining > 0:
        body = fhandle + struct.pack(">q", pos) + struct.pack(">i", remaining)
        status, data = _send_req(sock, streamid, kXR_read, body=body)
        assert status in (kXR_ok, kXR_oksofar), f"read status {status}"
        if not data:
            break
        out += data
        pos += len(data)
        remaining -= len(data)
        if status == kXR_ok and len(data) < remaining + len(data):
            # a kXR_ok short read is EOF for this request window
            if len(data) < (length - (len(out) - len(data))):
                # nothing more expected once the server returned a final ok
                pass
    return out


def _write_data_file(name, content):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    with open(os.path.join(EXPORT_DIR, name), "wb") as f:
        f.write(content)


def _rm_export_file(name):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    try:
        os.remove(os.path.join(EXPORT_DIR, name))
    except FileNotFoundError:
        pass


def _read_export_file(name):
    with open(os.path.join(EXPORT_DIR, name), "rb") as f:
        return f.read()


def _open_write(sock, streamid, path):
    """Open a file for write (create/overwrite), returning its 4-byte fhandle."""
    opts = kXR_open_updt | kXR_new | kXR_delete
    open_body = struct.pack(">HH", 0o644, opts) + b"\x00" * 12
    status, body = _send_req(sock, streamid, kXR_open, body=open_body,
                             payload=path.encode() + b"\x00")
    assert status == kXR_ok and len(body) >= 4, f"write-open failed: status={status}"
    return body[:4]


def _write_range(sock, streamid, fhandle, offset, data, pathid=0):
    """Send one kXR_write (header + payload) on `sock`.  Returns the reply status.
    A bound secondary carries the WHOLE write inline (pathid 0) — the connection
    itself is the substream, mirroring the bound-read routing."""
    body = fhandle + struct.pack(">q", offset) + bytes([pathid]) + b"\x00" * 3
    status, _ = _send_req(sock, streamid, kXR_write, body=body, payload=data)
    return status


def _close_handle(sock, streamid, fhandle):
    body = fhandle + b"\x00" * 12
    status, _ = _send_req(sock, streamid, kXR_close, body=body)
    return status


def _det(n):
    """Deterministic period-251 content, tiled to n bytes."""
    p = bytes(i % 251 for i in range(251))
    full, rem = divmod(n, 251)
    return p * full + p[:rem]


# ---------------------------------------------------------------------------
# Fixture — shared anonymous (substreams-ON-by-default) endpoint
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def endpoint(test_env):
    return test_env["server_host"], test_env["anon_port"]


@pytest.mark.requires_local_server
class TestDataSubstreamsParallel:

    def test_server_default_accepts_bind(self, endpoint):
        """With no special config, the server accepts kXR_bind — i.e.
        brix_data_substreams defaults ON."""
        host, port = endpoint
        primary, sessid = _establish_primary(host, port)
        try:
            sec, pathid = _bind_secondary(host, port, sessid, b"\x00\x10")
            assert 1 <= pathid <= 253
            sec.close()
        finally:
            primary.close()

    def test_striped_parallel_read_reassembles(self, endpoint):
        """A file striped into N contiguous slices, each read on a DIFFERENT bound
        secondary, reassembles byte-exact — the core parallel-download property."""
        host, port = endpoint
        n_streams = 4
        size = 240 * 1024               # 240 KiB, evenly divisible by 4
        content = _det(size)
        _write_data_file("subs-stripe.bin", content)

        primary, sessid = _establish_primary(host, port)
        primary_fh = _open_read(primary, b"\x00\x01", "/subs-stripe.bin")
        secs = []
        try:
            for i in range(n_streams):
                sock, _ = _bind_secondary(host, port, sessid,
                                          bytes([0, 0x20 + i]))
                secs.append(sock)

            slice_len = size // n_streams
            assembled = bytearray(size)
            for i in range(n_streams):
                off = i * slice_len
                data = _read_range(secs[i], bytes([0, 0x20 + i]), primary_fh,
                                   off, slice_len)
                assert len(data) == slice_len, (
                    f"stream {i}: got {len(data)} want {slice_len}")
                assembled[off:off + slice_len] = data

            assert bytes(assembled) == content, "reassembled stripes != source"
        finally:
            for s in secs:
                s.close()
            primary.close()

    def test_concurrent_substream_reads_threaded(self, endpoint):
        """Genuinely concurrent in-flight reads: each secondary reads its slice in
        its own thread; all must return correct bytes for their offset."""
        host, port = endpoint
        n_streams = 4
        size = 200 * 1024
        content = _det(size)
        _write_data_file("subs-concurrent.bin", content)

        primary, sessid = _establish_primary(host, port)
        primary_fh = _open_read(primary, b"\x00\x01", "/subs-concurrent.bin")
        secs = []
        results = [None] * n_streams
        errors = [None] * n_streams
        try:
            for i in range(n_streams):
                sock, _ = _bind_secondary(host, port, sessid,
                                          bytes([0, 0x40 + i]))
                secs.append(sock)

            slice_len = size // n_streams

            def worker(idx):
                try:
                    off = idx * slice_len
                    results[idx] = _read_range(secs[idx], bytes([0, 0x40 + idx]),
                                               primary_fh, off, slice_len)
                except Exception as exc:               # noqa: BLE001
                    errors[idx] = exc

            threads = [threading.Thread(target=worker, args=(i,))
                       for i in range(n_streams)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            for i in range(n_streams):
                assert errors[i] is None, f"stream {i} raised: {errors[i]}"
                off = i * slice_len
                assert results[i] == content[off:off + slice_len], (
                    f"stream {i} returned wrong bytes")
        finally:
            for s in secs:
                s.close()
            primary.close()

    def test_primary_and_secondaries_read_same_handle(self, endpoint):
        """The primary and its bound secondaries can all read the same handle;
        every read returns the correct region regardless of which connection
        serves it."""
        host, port = endpoint
        size = 128 * 1024
        content = _det(size)
        _write_data_file("subs-shared.bin", content)

        primary, sessid = _establish_primary(host, port)
        primary_fh = _open_read(primary, b"\x00\x01", "/subs-shared.bin")
        sec_a = sec_b = None
        try:
            sec_a, _ = _bind_secondary(host, port, sessid, b"\x00\x51")
            sec_b, _ = _bind_secondary(host, port, sessid, b"\x00\x52")

            quarter = size // 4
            # interleave reads across primary + 2 secondaries
            d0 = _read_range(primary, b"\x00\x01", primary_fh, 0, quarter)
            d1 = _read_range(sec_a, b"\x00\x51", primary_fh, quarter, quarter)
            d2 = _read_range(sec_b, b"\x00\x52", primary_fh, 2 * quarter, quarter)
            d3 = _read_range(primary, b"\x00\x01", primary_fh, 3 * quarter, quarter)

            assert d0 == content[0:quarter]
            assert d1 == content[quarter:2 * quarter]
            assert d2 == content[2 * quarter:3 * quarter]
            assert d3 == content[3 * quarter:4 * quarter]
        finally:
            if sec_a:
                sec_a.close()
            if sec_b:
                sec_b.close()
            primary.close()

    def test_each_secondary_reads_whole_file(self, endpoint):
        """Every bound secondary can independently read the ENTIRE file byte-exact
        (overlapping ranges, not just disjoint stripes)."""
        host, port = endpoint
        size = 96 * 1024
        content = _det(size)
        _write_data_file("subs-whole.bin", content)

        primary, sessid = _establish_primary(host, port)
        primary_fh = _open_read(primary, b"\x00\x01", "/subs-whole.bin")
        secs = []
        try:
            for i in range(3):
                sock, _ = _bind_secondary(host, port, sessid,
                                          bytes([0, 0x60 + i]))
                secs.append((sock, bytes([0, 0x60 + i])))
            for sock, sid in secs:
                data = _read_range(sock, sid, primary_fh, 0, size)
                assert data == content, "whole-file bound read mismatch"
        finally:
            for sock, _ in secs:
                sock.close()
            primary.close()


@pytest.mark.requires_local_server
class TestDataSubstreamWrites:
    """Phase 94: bound secondaries carry kXR_write payloads for a primary-published
    writable fd handle — parallel UPLOAD.  The primary opens (and publishes) the
    writable handle; each secondary writes a DISJOINT byte range on its own
    connection; the concatenation must land byte-exact on disk in the server's
    export.  The export dir is fd-backed, so disjoint-offset pwrites from the
    independent reopened fds are POSIX-safe."""

    def test_single_bound_write_lands(self, endpoint):
        """One secondary writes the whole file; it lands byte-exact on disk."""
        host, port = endpoint
        size = 64 * 1024
        content = _det(size)
        name = "subs-w-single.bin"
        _rm_export_file(name)

        primary, sessid = _establish_primary(host, port)
        try:
            fh = _open_write(primary, b"\x00\x01", "/" + name)
            sec, _ = _bind_secondary(host, port, sessid, b"\x00\x30")
            try:
                st = _write_range(sec, b"\x00\x30", fh, 0, content)
                assert st == kXR_ok, f"bound write status {st}"
            finally:
                sec.close()
            assert _close_handle(primary, b"\x00\x01", fh) == kXR_ok
        finally:
            primary.close()

        assert _read_export_file(name) == content, "bound write not byte-exact"

    def test_striped_parallel_write_reassembles(self, endpoint):
        """N contiguous slices, each written on a DIFFERENT bound secondary, land as
        the byte-exact whole file — the core parallel-upload property."""
        host, port = endpoint
        n_streams = 4
        size = 240 * 1024
        content = _det(size)
        name = "subs-w-stripe.bin"
        _rm_export_file(name)

        primary, sessid = _establish_primary(host, port)
        secs = []
        try:
            fh = _open_write(primary, b"\x00\x01", "/" + name)
            for i in range(n_streams):
                s, _ = _bind_secondary(host, port, sessid, bytes([0, 0x31 + i]))
                secs.append(s)

            slice_len = size // n_streams
            for i in range(n_streams):
                off = i * slice_len
                st = _write_range(secs[i], bytes([0, 0x31 + i]), fh, off,
                                  content[off:off + slice_len])
                assert st == kXR_ok, f"stream {i} write status {st}"

            assert _close_handle(primary, b"\x00\x01", fh) == kXR_ok
        finally:
            for s in secs:
                s.close()
            primary.close()

        assert _read_export_file(name) == content, "striped writes != source"

    def test_concurrent_bound_writes_threaded(self, endpoint):
        """Genuinely concurrent in-flight writes: each secondary writes its slice in
        its own thread; the file must reassemble byte-exact."""
        host, port = endpoint
        n_streams = 4
        size = 200 * 1024
        content = _det(size)
        name = "subs-w-concurrent.bin"
        _rm_export_file(name)

        primary, sessid = _establish_primary(host, port)
        secs = []
        errors = [None] * n_streams
        try:
            fh = _open_write(primary, b"\x00\x01", "/" + name)
            for i in range(n_streams):
                s, _ = _bind_secondary(host, port, sessid, bytes([0, 0x41 + i]))
                secs.append(s)

            slice_len = size // n_streams

            def worker(idx):
                try:
                    off = idx * slice_len
                    st = _write_range(secs[idx], bytes([0, 0x41 + idx]), fh, off,
                                      content[off:off + slice_len])
                    if st != kXR_ok:
                        errors[idx] = f"status {st}"
                except Exception as exc:               # noqa: BLE001
                    errors[idx] = exc

            threads = [threading.Thread(target=worker, args=(i,))
                       for i in range(n_streams)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            for i in range(n_streams):
                assert errors[i] is None, f"stream {i} failed: {errors[i]}"
            assert _close_handle(primary, b"\x00\x01", fh) == kXR_ok
        finally:
            for s in secs:
                s.close()
            primary.close()

        assert _read_export_file(name) == content, "concurrent writes != source"

    def test_bound_conn_cannot_open(self, endpoint):
        """Security-negative: a bound secondary may NOT open/create a file itself —
        only the primary is the namespace authority."""
        host, port = endpoint
        primary, sessid = _establish_primary(host, port)
        sec, _ = _bind_secondary(host, port, sessid, b"\x00\x3a")
        try:
            opts = kXR_open_updt | kXR_new | kXR_delete
            open_body = struct.pack(">HH", 0o644, opts) + b"\x00" * 12
            status, _ = _send_req(sec, b"\x00\x3a", kXR_open, body=open_body,
                                  payload=b"/subs-w-evil.bin\x00")
            assert status == kXR_error, f"bound open must be refused, got {status}"
        finally:
            sec.close()
            primary.close()

    def test_bound_write_unpublished_handle_refused(self, endpoint):
        """Security-negative: a bound write to a handle the primary never published
        is refused (no wild writes to arbitrary handle indices)."""
        host, port = endpoint
        primary, sessid = _establish_primary(host, port)
        sec, _ = _bind_secondary(host, port, sessid, b"\x00\x3b")
        try:
            fh = bytes([7, 0, 0, 0])   # handle index 7 never opened/published
            st = _write_range(sec, b"\x00\x3b", fh, 0, b"x" * 128)
            assert st == kXR_error, f"write to unpublished handle must error, got {st}"
        finally:
            sec.close()
            primary.close()


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")
_XRDFS = os.path.join(_REPO, "client", "bin", "xrdfs")


@pytest.mark.requires_local_server
@pytest.mark.skipif(not os.path.exists(_XRDCP),
                    reason="brix-xrdcp not built (client/bin/xrdcp)")
class TestClientUploadFanout:
    """The BriX client (`brix-xrdcp`) fans an upload across bound secondaries BY
    DEFAULT (streams=4).  Against this fd-export endpoint the secondaries carry the
    bulk of the chunks; the transfer is byte-exact.  The BRIX_STREAMS_DEBUG summary
    proves the secondaries actually carried data (not a silent fall-back)."""

    def test_default_upload_fans_out_byte_exact(self, endpoint, tmp_path):
        host, port = endpoint
        size = 8 * 1024 * 1024                     # 8 MiB → 128 × 64 KiB chunks
        content = _det(size)
        src = tmp_path / "fanout-src.bin"
        src.write_bytes(content)
        name = "client-fanout.bin"
        _rm_export_file(name)

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        res = subprocess.run(
            [_XRDCP, "-f", str(src), f"root://{host}:{port}//{name}"],
            capture_output=True, text=True, env=env, timeout=120)
        assert res.returncode == 0, f"xrdcp failed: {res.stderr}"

        # byte-exact on the server's export
        assert _read_export_file(name) == content, "client upload not byte-exact"

        # the diagnostic line proves the secondaries carried chunks
        dbg = [l for l in res.stderr.splitlines() if "upload substreams=" in l]
        assert dbg, f"no substream diagnostic emitted: {res.stderr}"
        # e.g. "brix: upload substreams=3 chunks-on-secondaries=96"
        n_sec = int(dbg[-1].split("substreams=")[1].split()[0])
        on_sec = int(dbg[-1].split("chunks-on-secondaries=")[1].split()[0])
        assert n_sec >= 1, "client did not establish any bound secondary by default"
        assert on_sec > 0, "no chunks were carried by a secondary (silent fallback?)"


@pytest.mark.requires_local_server
@pytest.mark.skipif(not os.path.exists(_XRDCP),
                    reason="brix-xrdcp not built (client/bin/xrdcp)")
class TestClientDownloadFanout:
    """The BriX client (`brix-xrdcp`) also fans a DOWNLOAD across the bound
    secondaries BY DEFAULT (streams=4).  kXR_read carries no pathid, so a read
    issued on a bound secondary is served there against the primary-published
    handle; the client round-robins its reads over primary+secondaries.  Any
    secondary miss falls back to the primary read, so this is byte-exact even
    against a server that won't serve bound reads."""

    def test_default_download_fans_out_byte_exact(self, endpoint, tmp_path):
        host, port = endpoint
        # The download reads XRDC_COPY_CHUNK (8 MiB) per pump iteration, so the
        # file must span several chunks for the round-robin to reach a secondary:
        # 40 MiB → 5 reads → offsets 8/16/24 MiB land on bound secondaries.
        size = 40 * 1024 * 1024
        content = _det(size)
        name = "client-dl-fanout.bin"
        _write_data_file(name, content)            # seed the server export
        dst = tmp_path / "dl-fanout.bin"

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        res = subprocess.run(
            [_XRDCP, "-f", f"root://{host}:{port}//{name}", str(dst)],
            capture_output=True, text=True, env=env, timeout=120)
        assert res.returncode == 0, f"xrdcp download failed: {res.stderr}"

        assert dst.read_bytes() == content, "client download not byte-exact"

        dbg = [l for l in res.stderr.splitlines() if "download substreams=" in l]
        assert dbg, f"no download substream diagnostic emitted: {res.stderr}"
        # e.g. "brix: download substreams=3 chunks-on-secondaries=96"
        n_sec = int(dbg[-1].split("substreams=")[1].split()[0])
        on_sec = int(dbg[-1].split("chunks-on-secondaries=")[1].split()[0])
        assert n_sec >= 1, "client did not establish any bound secondary by default"
        assert on_sec > 0, "no chunks were read on a secondary (silent fallback?)"

    def test_parallel_striped_download_byte_exact(self, endpoint, tmp_path):
        """--parallel runs the TRUE concurrent striped download: one thread per
        bound connection, each pwrite-ing its disjoint byte range.  The stripes
        are reassembled by offset, so the file is byte-exact; the diagnostic
        proves >=2 stripes actually ran (real multi-stream, not the serial pump)."""
        host, port = endpoint
        size = 40 * 1024 * 1024                    # 4 stripes of 10 MiB @ streams=4
        content = _det(size)
        name = "client-par-dl.bin"
        _write_data_file(name, content)
        dst = tmp_path / "par-dl.bin"

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        res = subprocess.run(
            [_XRDCP, "--parallel", "-S", "4", "-f",
             f"root://{host}:{port}//{name}", str(dst)],
            capture_output=True, text=True, env=env, timeout=120)
        assert res.returncode == 0, f"parallel download failed: {res.stderr}"
        assert dst.read_bytes() == content, "parallel striped download not byte-exact"

        dbg = [l for l in res.stderr.splitlines() if "parallel-download stripes=" in l]
        assert dbg, f"parallel path did not engage: {res.stderr}"
        stripes = int(dbg[-1].split("stripes=")[1].split()[0])
        assert stripes >= 2, f"expected >=2 concurrent stripes, got {stripes}"


def _server_checksum(host, port, name):
    """Ask the server to compute the checksum of an already-stored file (kXR_query
    checksum via `brix-xrdfs query checksum`).  Returns (algo, hexdigest)."""
    res = subprocess.run(
        [_XRDFS, f"root://{host}:{port}/", "query", "checksum", f"/{name}"],
        capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, f"xrdfs query checksum failed: {res.stderr}"
    parts = res.stdout.split()
    assert len(parts) >= 2, f"unexpected checksum reply: {res.stdout!r}"
    return parts[0], parts[1].lower()


@pytest.mark.requires_local_server
@pytest.mark.skipif(not (os.path.exists(_XRDCP) and os.path.exists(_XRDFS)),
                    reason="brix-xrdcp / brix-xrdfs not built (client/bin)")
class TestSubwrittenChecksumParity:
    """S5 (phase-94 §4.4): a file written across bound secondaries (disjoint,
    possibly out-of-order pwrites@offset) must hash IDENTICALLY to the same bytes
    written on a single stream.  We upload the same content twice — once with the
    default streams=4 fan-out (genuinely sub-written: we assert chunks-on-secondaries>0
    so the parity check is not vacuous) and once single-stream (-S 1) — then ask the
    SERVER to checksum both.  Guards against a future streaming/rolling digest that
    would silently break under out-of-order disjoint substream writes."""

    def test_subwritten_file_checksum_matches_single_stream(self, endpoint, tmp_path):
        host, port = endpoint
        size = 8 * 1024 * 1024                      # spans many 64 KiB chunks
        content = _det(size)
        src = tmp_path / "cksum-src.bin"
        src.write_bytes(content)

        sub_name = "cksum-subwritten.bin"
        one_name = "cksum-singlestream.bin"
        _rm_export_file(sub_name)
        _rm_export_file(one_name)

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        # (1) sub-written: default streams=4 fan-out across bound secondaries
        r_sub = subprocess.run(
            [_XRDCP, "-f", str(src), f"root://{host}:{port}//{sub_name}"],
            capture_output=True, text=True, env=env, timeout=120)
        assert r_sub.returncode == 0, f"sub-written upload failed: {r_sub.stderr}"
        dbg = [l for l in r_sub.stderr.splitlines() if "upload substreams=" in l]
        assert dbg, f"no upload diagnostic: {r_sub.stderr}"
        on_sec = int(dbg[-1].split("chunks-on-secondaries=")[1].split()[0])
        assert on_sec > 0, "parity test vacuous: no chunks landed on a secondary"

        # (2) single-stream reference: -S 1 forces one connection
        r_one = subprocess.run(
            [_XRDCP, "-f", "-S", "1", str(src), f"root://{host}:{port}//{one_name}"],
            capture_output=True, text=True, timeout=120)
        assert r_one.returncode == 0, f"single-stream upload failed: {r_one.stderr}"

        # both landed byte-exact on disk
        assert _read_export_file(sub_name) == content
        assert _read_export_file(one_name) == content

        # the SERVER's checksum of the sub-written file equals the single-stream one
        algo_sub, ck_sub = _server_checksum(host, port, sub_name)
        algo_one, ck_one = _server_checksum(host, port, one_name)
        assert algo_sub == algo_one, f"algo mismatch {algo_sub} vs {algo_one}"
        assert ck_sub == ck_one, (
            f"sub-written checksum {ck_sub} != single-stream {ck_one} "
            f"({algo_sub}) — out-of-order substream writes corrupted the digest")

        # and it matches an independent computation of the source bytes
        if algo_sub == "adler32":
            assert ck_sub == format(zlib.adler32(content) & 0xffffffff, "08x")
        elif algo_sub in ("crc32", "crc32c"):
            assert ck_sub == format(zlib.crc32(content) & 0xffffffff, "08x") \
                or algo_sub == "crc32c"   # crc32c differs from zlib crc32; parity above suffices

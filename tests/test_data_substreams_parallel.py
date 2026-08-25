from split_continuation import reexport as _reexport
def _phase_test_concurrent_substream_reads_threaded_1(threads):
    for t in threads:
        t.join(timeout=30)

def _phase_test_concurrent_substream_reads_threaded_2(secs):
    for s in secs:
        s.close()

def _phase_test_concurrent_bound_writes_threaded_3(threads):
    for t in threads:
        t.join(timeout=30)

def _phase_test_concurrent_bound_writes_threaded_4(n_streams, errors):
    for i in range(n_streams):
        _check_test_concurrent_bound_writes_threaded_6(errors, i)

def _phase_test_concurrent_bound_writes_threaded_5(secs):
    for s in secs:
        s.close()


def _spawn_worker_threads(worker, n_streams):
    return [threading.Thread(target=worker, args=(i,))
            for i in range(n_streams)]


def _check_test_concurrent_substream_reads_threaded_1(errors, i):
    assert errors[i] is None, f"stream {i} raised: {errors[i]}"

def _check_test_concurrent_substream_reads_threaded_2(results, i, content, off, slice_len):
    assert results[i] == content[off:off + slice_len], (
        f"stream {i} returned wrong bytes")

def _check_test_striped_parallel_write_reassembles_5(content, name):
    assert _read_export_file(name) == content, "striped writes != source"

def _check_test_striped_parallel_write_reassembles_4(primary, fh):
    assert _close_handle(primary, b"\x00\x01", fh) == kXR_ok

def _check_test_striped_parallel_write_reassembles_3(st, i):
    assert st == kXR_ok, f"stream {i} write status {st}"

def _check_test_concurrent_bound_writes_threaded_8(content, name):
    assert _read_export_file(name) == content, "concurrent writes != source"

def _check_test_concurrent_bound_writes_threaded_7(primary, fh):
    assert _close_handle(primary, b"\x00\x01", fh) == kXR_ok

def _check_test_concurrent_bound_writes_threaded_6(errors, i):
    assert errors[i] is None, f"stream {i} failed: {errors[i]}"


_reexport(globals(), "_test_data_substreams_parallel_helpers")

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

            threads = _spawn_worker_threads(worker, n_streams)
            for t in threads:
                t.start()
            _phase_test_concurrent_substream_reads_threaded_1(threads)

            for i in range(n_streams):
                _check_test_concurrent_substream_reads_threaded_1(errors, i)
                off = i * slice_len
                _check_test_concurrent_substream_reads_threaded_2(results, i, content, off, slice_len)
        finally:
            _phase_test_concurrent_substream_reads_threaded_2(secs)
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
                _check_test_striped_parallel_write_reassembles_3(st, i)

            _check_test_striped_parallel_write_reassembles_4(primary, fh)
        finally:
            for s in secs:
                s.close()
            primary.close()

        _check_test_striped_parallel_write_reassembles_5(content, name)

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

            threads = _spawn_worker_threads(worker, n_streams)
            for t in threads:
                t.start()
            _phase_test_concurrent_bound_writes_threaded_3(threads)

            _phase_test_concurrent_bound_writes_threaded_4(n_streams, errors)
            _check_test_concurrent_bound_writes_threaded_7(primary, fh)
        finally:
            _phase_test_concurrent_bound_writes_threaded_5(secs)
            primary.close()

        _check_test_concurrent_bound_writes_threaded_8(content, name)

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

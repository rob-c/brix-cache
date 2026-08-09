from split_continuation import reexport as _reexport
_reexport(globals(), "_test_concurrent_helpers")

class TestConcurrent:

    # ---- single-connection baseline (reuse in later assertions) -----------

    def test_baseline_single_anon(self):
        """Single transfer baseline for anonymous endpoint."""
        results, wall = _run_concurrent(1, ANON_URL)
        _assert_and_report(results, 1, wall, "anon n=1 baseline")

    def test_baseline_single_gsi(self):
        """Single transfer baseline for GSI endpoint."""
        results, wall = _run_concurrent(1, GSI_URL)
        _assert_and_report(results, 1, wall, "gsi  n=1 baseline")

    # ---- concurrent anonymous --------------------------------------------

    def test_concurrent_2_anon(self):
        """2 simultaneous anonymous transfers — all must complete correctly."""
        results, wall = _run_concurrent(2, ANON_URL)
        _assert_and_report(results, 2, wall, "anon n=2")

    def test_concurrent_4_anon(self):
        """4 simultaneous anonymous transfers."""
        results, wall = _run_concurrent(4, ANON_URL)
        _assert_and_report(results, 4, wall, "anon n=4")

    def test_concurrent_8_anon(self):
        """8 simultaneous anonymous transfers."""
        results, wall = _run_concurrent(8, ANON_URL)
        _assert_and_report(results, 8, wall, "anon n=8")

    # ---- concurrent GSI --------------------------------------------------

    def test_concurrent_2_gsi(self):
        """2 simultaneous GSI-authenticated transfers."""
        results, wall = _run_concurrent(2, GSI_URL)
        _assert_and_report(results, 2, wall, "gsi  n=2")

    def test_concurrent_4_gsi(self):
        """4 simultaneous GSI-authenticated transfers."""
        results, wall = _run_concurrent(4, GSI_URL)
        _assert_and_report(results, 4, wall, "gsi  n=4")

    def test_concurrent_8_gsi(self):
        """8 simultaneous GSI-authenticated transfers."""
        results, wall = _run_concurrent(8, GSI_URL)
        _assert_and_report(results, 8, wall, "gsi  n=8")

    # ---- mixed anon + GSI ------------------------------------------------

    def test_concurrent_mixed_anon_and_gsi(self):
        """
        4 anonymous + 4 GSI transfers simultaneously from the same server.
        Verifies the server correctly multiplexes authenticated and
        unauthenticated connections in one event loop.
        """
        with _worker_pool(8) as pool:
            t0 = time.perf_counter()
            futures = (
                [pool.submit(_transfer_worker, i,   ANON_URL) for i in range(4)]
              + [pool.submit(_transfer_worker, i+4, GSI_URL)  for i in range(4)]
            )
            results = [f.result() for f in as_completed(futures)]
        wall = time.perf_counter() - t0

        anon_results = [r for r in results if ANON_URL in r["url"]]
        gsi_results  = [r for r in results if GSI_URL  in r["url"]]

        _assert_and_report(anon_results, 4, wall, "mixed → anon side")
        _assert_and_report(gsi_results,  4, wall, "mixed → gsi  side")

    # ---- scalability assertion -------------------------------------------

    @pytest.mark.timeout(240)
    def test_aggregate_throughput_scales_with_connections(self):
        """
        Aggregate throughput with 4 connections should be at least 1.5× that
        of 1 connection — i.e. the server actually parallelises I/O rather
        than serialising requests.
        """
        # Warm connections first so we measure data transfer not handshake
        _run_concurrent(1, ANON_URL)
        _run_concurrent(4, ANON_URL)

        # Best-of-2 to reduce single-sample noise
        wall1 = min(_run_concurrent(1, ANON_URL)[1], _run_concurrent(1, ANON_URL)[1])
        wall4 = min(_run_concurrent(4, ANON_URL)[1], _run_concurrent(4, ANON_URL)[1])

        agg1 = LARGE_FILE_SIZE / wall1
        agg4 = (4 * LARGE_FILE_SIZE) / wall4
        ratio = agg4 / agg1

        print(
            f"\n  n=1 aggregate: {agg1/1e6:.0f} MB/s  wall={wall1:.2f}s"
            f"\n  n=4 aggregate: {agg4/1e6:.0f} MB/s  wall={wall4:.2f}s"
            f"\n  scale-up ratio: {ratio:.2f}x"
        )

        assert ratio >= 1.5, (
            f"Expected ≥1.5× aggregate throughput at n=4 vs n=1, got {ratio:.2f}×. "
            f"n=1={agg1/1e6:.0f} MB/s  n=4={agg4/1e6:.0f} MB/s"
        )


class TestConcurrentTLS:
    """
    Same concurrency matrix as TestConcurrent but against the roots:// endpoint
    (GSI auth + kXR_ableTLS in-protocol TLS upgrade).
    """

    def test_baseline_single_gsi_tls(self):
        """Single transfer baseline for GSI+TLS endpoint."""
        results, wall = _run_concurrent(1, GSI_TLS_URL)
        _assert_and_report(results, 1, wall, "gsi+tls n=1 baseline")

    def test_concurrent_2_gsi_tls(self):
        """2 simultaneous GSI+TLS transfers."""
        results, wall = _run_concurrent(2, GSI_TLS_URL)
        _assert_and_report(results, 2, wall, "gsi+tls n=2")

    def test_concurrent_4_gsi_tls(self):
        """4 simultaneous GSI+TLS transfers."""
        results, wall = _run_concurrent(4, GSI_TLS_URL)
        _assert_and_report(results, 4, wall, "gsi+tls n=4")

    def test_concurrent_8_gsi_tls(self):
        """8 simultaneous GSI+TLS transfers."""
        results, wall = _run_concurrent(8, GSI_TLS_URL)
        _assert_and_report(results, 8, wall, "gsi+tls n=8")

    def test_concurrent_mixed_gsi_and_gsi_tls(self):
        """
        4 plain-GSI + 4 GSI+TLS transfers simultaneously.
        Verifies the server correctly multiplexes TLS-upgraded and plain
        connections within one event loop.
        """
        with _worker_pool(8) as pool:
            t0 = time.perf_counter()
            futures = (
                [pool.submit(_transfer_worker, i,   GSI_URL)     for i in range(4)]
              + [pool.submit(_transfer_worker, i+4, GSI_TLS_URL) for i in range(4)]
            )
            results = [f.result() for f in as_completed(futures)]
        wall = time.perf_counter() - t0

        gsi_results     = [r for r in results if GSI_URL     in r["url"] and GSI_TLS_URL not in r["url"]]
        gsi_tls_results = [r for r in results if GSI_TLS_URL in r["url"]]

        _assert_and_report(gsi_results,     4, wall, "mixed → gsi      side")
        _assert_and_report(gsi_tls_results, 4, wall, "mixed → gsi+tls  side")

    @pytest.mark.timeout(240)
    def test_aggregate_throughput_scales_gsi_tls(self):
        """
        Aggregate throughput with 4 GSI+TLS connections should be at least
        1.5× that of 1 connection — TLS overhead should not serialise I/O.
        """
        _run_concurrent(1, GSI_TLS_URL)
        _run_concurrent(4, GSI_TLS_URL)

        wall1 = min(_run_concurrent(1, GSI_TLS_URL)[1], _run_concurrent(1, GSI_TLS_URL)[1])
        wall4 = min(_run_concurrent(4, GSI_TLS_URL)[1], _run_concurrent(4, GSI_TLS_URL)[1])

        agg1 = LARGE_FILE_SIZE / wall1
        agg4 = (4 * LARGE_FILE_SIZE) / wall4
        ratio = agg4 / agg1

        print(
            f"\n  gsi+tls n=1 aggregate: {agg1/1e6:.0f} MB/s  wall={wall1:.2f}s"
            f"\n  gsi+tls n=4 aggregate: {agg4/1e6:.0f} MB/s  wall={wall4:.2f}s"
            f"\n  scale-up ratio: {ratio:.2f}x"
        )

        assert ratio >= 1.5, (
            f"Expected ≥1.5× aggregate throughput at n=4 vs n=1, got {ratio:.2f}×. "
            f"n=1={agg1/1e6:.0f} MB/s  n=4={agg4/1e6:.0f} MB/s"
        )


# ---------------------------------------------------------------------------
# Phase-32 WS3 / phase-33 P1.2 — concurrent in-flight cold AIO reads
# ---------------------------------------------------------------------------
#
# The classes above run each transfer in its OWN process, so each gets its own
# brix connection: concurrency across connections, never within one.  The recv
# state-machine flip these tests guard operates *within* a single connection —
# it lets several cold single-shot buffered reads be in flight at once instead
# of freezing recv after the first is handed to the AIO thread pool.  To
# exercise it we open many File handles to the SAME roots:// URL from threads:
# the XRootD client pools them onto one physical connection, so their reads
# multiplex on it (the proxy worker services each call on its own thread —
# tests/_xrdcl_worker.py).

_PIPE_FILE = "pipelined-tls.bin"



class TestPipelinedTLSReads:
    """Concurrent in-flight buffered (cold) AIO reads on ONE connection.

    Only the roots:// endpoint reaches read_post_aio — a cleartext regular-file
    read is served zero-copy by sendfile and never buffers (see
    read_sendfile_eligible).  Each read here is 1 MiB, i.e. <= BRIX_READ_WINDOW
    (2 MiB), so it is a single-shot buffered read: exactly the counted=1 path
    the flip lets pipeline (windowed reads > one window stay serial).
    """

    pytestmark = pytest.mark.timeout(120)

    READ   = 1 * 1024 * 1024
    NREADS = 16                          # > default brix_pipeline_depth (8):
    SIZE   = NREADS * (1 * 1024 * 1024)  # also drives the backpressure gate

    @classmethod
    def _ensure_file(cls) -> bytes:
        """Upload the patterned file once via the fast cleartext anon endpoint
        (same posix {DATA_DIR} export the roots:// server reads)."""
        content = _pipe_pattern(cls.SIZE)
        f = client.File()
        st, _ = f.open(f"{ANON_URL}//{_PIPE_FILE}",
                       OpenFlags.DELETE | OpenFlags.NEW)
        assert st.ok, f"upload open failed: {st.message}"
        # Write in <=8 MiB slices: pyxrootd relays each write as one base64 JSON
        # line through the single-worker proxy, and a single multi-MiB payload can
        # exceed the worker op timeout.  Chunking keeps each relayed message small
        # while producing a byte-identical file.
        chunk, off = 8 * 1024 * 1024, 0
        while off < len(content):
            part = content[off:off + chunk]
            st, _ = f.write(part, offset=off)
            assert st.ok, f"upload write@{off} failed: {st.message}"
            off += len(part)
        f.close()
        return content

    def test_pipelined_reads_demux_byte_exact(self):
        """Success + concurrency: NREADS reads issued simultaneously on one TLS
        connection each return their own slice byte-exact.  Proves per-streamID
        demultiplexing survives the concurrent-read flip and that the pipeline
        depth cap (NREADS > 8) does not drop or reorder responses."""
        content = self._ensure_file()
        with ThreadPoolExecutor(max_workers=self.NREADS) as pool:
            futs = [
                pool.submit(_tls_read_slice, i, i * self.READ, self.READ,
                            content[i * self.READ:(i + 1) * self.READ])
                for i in range(self.NREADS)
            ]
            results = [fu.result() for fu in as_completed(futs)]
        bad = [(i, d) for i, ok, d in results if not ok]
        assert not bad, f"concurrent TLS reads failed/mis-demuxed: {bad}"
        assert len(results) == self.NREADS

    def test_pipelined_reads_churn_survives(self):
        """Teardown safety: many rounds of heavily-concurrent TLS reads, each
        round closing 16 handles on the shared connection while sibling reads
        are still in the AIO pool.  Regression guard for the aio_inflight
        teardown-deferral — a kXR_close (namespace mutation) or disconnect must
        defer until in-flight reads drain, never freeing a read buffer a worker
        thread is still preading.  Final liveness probe proves the worker kept
        serving.  (test_aio.TestAioDestroyedGuard's RST/FIN drivers cover the
        cleartext sendfile path; this covers the buffered read_post_aio path,
        reachable only over TLS.)"""
        content = self._ensure_file()
        for _ in range(6):
            with ThreadPoolExecutor(max_workers=self.NREADS) as pool:
                futs = [
                    pool.submit(_tls_read_slice, i, i * self.READ, self.READ,
                                content[i * self.READ:(i + 1) * self.READ])
                    for i in range(self.NREADS)
                ]
                for fu in as_completed(futs):
                    fu.result()
        idx, ok, detail = _tls_read_slice(0, 0, self.READ, content[:self.READ])
        assert ok, f"server stopped serving after churn: {detail}"

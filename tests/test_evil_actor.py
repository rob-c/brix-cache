from split_continuation import reexport as _reexport
_reexport(globals(), "_test_evil_actor_helpers")

def test_a_hostile_frame_barrage(srv):
    """Fire every hostile frame from fresh sessions, repeatedly; no worker may
    crash and the server must keep serving."""
    srv.mark_log()
    for _ in range(FUZZ_REPEAT):
        for name, raw in _build_attacks(srv):
            try:
                s = _session(srv.root_port)
            except Exception:
                continue                 # transient; server liveness checked below
            try:
                s.sendall(raw)
                s.settimeout(2.0)
                try:
                    _read_response(s)    # consume a reply if any (rejection)
                except Exception:
                    pass                 # clean close / no reply = a valid rejection
            finally:
                try:
                    s.close()
                except OSError:
                    pass
    srv.assert_healthy("Phase A hostile-frame barrage")



def test_b_disconnect_mid_aio_uaf(srv):
    """Large offloaded read/pgread/readv/write + immediate hard RST, hammered from
    many connections. A use-after-free on the worker thread (freeing the scratch/
    payload buffer the worker is still pread/pwriting) surfaces as a SIGSEGV/ASAN
    abort in a worker — caught by the post-phase health check."""
    srv.mark_log()
    counter = [0]
    stop_at = time.time() + 90
    threads = [threading.Thread(target=_aio_rst_worker,
                                args=(srv.root_port, AIO_ROUNDS, stop_at, counter))
               for _ in range(AIO_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    print("\n[evil] AIO-RST rounds fired: %d" % counter[0])
    srv.assert_healthy("Phase B disconnect-mid-AIO")


# ---------------------------------------------------------------------------
# Phase C — endsess-then-pipelined-read + RST (post-teardown reuse / dbl-free)
# ---------------------------------------------------------------------------

def test_c_endsess_pipelined_then_rst(srv):
    srv.mark_log()
    for _ in range(200):
        s = None
        try:
            s = _connect(srv.root_port, timeout=4)
            _login(s)
            fh = _open_big(s)
        except Exception:
            if s is not None:
                _rst_close(s)
            continue
        # endsess + a pipelined large pgread in ONE segment, then RST
        pkt = _frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x05")
        pkt += _frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 16 << 20), sid=b"\x00\x06")
        try:
            s.sendall(pkt)
        except OSError:
            pass
        _rst_close(s)
    srv.assert_healthy("Phase C endsess+pipeline+RST")


# ---------------------------------------------------------------------------
# Phase D — resource exhaustion (handles / sessions) must shed, not crash
# ---------------------------------------------------------------------------

def test_d_resource_exhaustion(srv):
    srv.mark_log()
    # 1) exhaust the 16-slot handle table on one session, then keep opening
    s = _session(srv.root_port)
    try:
        for _ in range(64):
            _open(s, "/big.bin", flags=0x0010)   # >16 opens → must return errors
    except Exception:
        pass
    finally:
        try: s.close()
        except OSError: pass

    # 2) many concurrent sessions each flooding huge pgreads (budget shedding)
    def flood():
        try:
            s = _session(srv.root_port)
            fh = _open_big(s)
            for _ in range(20):
                s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 48 << 20)))
            try: s.settimeout(1.0); _read_response(s)
            except Exception: pass
            _rst_close(s)
        except Exception:
            pass
    ts = [threading.Thread(target=flood) for _ in range(24)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=60)

    # 3) connect/disconnect storm (session registry churn)
    for _ in range(300):
        try:
            s = _connect(srv.root_port, timeout=2)
            _rst_close(s)
        except Exception:
            pass
    srv.assert_healthy("Phase D resource exhaustion")


# ---------------------------------------------------------------------------
# Phase E — final proof the server is intact and serves correct bytes
# ---------------------------------------------------------------------------

def test_e_server_intact_and_correct(srv):
    srv.mark_log()
    expected = bytes((i * 31 + 7) & 0xFF for i in range(65536))
    s = _session(srv.root_port)
    try:
        fh = _open_big(s)
        # a normal read of the first 64 KiB must return the exact bytes
        s.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, 0, 65536)))
        st, body = _read_response(s)
        assert st == kXR_ok, "post-attack read failed: %r" % st
        assert body == expected, "post-attack read returned wrong bytes"
        # a normal pgread must still verify (status framing intact)
        s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, 0, 65536)))
        st, _ = _read_response(s)
        assert st in (kXR_ok, kXR_status), "post-attack pgread failed: %r" % st
    finally:
        try: s.close()
        except OSError: pass
    srv.assert_healthy("Phase E final integrity")

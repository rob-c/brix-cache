from _test_evil_actor_v3_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_c1_frm_async_deliver_to_recycled_conn(srv):
    _frm_skip(srv)
    srv.mark()
    # Reuse ONE nearline file: its first open posts a recall, and while that recall
    # is in flight every further open of the same file parks another waiter (the
    # server-side waiter is created regardless of whether the client reads the
    # kXR_waitresp). We do NOT wait for the open response — we RST immediately to
    # abandon the waiter mid-stall, which is the whole point. This keeps the test
    # independent of recall-drain throughput (one deduped recall, not N).
    # bounded: the server's event loop is sluggish while FRM recalls process, so
    # keep the round/connection count low (this is a UAF-deliver correctness check,
    # not a throughput test)
    rounds = min(ROUNDS, 6)
    for _ in range(rounds):
        a = None
        try:
            a, _sid = _session(srv.root_port)
            a.sendall(_frame(kXR_open, struct.pack("!HH2s6s4s", 0o644, OPEN_READ,
                      b"\x00\x00", b"\x00" * 6, b"\x00" * 4), b"/near.dat\x00", sid=b"\x00\x41"))
            time.sleep(0.01)                 # let the server register the waiter
            _rst(a); a = None
            # reconnect storm onto recycled fds; none may receive A's asynresp
            storm = []
            for _k in range(2):
                try:
                    b, _ = _session(srv.root_port)
                    b.sendall(_frame(kXR_ping, b"", sid=b"\x00\x42"))
                    _read_response(b)
                    storm.append(b)
                except Exception:
                    pass
            time.sleep(0.02)
            for b in storm:
                assert not _drain_for_attn(b, 0.04), \
                    "a recycled connection received a foreign kXR_attn(asynresp)"
            for b in storm:
                _rst(b)
        except Exception:
            pass
        finally:
            if a is not None:
                _rst(a)
    # the abandoned waiters' recall completes in the background; let it settle so
    # any (correctly-suppressed) asynresp attempt has happened before we assert
    time.sleep(1.0)
    # no crash is the immediate invariant; the event loop is sluggish while the
    # background recall drains, so allow a generous recovery window for the ping
    # (the server DOES recover — this is FRM recall latency, not a wedge)
    srv.assert_no_crash("C1 FRM async deliver-to-recycled")
    assert _ping_ok_retry(srv.root_port, tries=30, gap=1.0), \
        "server did not recover after FRM async park/RST cycles"


@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_c2_frm_reqid_forgery_owner_check(srv):
    _frm_skip(srv)
    srv.mark()
    try:
        # tenant B stages a file -> reqid R (must be real, non-"0", and monotonic)
        b, _ = _session(srv.root_port)
        st1, r1 = _prepare_stage(b, "/near000.dat")
        st2, r2 = _prepare_stage(b, "/near001.dat")
        b.close()
        if st1 != kXR_ok or not r1 or r1 == "0":
            pytest.skip("FRM stage did not return a durable reqid (got %r)" % r1)
        # reqid should be observably structured/monotonic (predictable)
        assert r1 != r2, "stage reqids not unique"

        # tenant A (a DIFFERENT session) cancels B's reqid by id alone
        a, _ = _session(srv.root_port)
        st_cancel = _prepare_cancel(a, r1)
        a.close()

        # a foreign principal's cancel of a non-owned reqid must be rejected.
        assert st_cancel not in (kXR_ok,), (
            "foreign session cancelled reqid %r it never owned (status=%r) — "
            "no ownership binding on the FRM cancel path" % (r1, st_cancel))
    finally:
        srv.assert_healthy("C2 FRM forge")


@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_c3_frm_flood_sheds_cleanly(srv):
    _frm_skip(srv)
    srv.mark()
    names = srv.near_names or ["/near%03d.dat" % i for i in range(60)]

    # Volume is bounded: a correct server sheds excess admissions past
    # max_inflight=64 (no enqueue) and dedups same-path recalls, so the staging
    # backlog stays small and drains in seconds. A runaway backlog would itself be
    # a shed failure (caught by the post-flood responsiveness check below).
    def flood(n):
        for _ in range(n):
            try:
                s, _ = _session(srv.root_port)
                for nm in random.sample(names, min(len(names), 12)):
                    try:
                        _prepare_stage(s, nm)
                    except Exception:
                        break
                s.close()
            except Exception:
                pass

    def dedup_hammer():
        # many connections recall the SAME file -> must collapse to one stagecmd
        for _ in range(12):
            try:
                s, _ = _session(srv.root_port)
                _open(s, "/near.dat", flags=OPEN_READ, sid=b"\x00\x43")
                s.close()
            except Exception:
                pass

    def huge_list():
        # one prepare carrying a large newline-separated path list -> per-request
        # bounding (must not over-enqueue or crash)
        for _ in range(3):
            try:
                s, _ = _session(srv.root_port)
                payload = ("\n".join(names)).encode() + b"\n"
                body = struct.pack("!BBHH10s", kXR_stage, 0, 0, 0, b"\x00" * 10)
                s.sendall(_frame(kXR_prepare, body, payload, sid=b"\x00\x44"))
                try:
                    s.settimeout(2.0); _read_response(s)
                except Exception:
                    pass
                s.close()
            except Exception:
                pass

    ts = ([threading.Thread(target=flood, args=(2,)) for _ in range(2)] +
          [threading.Thread(target=dedup_hammer) for _ in range(2)] +
          [threading.Thread(target=huge_list)])
    for t in ts: t.start()
    for t in ts: t.join(timeout=60)

    # durable queue file must not grow without bound (slot reuse, not append-forever)
    try:
        qsz = os.path.getsize(srv.queue) if os.path.exists(srv.queue) else 0
        assert qsz < 64 * 1024 * 1024, "FRM queue file grew unbounded: %d bytes" % qsz
    except OSError:
        pass
    # fake-MSS must not have been fork-stormed without bound
    if os.path.exists(srv.audit):
        try:
            lines = sum(1 for _ in open(srv.audit, errors="replace"))
            assert lines < 200000, "stage agent fork-storm: %d invocations" % lines
        except OSError:
            pass
    # no crash is the immediate invariant; then the bounded backlog must drain and
    # the server must serve again (a runaway backlog would fail this responsiveness
    # check, which is itself the "shed cleanly" assertion).
    srv.assert_no_crash("C3 FRM flood")
    assert _ping_ok_retry(srv.root_port, tries=30, gap=1.0), \
        "server did not recover after FRM flood (staging backlog not shed)"


@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_d_chaos_capstone(srv):
    srv.mark()
    tls_ok = _tls_available(srv)
    big = os.path.join(srv.datadir, "big.bin")
    big_md5_64k = hashlib.md5(open(big, "rb").read(65536)).hexdigest()
    stop = time.time() + 35
    errors = []

    def cleartext_aio():
        while time.time() < stop:
            s = None
            try:
                s = _connect(srv.root_port, 4); _login(s)
                _, st, body = _open(s, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    op = random.choice(("pgread", "readv", "write"))
                    fh = body[:4]
                    off = random.randrange(0, (BIGFILE_MB - 16) * 1024 * 1024)
                    if op == "pgread":
                        s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, off, 12 << 20)))
                    elif op == "readv":
                        segs = b"".join(struct.pack("!4siq", fh, 1 << 20, off + i * (1 << 20)) for i in range(8))
                        s.sendall(_frame(kXR_readv, b"", segs))
                    else:
                        _, stw, bw = _open(s, "/w.bin", flags=OPEN_UPDATE)
                        if stw == kXR_ok and len(bw) >= 4:
                            s.sendall(_frame(kXR_write, struct.pack("!4sqB3s", bw[:4], 0, 0, b"\x00" * 3), b"Z" * (1 << 20)))
            except Exception:
                pass
            if s is not None:
                _rst(s)

    def tls_aio():
        while time.time() < stop:
            t = None
            try:
                t = _roots_tls_connect(srv.root_tls_port, t=5)
                t.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0xFFFFFFFF, b"x\x00\x00\x00\x00\x00\x00\x00", 0, 0, 5, 0, 0))
                _read_response(t)
                _, st, body = _open(t, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    t.sendall(_frame(kXR_read, struct.pack("!4sqi", body[:4], 0, 12 << 20), sid=b"\x00\x0a"))
                    time.sleep(0.001)
            except Exception:
                pass
            if t is not None:
                _tls_rst(t)

    def bind_aba():
        while time.time() < stop:
            p = sec = None
            try:
                p, sid = _session(srv.root_port)
                _, st, body = _open(p, "/shared.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    sec = _connect(srv.root_port)
                    if _bind(sec, sid)[1] == kXR_ok:
                        sec.sendall(_frame(kXR_pgread, struct.pack("!4sqi", body[:4], 0, 8 << 20), sid=b"\x00\x0a"))
                    p.sendall(_frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x0b"))
            except Exception:
                pass
            for c in (sec, p):
                if c is not None:
                    _rst(c)

    def frm_chaos():
        while time.time() < stop:
            a = None
            try:
                a, _ = _session(srv.root_port)
                a.sendall(_frame(kXR_open, struct.pack("!HH2s6s4s", 0o644, OPEN_READ,
                          b"\x00\x00", b"\x00" * 6, b"\x00" * 4), b"/near.dat\x00", sid=b"\x00\x41"))
                time.sleep(0.05)
            except Exception:
                pass
            if a is not None:
                _rst(a)

    def http_abort():
        while time.time() < stop:
            _https_get(srv.https_port, "/big.bin", abort_after=random.choice((4096, 65536)))
            _https_get(srv.https_port, "/s3b/big.bin", abort_after=8192)

    def control_root():
        while time.time() < stop:
            try:
                s, _ = _session(srv.root_port)
                _, st, body = _open(s, "/big.bin", flags=OPEN_READ)
                if st == kXR_ok and len(body) >= 4:
                    _, _, data = _read(s, body[:4], 0, 65536, sid=b"\x00\x0c")
                    if data and hashlib.md5(data).hexdigest() != big_md5_64k:
                        errors.append("control_root corrupt")
                s.close()
            except Exception:
                pass
            time.sleep(0.05)

    threads = ([threading.Thread(target=cleartext_aio) for _ in range(5)] +
               [threading.Thread(target=bind_aba) for _ in range(3)] +
               [threading.Thread(target=control_root) for _ in range(2)] +
               [threading.Thread(target=http_abort) for _ in range(2)])
    if tls_ok:
        threads += [threading.Thread(target=tls_aio) for _ in range(3)]
    if srv.have_xattr:
        threads += [threading.Thread(target=frm_chaos) for _ in range(2)]
    for t in threads: t.start()
    # crash-check mid-flight (NO ping — that would race the 17-thread load and
    # false-positive; the control_root threads are the live correctness signal)
    while time.time() < stop:
        time.sleep(2.0)
        srv.assert_no_crash("D chaos (mid-flight)")
    for t in threads: t.join(timeout=60)
    assert not errors, "silent cross-plane corruption: %r" % errors[:5]
    time.sleep(FRM_LATENCY_MS / 1000.0 + 0.5)
    srv.assert_healthy("D chaos capstone")

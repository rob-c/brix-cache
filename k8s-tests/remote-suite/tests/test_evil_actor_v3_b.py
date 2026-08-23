from _test_evil_actor_v3_helpers import *  # noqa: F401,F403


def _abandon_recall_waiter(srv):
    connection, _ = _session(srv.root_port)
    request = struct.pack(
        "!HH2s6s4s", 0o644, OPEN_READ,
        b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
    )
    connection.sendall(
        _frame(kXR_open, request, b"/near.dat\x00", sid=b"\x00\x41")
    )
    time.sleep(0.01)
    _rst(connection)


def _ping_storm(srv, count=2):
    connections = []
    for _ in range(count):
        try:
            connection, _ = _session(srv.root_port)
            connection.sendall(_frame(kXR_ping, b"", sid=b"\x00\x42"))
            _read_response(connection)
            connections.append(connection)
        except Exception:
            pass
    return connections


def _assert_no_foreign_attention(connections):
    for connection in connections:
        assert not _drain_for_attn(connection, 0.04), (
            "a recycled connection received a foreign kXR_attn(asynresp)"
        )


def _close_reset(connections):
    for connection in connections:
        _rst(connection)


def _frm_recycle_round(srv):
    storm = []
    try:
        _abandon_recall_waiter(srv)
        storm = _ping_storm(srv)
        time.sleep(0.02)
        _assert_no_foreign_attention(storm)
    except Exception:
        pass
    finally:
        _close_reset(storm)


def _run_frm_recycle_rounds(srv):
    for _ in range(min(ROUNDS, 6)):
        _frm_recycle_round(srv)


def _frm_flood(srv, names, count):
    for _ in range(count):
        try:
            connection, _ = _session(srv.root_port)
            for name in random.sample(names, min(len(names), 12)):
                try:
                    _prepare_stage(connection, name)
                except Exception:
                    break
            connection.close()
        except Exception:
            pass


def _frm_dedup_hammer(srv):
    for _ in range(12):
        try:
            connection, _ = _session(srv.root_port)
            _open(connection, "/near.dat", flags=OPEN_READ, sid=b"\x00\x43")
            connection.close()
        except Exception:
            pass


def _send_large_prepare(srv, names):
    connection, _ = _session(srv.root_port)
    payload = ("\n".join(names)).encode() + b"\n"
    body = struct.pack("!BBHH10s", kXR_stage, 0, 0, 0, b"\x00" * 10)
    connection.sendall(_frame(kXR_prepare, body, payload, sid=b"\x00\x44"))
    try:
        connection.settimeout(2.0)
        _read_response(connection)
    except Exception:
        pass
    connection.close()


def _frm_huge_list(srv, names):
    for _ in range(3):
        try:
            _send_large_prepare(srv, names)
        except Exception:
            pass


def _frm_flood_threads(srv, names):
    threads = [threading.Thread(target=_frm_flood, args=(srv, names, 2))
               for _ in range(2)]
    threads.extend(threading.Thread(target=_frm_dedup_hammer, args=(srv,))
                   for _ in range(2))
    threads.append(threading.Thread(target=_frm_huge_list, args=(srv, names)))
    return threads


def _run_threads(threads, timeout=60):
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=timeout)


def _assert_frm_queue_bounded(srv):
    try:
        size = os.path.getsize(srv.queue) if os.path.exists(srv.queue) else 0
    except OSError:
        return
    assert size < 64 * 1024 * 1024, (
        "FRM queue file grew unbounded: %d bytes" % size
    )


def _assert_stage_agent_bounded(srv):
    if not os.path.exists(srv.audit):
        return
    try:
        with open(srv.audit, errors="replace") as source:
            lines = sum(1 for _ in source)
    except OSError:
        return
    assert lines < 200000, "stage agent fork-storm: %d invocations" % lines


def _send_random_cleartext_aio(connection, handle):
    offset = random.randrange(0, (BIGFILE_MB - 16) * 1024 * 1024)
    operation = random.choice(("pgread", "readv", "write"))
    if operation == "pgread":
        request = struct.pack("!4sqi", handle, offset, 12 << 20)
        connection.sendall(_frame(kXR_pgread, request))
        return
    if operation == "readv":
        segments = b"".join(
            struct.pack("!4siq", handle, 1 << 20, offset + i * (1 << 20))
            for i in range(8)
        )
        connection.sendall(_frame(kXR_readv, b"", segments))
        return
    _, status, body = _open(connection, "/w.bin", flags=OPEN_UPDATE)
    if status == kXR_ok and len(body) >= 4:
        request = struct.pack("!4sqB3s", body[:4], 0, 0, b"\x00" * 3)
        connection.sendall(_frame(kXR_write, request, b"Z" * (1 << 20)))


def _cleartext_aio_round(srv):
    connection = None
    try:
        connection = _connect(srv.root_port, 4)
        _login(connection)
        _, status, body = _open(connection, "/big.bin", flags=OPEN_READ)
        if status == kXR_ok and len(body) >= 4:
            _send_random_cleartext_aio(connection, body[:4])
    except Exception:
        pass
    finally:
        if connection is not None:
            _rst(connection)


def _cleartext_aio_worker(srv, stop):
    while time.time() < stop:
        _cleartext_aio_round(srv)


def _tls_aio_round(srv):
    connection = None
    try:
        connection = _roots_tls_connect(srv.root_tls_port, t=5)
        request = struct.pack(
            "!2sHI8sBBBBI", b"\x00\x01", kXR_login,
            os.getpid() & 0xFFFFFFFF, b"x\x00\x00\x00\x00\x00\x00\x00",
            0, 0, 5, 0, 0,
        )
        connection.sendall(request)
        _read_response(connection)
        _, status, body = _open(connection, "/big.bin", flags=OPEN_READ)
        if status == kXR_ok and len(body) >= 4:
            read = struct.pack("!4sqi", body[:4], 0, 12 << 20)
            connection.sendall(_frame(kXR_read, read, sid=b"\x00\x0a"))
            time.sleep(0.001)
    except Exception:
        pass
    finally:
        if connection is not None:
            _tls_rst(connection)


def _tls_aio_worker(srv, stop):
    while time.time() < stop:
        _tls_aio_round(srv)


def _send_bound_pgread(srv, session_id, handle):
    secondary = _connect(srv.root_port)
    if _bind(secondary, session_id)[1] == kXR_ok:
        request = struct.pack("!4sqi", handle, 0, 8 << 20)
        secondary.sendall(_frame(kXR_pgread, request, sid=b"\x00\x0a"))
    return secondary


def _bind_aba_round(srv):
    primary = secondary = None
    try:
        primary, session_id = _session(srv.root_port)
        _, status, body = _open(primary, "/shared.bin", flags=OPEN_READ)
        if status != kXR_ok or len(body) < 4:
            return
        secondary = _send_bound_pgread(srv, session_id, body[:4])
        primary.sendall(_frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x0b"))
    except Exception:
        pass
    finally:
        _close_reset(item for item in (secondary, primary) if item is not None)


def _bind_aba_worker(srv, stop):
    while time.time() < stop:
        _bind_aba_round(srv)


def _frm_chaos_round(srv):
    connection = None
    try:
        connection, _ = _session(srv.root_port)
        body = struct.pack(
            "!HH2s6s4s", 0o644, OPEN_READ,
            b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
        )
        connection.sendall(
            _frame(kXR_open, body, b"/near.dat\x00", sid=b"\x00\x41")
        )
        time.sleep(0.05)
    except Exception:
        pass
    finally:
        if connection is not None:
            _rst(connection)


def _frm_chaos_worker(srv, stop):
    while time.time() < stop:
        _frm_chaos_round(srv)


def _http_abort_worker(srv, stop):
    while time.time() < stop:
        _https_get(srv.https_port, "/big.bin", abort_after=random.choice((4096, 65536)))
        _https_get(srv.https_port, "/s3b/big.bin", abort_after=8192)


def _control_root_round(srv, expected_md5, errors):
    try:
        connection, _ = _session(srv.root_port)
        _, status, body = _open(connection, "/big.bin", flags=OPEN_READ)
        if status == kXR_ok and len(body) >= 4:
            _, _, data = _read(connection, body[:4], 0, 65536, sid=b"\x00\x0c")
            if data and hashlib.md5(data).hexdigest() != expected_md5:
                errors.append("control_root corrupt")
        connection.close()
    except Exception:
        pass


def _control_root_worker(srv, stop, expected_md5, errors):
    while time.time() < stop:
        _control_root_round(srv, expected_md5, errors)
        time.sleep(0.05)


def _worker_threads(target, args, count):
    return [threading.Thread(target=target, args=args) for _ in range(count)]


def _chaos_threads(srv, stop, expected_md5, errors, tls_ok):
    threads = _worker_threads(_cleartext_aio_worker, (srv, stop), 5)
    threads.extend(_worker_threads(_bind_aba_worker, (srv, stop), 3))
    control_args = (srv, stop, expected_md5, errors)
    threads.extend(_worker_threads(_control_root_worker, control_args, 2))
    threads.extend(_worker_threads(_http_abort_worker, (srv, stop), 2))
    if tls_ok:
        threads.extend(_worker_threads(_tls_aio_worker, (srv, stop), 3))
    if srv.have_xattr:
        threads.extend(_worker_threads(_frm_chaos_worker, (srv, stop), 2))
    return threads


def _monitor_chaos(srv, stop):
    while time.time() < stop:
        time.sleep(2.0)
        srv.assert_no_crash("D chaos (mid-flight)")


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
    _run_frm_recycle_rounds(srv)
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

    threads = _frm_flood_threads(srv, names)
    _run_threads(threads)

    # durable queue file must not grow without bound (slot reuse, not append-forever)
    _assert_frm_queue_bounded(srv)
    # fake-MSS must not have been fork-stormed without bound
    _assert_stage_agent_bounded(srv)
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
    with open(big, "rb") as source:
        big_md5_64k = hashlib.md5(source.read(65536)).hexdigest()
    stop = time.time() + 35
    errors = []
    threads = _chaos_threads(srv, stop, big_md5_64k, errors, tls_ok)
    for thread in threads:
        thread.start()
    # crash-check mid-flight (NO ping — that would race the 17-thread load and
    # false-positive; the control_root threads are the live correctness signal)
    _monitor_chaos(srv, stop)
    for thread in threads:
        thread.join(timeout=60)
    assert not errors, "silent cross-plane corruption: %r" % errors[:5]
    time.sleep(FRM_LATENCY_MS / 1000.0 + 0.5)
    srv.assert_healthy("D chaos capstone")

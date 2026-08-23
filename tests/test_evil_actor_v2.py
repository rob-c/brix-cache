from split_continuation import reexport as _reexport
_reexport(globals(), "_test_evil_actor_v2_helpers")


def _reset_connections(connections):
    for connection in connections:
        if connection is not None:
            _rst(connection)


def _write_bytes(path, content):
    with open(path, "wb") as target:
        target.write(content)


def _swap_shared_file(path):
    try:
        os.unlink(path)
    except OSError:
        pass
    _write_bytes(path, b"SWAPPED!" * 4096)


def _consume_response(connection):
    try:
        connection.settimeout(3.0)
        _read_response(connection)
    except Exception:
        pass


def _bind_inode_swap_round(srv, shared):
    primary = secondary = None
    try:
        primary, session_id = _session(srv.root_port)
        status, body = _open(primary, "/shared.bin", flags=0x0010)
        if status != kXR_ok or len(body) < 4:
            return
        handle = body[:4]
        secondary = _connect(srv.root_port)
        if _bind(secondary, session_id)[0] != kXR_ok:
            return
        request = struct.pack("!4sqi", handle, 0, 8 << 20)
        secondary.sendall(_frame(kXR_pgread, request, sid=b"\x00\x0a"))
        time.sleep(0.002)
        primary.sendall(_frame(
            kXR_close, handle + b"\x00" * 12, sid=b"\x00\x0b"
        ))
        _swap_shared_file(shared)
        _consume_response(secondary)
    except Exception:
        pass
    finally:
        _reset_connections((secondary, primary))


def _bound_secondaries(srv, session_id, count=5):
    connections = []
    for _ in range(count):
        connection = _connect(srv.root_port)
        if _bind(connection, session_id)[0] == kXR_ok:
            connections.append(connection)
        else:
            _rst(connection)
    return connections


def _fire_pgreads(connections, handle, offset):
    request = struct.pack("!4sqi", handle, offset, 8 << 20)
    for connection in connections:
        try:
            connection.sendall(_frame(kXR_pgread, request, sid=b"\x00\x0a"))
        except OSError:
            pass


def _many_secondaries_round(srv):
    primary = None
    secondaries = []
    try:
        primary, session_id = _session(srv.root_port)
        status, body = _open(primary, "/big.bin", flags=0x0010)
        if status != kXR_ok or len(body) < 4:
            return
        handle = body[:4]
        secondaries = _bound_secondaries(srv, session_id)
        offset = random.randrange(0, (BIGFILE_MB - 8) * 1024 * 1024)
        _fire_pgreads(secondaries, handle, offset)
        primary.sendall(_frame(
            kXR_close, handle + b"\x00" * 12, sid=b"\x00\x0b"
        ))
    except Exception:
        pass
    finally:
        _reset_connections([*secondaries, primary])


def _forged_bind_accepted(srv):
    connection = _connect(srv.root_port)
    try:
        session_id = bytes(random.randrange(256) for _ in range(16))
        return _bind(connection, session_id)[0] == kXR_ok
    except Exception:
        return False
    finally:
        _rst(connection)


def _forged_bind_count(srv, attempts):
    return sum(_forged_bind_accepted(srv) for _ in range(attempts))


def _pipelined_scratch_round(srv):
    connection = None
    try:
        connection = _connect(srv.root_port, 4)
        _login(connection)
        status, body = _open(connection, "/big.bin", flags=0x0010)
        if status != kXR_ok or len(body) < 4:
            return
        handle = body[:4]
        packet = _frame(
            kXR_read, struct.pack("!4sqi", handle, 0, 4 << 20), sid=b"\x00\x21"
        )
        segments = b"".join(
            struct.pack("!4siq", handle, 1 << 20, index << 20)
            for index in range(4)
        )
        packet += _frame(kXR_readv, b"", segments, sid=b"\x00\x22")
        packet += _frame(
            kXR_pgread, struct.pack("!4sqi", handle, 0, 4 << 20),
            sid=b"\x00\x23",
        )
        connection.sendall(packet)
    except Exception:
        pass
    finally:
        if connection is not None:
            _rst(connection)


def _send_fuzz_truncate(connection, rng, handle):
    length = rng.choice((-1, 0, 1 << 62))
    connection.sendall(_frame(
        kXR_truncate, handle + struct.pack("!q", length) + b"\x00" * 4
    ))


def _send_fuzz_checkpoint(connection, rng, handle):
    write = _frame(
        kXR_write,
        struct.pack("!4sqB3s", b"\x07\x00\x00\x00", 0, 0, b"\x00" * 3),
        b"x" * 16,
    )
    payload = write if rng.random() < 0.5 else b""
    body = handle + bytes([rng.randrange(6)]) + b"\x00" * 11
    connection.sendall(_frame(kXR_chkpoint, body, payload))


def _send_fuzz_fattr(connection, rng, handle):
    body = (
        handle + bytes([rng.randrange(256)])
        + bytes([rng.choice((0, 1, 16, 255))]) + b"\x00" * 10
    )
    connection.sendall(
        _frame(kXR_fattr, body, b"\xff" * rng.choice((0, 2, 40)))
    )


def _send_fuzz_sync(connection, rng, handle):
    connection.sendall(_frame(kXR_sync, handle + b"\x00" * 12))


def _send_fuzz_endsess(connection, rng, handle):
    session_id = bytes(rng.randrange(256) for _ in range(16))
    packet = _frame(kXR_endsess, session_id)
    packet += _frame(kXR_read, struct.pack("!4sqi", handle, 0, 4 << 20))
    connection.sendall(packet)


def _send_fuzz_operation(connection, rng, handle):
    operations = {
        kXR_truncate: _send_fuzz_truncate,
        kXR_chkpoint: _send_fuzz_checkpoint,
        kXR_fattr: _send_fuzz_fattr,
        kXR_sync: _send_fuzz_sync,
        kXR_endsess: _send_fuzz_endsess,
    }
    opcode = rng.choice(tuple(operations))
    operations[opcode](connection, rng, handle)


def _consume_fuzz_response(connection):
    try:
        connection.settimeout(1.0)
        _read_response(connection)
    except Exception:
        pass


def _stateful_fuzz_round(srv, rng):
    connection = None
    try:
        connection = _connect(srv.root_port, 4)
        _login(connection)
        status, body = _open(connection, "/w.bin", flags=0x0010 | 0x0020)
        handle = body[:4] if status == kXR_ok and len(body) >= 4 else b"\x00" * 4
        _send_fuzz_operation(connection, rng, handle)
        _consume_fuzz_response(connection)
    except Exception:
        pass
    finally:
        if connection is not None:
            _rst(connection)


def _root_rw_worker(srv, stop):
    while time.time() < stop:
        connection = None
        try:
            connection = _connect(srv.root_port, 3)
            _login(connection)
            status, body = _open(connection, "/xp.bin", flags=0x0010)
            if status == kXR_ok and len(body) >= 4:
                _read(connection, body[:4], 0, 1 << 20)
        except Exception:
            pass
        finally:
            if connection is not None:
                _rst(connection)


def _webdav_worker(stop):
    propfind = b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
    while time.time() < stop:
        _http("GET", "/xp.bin")
        _http("PROPFIND", "/xp.bin", body=propfind)


def _s3_worker(stop):
    while time.time() < stop:
        _http("GET", "/s3b/xp.bin", port=_XP_S3[0])
        _http("HEAD", "/s3b/xp.bin", port=_XP_S3[0])


def _swap_file_round(shared, original):
    try:
        _write_bytes(shared, b"X" * random.randrange(4096, 1 << 20))
        time.sleep(0.01)
        os.unlink(shared)
    except OSError:
        pass
    _write_bytes(shared, original)
    time.sleep(0.01)


def _swapper_worker(shared, original, stop):
    while time.time() < stop:
        _swap_file_round(shared, original)


def _worker_threads(target, args, count):
    return [threading.Thread(target=target, args=args) for _ in range(count)]


def _cross_protocol_threads(srv, shared, original, stop):
    threads = _worker_threads(_root_rw_worker, (srv, stop), 4)
    threads.extend(_worker_threads(_webdav_worker, (stop,), 3))
    threads.extend(_worker_threads(_s3_worker, (stop,), 2))
    threads.extend(_worker_threads(_swapper_worker, (shared, original, stop), 2))
    return threads


def _run_threads(threads, timeout=60):
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=timeout)


def test_p1_bind_handle_inode_swap_race(srv):
    """A bound secondary reads a primary-published handle while the file is
    close+unlink+recreate'd underneath (shim holds the secondary's worker pread
    open across the swap). Must not crash/UAF a worker."""
    srv.mark()
    shared = os.path.join(srv.datadir, "shared.bin")
    with open(shared, "rb") as source:
        original = source.read()
    for i in range(ROUNDS):
        _bind_inode_swap_round(srv, shared)
        if i % 40 == 0:
            _write_bytes(shared, original)
    _write_bytes(shared, original)
    srv.assert_healthy("P1 bind inode-swap race")


def test_p1b_many_secondaries_close_race(srv):
    """N bound secondaries with in-flight reads on one primary handle while the
    primary closes it — exercises the per-secondary revocation/in-flight window."""
    srv.mark()
    for _ in range(max(20, ROUNDS // 4)):
        _many_secondaries_round(srv)
    srv.assert_healthy("P1b many-secondaries close race")


# --------------------------- P2: cross-session bind security contract --------

def test_p2_bind_security_contract(srv):
    """A secondary needs only a captured sessid to inherit identity + read the
    primary's handle (bearer-token model); a forged/random sessid is rejected."""
    srv.mark()
    p, sid = _session(srv.root_port)
    try:
        st, body = _open(p, "/big.bin", flags=0x0010)
        assert st == kXR_ok and len(body) >= 4
        fh = body[:4]
        # captured sessid => bind succeeds + can read the primary's handle
        sec = _connect(srv.root_port)
        st_b, pbody = _bind(sec, sid)
        assert st_b == kXR_ok, "bind with captured sessid should succeed"
        rst, _ = _read(sec, fh, 0, 65536, sid=b"\x00\x0c")
        assert rst in (kXR_ok, kXR_status), \
            "bound secondary should read the primary handle: %r" % rst
        _rst(sec)
        # forged/random sessids must NOT grant a session
        forged_ok = _forged_bind_count(srv, 64)
        assert forged_ok == 0, (
            "%d/64 RANDOM sessids were accepted by kXR_bind — the session id is "
            "guessable/forgeable (it is not a CSPRNG): session-hijack risk" % forged_ok)
    finally:
        _rst(p)
    srv.assert_healthy("P2 bind security contract")


# --------------------------- P3: disconnect-mid-AIO (shim-widened) -----------


def test_p3_disconnect_mid_aio_widened(srv):
    srv.mark()
    counter = [0]; stop_at = time.time() + 70
    ts = [threading.Thread(target=_aio_rst_worker,
                           args=(srv.root_port, srv.datadir, ROUNDS, stop_at, counter))
          for _ in range(6)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=120)
    print("\n[evil2] P3 shim-widened AIO-RST rounds: %d" % counter[0])
    srv.assert_healthy("P3 disconnect-mid-AIO (widened)")


# --------------------------- P4: pipelined scratch reuse ---------------------

def test_p4_pipelined_scratch_reuse(srv):
    srv.mark()
    for _ in range(max(40, ROUNDS // 2)):
        _pipelined_scratch_round(srv)
    srv.assert_healthy("P4 pipelined scratch reuse")


# --------------------------- P5: stateful / less-tested opcode fuzz ----------

def test_p5_stateful_opcode_fuzz(srv):
    srv.mark()
    rng = random.Random(1337)
    for _ in range(max(60, ROUNDS)):
        _stateful_fuzz_round(srv, rng)
    srv.assert_healthy("P5 stateful opcode fuzz")


# --------------------------- P6: cross-protocol simultaneous assault ---------


def test_p6_cross_protocol_assault(srv):
    srv.mark()
    _XP_HTTP[0] = srv.webdav_port
    _XP_S3[0] = srv.s3_port
    shared = os.path.join(srv.datadir, "xp.bin")
    with open(shared, "rb") as source:
        original = source.read()
    stop = time.time() + 25
    threads = _cross_protocol_threads(srv, shared, original, stop)
    _run_threads(threads)
    _write_bytes(shared, original)
    srv.assert_healthy("P6 cross-protocol assault")


# --------------------------- P7: survival + integrity -----------------------

def test_p7_integrity(srv):
    srv.mark()
    expected = bytes((i * 31 + 7) & 0xFF for i in range(65536))
    s, _ = _session(srv.root_port)
    try:
        st, body = _open(s, "/big.bin", flags=0x0010)
        assert st == kXR_ok and len(body) >= 4
        fh = body[:4]
        st, data = _read(s, fh, 0, 65536)
        assert st == kXR_ok, "post-assault read failed: %r" % st
        assert data == expected, "post-assault read returned wrong bytes"
    finally:
        _rst(s)
    srv.assert_healthy("P7 final integrity")

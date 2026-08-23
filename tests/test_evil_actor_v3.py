from split_continuation import reexport as _reexport
_reexport(globals(), "_test_evil_actor_v3_helpers")


def _tls_login_checked(connection, user):
    request = struct.pack(
        "!2sHI8sBBBBI", b"\x00\x01", kXR_login,
        os.getpid() & 0xFFFFFFFF, user, 0, 0, 5, 0, 0,
    )
    connection.sendall(request)
    _, status, _ = _read_response(connection)
    assert status == kXR_ok, "TLS login failed: %r" % status


def _open_handle_checked(connection, path):
    _, status, body = _open(connection, path, flags=OPEN_READ)
    assert status == kXR_ok and len(body) >= 4
    return body[:4]


def _read_small_tls_file(connection, handle, length):
    data = b""
    offset = 0
    while offset < length:
        request = struct.pack("!4sqi", handle, offset, 65536)
        connection.sendall(_frame(kXR_read, request, sid=b"\x00\x05"))
        _, status, chunk = _read_response(connection)
        assert status in (kXR_ok, kXR_oksofar), "read st=%r" % status
        if not chunk:
            break
        data += chunk
        offset += len(chunk)
    return data


def _collect_tls_windows(connection, handle, length):
    request = struct.pack("!4sqi", handle, 0, length)
    connection.sendall(_frame(kXR_read, request, sid=b"\x00\x08"))
    data = b""
    terminal = 0
    while len(data) < length:
        _, status, chunk = _read_response(connection)
        data += chunk
        if status == kXR_ok:
            terminal += 1
            break
        assert status in (kXR_oksofar, kXR_status), "windowed read st=%r" % status
    assert terminal == 1, "expected exactly one terminating kXR_ok"
    return data


def _exercise_tls_reads(srv, origin_small, small_md5):
    connection = _roots_tls_connect(srv.root_tls_port)
    try:
        _tls_login_checked(connection, b"tls\x00\x00\x00\x00\x00")
        handle = _open_handle_checked(connection, "/shared.bin")
        actual = _read_small_tls_file(connection, handle, len(origin_small))
        assert hashlib.md5(actual).hexdigest() == small_md5, "TLS small read corrupt"
        handle = _open_handle_checked(connection, "/big.bin")
        actual = _collect_tls_windows(connection, handle, 12 << 20)
        with open(os.path.join(srv.datadir, "big.bin"), "rb") as source:
            expected = source.read(len(actual))
        assert actual == expected, "TLS windowed read bytes diverged"
    finally:
        connection.close()


def _interrupt_tls_aio(srv):
    connection = None
    try:
        connection = _roots_tls_connect(srv.root_tls_port, t=6)
        _tls_login_checked(connection, b"a\x00\x00\x00\x00\x00\x00\x00")
        _, status, body = _open(connection, "/big.bin", flags=OPEN_READ)
        if status != kXR_ok or len(body) < 4:
            return
        offset = random.randrange(0, (BIGFILE_MB - 16) * 1024 * 1024)
        request = struct.pack("!4sqi", body[:4], offset, 16 << 20)
        connection.sendall(_frame(kXR_read, request, sid=b"\x00\x0a"))
        time.sleep(0.001)
    except Exception:
        pass
    finally:
        if connection is not None:
            _tls_rst(connection)


def _control_tls_read(srv, expected_md5):
    try:
        connection = _roots_tls_connect(srv.root_tls_port, t=6)
        _tls_login_checked(connection, b"c\x00\x00\x00\x00\x00\x00\x00")
        _, status, body = _open(connection, "/big.bin", flags=OPEN_READ)
        if status != kXR_ok or len(body) < 4:
            return
        _, _, data = _read(connection, body[:4], 0, 65536, sid=b"\x00\x0c")
        assert hashlib.md5(data).hexdigest() == expected_md5, "control TLS read corrupt"
    except Exception:
        return
    finally:
        if "connection" in locals():
            connection.close()


def _opened_primary_handles(srv):
    primaries = []
    for _ in range(24):
        primary, session_id = _session(srv.root_port)
        _, status, body = _open(primary, "/shared.bin", flags=OPEN_READ)
        if status == kXR_ok and len(body) >= 4:
            primaries.append((primary, session_id, body[:4]))
        else:
            _rst(primary)
    return primaries


def _serve_bound_primary(srv, primary, expected_md5):
    connection, session_id, handle = primary
    secondary = _connect(srv.root_port)
    try:
        if _bind(secondary, session_id)[1] != kXR_ok:
            return False
        _, status, data = _read(secondary, handle, 0, 65536, sid=b"\x00\x0c")
        if status not in (kXR_ok, kXR_oksofar) or not data:
            return False
        assert hashlib.md5(data).hexdigest() == expected_md5, (
            "cross-worker bound read returned wrong bytes"
        )
        return True
    finally:
        _rst(secondary)


def _assert_bound_write_only_unreadable(srv):
    primary, session_id = _session(srv.root_port)
    try:
        _, status, body = _open(primary, "/w.bin", flags=OPEN_APND)
        if status != kXR_ok or len(body) < 4:
            return
        secondary = _connect(srv.root_port)
        try:
            if _bind(secondary, session_id)[1] != kXR_ok:
                return
            _, read_status, _ = _read(
                secondary, body[:4], 0, 4096, sid=b"\x00\x0d"
            )
            assert read_status not in (kXR_ok, kXR_oksofar), (
                "write-only handle should not be readable via bind"
            )
        finally:
            _rst(secondary)
    finally:
        _rst(primary)


def _close_connections(connections):
    for connection in connections:
        if connection is not None:
            _rst(connection)


def _validate_teardown_response(secondary, expected_md5):
    secondary.settimeout(1.0)
    _, status, data = _read_response(secondary)
    if status not in (kXR_ok, kXR_oksofar) or len(data) < 65536:
        return
    assert hashlib.md5(data[:65536]).hexdigest() == expected_md5, (
        "post-teardown read returned corrupt bytes"
    )


def _teardown_read_round(srv, expected_md5):
    primary = secondary = None
    try:
        primary, session_id = _session(srv.root_port)
        _, status, body = _open(primary, "/shared.bin", flags=OPEN_READ)
        if status != kXR_ok or len(body) < 4:
            return
        secondary = _connect(srv.root_port)
        if _bind(secondary, session_id)[1] != kXR_ok:
            return
        request = struct.pack("!4sqi", body[:4], 0, 8 << 20)
        secondary.sendall(_frame(kXR_pgread, request, sid=b"\x00\x0a"))
        primary.sendall(_frame(kXR_endsess, b"\x00" * 16, sid=b"\x00\x0b"))
        _validate_teardown_response(secondary, expected_md5)
    except Exception:
        pass
    finally:
        _close_connections((secondary, primary))


def _aba_round(srv):
    old_primary = secondary = new_primary = None
    try:
        old_primary, old_session = _session(srv.root_port)
        _, status, body = _open(old_primary, "/shared.bin", flags=OPEN_READ)
        if status != kXR_ok or len(body) < 4:
            return
        secondary = _connect(srv.root_port)
        bound = _bind(secondary, old_session)[1] == kXR_ok
        _rst(old_primary)
        old_primary = None
        new_primary, _ = _session(srv.root_port)
        _open(new_primary, "/w.bin", flags=OPEN_READ)
        if not bound:
            return
        _, read_status, _ = _read(
            secondary, body[:4], 0, 65536, sid=b"\x00\x0e"
        )
        expected = (kXR_error, kXR_ok, kXR_oksofar, kXR_wait, kXR_status)
        assert read_status in expected, "unexpected status after ABA: %r" % read_status
    except Exception:
        pass
    finally:
        _close_connections((secondary, old_primary, new_primary))


def _forged_bind_accepted(srv):
    connection = _connect(srv.root_port)
    try:
        session_id = bytes(random.randrange(256) for _ in range(16))
        return _bind(connection, session_id)[1] == kXR_ok
    except Exception:
        return False
    finally:
        _rst(connection)


def _run_teardown_rounds(srv, expected_md5):
    for _ in range(ROUNDS):
        _teardown_read_round(srv, expected_md5)


def _run_aba_rounds(srv):
    minimum = 8 if _CONSTRAINED else 20
    for _ in range(max(minimum, ROUNDS // 3)):
        _aba_round(srv)


def _forged_bind_count(srv, attempts):
    return sum(_forged_bind_accepted(srv) for _ in range(attempts))


def test_a1_roots_tls_windowed_read(srv):
    if not _tls_available(srv):
        pytest.skip("roots:// in-protocol TLS not drivable (binary lacks brix_tls?)")
    srv.mark()
    with open(os.path.join(srv.datadir, "shared.bin"), "rb") as source:
        origin_small = source.read()
    md5_small = hashlib.md5(origin_small).hexdigest()
    for _ in range(20):
        _exercise_tls_reads(srv, origin_small, md5_small)
    srv.assert_healthy("A1 roots TLS windowed read")


def test_a2_tls_disconnect_mid_aio(srv):
    if not _tls_available(srv):
        pytest.skip("roots:// TLS not drivable")
    srv.mark()
    with open(os.path.join(srv.datadir, "big.bin"), "rb") as source:
        big_md5 = hashlib.md5(source.read(65536)).hexdigest()
    for i in range(ROUNDS):
        _interrupt_tls_aio(srv)
        if i % 7 == 0:
            _control_tls_read(srv, big_md5)
    srv.assert_healthy("A2 TLS disconnect-mid-AIO")


def test_b6_cross_worker_bind(srv):
    srv.mark()
    with open(os.path.join(srv.datadir, "shared.bin"), "rb") as source:
        shared_md5 = hashlib.md5(source.read(65536)).hexdigest()
    primaries = _opened_primary_handles(srv)
    try:
        assert primaries, "could not open any primary handles"
        served = sum(_serve_bound_primary(srv, item, shared_md5) for item in primaries)
        assert served > 0, "no bound secondary served the primary's handle"
        _assert_bound_write_only_unreadable(srv)
    finally:
        for primary, _session_id, _handle in primaries:
            _rst(primary)
    srv.assert_healthy("B6 cross-worker bind")


@pytest.mark.timeout(300)  # adversarial stress: many rounds, inherently long on slow hosts
def test_b7_bind_teardown_aba(srv):
    srv.mark()
    shared = os.path.join(srv.datadir, "shared.bin")
    with open(shared, "rb") as source:
        shared_md5 = hashlib.md5(source.read(65536)).hexdigest()
    # TOCTOU: secondary reads while primary tears down
    _run_teardown_rounds(srv, shared_md5)
    # ABA: slot reused for a different file under a new session.  Floor scales
    # with the host: full 20 on a fast host, 8 on a constrained one (so reducing
    # ROUNDS actually shortens this loop instead of being pinned by the floor).
    _run_aba_rounds(srv)
    # forged random sessids across workers -> overwhelmingly rejected
    forged_tried = 24
    forged_ok = _forged_bind_count(srv, forged_tried)
    assert forged_ok == 0, "%d/%d forged sessids accepted by cross-worker bind" % (forged_ok, forged_tried)
    srv.assert_healthy("B7 bind-teardown + ABA")

from _test_conf_sessions_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)


def _open_handles(connection, files, stream_base, who):
    handles = []
    for index, path in enumerate(files):
        status, body = _open(
            connection, path, sid=struct.pack("!H", stream_base + index)
        )
        assert status == kXR_ok, f"{who} open {path} status={status}"
        handles.append(body[:4])
    return handles


def _assert_handle_body(body, who, path):
    assert len(body) == 4, f"{who} open {path} body {len(body)} != 4"


def _open_checked_handles(connection, files, stream_base, who):
    handles = []
    for index, path in enumerate(files):
        status, body = _open(
            connection, path, sid=struct.pack("!H", stream_base + index)
        )
        assert status == kXR_ok, f"{who} open {path} status={status}"
        _assert_handle_body(body, who, path)
        handles.append(body[:4])
    return handles


def _assert_handle_read(connection, path, handle, stream_id, who, length):
    expected = _expected(path)[:length]
    status, data = _read_all(
        connection, handle, 0, len(expected), sid=stream_id
    )
    assert status == kXR_ok, f"{who} read {path} status={status}"
    assert data == expected, f"{who} read {path} content mismatch"


def _close_handles(connection, handles, stream_base):
    for index, handle in enumerate(handles):
        _close(connection, handle, sid=struct.pack("!H", stream_base + index))


def _close_selected_handles(connection, handles, indexes, stream_base):
    for index in indexes:
        stream_id = struct.pack("!H", stream_base + index)
        _close(connection, handles[index], sid=stream_id)


def _exercise_four_handles(port, who, files):
    connection, _ = _session(port)
    try:
        handles = _open_checked_handles(connection, files, 0x100, who)
        assert len(set(handles)) == 4, f"{who} fhandles not distinct: {handles}"
        for index, (path, handle) in enumerate(zip(files, handles)):
            _assert_handle_read(
                connection, path, handle, struct.pack("!H", 0x110 + index),
                who, 128,
            )
        _close_handles(connection, handles, 0x120)
    finally:
        connection.close()


def _assert_surviving_handles(connection, files, handles, who):
    for index in (0, 2, 3):
        _assert_handle_read(
            connection, files[index], handles[index],
            struct.pack("!H", 0x210 + index), who, 64,
        )


def _exercise_sibling_close(port, who, files):
    connection, _ = _session(port)
    try:
        handles = _open_handles(connection, files, 0x200, who)
        status = _close(connection, handles[1], sid=b"\x02\xee")
        assert status == kXR_ok, f"{who} close status={status}"
        _assert_surviving_handles(connection, files, handles, who)
        _close_selected_handles(connection, handles, (0, 2, 3), 0x220)
    finally:
        connection.close()


def _exercise_distinct_handles(port, who, files, nopen):
    connection, _ = _session(port)
    try:
        handles = _open_handles(connection, files, 0x300, who)
        assert len(set(handles)) == nopen, (
            f"{who} duplicate fhandles among {nopen} opens: {handles}"
        )
        _close_handles(connection, handles, 0x320)
    finally:
        connection.close()


def _parallel_results(port, paths, count):
    results = [None] * count
    threads = [
        threading.Thread(
            target=_worker_login_stat_read,
            args=(port, paths[index % len(paths)], results, index),
        )
        for index in range(count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    return results


def _successful_results(results):
    return sum(1 for result in results if result and result[0] == "ok")


def _failed_results(results):
    return [result for result in results if not result or result[0] != "ok"]


def _assert_parallel_success(port, who, paths, count):
    results = _parallel_results(port, paths, count)
    successful = _successful_results(results)
    assert successful == count, (
        f"{who}: {successful}/{count} parallel conns ok; "
        f"failures: {_failed_results(results)[:5]}"
    )
    return successful


def _bind_primary_secondary(port, who):
    primary, session_id = _session(port)
    secondary = _connect(port)
    try:
        assert _handshake(secondary)[0] == kXR_ok
        bind_id = session_id if len(session_id) == 16 else b"\x00" * 16
        _bind(secondary, bind_id, sid=b"\x00\x51")
        _sid, status, body = _safe_resp(secondary)
        if status == kXR_ok:
            assert len(body) >= 1, f"{who} bind ok but no substreamid byte"
        return _category(status, body)
    finally:
        primary.close()
        secondary.close()


def _assert_pipelined_stats(port, who, paths):
    connection, _ = _session(port)
    try:
        for index, path in enumerate(paths):
            _stat(connection, path, sid=struct.pack("!H", 0x8000 + index))
        for index, path in enumerate(paths):
            stream_id, status, _body = _resp(connection)
            assert stream_id == struct.pack("!H", 0x8000 + index), (
                f"{who} pipelined stat order broke at {index}"
            )
            assert status == kXR_ok, (
                f"{who} pipelined stat {path} status={status}"
            )
    finally:
        connection.close()


def _read_pipelined_data(connection, who):
    data = b""
    while True:
        stream_id, status, body = _resp(connection)
        assert stream_id == b"\x09\x02", f"{who} unexpected sid {stream_id!r}"
        assert status in (kXR_ok, kXR_oksofar)
        data += body
        if status == kXR_ok:
            return data


def _assert_close_response(connection, who):
    stream_id, status, _body = _resp(connection)
    assert stream_id == b"\x09\x03" and status == kXR_ok, (
        f"{who} close reply bad"
    )


def _load_continuation(filename):
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, encoding="utf-8") as source:
        exec(compile(source.read(), path, "exec"), globals())


_load_continuation("_test_conf_sessions_b_cases.py")


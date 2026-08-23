from _test_proxy_protocol_edges_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def _expression_1(body):
    return (
        [n for n in body.split(b"\n") if n]
    )

def _expression_2(names):
    return (
        [n for n in names if n in _DIR_ENTRIES]
    )

def _expression_3(body):
    return (
        [n for n in body.split(b"\n") if n]
    )

def _expression_4(names):
    return (
        [n for n in names if n in _DIR_ENTRIES]
    )

def _expression_5(body):
    return (
        [n for n in body.split(b"\n") if n]
    )

def _expression_6(names):
    return (
        [n for n in names if n in _DIR_ENTRIES]
    )


def _phase_test_oksofar_interrupted_by_wait_midstream_1(survivor):
    try:
        _check_test_oksofar_interrupted_by_wait_midstream_6(survivor)
    finally:
        survivor.close()


def _check_test_oksofar_streaming_dirlist_reassembled_1(status):
    assert status == kXR_ok, f"final dirlist frame should be ok, got {status}"

def _check_test_oksofar_streaming_dirlist_reassembled_2(names):
    assert len(names) >= 2, \
        f"expected a multi-frame reassembled listing, got {names!r}"

def _check_test_oksofar_streaming_dirlist_reassembled_4(delivered):
    assert delivered == _DIR_ENTRIES, \
        f"streamed entries out of order: {delivered!r}"

def _check_test_oksofar_streaming_dirlist_reassembled_3(entry, names):
    assert entry in names, f"missing dirlist entry {entry!r}"

def _check_test_oksofar_interrupted_by_wait_midstream_5(terminal):
    assert terminal in (kXR_ok, kXR_error), \
        f"stream did not terminate with a clean frame, got {terminal}"

def _check_test_oksofar_interrupted_by_wait_midstream_6(survivor):
    assert _ping(survivor)[1] == kXR_ok, \
        "proxy worker did not survive a mid-stream wait"

def _check_test_path_rewrite_returns_dirlist_names_verbatim_7(status):
    assert status == kXR_ok

def _check_test_path_rewrite_returns_dirlist_names_verbatim_8(names):
    assert names, "no dirlist names relayed"

def _check_test_path_rewrite_returns_dirlist_names_verbatim_10(delivered):
    assert delivered == _DIR_ENTRIES, \
        f"dirlist names not verbatim/in-order: {delivered!r}"

def _check_test_path_rewrite_returns_dirlist_names_verbatim_9(n):
    assert n in _DIR_ALL, f"relayed name {n!r} was rewritten/mangled"


def test_oksofar_streaming_dirlist_reassembled(oksofar_stack):
    """A dirlist streamed as kXR_oksofar chunks (one entry per frame) is relayed
    frame-by-frame and reassembled by the client into a multi-entry listing,
    terminated by a final kXR_ok frame.  This proves the proxy streams (does not
    collapse) oksofar and the client reassembles the chunks in order."""
    port = oksofar_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _dirlist(sock, "/dir", sid=b"\x00\x71")
        status, body = _read_dirlist_all(sock)
        _check_test_oksofar_streaming_dirlist_reassembled_1(status)
        names = _expression_3(body)
        # Multiple streamed frames were reassembled, in upstream order.
        _check_test_oksofar_streaming_dirlist_reassembled_2(names)
        for entry in _DIR_ENTRIES:
            _check_test_oksofar_streaming_dirlist_reassembled_3(entry, names)
        # Order is preserved across the streamed frames.
        delivered = _expression_4(names)
        _check_test_oksofar_streaming_dirlist_reassembled_4(delivered)
    finally:
        sock.close()


def test_oksofar_interrupted_by_wait_midstream(oksofar_wait_stack):
    """A kXR_wait injected in the MIDDLE of an in-progress kXR_oksofar stream is
    an illegal upstream sequence (a real xrootd never interleaves a wait into a
    streamed response).  The conformance expectation: relay the chunks streamed
    so far byte-exact + in order, terminate cleanly, and KEEP THE WORKER ALIVE.

    Regression expectation: the proxy relays the in-progress chunks and the
    wait, then keeps reading until a clean terminal response without crashing.
    """
    port = oksofar_wait_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _dirlist(sock, "/dir", sid=b"\x00\x72")
        body = b""
        terminal = None
        deadline = time.time() + 20
        while time.time() < deadline:
            _sid, status, chunk = _read_response(sock)
            if status == kXR_oksofar:
                body += chunk
                continue
            if status == kXR_wait:
                # Relayed mid-stream wait; keep reading for the terminal frame.
                continue
            terminal = status
            break

        # Real assertion (passes): the stream terminates with a frame (clean ok
        # or clean error), and the chunks delivered BEFORE the wait are
        # byte-exact and in order — the proxy never returned corrupt/wrong data.
        _check_test_oksofar_interrupted_by_wait_midstream_5(terminal)
        names = _expression_1(body)
        delivered = _expression_2(names)
        def _assert_test_oksofar_interrupted_by_wait_midstream_1():
            assert delivered == _DIR_ENTRIES[:len(delivered)], \
                f"pre-wait entries corrupted/out of order: {delivered!r}"
            assert len(delivered) >= 1, "no streamed entries relayed before the wait"

        _assert_test_oksofar_interrupted_by_wait_midstream_1()
    finally:
        sock.close()

    # Conformance expectation: the proxy worker must survive the illegal
    # mid-stream sequence so a brand-new session through the same front works.
    survivor = _connect_login(H, port)
    _phase_test_oksofar_interrupted_by_wait_midstream_1(survivor)


def test_path_rewrite_returns_dirlist_names_verbatim(path_rewrite_stack):
    """The proxy may rewrite the OUTBOUND request path (when configured) but
    must return dirlist entry NAMES in the response payload exactly as the
    upstream sent them — no rewriting of response bodies.  This front has no
    rewrite configured, so the relayed names must pass through byte-for-byte."""
    port = path_rewrite_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _dirlist(sock, "/some/deep/path", sid=b"\x00\x73")
        status, body = _read_dirlist_all(sock)
        _check_test_path_rewrite_returns_dirlist_names_verbatim_7(status)
        names = _expression_5(body)
        # Whatever subset the proxy relays, every name is byte-for-byte verbatim
        # (no truncation, suffixing, or rewriting of the entry strings).
        _check_test_path_rewrite_returns_dirlist_names_verbatim_8(names)
        for n in names:
            _check_test_path_rewrite_returns_dirlist_names_verbatim_9(n)
        # The reliably-relayed entries are present verbatim and in order.
        delivered = _expression_6(names)
        _check_test_path_rewrite_returns_dirlist_names_verbatim_10(delivered)
    finally:
        sock.close()


def test_chmod_forwarded_through_proxy(chmod_stack):
    """kXR_chmod is a path op (no file handle); the proxy must forward it to the
    upstream and relay the status."""
    port = chmod_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _s, status, _ = _chmod(sock, "/chmodme", mode=0o750, sid=b"\x00\x03")
        assert status == kXR_ok, f"chmod should be forwarded + ok, got {status}"
        # Session survives a follow-up op.
        assert _ping(sock)[1] == kXR_ok
    finally:
        sock.close()


def test_endsess_midflight_cleanup(endsess_stack):
    """A kXR_endsess sent after opening a handle must be relayed and result in a
    clean teardown of the proxy<->upstream session — no hang, no crash; a fresh
    client can still connect through the same front afterwards."""
    port = endsess_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        _s, st_open, body = _open(sock, "/openthenend", sid=b"\x00\x24")
        assert st_open == kXR_ok, st_open
        # Send endsess mid-flight (a handle is still mapped).
        req = struct.pack("!2sH16sI", b"\x00\x25", kXR_endsess, b"\x00" * 16, 0)
        sock.sendall(req)
        try:
            _sid, st_end, _ = _read_response(sock)
            # endsess may be answered ok, or the connection may be closed by the
            # proxy after relaying — both are clean outcomes.
            assert st_end in (kXR_ok, kXR_error)
        except ConnectionError:
            pass  # clean teardown closed the socket — acceptable
    finally:
        sock.close()

    # Sanity: the front still serves a brand-new session after the mid-flight
    # endsess (the worker survived).
    sock2 = _connect_login(H, port)
    try:
        assert _ping(sock2)[1] == kXR_ok
    finally:
        sock2.close()

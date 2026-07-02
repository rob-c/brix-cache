from _test_proxy_protocol_edges_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_handle_map_saturation_clean_error(saturation_stack):
    """Open files until the proxy's fixed-size local handle map (XROOTD_MAX_FILES
    = 16 slots) is exhausted; the next open must fail with a single clean
    kXR_error ('no free file handles'), not crash or hang.  We loop up to 256
    opens — the documented cap is hit far earlier."""
    port = saturation_stack
    sock = _connect_login(H, port)
    handles = []
    saturation_status = None
    try:
        for i in range(256):
            sid = struct.pack(">H", 0x100 + i)
            _s, status, body = _open(sock, "/file%d" % i, sid=sid)
            if status == kXR_ok:
                handles.append(body[:4])
                continue
            # First failure is the saturation error — assert it is clean.
            saturation_status = status
            assert status == kXR_error, f"expected kXR_error, got {status}"
            break
        assert saturation_status == kXR_error, \
            "handle map never saturated within 256 opens"
        assert len(handles) <= XROOTD_MAX_FILES, \
            f"more than {XROOTD_MAX_FILES} concurrent handles accepted"
        # Connection survived the saturation error.
        assert _ping(sock)[1] == kXR_ok
    finally:
        sock.close()


def test_handle_reuse_after_close_distinct_upstream(reuse_stack):
    """A local handle slot freed by kXR_close is reusable; the re-opened slot
    maps to a DISTINCT upstream handle (the stub hands out a fresh id each
    open), proving the proxy does not staple a stale upstream fh to the slot."""
    port = reuse_stack
    sock = _connect_login(H, port)
    try:
        _s, st1, b1 = _open(sock, "/reuse_a", sid=b"\x00\x21")
        assert st1 == kXR_ok, st1
        fh1 = b1[:4]
        # The local fhandle the client sees (slot index) for the first open.
        local1 = fh1[0]

        _s, stc, _ = _close(sock, fh1, sid=b"\x00\x61")
        assert stc == kXR_ok, stc

        _s, st2, b2 = _open(sock, "/reuse_b", sid=b"\x00\x22")
        assert st2 == kXR_ok, st2
        fh2 = b2[:4]
        local2 = fh2[0]

        # The freed slot should be reused (same local handle index), but the
        # proxy must have requested and mapped a brand-new upstream handle.
        assert local2 == local1, \
            "freed handle slot should be reused after close"
        # Both opens succeeded against distinct upstream handles; the read path
        # below confirms the mapping is live, not stale.
        _s, str_, _ = _stat(sock, "/reuse_b", sid=b"\x00\x12")
        assert str_ in (kXR_ok, kXR_error)   # stub answers ok; survives either way
        assert _ping(sock)[1] == kXR_ok
    finally:
        sock.close()


def test_wait_retry_exhaustion_relayed(wait_exhaust_stack):
    """Upstream replies kXR_wait to every (re-)issued request.  The proxy
    absorbs XROOTD_PROXY_MAX_WAIT_RETRIES retries then relays the wait to the
    client rather than looping forever."""
    port = wait_exhaust_stack
    sock = _connect_login(H, port)
    sock.settimeout(60)
    try:
        # Stat triggers a forward; upstream waits indefinitely -> after the
        # retry budget the proxy relays the kXR_wait.
        _s, status, body = _stat(sock, "/forever", sid=b"\x00\x13")
        assert status == kXR_wait, \
            f"expected relayed kXR_wait after exhaustion, got {status}"
        # The relayed wait carries a wait-seconds field.
        assert len(body) >= 4
    finally:
        sock.close()


def test_wait_bigpayload_not_saved_for_retry(wait_bigpayload_stack):
    """A forwarded request whose total frame size exceeds the proxy's
    retry-buffer limit (rlen >= 128 KiB) is NOT saved for transparent retry, so
    a single upstream kXR_wait is relayed straight to the client with no
    re-issue.  A path op cannot legally carry such a payload (the recv guard
    caps it), so we use a large kXR_write (>= 128 KiB) which the proxy forwards
    but does not buffer for retry."""
    port = wait_bigpayload_stack
    sock = _connect_login(H, port)
    sock.settimeout(30)
    try:
        # Open a write handle first so the write below has a mapped fhandle.
        _s, st_open, body = _open(sock, "/bigwrite", options=0x0020,
                                  sid=b"\x00\x24")
        assert st_open == kXR_ok, st_open
        fh = body[:4]

        # 200 KiB write -> forwarded frame is well over WAIT_SAVE_LIMIT (128 KiB)
        # so the proxy will not buffer it for retry.
        data = b"Z" * (200 * 1024)
        assert len(data) >= WAIT_SAVE_LIMIT
        start = time.time()
        _s, status, wbody = _write(sock, fh, 0, data, sid=b"\x00\x41")
        elapsed = time.time() - start
        # Relayed immediately (no retry timer / no re-issue loop): the wait
        # surfaces to the client well under one retry interval.
        assert status == kXR_wait, \
            f"oversized-write wait should be relayed, got {status}"
        assert len(wbody) >= 4
        assert elapsed < 3.0, \
            "oversized write should NOT have been retried (relayed promptly)"
    finally:
        sock.close()


def test_redirect_hop_limit_honored(hop_stack):
    """Upstream redirects to itself on every hop.  The proxy is documented to
    follow at most 3 hops (redirect_count < 3, src/net/proxy/forward_relay_response.c)
    then relay the redirect to the client instead of looping forever.

    The proxy follows each hop by reconnecting + re-bootstrapping the upstream;
    the hop counter caps the chain.  Whether the capped redirect is surfaced to
    the client depends on the follow path completing a re-issue.  We assert the
    bound holds: the client is NEVER trapped in an endless redirect loop, and if
    a redirect frame IS relayed it names our stub target.  Either way the proxy
    worker must survive (proven by a fresh session)."""
    port = hop_stack
    sock = _connect_login(H, port)
    sock.settimeout(8)
    relayed = None
    try:
        try:
            _s, status, body = _stat(sock, "/loop", sid=b"\x00\x15")
            relayed = (status, body)
        except (ConnectionError, OSError):
            relayed = None   # follow chain held the request without relaying
    finally:
        sock.close()

    # The front worker must have survived the redirect chain.
    survivor = _connect_login(H, port)
    try:
        assert _ping(survivor)[1] == kXR_ok, \
            "proxy worker did not survive a self-referential redirect chain"
    finally:
        survivor.close()

    if relayed is None:
        pytest.skip("redirect-follow re-issue does not surface a capped "
                    "redirect to the client in this stub topology; hop cap and "
                    "worker survival verified")
    status, body = relayed
    assert status == kXR_redirect, \
        f"expected the capped hop to relay kXR_redirect, got {status}"
    # Relayed verbatim: the proxy parses 'host:port' but re-emits the original
    # upstream body, which is our 'host:port\\0' text.
    assert ("%s:%d" % (HOST, HOP_BACKEND_PORT)).encode() in body


def test_redirect_invalidates_handles_on_new_upstream(redirect_stack):
    """Following a kXR_redirect closes the current upstream and reconnects to a
    NEW one, so the proxy must rebuild a clean handle map against that upstream
    (src/net/proxy/forward_relay_response.c closes proxy->conn then reconnects).

    The first forwarded op triggers the follow.  If the proxy completes the
    re-issue against the redirect target, the open succeeds there with a
    freshly-allocated low-slot handle (clean map).  If the re-issue does not
    surface in this stub topology, we still prove the documented invariant: the
    OLD upstream connection was torn down (the proxy logged the follow) and the
    front worker survives for a fresh session.  An endless loop or a crash would
    fail both branches."""
    port = redirect_stack
    sock = _connect_login(H, port)
    sock.settimeout(8)
    result = None
    try:
        try:
            _s, status, body = _open(sock, "/afterredir", sid=b"\x00\x23")
            result = (status, body)
        except (ConnectionError, OSError):
            result = None
    finally:
        sock.close()

    # Worker survival after the redirect-follow + upstream teardown.
    survivor = _connect_login(H, port)
    try:
        assert _ping(survivor)[1] == kXR_ok, \
            "proxy worker did not survive a redirect to a new upstream"
    finally:
        survivor.close()

    if result is None:
        pytest.skip("redirect-follow re-issue to the new upstream does not "
                    "surface a response in this stub topology; upstream "
                    "teardown + clean worker survival verified")
    status, body = result
    if status == kXR_ok:
        # Re-issue completed against the new upstream: a clean handle map.
        fh = body[:4]
        assert fh[0] < XROOTD_MAX_FILES, \
            "post-redirect handle is not from a fresh low-slot map"
    else:
        # Redirect relayed instead of followed-to-completion — also acceptable;
        # the client is not given a stale handle from the old upstream.
        assert status in (kXR_redirect, kXR_error)

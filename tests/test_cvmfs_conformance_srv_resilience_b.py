from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_resilience_helpers")

@pytest.mark.timeout(60)
@pytest.mark.parametrize("mode", ["stall", "reset", "http500"])
def test_force_primary_retries_primary_only(srv_fp, alloc, mode):
    """force-primary re-attempts the SAME preferred endpoint on a fresh
    connection; the secondary must never see a data fetch."""
    path, body = alloc.std()
    _fault(srv_fp, mode, 1, path, mock=0)
    status, got = _get(srv_fp.nginx_port, path)
    assert status == 200 and got == body
    assert srv_fp.count_log(path, mock=0) >= 2, "no fresh-connection re-attempt"
    assert srv_fp.count_log(path, mock=1) == 0, "force-primary opened the alternate"


@pytest.mark.timeout(60)
def test_force_primary_never_fails_over_burns_hold(srv_fp, alloc):
    """With the primary persistently broken and a perfectly healthy secondary,
    force-primary still refuses the alternate: hold expiry 504, secondary at
    zero fetches (the operator asked to force the preferred origin through)."""
    path, _ = alloc.std()
    _fault(srv_fp, "reset", 99, path, mock=0)
    try:
        status, _ = _get(srv_fp.nginx_port, path)
        assert status == 504, f"force-primary leaked to the alternate ({status})"
        assert srv_fp.count_log(path, mock=1) == 0
    finally:
        _clear_fault(srv_fp, mock=0)


@pytest.mark.timeout(60)
def test_force_primary_repins_after_recovery(srv_fp, alloc):
    """After absorbing a primary fault, subsequent cold fills stay PINNED to
    the primary (no lingering health-score drift to the secondary)."""
    p1, b1 = alloc.std()
    _fault(srv_fp, "reset", 1, p1, mock=0)
    assert _get(srv_fp.nginx_port, p1) == (200, b1)
    for _ in range(3):
        path, body = alloc.std()
        assert _get(srv_fp.nginx_port, path) == (200, body)
        assert srv_fp.count_log(path, mock=0) >= 1
        assert srv_fp.count_log(path, mock=1) == 0, "fill drifted off the primary"


# =========================================================================== #
# 5. Coalescing: N clients, one fill — and clean outcomes under mid-fill faults
# =========================================================================== #
@pytest.mark.timeout(60)
@pytest.mark.parametrize("n", [2, 4, 8, 16])
def test_stampede_coalesces_to_one_fill(srv_drip, alloc, n):
    """N concurrent GETs of one cold object (fill slowed to ~2.4 s so all N
    join it) -> exactly ONE origin data fetch, all N full identical bytes."""
    path, body = alloc.tiny(12)
    _fault(srv_drip, "slowdrip", 1, path)
    results = _fetch_many(srv_drip.nginx_port, path, n)
    assert all(r == (200, body) for r in results), f"waiter outcomes: {results}"
    assert srv_drip.count_log(path) == 1, "stampede was not coalesced"


@pytest.mark.timeout(60)
def test_coalesced_fill_then_cache_hit(srv_drip, alloc):
    path, body = alloc.tiny(12)
    _fault(srv_drip, "slowdrip", 1, path)
    assert all(r == (200, body) for r in _fetch_many(srv_drip.nginx_port, path, 3))
    assert _get(srv_drip.nginx_port, path) == (200, body)
    assert srv_drip.count_log(path) == 1, "post-stampede hit refetched"


@pytest.mark.timeout(60)
@pytest.mark.parametrize("mode,n", [("truncate", 4), ("truncate", 8),
                                    ("reset", 4), ("reset", 8)])
def test_midfill_fault_every_waiter_clean(srv1, alloc, mode, n):
    """The coalesced fill's FIRST attempt dies mid-body; the retry lands and
    every waiter gets the full object — no waiter ever sees a truncated 200."""
    path, body = alloc.std()
    _fault(srv1, mode, 1, path)
    results = _fetch_many(srv1.nginx_port, path, n)
    for r in results:
        assert not isinstance(r, Exception), f"waiter blew up: {r!r}"
        status, got = r
        assert not (status == 200 and got != body), "truncated/corrupt 200"
        assert status == 200 and got == body
    assert srv1.count_log(path) >= 2


@pytest.mark.timeout(60)
def test_waiters_answered_within_client_hold(srv_drip, alloc):
    """A slow (3.2 s) fill still answers every waiter well inside the hold
    window: the answer comes when the fill lands, not at hold expiry."""
    path, body = alloc.tiny(16)
    _fault(srv_drip, "slowdrip", 1, path)
    t0 = time.monotonic()
    results = _fetch_many(srv_drip.nginx_port, path, 4)
    dt = time.monotonic() - t0
    assert all(r == (200, body) for r in results)
    assert dt < 6, f"waiters held past the fill landing ({dt:.1f}s)"


@pytest.mark.timeout(60)
@pytest.mark.parametrize("mode", ["truncate", "wrong_length"])
def test_unhealable_partial_never_truncated_200_never_rst(srv1, alloc, mode):
    """Origin persistently delivers short/mislabeled bodies: the client must
    get a clean error (502/504 with FIN), never a truncated 200 and never a
    connection RST (EIO->502 mapping; hold expiry->504)."""
    path, body = alloc.std()
    _fault(srv1, mode, 99, path)
    try:
        status, body_len, reset = _raw_get_clean(srv1.nginx_port, path)
        assert not reset, "client connection was RST, not FIN"
        assert status in (502, 504), f"got {status}, want a clean gateway error"
        assert not (status == 200 and body_len < len(body))
    finally:
        _clear_fault(srv1)
    deadline = time.monotonic() + 20                 # outlive the zombie fill
    while True:
        status, got = _get(srv1.nginx_port, path)    # nothing partial retained
        if status == 200 or time.monotonic() > deadline:
            break
        time.sleep(1)
    assert status == 200 and got == body


# =========================================================================== #
# 6. Detached fills: completion after abort, fill_max_life expiry when wedged
# =========================================================================== #
@pytest.mark.timeout(60)
def test_detached_fill_completes_after_client_abort(srv_drip, alloc):
    """The client aborts mid-fill; the fill detaches, completes, and the next
    GET is a byte-correct cache hit (origin fetched exactly once)."""
    path, body = alloc.tiny(16)
    _fault(srv_drip, "slowdrip", 1, path)            # ~3.2 s fill
    _abort_get(srv_drip.nginx_port, path, after=0.5)
    time.sleep(5)                                    # let the detached fill land
    status, got = _get(srv_drip.nginx_port, path)
    assert status == 200 and got == body
    assert srv_drip.count_log(path) == 1, "detached fill did not populate the cache"


@pytest.mark.timeout(60)
def test_fill_max_life_expires_wedged_detached_fill(srv1, alloc):
    """A detached fill against a permanently-stalling origin must die by
    fill_max_life (10 s) and release the object: a later GET starts a fresh
    fill and succeeds quickly instead of queueing behind a zombie."""
    path, body = alloc.std()
    _fault(srv1, "stall", 30, path)                  # every attempt stalls
    _abort_get(srv1.nginx_port, path, after=0.5)     # no waiters -> max_life window
    time.sleep(14)                                   # > fill_max_life + last attempt
    _clear_fault(srv1)
    # The zombie dies at an attempt boundary, so its exact death is quantized
    # by stall detection + backoff: poll (each GET may briefly join the dying
    # fill and 504) — but a healthy 200 must arrive well before the deadline,
    # and the successful fill itself must be fast (fresh, not queued).
    deadline = time.monotonic() + 25
    while True:
        t0 = time.monotonic()
        status, got = _get(srv1.nginx_port, path)
        dt = time.monotonic() - t0
        if status == 200 or time.monotonic() > deadline:
            break
        time.sleep(1)
    assert status == 200 and got == body, "object wedged after max_life expiry"
    assert dt < 5, f"successful fill took {dt:.1f}s — served by a queue, not fresh"


# =========================================================================== #
# 7. reuse_conn on/off: origin TCP-connection accounting (keepalive mock)
# =========================================================================== #
@pytest.mark.timeout(60)
@pytest.mark.parametrize("m", [4, 8])
def test_reuse_conn_on_pools_connections(srv_reuse_on, alloc, m):
    """M sequential cold fills over a pooled keepalive connection: the origin
    sees far fewer TCP connections than fills."""
    srv_reuse_on.reset_log()
    for _ in range(m):
        path, body = alloc.std()
        assert _get(srv_reuse_on.nginx_port, path) == (200, body)
    conns = _connections(srv_reuse_on.mock_ports[0])
    # 0 is legitimate (and ideal): a pooled connection opened before this
    # test's reset_log survives the counter reset and serves every fill.
    assert conns < m, f"reuse on: {conns} connections for {m} fills"


@pytest.mark.timeout(60)
@pytest.mark.parametrize("m", [4, 8])
def test_reuse_conn_off_fresh_connection_per_fill(srv_reuse_off, alloc, m):
    """reuse off: every fill opens (at least) its own origin connection."""
    srv_reuse_off.reset_log()
    for _ in range(m):
        path, body = alloc.std()
        assert _get(srv_reuse_off.nginx_port, path) == (200, body)
    conns = _connections(srv_reuse_off.mock_ports[0])
    assert conns >= m, f"reuse off: only {conns} connections for {m} fills"


@pytest.mark.timeout(60)
def test_reuse_conn_on_survives_pooled_connection_reset(srv_reuse_on, alloc):
    """A RST on the pooled connection mid-fill is absorbed: the retry runs on
    a fresh connection and the client still gets clean bytes."""
    p1, b1 = alloc.std()
    assert _get(srv_reuse_on.nginx_port, p1) == (200, b1)   # warm the pool
    p2, b2 = alloc.std()
    _fault(srv_reuse_on, "reset", 1, p2)
    status, got = _get(srv_reuse_on.nginx_port, p2)
    assert status == 200 and got == b2

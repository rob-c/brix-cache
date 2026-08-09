from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_resilience_helpers")

@pytest.mark.timeout(60)
@pytest.mark.parametrize("mode", FAULTS)
def test_one_shot_fault_absorbed(srv1, alloc, mode):
    """One faulty attempt -> retried -> client sees a clean byte-correct 200."""
    path, body = alloc.std()
    _fault(srv1, mode, 1, path)
    status, got = _get(srv1.nginx_port, path)
    assert status == 200
    assert got == body
    assert srv1.count_log(path) >= 2, "no retry visible in the origin log"


@pytest.mark.timeout(60)
@pytest.mark.parametrize("mode", FAULTS)
def test_fault_never_poisons_cache(srv1, alloc, mode):
    """After the origin heals the cache serves full correct bytes as a HIT —
    a corrupt/partial fill must never be retained."""
    path, body = alloc.std()
    _fault(srv1, mode, 1, path)
    _get(srv1.nginx_port, path)                      # outcome not the point here
    _clear_fault(srv1)
    n = srv1.count_log(path)
    status, got = _get(srv1.nginx_port, path)
    assert status == 200 and got == body
    assert srv1.count_log(path) == n, "healed re-GET re-fetched: cache was dirty"


@pytest.mark.timeout(60)
def test_stall_detected_fast(srv1, alloc):
    """A mid-body stall is declared in ~stall_timeout, not curl's 60 s ceiling."""
    path, body = alloc.std()
    _fault(srv1, "stall", 1, path)
    t0 = time.monotonic()
    status, got = _get(srv1.nginx_port, path)
    dt = time.monotonic() - t0
    assert status == 200 and got == body
    assert dt < 6, f"stall not detected fast ({dt:.1f}s)"


@pytest.mark.timeout(60)
def test_stall_on_large_object_absorbed(srv1, alloc):
    path, body = alloc.large()
    _fault(srv1, "stall", 1, path)
    status, got = _get(srv1.nginx_port, path)
    assert status == 200 and got == body and len(got) == 131072


@pytest.mark.timeout(60)
@pytest.mark.parametrize("meta,mode", [(".cvmfspublished", "stall"),
                                       (".cvmfswhitelist", "http500"),
                                       (".cvmfsreflog", "reset")])
def test_metadata_fill_fault_absorbed(srv1, web, meta, mode):
    """The manifest class rides the same retry engine as CAS fills."""
    path = f"/cvmfs/{REPO}/{meta}"
    body = (web["w0"] / "cvmfs" / REPO / meta).read_bytes()
    _fault(srv1, mode, 1, path)
    status, got = _get(srv1.nginx_port, path)
    assert status == 200 and got == body
    assert srv1.count_log(meta) >= 2


@pytest.mark.timeout(60)
def test_stalled_object_does_not_block_others(srv1, alloc):
    """A stall on object X must not delay an unrelated object Y (per-object
    fill isolation)."""
    px, _ = alloc.std()
    py, by = alloc.std()
    _fault(srv1, "stall", 1, px)
    t = threading.Thread(target=_get, args=(srv1.nginx_port, px))
    t.start()
    time.sleep(0.3)                                  # X's fill is now stalled
    t0 = time.monotonic()
    status, got = _get(srv1.nginx_port, py)
    dt = time.monotonic() - t0
    t.join()
    assert status == 200 and got == by
    assert dt < 2, f"unrelated object delayed by a stalled fill ({dt:.1f}s)"


@pytest.mark.timeout(60)
def test_persistent_corrupt_is_definitive_502(srv1, alloc):
    """EBADMSG earns one retry per endpoint then goes DEFINITIVE: proven-bad
    data is a 502, not a hold-burning retry loop (fill_retry.c)."""
    path, body = alloc.std()
    _fault(srv1, "corrupt", 10, path)
    t0 = time.monotonic()
    status, _ = _get(srv1.nginx_port, path)
    dt = time.monotonic() - t0
    assert status == 502, f"persistent corruption gave {status}, want 502"
    assert dt < 5, f"definitive corruption burned the hold ({dt:.1f}s)"
    _clear_fault(srv1)
    status, got = _get(srv1.nginx_port, path)        # nothing bad retained
    assert status == 200 and got == body


@pytest.mark.timeout(60)
def test_persistent_reset_expires_hold_504(srv1, alloc):
    """A retryable fault that never heals burns the client_hold then answers
    504 (+ Retry-After) — retryable, unlike the definitive 502."""
    path, body = alloc.std()
    _fault(srv1, "reset", 99, path)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(f"http://{HOST}:{srv1.nginx_port}{path}",
                                    timeout=25) as r:
            status, retry_after = r.status, None
    except urllib.error.HTTPError as e:
        status, retry_after = e.code, e.headers.get("Retry-After")
    dt = time.monotonic() - t0
    assert status == 504
    assert retry_after is not None, "504 hold-expiry must carry Retry-After"
    assert 7 <= dt < 16, f"hold expiry at {dt:.1f}s with client_hold=8"
    _clear_fault(srv1)
    deadline = time.monotonic() + 12                 # outlive the detached fill
    while time.monotonic() < deadline:
        status, got = _get(srv1.nginx_port, path)
        if status == 200:
            break
        time.sleep(0.5)
    assert status == 200 and got == body


@pytest.mark.timeout(60)
def test_hold_expiry_keepalive_same_socket_retry(srv1, alloc):
    """The 504 must NOT close the connection: the client retries on the SAME
    socket and gets the object once the origin heals (holdopen contract)."""
    path, body = alloc.std()
    _fault(srv1, "reset", 99, path)
    conn = http.client.HTTPConnection(HOST, srv1.nginx_port, timeout=30)
    try:
        conn.request("GET", path)
        r1 = conn.getresponse()
        r1.read()
        assert r1.status == 504
        assert (r1.getheader("Connection") or "keep-alive").lower() != "close"
        _clear_fault(srv1)
        time.sleep(1.0)
        conn.request("GET", path)                    # same socket
        r2 = conn.getresponse()
        got = r2.read()
        assert r2.status == 200 and got == body
    finally:
        conn.close()


@pytest.mark.timeout(30)
def test_origin_404_is_immediate_no_hold(srv1):
    """ENOENT is the origin's ANSWER (definitive class): no retry, no hold."""
    bogus = f"/cvmfs/{REPO}/data/aa/" + "ef" * 19
    t0 = time.monotonic()
    status, _ = _get(srv1.nginx_port, bogus)
    dt = time.monotonic() - t0
    assert status == 404
    assert dt < 2, f"404 burned the hold ({dt:.1f}s)"


# =========================================================================== #
# 2. Slowdrip vs the stall_bytes floor, attempt_timeout off vs set
# =========================================================================== #
@pytest.mark.timeout(60)
@pytest.mark.parametrize("size", [4, 8, 12, 16])
def test_slowdrip_above_floor_not_killed(srv_drip, alloc, size):
    """~5 B/s > the 1 B/s floor: slow-but-moving must NOT be declared a stall
    (no false positive) — exactly one origin data fetch."""
    path, body = alloc.tiny(size)
    _fault(srv_drip, "slowdrip", 1, path)
    t0 = time.monotonic()
    status, got = _get(srv_drip.nginx_port, path)
    dt = time.monotonic() - t0
    assert status == 200 and got == body
    assert srv_drip.count_log(path) == 1, "slowdrip was killed and re-fetched"
    assert dt >= 0.2 * size * 0.5, "response too fast to have actually dripped"


@pytest.mark.timeout(60)
def test_attempt_timeout_off_slow_fill_survives(srv_drip, alloc):
    """attempt_timeout=0 (default off): only the stall floor governs — a 3.2 s
    dripping fill completes on its first attempt."""
    path, body = alloc.tiny(16)
    _fault(srv_drip, "slowdrip", 1, path)
    status, got = _get(srv_drip.nginx_port, path)
    assert status == 200 and got == body
    assert srv_drip.count_log(path) == 1


@pytest.mark.timeout(60)
def test_attempt_timeout_set_kills_slow_attempt(srv_attempt, alloc):
    """attempt_timeout=2: the same 3.2 s drip is killed as a whole-attempt
    ceiling despite making progress, then the retry lands clean."""
    path, body = alloc.tiny(16)
    _fault(srv_attempt, "slowdrip", 1, path)
    status, got = _get(srv_attempt.nginx_port, path)
    assert status == 200 and got == body
    assert srv_attempt.count_log(path) >= 2, "attempt ceiling never fired"


@pytest.mark.timeout(30)
def test_attempt_timeout_healthy_fill_unaffected(srv_attempt, alloc):
    path, body = alloc.std()
    status, got = _get(srv_attempt.nginx_port, path)
    assert status == 200 and got == body
    assert srv_attempt.count_log(path) == 1


@pytest.mark.timeout(60)
def test_raised_floor_kills_slowdrip(srv1, alloc):
    """stall_bytes=100 on srv1: the ~5 B/s drip is below the floor -> declared
    a stall (~stall_timeout) and re-fetched clean — the floor's other edge."""
    path, body = alloc.tiny(32)                      # 6.4 s drip >> ~3 s abort
    _fault(srv1, "slowdrip", 1, path)
    status, got = _get(srv1.nginx_port, path)
    assert status == 200 and got == body
    assert srv1.count_log(path) >= 2, "sub-floor drip was not killed"


@pytest.mark.timeout(30)
def test_raised_floor_healthy_fill_unaffected(srv1, alloc):
    path, body = alloc.std()
    status, got = _get(srv1.nginx_port, path)
    assert status == 200 and got == body
    assert srv1.count_log(path) == 1


# =========================================================================== #
# 3. Two-endpoint failover (policy = failover)
# =========================================================================== #
@pytest.mark.timeout(30)
def test_two_endpoint_healthy_baseline(srv_fo, alloc):
    path, body = alloc.std()
    status, got = _get(srv_fo.nginx_port, path)
    assert status == 200 and got == body


@pytest.mark.timeout(30)
def test_primary_404_is_definitive_not_masked(srv_fo, web, alloc):
    """404 vs down: a primary 404 is the origin's ANSWER — it must NOT be
    masked by failing over, even though the secondary holds the object
    (sd_http_select.c: an HTTP 4xx is not a transport failure). Runs BEFORE
    the fault tests below so health scores still point at the primary."""
    path, body = alloc.std()
    rel = path[len("/cvmfs/"):]
    (web["wp"] / "cvmfs" / rel).unlink()             # primary-only deletion
    t0 = time.monotonic()
    status, _ = _get(srv_fo.nginx_port, path)
    dt = time.monotonic() - t0
    assert status == 404, f"primary 404 was masked (got {status})"
    assert dt < 2


# fill_retry.c sizes the EBADMSG verify budget as one try per endpoint; the
# former divergence (verify failures never raised fail_score, so every retry
# re-picked the corrupt primary and the client got 502 with the clean
# secondary unconsulted) was fixed 2026-07-18 — EBADMSG retries now rotate
# endpoints, matching the official expectation asserted here.
def test_corrupt_primary_fails_over_to_clean_secondary(srv_fo, alloc):
    """EBADMSG's verify budget is one try per endpoint: a path-local corruption
    on the primary must end with the secondary's clean bytes, not a 502."""
    path, body = alloc.std()
    _fault(srv_fo, "corrupt", 99, path, mock=0)
    try:
        status, got = _get(srv_fo.nginx_port, path)
        assert status == 200 and got == body
        assert srv_fo.count_log(path, mock=1) >= 1
    finally:
        _clear_fault(srv_fo, mock=0)


@pytest.mark.timeout(60)
@pytest.mark.parametrize("mode", FO_FAULTS)
def test_transport_fault_fails_over_to_secondary(srv_fo, alloc, mode):
    """A persistent transport fault on the primary earns the one-alternate
    attempt: the client sees a clean byte-correct 200 served by mock 1."""
    path, body = alloc.std()
    _fault(srv_fo, mode, 99, path, mock=0)
    try:
        status, got = _get(srv_fo.nginx_port, path)
        assert status == 200 and got == body
        assert srv_fo.count_log(path, mock=1) >= 1, "secondary never served"
    finally:
        _clear_fault(srv_fo, mock=0)


@pytest.mark.timeout(60)
@pytest.mark.parametrize("mode", FO_FAULTS)
def test_failover_result_cached_clean(srv_fo, alloc, mode):
    """A failover-served object is a normal cache entry: the healed re-GET is
    a hit (no new fetch on either origin) with full correct bytes."""
    path, body = alloc.std()
    _fault(srv_fo, mode, 99, path, mock=0)
    try:
        status, got = _get(srv_fo.nginx_port, path)
        assert status == 200 and got == body
    finally:
        _clear_fault(srv_fo, mock=0)
    n0, n1 = srv_fo.count_log(path, mock=0), srv_fo.count_log(path, mock=1)
    status, got = _get(srv_fo.nginx_port, path)
    assert status == 200 and got == body
    assert srv_fo.count_log(path, mock=0) == n0
    assert srv_fo.count_log(path, mock=1) == n1


@pytest.mark.timeout(60)
def test_http500_primary_recovers(srv_fo, alloc):
    """A 5xx on the primary is retryable (fill_retry class RETRY): the client
    still ends with a clean byte-correct 200 inside the hold."""
    path, body = alloc.std()
    _fault(srv_fo, "http500", 2, path, mock=0)
    try:
        status, got = _get(srv_fo.nginx_port, path)
        assert status == 200 and got == body
    finally:
        _clear_fault(srv_fo, mock=0)


@pytest.mark.timeout(60)
def test_dead_primary_served_from_secondary(srv_dead, alloc):
    """Primary DOWN (connect refused) is a transport failure: failover serves
    a clean byte-correct 200 — the 404-vs-down distinction's other half."""
    path, body = alloc.std()
    status, got = _get(srv_dead.nginx_port, path)
    assert status == 200 and got == body
    assert srv_dead.count_log(path, mock=1) >= 1


@pytest.mark.timeout(60)
def test_dead_primary_failover_is_fast(srv_dead, alloc):
    """connect_timeout=1 bounds the dead-primary detour."""
    path, body = alloc.std()
    t0 = time.monotonic()
    status, got = _get(srv_dead.nginx_port, path)
    dt = time.monotonic() - t0
    assert status == 200 and got == body
    assert dt < 4, f"dead-primary failover took {dt:.1f}s"


@pytest.mark.timeout(60)
def test_dead_primary_result_cached_clean(srv_dead, alloc):
    path, body = alloc.std()
    assert _get(srv_dead.nginx_port, path) == (200, body)
    n1 = srv_dead.count_log(path, mock=1)
    assert _get(srv_dead.nginx_port, path) == (200, body)
    assert srv_dead.count_log(path, mock=1) == n1, "failover hit refetched"


# =========================================================================== #
# 4. force-primary: never open the alternate; re-pin after recovery
# =========================================================================== #

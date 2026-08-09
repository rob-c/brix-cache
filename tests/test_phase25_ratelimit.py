from split_continuation import reexport as _reexport
_reexport(globals(), "_test_phase25_ratelimit_helpers")

def test_ratelimit_module_present():
    for f in ("src/net/ratelimit/ratelimit.h", "src/net/ratelimit/ratelimit.c",
              "src/net/ratelimit/ratelimit_zone.c", "src/net/ratelimit/ratelimit_keys.c",
              "src/net/ratelimit/ratelimit_http.c",
              "src/net/ratelimit/ratelimit_stream.c", "src/observability/metrics/ratelimit.c"):
        assert (ROOT / f).exists(), f
    cfg = _read("config")
    assert "src/net/ratelimit/ratelimit_zone.c" in cfg
    assert "src/net/ratelimit/ratelimit_stream.c" in cfg


def test_stream_gate_and_charge_wired():
    d = _read("src/protocols/root/handshake/dispatch.c")
    assert "brix_rl_stream_gate" in d
    # phase-79 file-size split: read.c's zero-copy serve path (which charges the
    # bandwidth rate-limiter) moved into read_sendfile.c.
    assert "brix_rl_charge_ctx" in _read(
        "src/protocols/root/read/read_sendfile.c")
    assert "brix_rl_charge_ctx" in _read("src/protocols/root/write/write.c")
    s = _read("src/net/ratelimit/ratelimit_stream.c")
    assert "brix_send_wait" in s


def test_http_handler_and_filter_wired():
    pc = _read("src/protocols/webdav/postconfig.c")
    assert "brix_rl_http_access_handler" in pc
    assert "brix_rl_http_log_handler" in pc      # bandwidth charge (log phase)
    h = _read("src/net/ratelimit/ratelimit_http.c")
    assert "NGX_HTTP_TOO_MANY_REQUESTS" in h
    assert "Retry-After" in h
    assert "brix_rl_charge_bytes" in h


def test_directives_distinct_from_phase20():
    # Phase 25 directives must be distinct from the Phase 20 brix_rate_limit.
    # phase-79 split: the clustering/traffic directive tables moved into
    # directives_net.h on both surfaces.
    wd = _read("src/protocols/webdav/directives_net.h")
    st = _read("src/protocols/root/stream/directives_net.h")
    for name in ("brix_rate_limit_zone", "brix_rate_limit_rule",
                 "brix_bandwidth_limit"):
        assert name in wd, name
        assert name in st, name


def test_metrics_and_dashboard_wired():
    m = _read("src/observability/metrics/metrics.h")
    assert "rl_throttled_http_total" in m
    assert "rl_throttled_stream_total" in m
    assert "brix_rate_limit_throttled_total" in _read("src/observability/metrics/ratelimit.c")
    # phase-79 file-size split: the dashboard route table (incl. the ratelimit
    # API route) moved from dashboard/module.c into dashboard/module_dispatch.c.
    assert "/brix/api/v1/ratelimit" in _read(
        "src/observability/dashboard/module_dispatch.c")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #


def test_http_directives_parse(lifecycle):
    _parse_ok(lifecycle, "lc-rl-hparse", "nginx_rl_http.conf", _http_values(
        "            brix_rate_limit_rule zone=rl key=vo rate=500r/s burst=800;\n"
        "            brix_rate_limit_rule zone=rl key=ip rate=10r/s burst=10 nodelay;\n"
        "            brix_rate_limit_rule zone=rl key=volume:/store/tape rate=50r/s burst=80;\n"
        "            brix_bandwidth_limit zone=rl key=vo rate=100m/s burst=500m;\n",
        http_extra="    brix_rate_limit_zone zone=rl:4m;\n"))


def test_subject_key_wired_and_parses(lifecycle):
    # E-4 part 1: a SUBJECT (JWT/WLCG token subject) rate-limit key, hashed like
    # the DN so no raw identity ever reaches a metric label (INVARIANT #8).
    keys = _read("src/net/ratelimit/ratelimit_keys.c")
    assert "BRIX_RL_KEY_SUBJECT" in keys and "rl_key_sub_hash" in keys
    assert "sub:" in keys                       # hashed, low-cardinality label
    assert "BRIX_RL_KEY_SUBJECT" in _read("src/net/ratelimit/ratelimit.h")
    # both planes accept key=subject at config parse.
    _parse_ok(lifecycle, "lc-rl-subj-http", "nginx_rl_http.conf", _http_values(
        "            brix_rate_limit_rule zone=rl key=subject rate=10r/s burst=10;\n",
        http_extra="    brix_rate_limit_zone zone=rl:1m;\n"))
    _parse_ok(lifecycle, "lc-rl-subj-stream", "nginx_rl_stream.conf", _stream_values(
        "        brix_rate_limit_rule zone=rls key=subject rate=10r/s burst=10;\n",
        "    brix_rate_limit_zone zone=rls:1m;\n"))


def test_bad_rate_rejected(tmp_path):
    rc, out = _parse_fail(tmp_path,
                          "nginx_rl_http.conf", _http_values(
        "            brix_rate_limit_rule zone=rl key=ip rate=500 burst=10;\n",
        http_extra="    brix_rate_limit_zone zone=rl:1m;\n"))
    assert rc != 0
    assert "rate" in out.lower()


def test_unknown_zone_rejected(tmp_path):
    rc, out = _parse_fail(tmp_path,
                          "nginx_rl_http.conf", _http_values(
        "            brix_rate_limit_rule zone=missing key=ip rate=5r/s burst=5;\n"))
    assert rc != 0
    assert "zone" in out.lower()


def test_coexists_with_phase20_rate_limit(lifecycle):
    # The new directives and the Phase 20 brix_rate_limit must not collide.
    _parse_ok(lifecycle, "lc-rl-coexist", "nginx_rl_http.conf", _http_values(
        "            brix_rate_limit_rule zone=rl key=ip rate=10r/s burst=10;\n",
        http_extra="    brix_kv_zone kv 1m key=64 val=64;\n"
                   "    brix_rate_limit_zone zone=rl:1m;\n"))


# --------------------------------------------------------------------------- #
# Functional helpers                                                           #
# --------------------------------------------------------------------------- #


def test_http_429_after_burst(lifecycle, tmp_path):
    port = _start_http(
        lifecycle, tmp_path, "lc-rl-429",
        "            brix_rate_limit_rule zone=rl key=ip rate=2r/s burst=2;\n",
        http_extra="    brix_rate_limit_zone zone=rl:1m;\n",
        seed_files=[("f.txt", "hello\n")])
    codes = [_get(port, "/f.txt")[0] for _ in range(6)]
    assert codes[:2] == [200, 200], codes
    assert 429 in codes, codes
    # The throttled (non-nodelay) response carries Retry-After.
    st, hdrs = _get(port, "/f.txt")
    if st == 429:
        assert "retry-after" in hdrs, hdrs


def test_http_nodelay_immediate(lifecycle, tmp_path):
    port = _start_http(
        lifecycle, tmp_path, "lc-rl-nodelay",
        "            brix_rate_limit_rule zone=rl key=ip rate=1r/s burst=1 nodelay;\n",
        http_extra="    brix_rate_limit_zone zone=rl:1m;\n",
        seed_files=[("f.txt", "hello\n")])
    codes = [_get(port, "/f.txt")[0] for _ in range(4)]
    assert codes[0] == 200
    assert 429 in codes[1:], codes
    # nodelay → no Retry-After header.
    for _ in range(4):
        st, hdrs = _get(port, "/f.txt")
        if st == 429:
            assert "retry-after" not in hdrs, hdrs
            break


def test_http_bandwidth_throttled(lifecycle, tmp_path):
    # A tiny bandwidth cap: the first large GET is allowed, then the bucket
    # overflows and subsequent GETs are throttled (429).
    port = _start_http(
        lifecycle, tmp_path, "lc-rl-bw",
        "            brix_bandwidth_limit zone=rl key=ip rate=10k/s burst=120k;\n",
        http_extra="    brix_rate_limit_zone zone=rl:1m;\n",
        seed_files=[("big.bin", b"x" * 100000)])
    codes = [_get(port, "/big.bin")[0] for _ in range(5)]
    assert codes[0] == 200, codes          # first within burst
    assert 429 in codes, codes             # bucket overflows after charge



def test_dashboard_shows_throttle_count(lifecycle, tmp_path):
    port = _start_http(
        lifecycle, tmp_path, "lc-rl-dash",
        "            brix_rate_limit_rule zone=rl key=ip rate=2r/s burst=2;\n",
        http_extra="    brix_rate_limit_zone zone=rl:1m;\n",
        extra_locations=(
            "        location /brix/ {\n"
            "            brix_dashboard on;\n"
            "            brix_dashboard_password \"pw\";\n"
            "        }\n"),
        seed_files=[("f.txt", "hello\n")])
    # Drive throttling on the ip:127.0.0.1 principal.
    for _ in range(8):
        _get(port, "/f.txt")
    cookie = _curl_cookie(lifecycle, port)
    assert cookie, "dashboard login did not set a cookie"
    doc = _curl_ratelimit(lifecycle, port, cookie)
    principals = [p for z in doc.get("zones", []) for p in z["principals"]]
    assert principals, doc
    throttled = [p for p in principals if p["throttle_count"] > 0]
    assert throttled, principals
    # Sorted most-throttled first.
    counts = [p["throttle_count"] for p in principals]
    assert counts == sorted(counts, reverse=True), counts


# --------------------------------------------------------------------------- #
# Stream functional (raw XRootD wire)                                          #
# --------------------------------------------------------------------------- #


def test_stream_kxr_wait_after_burst(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = _start_stream(
        lifecycle, data, "lc-rl-swait",
        "        brix_rate_limit_rule zone=rls key=ip rate=2r/s burst=2;\n",
        "    brix_rate_limit_zone zone=rls:1m;\n")
    s = _xrd_login(HOST, port)
    # kXR_open is rate-limited; burst=2 then kXR_wait.
    statuses = []
    for _ in range(6):
        st, _b = _xrd_open(s, "/f.txt")
        statuses.append(st)
    s.close()
    assert KXR_WAIT in statuses, statuses


def test_stream_stat_never_throttled(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = _start_stream(
        lifecycle, data, "lc-rl-sstat",
        "        brix_rate_limit_rule zone=rls key=ip rate=1r/s burst=1;\n",
        "    brix_rate_limit_zone zone=rls:1m;\n")
    s = _xrd_login(HOST, port)
    # Many stats in a row — never kXR_wait (stat is exempt).
    for _ in range(8):
        st, _b = _xrd_stat(s, "/f.txt")
        assert st != KXR_WAIT, st
    s.close()


# --------------------------------------------------------------------------- #
# 6. Stream concurrency limiting (W7)                                          #
#                                                                             #
# The stream plane has no per-request LOG phase, so brix_concurrency_limit  #
# caps *concurrent connections* per principal: the gate acquires one in-flight #
# slot on the first rate-limited opcode (kXR_open/read/...) and releases it in #
# brix_on_disconnect.  Over-cap connections get kXR_wait; a freed slot is    #
# reusable.                                                                    #
# --------------------------------------------------------------------------- #

def test_stream_concurrency_wiring():
    # The directive is registered on the stream srv table (not HTTP-only) ...
    st = _read("src/protocols/root/stream/module.c")
    assert "brix_concurrency_limit" in st
    assert "brix_rl_conc_directive" in st
    # ... the gate acquires a slot ...
    rs = _read("src/net/ratelimit/ratelimit_stream.c")
    assert "brix_rl_conc_acquire" in rs
    assert "brix_rl_release_ctx" in rs
    # ... the per-connection slot lives on the ctx ...
    ctx = _read("src/core/types/context.h")
    assert "conc_rule" in ctx   # brix_ctx_rl_t field (context.h → ctx_structs.h split)
    assert "conc_key" in ctx
    # ... and the release is hooked on disconnect (no LOG phase on the stream).
    dc = _read("src/protocols/root/connection/disconnect.c")
    assert "brix_rl_release_ctx" in dc



def test_stream_concurrency_directive_parses(lifecycle):
    # Regression: brix_concurrency_limit used to be HTTP-only and would be
    # rejected in a stream{} server block. It must now parse there.
    _parse_ok(lifecycle, "lc-rl-cparse", "nginx_rl_stream.conf",
              _stream_values(_conc_knobs(4), _CONC_ZONE))


def test_stream_concurrency_bad_limit_rejected(tmp_path):
    # limit= must be a positive integer (security/neg: a 0 or garbage cap is a
    # silent no-cap footgun, so the parser must reject it).
    rc, out = _parse_fail(tmp_path,
                          "nginx_rl_stream.conf",
                          _stream_values(_conc_knobs(0), _CONC_ZONE))
    assert rc != 0
    assert "limit" in out.lower()


def test_stream_concurrency_cap_and_release(lifecycle, tmp_path):
    # limit=2: two concurrent connections each hold an in-flight slot; the third
    # concurrent connection's first rate-limited op (kXR_open) gets kXR_wait.
    # Closing a holder frees its slot for a fresh connection (release path).
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = _start_stream(lifecycle, data, "lc-rl-conc",
                         _conc_knobs(2), _CONC_ZONE)
    holders = []
    try:
        # Two concurrent connections each acquire a slot — neither waits.
        for _ in range(2):
            s = _xrd_login(HOST, port)
            st, _b = _xrd_open(s, "/f.txt")
            assert st != KXR_WAIT, ("holder should acquire a slot", st)
            holders.append(s)

        # Third concurrent connection exceeds the cap → kXR_wait, no slot held.
        s3 = _xrd_login(HOST, port)
        st3, _b = _xrd_open(s3, "/f.txt")
        assert st3 == KXR_WAIT, ("over-cap connection must wait", st3)
        s3.close()

        # Release a holder; its slot must come back (freed in on_disconnect).
        holders.pop(0).close()

        # Poll: a fresh connection should acquire within a short window once the
        # disconnect handler has run.
        acquired = False
        deadline = time.time() + 5
        while time.time() < deadline:
            s4 = _xrd_login(HOST, port)
            st4, _b = _xrd_open(s4, "/f.txt")
            if st4 != KXR_WAIT:
                acquired = True
                holders.append(s4)
                break
            s4.close()
            time.sleep(0.2)
        assert acquired, "freed concurrency slot was not reusable after disconnect"
    finally:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass


def test_stream_concurrency_high_limit_no_throttle(lifecycle, tmp_path):
    # Control: with a cap well above the offered load, concurrent connections all
    # proceed — proving the kXR_wait above is the cap, not an artifact of opening
    # several connections at once.
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = _start_stream(lifecycle, data, "lc-rl-conc-hi",
                         _conc_knobs(16), _CONC_ZONE)
    holders = []
    try:
        for _ in range(4):
            s = _xrd_login(HOST, port)
            st, _b = _xrd_open(s, "/f.txt")
            assert st != KXR_WAIT, ("under cap must not throttle", st)
            holders.append(s)
    finally:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 7. Phase 33 C4 — rate-limit key memoization                                 #
#                                                                             #
# The stream gate caches identity-stable keys (IP/VO/ISSUER/DN) per connection #
# so the per-read re-hash is removed.  These tests prove the cache preserves   #
# behaviour: identity throttling still fires on the (cached-key) read path,    #
# and VOLUME (path-dependent) rules are NEVER cached/collapsed — each path     #
# still buckets independently.                                                #
# --------------------------------------------------------------------------- #

def test_keycache_wiring():
    assert "BRIX_RL_RULE_CACHE_MAX" in _read("src/core/types/tunables.h")
    ctx = _read("src/core/types/context.h")
    assert "key_cache" in ctx and "key_cache_valid" in ctx  # brix_ctx_rl_t (ctx_structs.h)
    gate = _read("src/net/ratelimit/ratelimit_stream.c")
    assert "key_cache_valid" in gate  # accessed as rl.key_cache_valid (ctx_structs.h split)
    # VOLUME rules must be excluded from caching.
    assert "BRIX_RL_KEY_VOLUME" in gate


def test_keycache_read_path_still_throttles(lifecycle, tmp_path):
    # The read path is non-path-bearing, so it uses the CACHED identity key.
    # Throttling must still fire there: open once, then reads exhaust the burst
    # and return kXR_wait.
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello world\n")
    port = _start_stream(
        lifecycle, data, "lc-rl-keycache",
        "        brix_rate_limit_rule zone=rlk key=ip rate=2r/s burst=2;\n",
        "    brix_rate_limit_zone zone=rlk:1m;\n")
    s = _xrd_login(HOST, port)
    st, body = _xrd_open(s, "/f.txt")          # op 1 (within burst)
    assert st == KXR_OK, ("open should succeed within burst", st)
    fh = body[:4]
    # Hammer reads on the cached ip key; the burst is spent → kXR_wait.
    read_status = [_xrd_read(s, fh, 0, 5)[0] for _ in range(6)]
    s.close()
    assert KXR_WAIT in read_status, ("cached-key read path must throttle",
                                     read_status)

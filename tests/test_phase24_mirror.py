from split_continuation import reexport as _reexport
def _check_test_stream_data_write_abort_not_replayed_1(primary):
    assert _xrd_write_gapped(HOST, primary, "/wmir-abort.bin") == 0, \
        "primary sparse write should still succeed"

def _check_test_stream_data_write_abort_not_replayed_2(base_err, metrics):
    assert (_scrape_metric(metrics, "brix_mirror_errors_total", "stream") or 0) \
        == base_err, "an aborted write launches no replay (no error either)"

def _check_test_stream_data_write_over_cap_not_replayed_3(primary, body):
    assert _xrd_write_seq(HOST, primary, "/wmir-big.bin", body,
                          chunk=512 * 1024) == 0, "primary large write failed"

def _check_test_stream_data_write_over_cap_not_replayed_4(drop, base_drop):
    assert drop is not None and drop >= base_drop + 1, \
        "over-cap data-write should count a dropped mirror"

def _check_test_stream_data_write_over_cap_not_replayed_5(sdata):
    assert not (sdata / "wmir-big.bin").exists(), \
        "over-cap write must not reach the shadow"

def _check_test_stream_data_write_over_cap_not_replayed_6(metrics):
    assert (_scrape_metric(metrics, "brix_mirror_requests_total", "stream") or 0) == 0, \
        "an over-cap (aborted) write launches no replay"


_reexport(globals(), "_test_phase24_mirror_helpers")

def test_mirror_modules_present():
    for f in ("src/net/mirror/mirror.h", "src/net/mirror/http_mirror.c",
              "src/net/mirror/http_mirror.h", "src/net/mirror/stream_mirror.c",
              "src/net/mirror/stream_mirror.h"):
        assert (ROOT / f).exists(), f
    cfg = _read("config")
    assert "src/net/mirror/http_mirror.c" in cfg
    assert "src/net/mirror/stream_mirror.c" in cfg


def test_stream_dispatch_hook_present():
    d = _read("src/protocols/root/handshake/dispatch.c")
    assert "brix_stream_mirror_maybe" in d
    sm = _read("src/net/mirror/stream_mirror.c")
    # Reuses the proven bootstrap wire builder; replays the saved request.
    assert "brix_upstream_build_bootstrap" in sm
    assert "brix_mir_send_request" in sm
    assert "mirror_stream_divergence_total" in sm


def test_http_phase_handlers_present():
    h = _read("src/net/mirror/http_mirror.c")
    assert "brix_http_mirror_precontent_handler" in h
    assert "ngx_http_subrequest" in h
    assert "NGX_HTTP_SUBREQUEST_BACKGROUND" in h
    pc = _read("src/protocols/webdav/postconfig.c")
    assert "NGX_HTTP_PRECONTENT_PHASE" in pc
    assert "brix_http_mirror_precontent_handler" in pc


def test_directives_registered():
    # phase-79 split: the clustering/traffic directive tables moved into
    # directives_net.h on both surfaces (webdav via module_commands.c,
    # stream via module.c — each #includes its directives_net.h).
    wd = _read("src/protocols/webdav/directives_net.h")
    for name in ("brix_mirror_url", "brix_mirror_methods",
                 "brix_mirror_sample", "brix_mirror_strip_auth"):
        assert name in wd, name
    st = _read("src/protocols/root/stream/directives_net.h")
    for name in ("brix_stream_mirror_url", "brix_mirror_opcodes"):
        assert name in st, name


def test_metrics_present():
    m = _read("src/observability/metrics/metrics.h")
    assert "mirror_http_total" in m
    assert "mirror_stream_divergence_total" in m
    assert "brix_mirror_requests_total" in _read("src/observability/metrics/stream.c")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #


def test_http_mirror_directives_parse(lifecycle):
    # mirror_url targets are directive VALUES only — never dialed under `nginx -t`
    # — so a non-binding placeholder is correct (the two schemes keep them distinct).
    s1 = s2 = PARSE_PLACEHOLDER_PORT
    _parse_http(lifecycle, "lc-mir-hparse", (
        f"            brix_mirror_url     http://{HOST}:{s1};\n"
        f"            brix_mirror_url     https://{HOST}:{s2};\n"
        "            brix_mirror_methods GET HEAD PROPFIND;\n"
        "            brix_mirror_sample  25;\n"
        "            brix_mirror_strip_auth on;\n"
        "            brix_mirror_log_diverge on;\n"
        "            brix_mirror_timeout 3s;\n"
    ))


def test_http_mirror_bad_scheme_rejected(tmp_path):
    port = shadow = PARSE_PLACEHOLDER_PORT  # reject-parse: nginx -t never binds
    result = nginx_t(
        "nginx_mirror_http.conf",
        tmp_path,
        BIND_HOST=BIND_HOST,
        PORT=port,
        DATA_ROOT=str(tmp_path / "data"),
        LOG_DIR=str(tmp_path),
        TMP_DIR=str(tmp_path),
        MIRROR_KNOBS=f"            brix_mirror_url ftp://{HOST}:{shadow};\n",
    )
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "http://" in out


def test_stream_mirror_directives_parse(lifecycle):
    shadow = PARSE_PLACEHOLDER_PORT  # directive value only — nginx -t never dials it
    _parse_stream(lifecycle, "lc-mir-sparse", (
        "        brix_mirror_opcodes stat locate dirlist;\n"
        "        brix_mirror_sample 50;\n"
        "        brix_mirror_log_diverge on;\n"
        "        brix_mirror_timeout 3s;\n"
    ), shadow)


def test_stream_mirror_bad_opcode_rejected(tmp_path):
    port = shadow = PARSE_PLACEHOLDER_PORT  # reject-parse: nginx -t never binds
    result = nginx_t(
        "nginx_mirror_stream_parse.conf",
        tmp_path,
        BIND_HOST=BIND_HOST,
        HOST=HOST,
        PORT=port,
        SHADOW_PORT=shadow,
        DATA_ROOT=str(tmp_path / "data"),
        LOG_DIR=str(tmp_path),
        MIRROR_KNOBS="        brix_mirror_opcodes bogus;\n",
    )
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "brix_mirror_opcodes" in out


# --------------------------------------------------------------------------- #
# Phase 24 write mirroring (W1: stream metadata) — wiring + gate               #
# --------------------------------------------------------------------------- #

def test_stream_mirror_write_opcodes_and_gate_parse(lifecycle):
    """The write opcodes + brix_mirror_writes gate parse on the stream side."""
    shadow = PARSE_PLACEHOLDER_PORT  # directive value only — nginx -t never dials it
    _parse_stream(lifecycle, "lc-mir-wparse", (
        "        brix_mirror_writes on;\n"
        "        brix_mirror_opcodes mkdir rm rmdir mv truncate chmod;\n"
    ), shadow)


def test_mirror_writes_off_by_default_and_gated_in_source():
    """mirror_writes defaults off; the gate is independent of opcode selection."""
    mh = _read("src/net/mirror/mirror.h")
    # Write bits exist but are excluded from the default opcode mask.
    assert "BRIX_MIRROR_OP_MKDIR" in mh
    assert "BRIX_MIRROR_OP_WRITE" in mh
    assert "mirror_writes" in mh
    # OP_DEFAULT/OP_ALL must NOT pull in the write bits.
    op_all = re.search(r"define\s+BRIX_MIRROR_OP_ALL\b(.*?)\n\n", mh, re.S)
    assert op_all and "MKDIR" not in op_all.group(1) and "OP_WRITE" not in op_all.group(1)
    # The stream maybe() enforces mirror_writes as a second, independent guard.
    # phase-79 split: the launch/opcode-gating half of stream_mirror.c moved
    # into stream_mirror_launch.c.
    sm = _read("src/net/mirror/stream_mirror_launch.c")
    assert "OP_WRITE_ALL" in sm and "mirror_writes" in sm
    # Default merge is 0 (off) on both surfaces.  phase-79 split: the cluster/
    # mirror merge moved from server_conf.c into server_conf_merge_cluster.c,
    # and the webdav proxy/mirror merge from config.c into config_proxy.c.
    assert "conf->mirror.mirror_writes,\n                         prev->mirror.mirror_writes, 0" \
        in _read("src/core/config/server_conf_merge_cluster.c")
    assert "prev->mirror.mirror_writes, 0" in _read("src/protocols/webdav/config_proxy.c")


# --------------------------------------------------------------------------- #
# HTTP functional helpers                                                      #
# --------------------------------------------------------------------------- #


def test_get_fires_shadow_request(http_mirror_server):
    port, _ = http_mirror_server
    assert _http_get(port, "/hello.txt") == 200
    assert _wait_shadow("/hello.txt"), "shadow never received the mirrored GET"


def test_auth_stripped_from_shadow(http_mirror_server):
    port, _ = http_mirror_server
    status = _http_get(port, "/hello.txt",
                       extra_headers="Authorization: Bearer secret-token\r\n")
    assert status == 200
    assert _wait_shadow("/hello.txt")
    for p, hdrs in _shadow.received:
        assert "authorization" not in hdrs, \
            "shadow must not receive the client's Authorization header"


def test_shadow_failure_transparent(lifecycle, tmp_path):
    # Shadow port has nothing listening → mirror connect fails, but the primary
    # GET must still succeed (the client never sees the shadow path).
    dead_shadow = PROXY_DEAD_UPSTREAM_PORT
    port = _start_mirror_primary(
        lifecycle, tmp_path, "lc-mir-dead",
        (f"            brix_mirror_url     http://{HOST}:{dead_shadow};\n"
         "            brix_mirror_methods GET;\n"
         "            brix_mirror_sample  100;\n"
         "            brix_mirror_timeout 1s;\n"),
        seed_files=[("f.txt", "body\n")])
    assert _http_get(port, "/f.txt") == 200
    # Repeat — a failing mirror must not break subsequent requests.
    assert _http_get(port, "/f.txt") == 200


def test_write_not_mirrored(http_mirror_server):
    port, _ = http_mirror_server
    _put(port, "/uploaded.txt", b"data")
    # Give any (erroneous) mirror a chance to fire, then assert none did.
    time.sleep(1.0)
    assert "/uploaded.txt" not in _shadow_paths(), "PUT must never be mirrored"


def test_sample_zero_mirrors_nothing(lifecycle, tmp_path):
    _shadow.reset()
    port = _start_mirror_primary(
        lifecycle, tmp_path, "lc-mir-zero",
        (f"            brix_mirror_url     http://{HOST}:{MIRROR_SHADOW_PORT};\n"
         "            brix_mirror_methods GET;\n"
         "            brix_mirror_sample  0;\n"),
        seed_files=[("z.txt", "z\n")])
    assert _http_get(port, "/z.txt") == 200
    time.sleep(1.0)
    assert _shadow_paths() == [], "sample 0 must mirror nothing"


# --------------------------------------------------------------------------- #
# Stream functional helpers (raw XRootD wire)                                  #
# --------------------------------------------------------------------------- #


def test_stat_mirrored_to_shadow(lifecycle, tmp_path):
    primary, metrics = _start_stream_pair(
        lifecycle, tmp_path, "lc-mir-stream-ok",
        primary_files=["present.txt"], shadow_files=["present.txt"])
    _xrd_stat(HOST, primary, "/present.txt")
    got = _wait_metric(metrics, "brix_mirror_requests_total", "stream", 1)
    assert got is not None and got >= 1, \
        f"stream mirror request not counted (got {got})"


def test_divergence_counted(lifecycle, tmp_path):
    # Primary HAS the file (stat ok); shadow does NOT (kXR_NotFound) → divergence.
    primary, metrics = _start_stream_pair(
        lifecycle, tmp_path, "lc-mir-stream-div",
        primary_files=["only-here.txt"], shadow_files=[])
    _xrd_stat(HOST, primary, "/only-here.txt")
    got = _wait_metric(metrics, "brix_mirror_divergence_total", "stream", 1)
    assert got is not None and got >= 1, \
        f"divergence not counted (got {got})"


# --------------------------------------------------------------------------- #
# Phase 24 W2 — HTTP write-method mirroring (functional)                       #
# --------------------------------------------------------------------------- #


def test_put_body_mirrored_to_shadow(http_mirror_writes_server):
    """A PUT body is forwarded byte-exact to the shadow (W2 PUT body forwarding)."""
    primary, _ = http_mirror_writes_server
    body = bytes((i * 31 + 7) & 0xFF for i in range(5000))
    _http_req(primary, "PUT", "/w-up.bin", body)   # mirror fires in PRECONTENT
    assert _wait_shadow_method("PUT", "/w-up.bin"), "shadow never received the PUT"
    assert _shadow_body("/w-up.bin") == body, "shadow PUT body not byte-exact"


def test_delete_mirrored_to_shadow(http_mirror_writes_server):
    """DELETE is mirrored to the shadow (fires in PRECONTENT regardless of 404)."""
    primary, _ = http_mirror_writes_server
    _http_req(primary, "DELETE", "/w-gone.txt")
    assert _wait_shadow_method("DELETE", "/w-gone.txt"), \
        "shadow never received the DELETE"


def test_writes_off_not_mirrored(lifecycle, tmp_path):
    """With brix_mirror_writes off, a PUT is NOT replayed to the shadow."""
    _shadow.reset()
    port = _start_mirror_primary(
        lifecycle, tmp_path, "lc-mir-writesoff",
        _writes_knobs(MIRROR_SHADOW_PORT, writes="off"))
    _http_req(port, "PUT", "/off.bin", b"data")
    time.sleep(1.0)
    assert ("PUT", "/off.bin") not in _shadow.methods, \
        "PUT mirrored despite brix_mirror_writes off"


# --------------------------------------------------------------------------- #
# Phase 24 W3 — XRootD stream DATA-write mirroring (open->write->close replay)  #
#                                                                              #
# The audit's one open item for phase-24 was that the data-write mirror        #
# (src/net/mirror/stream_wmirror*.c) had unit/marker coverage but no live      #
# runtime validation of the actual detached shadow replay.  These three drive  #
# a real root:// open->write->close on the primary and assert against a live,  #
# writable embedded shadow origin: the file is replayed byte-exact (success),  #
# a non-sequential write aborts the mirror before any replay launches (error), #
# and the whole thing stays inert unless brix_mirror_writes is opted in        #
# (security-neg — replayed writes must never escape to the shadow namespace by  #
# default).                                                                    #
# --------------------------------------------------------------------------- #

def test_stream_data_write_mirrored_byte_exact(lifecycle, tmp_path):
    """A sequential open->write->close is replayed to the shadow byte-exact."""
    primary, metrics, sdata = _start_wmirror_pair(
        lifecycle, tmp_path, "lc-mir-stream-wr", "on")
    body = bytes((i * 37 + 11) & 0xFF for i in range(9000))   # spans >1 chunk
    assert _xrd_write_seq(HOST, primary, "/wmir-ok.bin", body) == 0, \
        "primary write sequence failed"
    got = _wait_metric(metrics, "brix_mirror_requests_total", "stream", 1)
    assert got is not None and got >= 1, \
        f"data-write replay not counted (got {got})"
    shadow_file = sdata / "wmir-ok.bin"
    assert _wait_file(shadow_file, len(body)), \
        "shadow never received the replayed data-write file"
    assert shadow_file.read_bytes() == body, "shadow file not byte-exact"


def test_stream_data_write_abort_not_replayed(lifecycle, tmp_path):
    """A non-sequential write aborts the mirror in the accumulator: the primary's
    own (sparse) write still succeeds, but no shadow replay is ever launched."""
    primary, metrics, sdata = _start_wmirror_pair(
        lifecycle, tmp_path, "lc-mir-stream-wrabort", "on")
    base_ok = _scrape_metric(metrics, "brix_mirror_requests_total", "stream") or 0
    base_err = _scrape_metric(metrics, "brix_mirror_errors_total", "stream") or 0
    _check_test_stream_data_write_abort_not_replayed_1(primary)
    time.sleep(1.5)   # a (wrongly) launched replay would have fired by now
    def _assert_test_stream_data_write_abort_not_replayed_1():
        assert not (sdata / "wmir-abort.bin").exists(), \
            "aborted (non-sequential) write must not reach the shadow"
        assert (_scrape_metric(metrics, "brix_mirror_requests_total", "stream") or 0) \
            == base_ok, "aborted write must not count a mirror success"

    _assert_test_stream_data_write_abort_not_replayed_1()
    _check_test_stream_data_write_abort_not_replayed_2(base_err, metrics)


def test_stream_data_write_over_cap_not_replayed(lifecycle, tmp_path):
    """A write stream exceeding the per-file cap (BRIX_WMIRROR_FILE_CAP, 4 MiB)
    aborts the accumulator: the primary stores the whole file fine, but the
    over-cap file is dropped (counted) and never replayed to the shadow."""
    primary, metrics, sdata = _start_wmirror_pair(
        lifecycle, tmp_path, "lc-mir-stream-wrcap", "on")
    base_drop = _scrape_metric(metrics, "brix_mirror_dropped_total", "stream") or 0
    body = b"\x5a" * (5 * 1024 * 1024)   # 5 MiB > 4 MiB per-file cap
    _check_test_stream_data_write_over_cap_not_replayed_3(primary, body)
    drop = _wait_metric(metrics, "brix_mirror_dropped_total", "stream",
                        base_drop + 1)
    _check_test_stream_data_write_over_cap_not_replayed_4(drop, base_drop)
    time.sleep(1.0)
    _check_test_stream_data_write_over_cap_not_replayed_5(sdata)
    _check_test_stream_data_write_over_cap_not_replayed_6(metrics)


def test_stream_data_write_off_not_mirrored(lifecycle, tmp_path):
    """Security-neg: with brix_mirror_writes off, a clean sequential write is NOT
    replayed — data writes never escape to the shadow namespace unless opted in."""
    primary, metrics, sdata = _start_wmirror_pair(
        lifecycle, tmp_path, "lc-mir-stream-wroff", "off")
    body = b"stays-local-only\n" * 64
    assert _xrd_write_seq(HOST, primary, "/wmir-off.bin", body) == 0
    time.sleep(1.5)
    assert not (sdata / "wmir-off.bin").exists(), \
        "data write replayed despite brix_mirror_writes off"
    assert (_scrape_metric(metrics, "brix_mirror_requests_total", "stream") or 0) == 0, \
        "no stream data-write mirror may fire with writes off"


# --------------------------------------------------------------------------- #
# 5. Disconnect-mid-write — UAF / heap-ownership drivers                       #
#                                                                              #
# These exercise the two lifetime hazards the phase-88 audit § 4 flagged as    #
# machine-checkable only under the B-2 ASan+UBSan lane:                        #
#   (a) a client that vanishes mid-upload (no kXR_close) — the accumulator's   #
#       malloc'd per-file buffers are live and must be freed exactly once by   #
#       brix_stream_wmirror_cleanup on connection teardown (LSan: leak;        #
#       ASan: use-after-free if teardown races a launch);                      #
#   (b) a client that closes (launching the DETACHED replay, which STEALS      #
#       f->data) then immediately drops the socket — the replay must own and   #
#       free the transferred heap buffer on its own cycle-pool lifetime, with  #
#       the client connection already gone (ASan: UAF on the stolen buffer).   #
# They assert observable behaviour on every run (worker survives; replay fires #
# or doesn't as expected); under the ASan lane the sanitizer is the extra gate #
# that no report is emitted. See tools/ci/asan.py (ASAN_TEST_CMD2).            #
# --------------------------------------------------------------------------- #

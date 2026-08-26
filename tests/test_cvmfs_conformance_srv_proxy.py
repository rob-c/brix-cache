from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_proxy_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_srv_proxy")

def test_valid_absolute_form_serves_cas_bytes(psrv):
    obj = psrv.objects()[1]
    origin = urllib.request.urlopen(psrv.mock_url + obj).read()
    status, _, body = af(psrv, tgt(psrv.mock_ports[0], obj))
    assert status == 200 and body == origin


@pytest.mark.parametrize("meta", [".cvmfspublished", ".cvmfswhitelist"])
def test_signed_metadata_via_proxy(psrv, meta):
    status, _, body = af(psrv, tgt(psrv.mock_ports[0], f"/cvmfs/{REPO}/{meta}"))
    assert status == 200 and body


def test_reflog_via_proxy_clean_miss(psrv):
    # mock has no reflog: a clean 404 through the proxy, never a 5xx.
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0], f"/cvmfs/{REPO}/.cvmfsreflog"))
    assert status in (200, 404)


def test_head_parity_on_cas(psrv):
    obj = psrv.objects()[2]
    gs, _, gbody = af(psrv, tgt(psrv.mock_ports[0], obj))
    hs, _, hbody = af(psrv, tgt(psrv.mock_ports[0], obj), method="HEAD")
    assert gs == 200 and hs == 200 and hbody == b""


def test_second_fetch_is_cache_hit_single_fill(psrv):
    obj = psrv.objects()[3]
    psrv.reset_log()
    s1, _, b1 = af(psrv, tgt(psrv.mock_ports[0], obj))
    s2, _, b2 = af(psrv, tgt(psrv.mock_ports[0], obj))
    assert s1 == s2 == 200 and b1 == b2
    assert psrv.count_log(obj) == 1, "proxy did not coalesce to a single origin fill"


def test_scheme_is_case_insensitive_upper(psrv):
    status, _, _ = af(psrv, f"HTTP://127.0.0.1:{psrv.mock_ports[0]}{MPATH}")  # net-literal-allow: absolute-form request-target payload under test
    assert status == 200


def test_scheme_is_case_insensitive_mixed(psrv):
    status, _, _ = af(psrv, f"hTtP://127.0.0.1:{psrv.mock_ports[0]}{MPATH}")  # net-literal-allow: absolute-form request-target payload under test
    assert status == 200


def test_port_leading_zero_is_decimal(psrv):
    status, _, _ = af(psrv, tgt(f"0{psrv.mock_ports[0]}", MPATH))
    assert status == 200


# (uri-builder, expected-status-set). Ports 0/65536/overflow/empty/non-numeric
# are brix 400s (request.c: 1..65535); userinfo and single-slash are nginx
# request-line parse 400s; non-http(s) schemes and shapeless paths are 403s.
_REJECTS = [
    ("port_zero", lambda m: f"http://127.0.0.1:0{MPATH}", {400}),  # net-literal-allow: absolute-form request-target payload under test
    ("port_65536", lambda m: f"http://127.0.0.1:65536{MPATH}", {400}),  # net-literal-allow: absolute-form request-target payload under test
    ("port_overflow", lambda m: f"http://127.0.0.1:99999999999{MPATH}", {400}),  # net-literal-allow: absolute-form request-target payload under test
    ("port_empty", lambda m: f"http://127.0.0.1:{MPATH}", {400}),  # net-literal-allow: absolute-form request-target payload under test
    ("port_nonnumeric", lambda m: f"http://127.0.0.1:8x0{MPATH}", {400}),  # net-literal-allow: absolute-form request-target payload under test
    ("userinfo", lambda m: f"http://user@127.0.0.1:{m}{MPATH}", {400}),  # net-literal-allow: absolute-form request-target payload under test
    ("scheme_https_on_cleartext", lambda m: f"https://127.0.0.1:{m}{MPATH}", {403}),  # net-literal-allow: absolute-form request-target payload under test
    ("scheme_ftp", lambda m: f"ftp://127.0.0.1:{m}{MPATH}", {403}),  # net-literal-allow: absolute-form request-target payload under test
    ("scheme_wss", lambda m: f"wss://127.0.0.1:{m}{MPATH}", {403}),  # net-literal-allow: absolute-form request-target payload under test
    ("empty_host", lambda m: f"http://{MPATH}", {400, 403}),
    ("single_slash", lambda m: f"http:/127.0.0.1:{m}{MPATH}", {400}),  # net-literal-allow: absolute-form request-target payload under test
    ("missing_path", lambda m: f"http://127.0.0.1:{m}", {403}),  # net-literal-allow: absolute-form request-target payload under test
    ("root_path_only", lambda m: f"http://127.0.0.1:{m}/", {403}),  # net-literal-allow: absolute-form request-target payload under test
]


@pytest.mark.parametrize("name,mk,expect", _REJECTS, ids=[r[0] for r in _REJECTS])
def test_absolute_form_reject_corpus(psrv, name, mk, expect):
    status, _, _ = af(psrv, mk(psrv.mock_ports[0]))
    assert status in expect, f"{name}: got {status}, want one of {expect}"


def test_port_65535_accepted_as_target(psrv):
    # Top of the valid range parses + allowlists; nothing listens there, so the
    # failure must be an upstream error — never a parse (400) or allowlist (403).
    status, _, _ = af(psrv, f"http://127.0.0.1:65535{MPATH}")  # net-literal-allow: absolute-form request-target payload under test
    assert status not in (0, 200, 400, 403)


def test_port_1_accepted_as_target(psrv):
    status, _, _ = af(psrv, f"http://127.0.0.1:1{MPATH}")  # net-literal-allow: absolute-form request-target payload under test
    assert status not in (0, 200, 400, 403)


def test_port_absent_defaults_to_80(psrv):
    # No ":port" => default 80 (request.c). The target parses and allowlists;
    # whatever :80 answers (nothing, or an unrelated local server) it must not
    # surface as a parse or allowlist reject.
    status, _, _ = af(psrv, f"http://127.0.0.1{MPATH}")  # net-literal-allow: absolute-form request-target payload under test
    assert status not in (0, 400, 403)


@pytest.mark.parametrize("method", ["PUT", "POST", "DELETE", "OPTIONS", "TRACE"])
def test_non_get_head_methods_405(psrv, method):
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0], MPATH), method=method)
    assert status == 405


def test_connect_authority_form_rejected(psrv):
    status, _, _ = raw_http(HOST, psrv.nginx_port,
                            f"CONNECT 127.0.0.1:{psrv.mock_ports[0]} HTTP/1.1")  # net-literal-allow: CONNECT request-target payload under test
    assert status in (0, 400, 405) and status != 200


def test_connect_absolute_uri_rejected(psrv):
    status, _, _ = raw_http(HOST, psrv.nginx_port,
                            f"CONNECT {tgt(psrv.mock_ports[0], MPATH)} HTTP/1.1")
    assert status != 200


def test_traversal_dotdot_rejected(psrv):
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0], f"/cvmfs/{REPO}/data/../secret"))
    assert status == 403


def test_traversal_encoded_dotdot_rejected(psrv):
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0],
                                f"/cvmfs/{REPO}/data/%2e%2e/secret"))
    assert status == 403


# --------------------------------------------------------------------------- #
# B. brix_cvmfs_upstream_allow enforcement + bypass attempts
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("host", ["localhost", "127.0.0.2", "127.0.0.1.", "27.0.0.1"])  # net-literal-allow: host-ACL mismatch payloads under test
def test_non_allowlisted_authority_403(psrv, host):
    # allowlist is '127.0.0.1': alternate spellings / resolving names / prefix
    # and suffix mutations of the entry must all be exact-string misses.
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0], MPATH, host=host))
    assert status == 403


def test_host_header_cannot_bypass_allowlist(psrv):
    # The request-TARGET authority is what is allowlisted; an allowed Host
    # header on a disallowed target must not open the proxy.
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0], MPATH, host="localhost"),  # net-literal-allow: upstream-authority payload matched by upstream_allow
                      headers={"Host": f"127.0.0.1:{psrv.mock_ports[0]}"})  # net-literal-allow: forwarded-host payload matched by upstream_allow
    assert status == 403


def test_disallowed_host_header_does_not_break_allowed_target(psrv):
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0], MPATH),
                      headers={"Host": "evil.example.com"})
    assert status == 200


def test_allowlist_reject_is_logged(psrv):
    st, _, _ = af(psrv, tgt(psrv.mock_ports[0], MPATH, host="not-allowed.invalid"))
    assert st == 403
    log = psrv.error_log.read_text(errors="replace")
    assert "cvmfs-reject:" in log
    assert "upstream authority not allowlisted" in log


def test_malformed_target_reject_is_logged(psrv):
    st, _, _ = af(psrv, f"http://127.0.0.1:65536{MPATH}")  # net-literal-allow: malformed proxy-target payload under test
    assert st == 400
    assert "malformed proxy target" in psrv.error_log.read_text(errors="replace")


def test_proxyabuse_guard_signal_on_disallowed_authority(psrv):
    # An absolute-form target naming a non-allowlisted upstream is an open-proxy
    # / SSRF probe: besides the human-readable cvmfs-reject WARN, the gate emits
    # the unified guard-core contract line (proto=cvmfs signal=proxyabuse) that
    # the [xrootd-guard-proxyabuse] fail2ban jail bans on, with the attempted
    # authority in the path field.
    st, _, _ = af(psrv, tgt(psrv.mock_ports[0], MPATH, host="ssrf.invalid"))
    assert st == 403
    log = psrv.error_log.read_text(errors="replace")
    # the error log is shared across this module's tests (the reject corpus
    # also emits proxyabuse lines), so select this probe's line by authority
    line = next((ln for ln in log.splitlines()
                 if "signal=proxyabuse" in ln and "ssrf.invalid" in ln), None)
    def _assert_test_proxyabuse_guard_signal_on_disallowed_authority_1():
        assert line is not None, "no proxyabuse guard line emitted"
        assert "proto=cvmfs" in line and "op=read" in line

    _assert_test_proxyabuse_guard_signal_on_disallowed_authority_1()
    # the attempted authority (host[:port]) rides the path field
    assert 'path="ssrf.invalid:' in line, line


def test_proxyabuse_guard_signal_on_malformed_target(psrv):
    # A malformed target port (400 path) is likewise a manipulation attempt and
    # emits the guard signal.
    st, _, _ = af(psrv, f"http://127.0.0.1:65536{MPATH}")  # net-literal-allow: malformed proxy-target payload under test
    assert st == 400
    assert any("signal=proxyabuse" in ln and "proto=cvmfs" in ln
               for ln in psrv.error_log.read_text(errors="replace").splitlines())


def test_name_allowlist_matches_case_insensitively(psrv_name):
    # entry 'LOCALHOST' must serve a 'localhost' target (request.c strncasecmp).
    status, _, body = af(psrv_name, tgt(psrv_name.mock_ports[0], MPATH,
                                        host="localhost"))  # net-literal-allow: upstream-authority payload matched by upstream_allow
    assert status == 200 and body


def test_name_allowlist_matches_mixed_case_target(psrv_name):
    status, _, _ = af(psrv_name, tgt(psrv_name.mock_ports[0], MPATH,
                                     host="LoCaLhOsT"))  # net-literal-allow: upstream-authority payload matched by upstream_allow
    assert status == 200


def test_name_allowlist_does_not_imply_its_ip(psrv_name):
    # 'LOCALHOST' allowlisted, target names 127.0.0.1: exact-string match only —
    # no resolution-based equivalence, so the IP spelling is refused.
    status, _, _ = af(psrv_name, tgt(psrv_name.mock_ports[0], MPATH))
    assert status == 403


def test_ipv6_literal_allowlisted_is_accepted(psrv_name):
    # '[::1]' is allowlisted (bracketed form, as nginx exposes the host span).
    # The mock listens on 127.0.0.1 only, so acceptance shows as a non-reject.
    status, _, _ = af(psrv_name, tgt(psrv_name.mock_ports[0], MPATH, host="[::1]"))  # net-literal-allow: upstream-authority payload matched by upstream_allow
    assert status not in (0, 400, 403)


def test_ipv6_literal_not_allowlisted_403(psrv):
    status, _, _ = af(psrv, tgt(psrv.mock_ports[0], MPATH, host="[::1]"))  # net-literal-allow: upstream-authority payload matched by upstream_allow
    assert status == 403


def test_no_allowlist_means_proxy_off(rev):
    # Reverse-mode location (no brix_cvmfs_upstream_allow): every absolute-form
    # target — even one naming the instance's own origin — is refused.
    status, _, _ = af(rev, tgt(rev.mock_ports[0], MPATH))
    assert status == 403


def test_no_allowlist_origin_form_still_served(rev):
    obj = rev.objects()[0]
    status, _, body = request(HOST, rev.nginx_port, "GET", obj)
    assert status == 200 and body == urllib.request.urlopen(rev.mock_url + obj).read()


# --------------------------------------------------------------------------- #
# C. brix_cvmfs_upstream_max registry cap
# --------------------------------------------------------------------------- #

def test_upstream_cap_third_authority_503_and_logged(upmax):
    m = upmax.mock_ports[0]
    s1, _, _ = af(upmax, tgt(m, MPATH))
    assert s1 == 200                                     # slot 1: the live mock
    s2, _, _ = af(upmax, tgt(DEAD1, MPATH))
    assert s2 not in (200, 400, 403)                     # slot 2: dead but registered
    s3, _, _ = af(upmax, tgt(DEAD2, MPATH))              # slot 3: beyond the cap
    assert s3 == 503
    assert "upstream registry full" in upmax.error_log.read_text(errors="replace")


def test_upstream_cap_existing_slots_unaffected(upmax):
    # After the registry filled, already-registered authorities keep serving.
    status, _, body = af(upmax, tgt(upmax.mock_ports[0], MPATH))
    assert status == 200 and body


# --------------------------------------------------------------------------- #
# D. brix_cvmfs_shared_cache — cross-upstream dedup
# --------------------------------------------------------------------------- #

def test_shared_cache_dedups_across_upstreams(shared_on):
    srv, twin = shared_on
    obj = srv.objects()[1]
    origin = urllib.request.urlopen(srv.mock_url + obj).read()
    srv.reset_log()
    s1, _, b1 = af(srv, tgt(srv.mock_ports[0], obj))
    s2, _, b2 = af(srv, tgt(twin, obj))
    assert s1 == s2 == 200 and b1 == origin and b2 == origin
    assert srv.count_log(obj) == 1, "fill via upstream A was not shared"
    assert mock_count(twin, obj) == 0, "second upstream was filled despite shared_cache"


def test_shared_cache_no_false_hits_for_distinct_objects(shared_on):
    srv, twin = shared_on
    obj = srv.objects()[2]                     # never fetched via any upstream yet
    before = mock_count(twin, obj)
    s, _, body = af(srv, tgt(twin, obj))
    assert s == 200
    assert mock_count(twin, obj) - before == 1, \
        "distinct object should fill, not false-hit"
    assert body == urllib.request.urlopen(f"http://{HOST}:{twin}{obj}").read()


def test_default_cache_is_isolated_per_upstream(shared_off):
    srv, twin = shared_off
    obj = srv.objects()[1]
    srv.reset_log()
    s1, _, b1 = af(srv, tgt(srv.mock_ports[0], obj))
    s2, _, b2 = af(srv, tgt(twin, obj))
    assert s1 == s2 == 200
    assert srv.count_log(obj) == 1 and mock_count(twin, obj) == 1, \
        "shared_cache off must fill once per upstream"


def test_isolated_fills_are_byte_identical(shared_off):
    srv, twin = shared_off
    obj = srv.objects()[2]
    origin = urllib.request.urlopen(srv.mock_url + obj).read()
    _, _, b1 = af(srv, tgt(srv.mock_ports[0], obj))
    _, _, b2 = af(srv, tgt(twin, obj))
    assert b1 == origin and b2 == origin


# --------------------------------------------------------------------------- #
# E. brix_cvmfs_unified_origin
# --------------------------------------------------------------------------- #

def test_unified_serves_request_naming_dead_origin(unified):
    srv, m = unified
    obj = _ctl_get(m, "objects")[1]
    origin = urllib.request.urlopen(f"http://{HOST}:{m}{obj}").read()
    # Client names a DEAD authority; the configured multi-endpoint backend
    # answers and the death is invisible (no error the client could mark).
    status, _, body = af(srv, tgt(DEAD3, obj))
    assert status == 200 and body == origin


def test_unified_collapses_all_authorities_onto_one_backend(unified):
    srv, m = unified
    obj = _ctl_get(m, "objects")[2]
    before = mock_count(m, obj)
    s1, _, b1 = af(srv, tgt(DEAD3, obj))       # authority A (dead, unlisted)
    s2, _, b2 = af(srv, tgt(DEAD2, obj))       # authority B (dead, unlisted)
    assert s1 == s2 == 200 and b1 == b2
    assert mock_count(m, obj) - before == 1, \
        "two named authorities must collapse into one unified-backend fill"


def test_unified_still_enforces_allowlist(unified):
    srv, m = unified
    status, _, _ = af(srv, tgt(m, MPATH, host="localhost"))  # net-literal-allow: upstream-authority payload matched by upstream_allow
    assert status == 403


# ---- config contract: unified_origin requires an http(s) origin backend ----


def test_unified_contract_missing_backend_rejected_at_load(tmp_path):
    rc, out = _nginx_t(tmp_path, "")
    assert rc != 0
    assert "brix_cvmfs_unified_origin" in out and "brix_storage_backend" in out


def test_unified_contract_non_http_backend_rejected_at_load(tmp_path):
    rc, out = _nginx_t(tmp_path, f'brix_storage_backend "posix:{tmp_path}";')
    assert rc != 0 and "brix_cvmfs_unified_origin" in out


def test_unified_contract_http_multi_endpoint_accepted(tmp_path):
    rc, out = _nginx_t(
        tmp_path,
        f'brix_storage_backend "http://127.0.0.1:{DEAD1}|http://127.0.0.1:{DEAD2}";')  # net-literal-allow: dead backend endpoints under test
    assert rc == 0, out

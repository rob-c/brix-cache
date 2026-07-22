# tests/test_cvmfs_conformance_srv_proxy.py — Phase-84 srv_proxy corpus (~60).
#
# Forward-proxy (CVMFS_HTTP_PROXY) mode conformance: absolute-form request-line
# grammar (ports / schemes / userinfo / IPv6 / missing path / CONNECT),
# brix_cvmfs_upstream_allow enforcement + bypass attempts,
# brix_cvmfs_upstream_max cap, brix_cvmfs_shared_cache dedup across upstreams,
# and brix_cvmfs_unified_origin (dead named origin hidden + config contract).
#
# Port block: srv_proxy 13180 (mocks 13180-13189, nginx 13190-13199; the top of
# the nginx sub-block, 13197-13199, is reserved here as guaranteed-dead ports —
# only 7 nginx instances are ever allocated).
#
# Behavior contract sources:
#   src/protocols/cvmfs/request.c   — scheme check, port 1..65535, host allowlist
#   src/protocols/cvmfs/gate.c      — classify-then-bind order, reject lines
#   src/protocols/cvmfs/upstreams.c — per-upstream registry, shared_cache subtree
#   src/protocols/cvmfs/cvmfs_module_merge.c — unified_origin config contract
import os
import subprocess
import sys
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import (NGINX_BIN, PortBlock, _ctl_get, _spawn_mock,
                                absolute_form_request, raw_http, request,
                                srv_instance)
from settings import BIND_HOST, HOST

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

REPO = "test.cern.ch"
MPATH = f"/cvmfs/{REPO}/.cvmfspublished"

BLOCK = PortBlock("srv_proxy")
# Guaranteed-dead in-block ports (never listened on; nginx allocation stops at 7).
DEAD1, DEAD2, DEAD3 = BLOCK.base + 17, BLOCK.base + 18, BLOCK.base + 19

# Keep dead-upstream connect failures fast across the whole module (client_hold
# bounds how long a failed fill parks the client before the error is emitted).
FAST = dict(connect_timeout=1, attempt_timeout=2, client_hold=2)


def af(srv, uri, method="GET", headers=None):
    """Absolute-form request through srv's nginx; returns (status, headers, body)."""
    return absolute_form_request(HOST, srv.nginx_port, uri,
                                 method=method, headers=headers)


def tgt(port, path, host="127.0.0.1"):  # net-literal-allow: upstream-authority payload matched by upstream_allow
    return f"http://{host}:{port}{path}"


def mock_count(port, needle):
    return sum(1 for e in _ctl_get(port, "log") if needle in e["path"])


# --------------------------------------------------------------------------- #
# Module fixtures — one instance per proxy configuration under test.
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def psrv():
    """Proxy mode, allowlist '127.0.0.1' (the srv_instance proxy default)."""
    with srv_instance(BLOCK, proxy_mode=True, objects=8, seed=101, **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def psrv_name():
    """Proxy mode, name-based allowlist (uppercase entry + IPv6 literal)."""
    with srv_instance(BLOCK, proxy_mode=True, objects=4, seed=102,
                      upstream_allow="LOCALHOST [::1]", **FAST) as srv:  # net-literal-allow: host-ACL match string under test
        yield srv


@pytest.fixture(scope="module")
def rev():
    """Reverse mode: no allowlist set at all — proxy mode is OFF."""
    with srv_instance(BLOCK, objects=4, seed=103) as srv:
        yield srv


@pytest.fixture(scope="module")
def upmax():
    """Proxy mode with a 2-slot upstream registry cap."""
    with srv_instance(BLOCK, proxy_mode=True, objects=4, seed=104,
                      upstream_max=2, **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def shared_on():
    """shared_cache on + a twin mock (same seed => byte-identical object set)."""
    with srv_instance(BLOCK, proxy_mode=True, objects=6, seed=71,
                      shared_cache="on", **FAST) as srv:
        twin = BLOCK.mock()
        _spawn_mock(srv.run, twin, objects=6, seed=71)
        yield srv, twin


@pytest.fixture(scope="module")
def shared_off():
    """Default per-upstream cache isolation + a twin mock."""
    with srv_instance(BLOCK, proxy_mode=True, objects=6, seed=72, **FAST) as srv:
        twin = BLOCK.mock()
        _spawn_mock(srv.run, twin, objects=6, seed=72)
        yield srv, twin


@pytest.fixture(scope="module")
def unified():
    """unified_origin on: one ranked multi-endpoint backend behind the proxy."""
    m = BLOCK.mock()
    backend = f'brix_storage_backend "http://{HOST}:{m}|http://127.0.0.1:{DEAD3}";'  # net-literal-allow: dead ranked backend endpoint under test
    with srv_instance(BLOCK, proxy_mode=True, n_mocks=0, unified_origin="on",
                      extra_directives=backend, **FAST) as srv:
        _spawn_mock(srv.run, m, objects=6, seed=105)
        yield srv, m


# --------------------------------------------------------------------------- #
# A. Absolute-form request-line corpus
# --------------------------------------------------------------------------- #

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
    assert line is not None, "no proxyabuse guard line emitted"
    assert "proto=cvmfs" in line and "op=read" in line
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

def _nginx_t(tmp_path, backend_line):
    prefix = tmp_path / "p"
    (prefix / "logs").mkdir(parents=True, exist_ok=True)
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    conf = tmp_path / "t.conf"
    conf.write_text(f"""daemon off; error_log {prefix}/logs/e.log; pid {prefix}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 32; }}
http {{ server {{ listen {BIND_HOST}:{DEAD3}; location / {{
    brix_cache_store posix:{cache};
    brix_cvmfs on;
    brix_cvmfs_upstream_allow {HOST};
    brix_cvmfs_unified_origin on;
    {backend_line}
}} }} }}
""")
    r = subprocess.run([NGINX_BIN, "-t", "-c", str(conf), "-p", str(prefix)],
                       capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stderr or "") + (r.stdout or "")


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

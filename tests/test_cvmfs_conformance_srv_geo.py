"""Phase-84 srv_geo — CVMFS GeoAPI conformance corpus (port block 13200).

Official contract: ``GET /cvmfs/<repo>/api/v1.0/geo/<caller-id>/<srv1,srv2,...>``
returns a comma-separated 1-based index permutation ordering the given servers
nearest-first.

Two server modes under test (gate.c:224):

* passthrough (``brix_cvmfs_geo_answer off``, the default) — geo.c relays the
  origin's reply verbatim, never cached (every request hits the origin).
* local answer (``brix_cvmfs_geo_answer rtt``) — geo_answer.c parses the server
  list, TCP-connect-probes each entry from the proxy's vantage and replies with
  a complete permutation: reachable (by RTT) -> unreachable -> unprobed, each
  bucket preserving the client's original order (geo_answer.c:334-373). Probes
  are guarded to ports {80,443,8000} (geo_answer.c:91-95), capped at
  brix_cvmfs_geo_max_servers, EWMA-cached per host:port for geo_cache_ttl, and
  any parse failure falls back to passthrough.

Probe observability: local ``ConnCounter`` listeners on fresh 127.84.x.y
loopback IPs (port 8000 — the only unprivileged allowed probe port) count TCP
connects, making RTT probes and the probe cache directly measurable. Fresh IPs
per test keep the per-worker EWMA cache from leaking between tests.

Infra gap: mock_stratum1.py answers the geo path BEFORE its /ctl/fault hook, so
origin-side geo faults (500 / scripted bodies) are injected via a local
MiniOrigin in this file instead.
"""

import itertools
import os
import re
import socket
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance

REPO = "test.cern.ch"
BLOCK = PortBlock("srv_geo")
# INFRA COLLISION: the standing test fleet's webdav-dellock nginx (dedicated
# fleet, /tmp/xrd-test/dedicated) listens on 13210 — the first nginx slot of
# this file's assigned block. Burn that slot so our instances start at 13211.
BLOCK.nginx()
MINI_ORIGIN_PORT = 13208        # inside our mock sub-block, never handed out
DEAD_ORIGIN_PORT = 13209        # nothing ever listens here

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

_ip_seq = itertools.count(1)


def fresh_ip() -> str:
    """A never-before-used loopback IP: unique EWMA-cache key + refused-fast."""
    n = next(_ip_seq)
    return f"127.84.{n // 250}.{n % 250 + 1}"


def geo_path(servers: str, caller: str = "x", repo: str = REPO) -> str:
    return f"/cvmfs/{repo}/api/v1.0/geo/{caller}/{servers}"


def geo_get(srv, servers, caller="x", repo=REPO, method="GET"):
    return request("127.0.0.1", srv.nginx_port, method, geo_path(servers, caller, repo))


def perm(body: bytes) -> list:
    text = body.decode()
    assert re.fullmatch(r"\d+(,\d+)*\n?", text), f"malformed geo reply: {text!r}"
    return [int(x) for x in text.strip().split(",")]


def assert_perm(body: bytes, n: int) -> list:
    p = perm(body)
    assert sorted(p) == list(range(1, n + 1)), f"not a permutation of 1..{n}: {p}"
    return p


def cache_files(srv) -> set:
    return {os.path.join(d, f) for d, _, fs in os.walk(srv.cache) for f in fs}


class ConnCounter:
    """TCP listener counting distinct connects — makes RTT probes observable."""

    def __init__(self, ip: str, port: int = 8000):
        self.ip, self.port, self.count = ip, port, 0
        self._lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((ip, port))
        self._srv.listen(32)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            with self._lock:
                self.count += 1
            c.close()

    @property
    def token(self) -> str:
        return f"{self.ip}:{self.port}"

    def close(self):
        self._srv.close()


class MiniOrigin:
    """Scriptable HTTP origin: per-substring (status, body) overrides + hit log."""

    def __init__(self, port: int):
        self.hits, self.script = [], {}
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits.append(self.path)
                status, body = 200, b"1,2,3\n"
                for needle, (st, bd) in outer.script.items():
                    if needle in self.path:
                        status, body = st, bd
                        break
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def listener():
    made = []

    def _make(ip=None, port=8000):
        l = ConnCounter(ip or fresh_ip(), port)
        made.append(l)
        return l

    yield _make
    for l in made:
        l.close()


# --------------------------------------------------------------------------- #
# module fixtures — one nginx+mock pair per configuration (block budget: 10/10)
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def pass_srv():
    with srv_instance(BLOCK, objects=2, seed=41) as s:
        yield s


@pytest.fixture(scope="module")
def rtt_srv():
    with srv_instance(BLOCK, objects=2, seed=42, geo_answer="rtt") as s:
        yield s


@pytest.fixture(scope="module")
def cap_srv():
    with srv_instance(BLOCK, objects=2, seed=43, geo_answer="rtt",
                      geo_max_servers=4) as s:
        yield s


@pytest.fixture(scope="module")
def ttl_srv():
    with srv_instance(BLOCK, objects=2, seed=44, geo_answer="rtt",
                      geo_cache_ttl=1) as s:
        yield s


@pytest.fixture(scope="module")
def dead_srv():
    """Passthrough whose configured origin is a port nothing listens on."""
    with srv_instance(BLOCK, objects=2, seed=45,
                      origins=f"http://127.0.0.1:{DEAD_ORIGIN_PORT}") as s:
        yield s


@pytest.fixture(scope="module")
def fault_srv():
    """Passthrough against a scriptable MiniOrigin (geo fault injection)."""
    origin = MiniOrigin(MINI_ORIGIN_PORT)
    try:
        with srv_instance(BLOCK, objects=2, seed=46,
                          origins=f"http://127.0.0.1:{MINI_ORIGIN_PORT}") as s:
            s.origin = origin
            yield s
    finally:
        origin.close()


# --------------------------------------------------------------------------- #
# passthrough mode: verbatim relay, never cached
# --------------------------------------------------------------------------- #

def test_passthrough_relays_identity_order(pass_srv):
    st, _, body = geo_get(pass_srv, "a.example.org,b.example.org,c.example.org")
    assert st == 200 and body == b"1,2,3\n"     # mock answers 1..N verbatim


def test_passthrough_single_server(pass_srv):
    st, _, body = geo_get(pass_srv, "solo.example.org")
    assert st == 200 and body == b"1\n"


def test_passthrough_large_list_verbatim(pass_srv):
    n = 20
    st, _, body = geo_get(pass_srv, ",".join(f"s{i}.org" for i in range(n)))
    assert st == 200 and perm(body) == list(range(1, n + 1))


def test_passthrough_never_cached(pass_srv):
    pass_srv.reset_log()
    for _ in range(3):
        st, _, _ = geo_get(pass_srv, "a.org,b.org")
        assert st == 200
    assert pass_srv.count_log("geo") == 3, "geo replies must never be cached"


def test_passthrough_distinct_callers_each_hit_origin(pass_srv):
    pass_srv.reset_log()
    geo_get(pass_srv, "a.org,b.org", caller="one")
    geo_get(pass_srv, "a.org,b.org", caller="two")
    assert pass_srv.count_log("geo") == 2


def test_passthrough_query_string_forwarded(pass_srv):
    pass_srv.reset_log()
    st, _, _ = request("127.0.0.1", pass_srv.nginx_port, "GET",
                       geo_path("a.org,b.org") + "?probe=marker7")
    assert st == 200
    assert pass_srv.count_log("probe=marker7") == 1


def test_passthrough_verbatim_scripted_body(fault_srv):
    fault_srv.origin.script["geo"] = (200, b"3,1,2\n")
    st, _, body = geo_get(fault_srv, "a.org,b.org,c.org")
    assert st == 200 and body == b"3,1,2\n", "reply must be relayed, not recomputed"
    fault_srv.origin.script.clear()


def test_passthrough_origin_500_relayed(fault_srv):
    fault_srv.origin.script["geo"] = (500, b"origin exploded")
    st, _, _ = geo_get(fault_srv, "a.org,b.org")
    assert st == 500
    fault_srv.origin.script.clear()


def test_passthrough_origin_404_relayed(fault_srv):
    fault_srv.origin.script["geo"] = (404, b"no geo db")
    st, _, _ = geo_get(fault_srv, "a.org,b.org")
    assert st == 404
    fault_srv.origin.script.clear()


def test_passthrough_origin_404_unknown_repo(pass_srv):
    st, _, _ = geo_get(pass_srv, "a.org,b.org", repo="unknown.cern.ch")
    assert st == 404                         # mock 404s a repo it does not host


def test_passthrough_origin_down_errors_not_hangs(dead_srv):
    t0 = time.monotonic()
    st, _, _ = geo_get(dead_srv, "a.org,b.org")
    assert st == 502, f"dead origin must yield an error status, got {st}"
    assert time.monotonic() - t0 < 10


def test_passthrough_head(pass_srv):
    st, _, body = geo_get(pass_srv, "a.org,b.org", method="HEAD")
    assert st == 200 and body == b""


def test_passthrough_never_materializes_cache_file(pass_srv):
    before = cache_files(pass_srv)
    for _ in range(2):
        geo_get(pass_srv, "a.org,b.org,c.org")
    assert cache_files(pass_srv) == before, "geo replies must not enter the CAS cache"


# --------------------------------------------------------------------------- #
# URL grammar + methods on the geo path
# --------------------------------------------------------------------------- #

def test_bare_geo_prefix_rejected_403(pass_srv):
    # rel "api/v1.0/geo/" with nothing after is not GEO (classify.c:84 rel_len > 13)
    st, _, _ = request("127.0.0.1", pass_srv.nginx_port, "GET",
                       f"/cvmfs/{REPO}/api/v1.0/geo/")
    assert st == 403


@pytest.mark.parametrize("method",
                         ["POST", "PUT", "DELETE", "OPTIONS", "PROPFIND", "TRACE"])
def test_non_get_method_405(pass_srv, method):
    st, _, _ = geo_get(pass_srv, "a.org,b.org", method=method)
    assert st == 405


# --------------------------------------------------------------------------- #
# local answer mode (geo_answer rtt): permutation contract
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n", [1, 2, 3, 5, 8])
def test_rtt_permutation_of_n(rtt_srv, n):
    # all-refused numeric hosts (default port 80, allowed): unreachable bucket
    # preserves the client's order, so the reply is exactly the identity.
    rtt_srv.reset_log()
    st, _, body = geo_get(rtt_srv, ",".join(fresh_ip() for _ in range(n)))
    assert st == 200
    assert assert_perm(body, n) == list(range(1, n + 1))
    assert rtt_srv.count_log("geo") == 0, "rtt mode must answer locally"


def test_rtt_reply_shape(rtt_srv):
    st, hdrs, body = geo_get(rtt_srv, f"{fresh_ip()},{fresh_ip()}")
    assert st == 200
    assert re.fullmatch(rb"\d+(,\d+)*\n", body), f"bad reply shape: {body!r}"
    assert hdrs.get("content-type", "").startswith("text/plain")


def test_rtt_no_origin_contact(rtt_srv):
    rtt_srv.reset_log()
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()}:8000,{fresh_ip()}:8000")
    assert st == 200 and len(perm(body)) == 2
    assert rtt_srv.get_log() == []


def test_rtt_duplicate_server_names(rtt_srv):
    d = fresh_ip()
    st, _, body = geo_get(rtt_srv, f"{d},{d},{d}")
    assert st == 200
    assert_perm(body, 3)                      # each duplicate keeps its own slot


def test_rtt_reachable_ranked_before_unreachable(rtt_srv, listener):
    l = listener()
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()}:8000,{l.token}")
    assert st == 200
    assert perm(body) == [2, 1], "reachable server must rank first"
    assert l.count >= 1, "reachable server was never probed"


def test_rtt_unresolvable_ranked_after_reachable(rtt_srv, listener):
    l = listener()
    st, _, body = geo_get(rtt_srv, f"{l.token},geo-nx-a.invalid:8000")
    assert st == 200
    assert perm(body) == [1, 2], "unresolvable host must rank after reachable"


def test_rtt_unresolvable_only_keeps_order(rtt_srv):
    st, _, body = geo_get(rtt_srv, "geo-nx-b.invalid,geo-nx-c.invalid")
    assert st == 200
    assert perm(body) == [1, 2]               # unreachable bucket is order-stable


def test_rtt_disallowed_port_unprobed_ranked_last(rtt_srv, listener):
    l = listener()
    # :9999 is outside the {80,443,8000} probe guard -> unprobed bucket (last)
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()}:9999,{l.token}")
    assert st == 200
    assert perm(body) == [2, 1]


def test_rtt_disallowed_port_never_connected(rtt_srv, listener):
    l = listener(port=9999)                   # listening, but guard must skip it
    st, _, body = geo_get(rtt_srv, l.token)
    assert st == 200 and perm(body) == [1]
    assert l.count == 0, "port-scanner guard breached: probed a non-CVMFS port"


def test_rtt_empty_token_mid_list(rtt_srv):
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()},,{fresh_ip()}")
    assert st == 200
    assert_perm(body, 3)                      # empty token keeps its slot


def test_rtt_trailing_comma(rtt_srv):
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()},{fresh_ip()},")
    assert st == 200
    assert_perm(body, 3)


def test_rtt_leading_comma(rtt_srv):
    st, _, body = geo_get(rtt_srv, f",{fresh_ip()},{fresh_ip()}")
    assert st == 200
    assert_perm(body, 3)


def test_rtt_all_empty_tokens(rtt_srv):
    st, _, body = geo_get(rtt_srv, ",,,")
    assert st == 200
    assert assert_perm(body, 4) == [1, 2, 3, 4]


def test_rtt_garbage_token_kept_ranked_last(rtt_srv, listener):
    l = listener()
    st, _, body = geo_get(rtt_srv, f"%21%21%21,{l.token}")   # '!!!' after decode
    assert st == 200
    assert perm(body) == [2, 1]


def test_rtt_ipv6_literal_token_unprobed(rtt_srv, listener):
    l = listener()
    st, _, body = geo_get(rtt_srv, f"%5B%3A%3A1%5D:8000,{l.token}")  # "[::1]:8000"
    assert st == 200
    assert perm(body) == [2, 1]               # '[' is not a host char -> unprobed


def test_rtt_query_string_ignored_by_parser(rtt_srv):
    rtt_srv.reset_log()
    st, _, body = request("127.0.0.1", rtt_srv.nginx_port, "GET",
                          geo_path(f"{fresh_ip()},{fresh_ip()}") + "?ip=1.2.3.4")
    assert st == 200 and len(assert_perm(body, 2)) == 2
    assert rtt_srv.count_log("geo") == 0


@pytest.mark.parametrize("caller", ["x", str(uuid.uuid4()), "proxy-3.example.org"])
def test_rtt_caller_id_variants(rtt_srv, caller):
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()},{fresh_ip()}", caller=caller)
    assert st == 200
    assert_perm(body, 2)


def test_rtt_missing_caller_segment_still_answers(rtt_srv):
    # /geo/<list> with no caller segment: the parser takes the last '/'-segment
    # as the list, so the lone segment is treated as the server list. Lenient
    # vs the official <caller>/<list> shape, but a complete answer, not a 5xx.
    rtt_srv.reset_log()
    st, _, _ = request("127.0.0.1", rtt_srv.nginx_port, "GET",
                       f"/cvmfs/{REPO}/api/v1.0/geo/{fresh_ip()},{fresh_ip()}")
    assert st == 200
    assert rtt_srv.count_log("geo") == 0


def test_rtt_head_request(rtt_srv):
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()},{fresh_ip()}", method="HEAD")
    assert st == 200 and body == b""


def test_rtt_never_materializes_cache_file(rtt_srv):
    before = cache_files(rtt_srv)
    for _ in range(2):
        geo_get(rtt_srv, f"{fresh_ip()},{fresh_ip()},{fresh_ip()}")
    assert cache_files(rtt_srv) == before


# --------------------------------------------------------------------------- #
# geo_max_servers cap (cap_srv: max 4)
# --------------------------------------------------------------------------- #

def test_cap_over_cap_list_still_full_permutation(cap_srv):
    st, _, body = geo_get(cap_srv, ",".join(fresh_ip() for _ in range(6)))
    assert st == 200
    # 0..3 probed (refused, order-stable) then 4..5 unprobed (order-stable)
    assert assert_perm(body, 6) == [1, 2, 3, 4, 5, 6]


def test_cap_entry_beyond_cap_not_probed(cap_srv, listener):
    l = listener()
    servers = ",".join(fresh_ip() for _ in range(5)) + f",{l.token}"
    st, _, body = geo_get(cap_srv, servers)
    assert st == 200 and len(perm(body)) == 6
    assert l.count == 0, "entry beyond geo_max_servers must not be probed"


def test_cap_entry_within_cap_probed(cap_srv, listener):
    l = listener()
    st, _, body = geo_get(cap_srv, f"{fresh_ip()},{l.token},{fresh_ip()}")
    assert st == 200
    assert perm(body)[0] == 2 and l.count >= 1


# --------------------------------------------------------------------------- #
# hard list-size boundary (64-entry parse cap -> fallback to passthrough)
# --------------------------------------------------------------------------- #

def test_rtt_64_entries_answered_locally(rtt_srv):
    rtt_srv.reset_log()
    st, _, body = geo_get(rtt_srv, ",".join(fresh_ip() for _ in range(64)))
    assert st == 200
    assert_perm(body, 64)
    assert rtt_srv.count_log("geo") == 0


def test_rtt_65_entries_falls_back_to_passthrough(rtt_srv):
    rtt_srv.reset_log()
    st, _, body = geo_get(rtt_srv, ",".join(f"s{i}.org" for i in range(65)))
    assert st == 200
    assert perm(body) == list(range(1, 66))   # the MOCK's answer, relayed
    assert rtt_srv.count_log("geo") == 1, "over-cap list must relay to origin"


def test_rtt_100_entries_no_5xx(rtt_srv):
    st, _, _ = geo_get(rtt_srv, ",".join(f"s{i}.org" for i in range(100)))
    assert st == 200


# --------------------------------------------------------------------------- #
# malformed-path fallback: passthrough or clean error, never a crash
# --------------------------------------------------------------------------- #

def test_rtt_empty_list_falls_back_to_passthrough(rtt_srv):
    rtt_srv.reset_log()
    st, _, _ = request("127.0.0.1", rtt_srv.nginx_port, "GET",
                       f"/cvmfs/{REPO}/api/v1.0/geo/x/")
    assert st == 200                          # relayed; the mock answers "1\n"
    assert rtt_srv.count_log("geo") == 1, "empty list must fall back to origin"


def test_rtt_pct_encoded_dotdot_clean_reject(rtt_srv):
    # %2e%2e normalizes the caller segment away -> no longer a geo shape
    st, _, _ = request("127.0.0.1", rtt_srv.nginx_port, "GET",
                       f"/cvmfs/{REPO}/api/v1.0/geo/x/%2e%2e")
    assert 400 <= st < 500, f"traversal junk must 4xx, got {st}"


def test_rtt_encoded_space_token_no_5xx(rtt_srv):
    st, _, body = geo_get(rtt_srv, f"%20%20,{fresh_ip()}")
    assert st == 200
    assert_perm(body, 2)                      # space token -> unprobed slot


def test_rtt_server_alive_after_junk_corpus(rtt_srv):
    for path in (f"/cvmfs/{REPO}/api/v1.0/geo/",
                 f"/cvmfs/{REPO}/api/v1.0/geo/x/%2e%2e",
                 geo_path("%7f%7f"),                          # DEL bytes token
                 geo_path(",,,,,,,,")):
        st, _, _ = request("127.0.0.1", rtt_srv.nginx_port, "GET", path)
        assert st != 500, f"{path} produced a 500"
    st, _, body = geo_get(rtt_srv, f"{fresh_ip()},{fresh_ip()}")
    assert st == 200 and len(assert_perm(body, 2)) == 2
    assert rtt_srv.nginx_pid is not None


# --------------------------------------------------------------------------- #
# RTT probe cache (per host:port EWMA, geo_cache_ttl)
# --------------------------------------------------------------------------- #

def test_rtt_cache_no_reprobe_within_ttl(rtt_srv, listener):
    l = listener()
    for _ in range(3):
        st, _, body = geo_get(rtt_srv, l.token)
        assert st == 200 and perm(body) == [1]
    assert l.count == 1, "repeat query within geo_cache_ttl must not re-probe"


def test_rtt_cache_is_per_host(rtt_srv, listener):
    a, b = listener(), listener()
    geo_get(rtt_srv, a.token)
    geo_get(rtt_srv, b.token)
    assert (a.count, b.count) == (1, 1)
    st, _, body = geo_get(rtt_srv, f"{a.token},{b.token}")   # both cached now
    assert st == 200 and len(perm(body)) == 2
    assert (a.count, b.count) == (1, 1), "cached hosts were re-probed"


def test_ttl_expiry_reprobes(ttl_srv, listener):
    l = listener()
    geo_get(ttl_srv, l.token)
    assert l.count == 1
    time.sleep(1.8)                           # geo_cache_ttl 1s -> stale
    geo_get(ttl_srv, l.token)
    assert l.count == 2, "expired cache entry must be re-probed"


def test_ttl_back_to_back_single_probe(ttl_srv, listener):
    l = listener()
    geo_get(ttl_srv, l.token)
    geo_get(ttl_srv, l.token)
    assert l.count == 1

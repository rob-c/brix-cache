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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"
BLOCK = PortBlock("srv_geo")
# INFRA COLLISION: the standing test fleet's webdav-dellock nginx (dedicated
# fleet, /tmp/xrd-test/dedicated) listens on 13210 — the first nginx slot of
# this file's assigned block. Burn that slot so our instances start at 13211.
BLOCK.nginx()
MINI_ORIGIN_PORT = BLOCK.base + 8   # inside our mock sub-block, never handed out
DEAD_ORIGIN_PORT = BLOCK.base + 9   # nothing ever listens here

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

_ip_seq = itertools.count(1)
# Give each pytest/xdist process its own /24 inside 127/8.  A module-level
# counter alone restarts at 1 in every worker, making two workers bind the same
# listener address (127.84.0.2:8000) when these cases join the parallel suite.
_ip_net = os.getpid() % (64 * 256)


def fresh_ip() -> str:
    """A never-before-used loopback IP: unique EWMA-cache key + refused-fast."""
    n = next(_ip_seq)
    return f"127.{64 + _ip_net // 256}.{_ip_net % 256}.{n % 250 + 1}"


def unresolvable_hosts(n: int) -> str:
    """Return deterministic, distinct hosts guaranteed not to resolve."""
    return ",".join(f"geo-unreachable-{i}.invalid" for i in range(n))


def geo_path(servers: str, caller: str = "x", repo: str = REPO) -> str:
    return f"/cvmfs/{repo}/api/v1.0/geo/{caller}/{servers}"


def geo_get(srv, servers, caller="x", repo=REPO, method="GET"):
    return request(HOST, srv.nginx_port, method, geo_path(servers, caller, repo))


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

        self.httpd = ThreadingHTTPServer((BIND_HOST, port), H)
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
                      origins=f"http://{HOST}:{DEAD_ORIGIN_PORT}") as s:
        yield s


@pytest.fixture(scope="module")
def fault_srv():
    """Passthrough against a scriptable MiniOrigin (geo fault injection)."""
    origin = MiniOrigin(MINI_ORIGIN_PORT)
    try:
        with srv_instance(BLOCK, objects=2, seed=46,
                          origins=f"http://{HOST}:{MINI_ORIGIN_PORT}") as s:
            s.origin = origin
            yield s
    finally:
        origin.close()


# --------------------------------------------------------------------------- #
# passthrough mode: verbatim relay, never cached
# --------------------------------------------------------------------------- #

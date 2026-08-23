"""Phase-84 srv_resilience conformance corpus (design row: srv_resilience, ~70).

Themes
------
* Stall detection: origin stalls mid-body -> the fill aborts per
  ``origin_stall_timeout`` and retries; a slowdrip above the ``stall_bytes``
  floor is NOT killed (no false positive); ``attempt_timeout`` off vs set.
* Failover: two-endpoint backend — primary stalls/resets/breaks -> served
  from the secondary (clean 200, byte-correct); ``fill_retry_policy failover``
  vs ``force-primary`` (force-primary never opens the alternate); a primary
  404 is the origin's ANSWER (definitive, no failover mask) vs primary DOWN
  (transport failure, failover).
* Coalescing: N concurrent GETs of a cold object -> exactly one origin data
  fetch, all N byte-identical; a mid-fill origin fault still gives every
  waiter a clean outcome (never a truncated 200, never a RST to the client).
* client_hold / fill_max_life: hold expiry -> 504 keep-alive + same-socket
  retry; detached fills complete after client abort; a wedged detached fill
  expires by ``fill_max_life`` and does not wedge the object forever.
* reuse_conn on/off: /ctl/connections over M sequential fills (keepalive
  mock) — pooled means few TCP connections, off means one per request.
* Every fault case also proves the cache never retains a corrupt/partial
  object: a follow-up GET after the origin heals returns full correct bytes.

Sources of truth: src/fs/cache/fill_retry.c (classification: ENOENT/EACCES
definitive, EBADMSG one-retry-per-endpoint then definitive, everything else
retryable within the waiters-aware client_hold/max_life window),
src/fs/backend/http/sd_http_select.c (one alternate on TRANSPORT failure only;
force-primary never fails over), src/protocols/cvmfs/handler.c (EIO -> 502,
hold expiry -> 504 + Retry-After, keep-alive), and the 2026-07-03
absorb-upstream-flakiness design doc.
"""

import hashlib
import http.client
import json
import os
import random
import re
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
def _expression_1(need, raw):
    return (
        need is None or len(raw) < need
    )

def _expression_2(need, raw):
    return (
        need is None and b"\r\n\r\n" in raw
    )

def _expression_3(first):
    return (
        int(first[1]) if len(first) > 1 else 0
    )


def _phase_raw_get_clean_1(m, head):
    if m:
        need = len(head) + 4 + int(m.group(1))


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, _spawn_mock, srv_instance
from settings import HOST

REPO = "test.cern.ch"

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

# Aggressive-but-fast knobs shared by every instance in this file. The floor
# is 100 B/s (not the 1 B/s default): curl smooths speed over a ~6 s window,
# so the mock's 64-byte pre-stall burst masks a 1 B/s floor for ~6 s — with a
# 100 B/s floor a mid-body stall is declared in ~stall_timeout+1 (~3 s),
# well inside the 8 s client hold. DRIP keeps the 1 B/s default floor for the
# slowdrip (~5 B/s) no-false-positive and coalescing themes.
FAST = dict(connect_timeout=1, stall_timeout=2, stall_bytes=100,
            client_hold=8, fill_max_life=10, manifest_ttl=60)
DRIP = {**FAST, "stall_bytes": 1}

# Fault modes whose first attempt must be absorbed by retry (single origin).
FAULTS = ["stall", "reset", "http500", "truncate", "wrong_length", "corrupt"]
# Transport-level faults that must trigger the one-alternate failover.
FO_FAULTS = ["stall", "reset", "truncate", "wrong_length"]


# --------------------------------------------------------------------------- #
# Webroot: a synthetic CAS tree (path = sha1(bytes), the verify-on-fill
# contract) shared read-only by every mock. `wp` is a byte-identical copy used
# as the failover PRIMARY so the 404-distinction test can delete from one side.
# --------------------------------------------------------------------------- #
def _write_obj(root, body):
    h = hashlib.sha1(body).hexdigest()
    d = root / "cvmfs" / REPO / "data" / h[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / h[2:]).write_bytes(body)
    return f"/cvmfs/{REPO}/data/{h[:2]}/{h[2:]}", body


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    root = tmp_path_factory.mktemp("res_web")
    w0 = root / "w0"
    rng = random.Random(8420)
    pools = {"std": [], "large": [], 4: [], 8: [], 12: [], 16: [], 32: []}
    for _ in range(110):
        pools["std"].append(_write_obj(w0, rng.randbytes(2048)))
    for _ in range(3):
        pools["large"].append(_write_obj(w0, rng.randbytes(131072)))
    for size, count in ((4, 6), (8, 8), (12, 10), (16, 14), (32, 4)):
        for _ in range(count):
            pools[size].append(_write_obj(w0, rng.randbytes(size)))
    meta = w0 / "cvmfs" / REPO
    (meta / ".cvmfspublished").write_bytes(
        b"Cdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\nB2048\nS1\nN" + REPO.encode()
        + b"\nT1\n--\nsig\n")
    (meta / ".cvmfswhitelist").write_bytes(b"synthetic-whitelist\n")
    (meta / ".cvmfsreflog").write_bytes(b"synthetic-reflog\n")
    wp = root / "wp"
    shutil.copytree(w0, wp)
    return {"w0": w0, "wp": wp, "pools": pools}


class _Alloc:
    """Hands out never-before-fetched (cold) objects; shared module-wide so no
    two tests ever collide on an object across the servers sharing `w0`."""

    def __init__(self, pools):
        self._it = {k: iter(v) for k, v in pools.items()}

    def std(self):
        return next(self._it["std"])

    def large(self):
        return next(self._it["large"])

    def tiny(self, size):
        return next(self._it[size])


@pytest.fixture(scope="module")
def alloc(web):
    return _Alloc(web["pools"])


@pytest.fixture(scope="module")
def block():
    return PortBlock("srv_resilience")


# --------------------------------------------------------------------------- #
# Server fixtures — all module-scoped (one 20-port block: <=10 mocks/nginx).
# --------------------------------------------------------------------------- #
@contextmanager
def _two_origin(block, primary_web, secondary_web, **knobs):
    """Two-endpoint backend. mock 0 = primary, mock 1 = secondary; a None
    webroot leaves that endpoint DEAD (reserved port, nothing listening).
    origin_select is pinned to `static` (configured order): the default `rtt`
    ranks whichever localhost mock's connect probe lands faster as the
    policy-preferred endpoint — a coin flip between two loopback mocks — and
    both failover and force-primary pin to the *preferred* endpoint, so
    "mock 0 is the primary" only holds under static selection."""
    knobs.setdefault("origin_select", "static")
    pa, pb = block.mock(), block.mock()
    origins = f"http://{HOST}:{pa}|http://{HOST}:{pb}"
    with srv_instance(block, n_mocks=0, origins=origins, **knobs) as srv:
        srv.mock_ports = [pa, pb]
        if primary_web is not None:
            _spawn_mock(srv.run, pa, webroot=primary_web)
        if secondary_web is not None:
            _spawn_mock(srv.run, pb, webroot=secondary_web)
        yield srv


@pytest.fixture(scope="module")
def srv1(web, block):
    """Single origin, aggressive stall knobs, default (failover) policy."""
    with srv_instance(block, webroot=web["w0"], **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def srv_drip(web, block, srv1):
    """stall_bytes floor at the 1 B/s default: a ~5 B/s slowdrip must survive.
    Shares srv1's mock (the module block has 10 mock slots and objects are
    allocated uniquely module-wide, so the shared origin log stays exact)."""
    origins = f"http://{HOST}:{srv1.mock_ports[0]}"
    with srv_instance(block, n_mocks=0, origins=origins, **DRIP) as srv:
        srv.mock_ports = [srv1.mock_ports[0]]
        yield srv


@pytest.fixture(scope="module")
def srv_fo(web, block):
    """Two live origins (identical trees), fill_retry_policy failover."""
    with _two_origin(block, web["wp"], web["w0"], **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def srv_fp(web, block):
    """Two live origins, fill_retry_policy force-primary."""
    with _two_origin(block, web["w0"], web["w0"],
                     fill_retry_policy="force-primary", **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def srv_dead(web, block):
    """Dead primary (reserved, unbound port) + live secondary."""
    with _two_origin(block, None, web["w0"], **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def srv_reuse_on(web, block):
    with srv_instance(block, webroot=web["w0"], keepalive=True,
                      reuse_conn="on", **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def srv_reuse_off(web, block):
    with srv_instance(block, webroot=web["w0"], keepalive=True,
                      reuse_conn="off", **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def srv_attempt(web, block):
    """attempt_timeout SET (floor back at 1 B/s so the whole-attempt ceiling —
    not the stall floor — is what kills a making-progress-but-slow attempt)."""
    knobs = {**DRIP, "attempt_timeout": 2}
    with srv_instance(block, webroot=web["w0"], **knobs) as srv:
        yield srv


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def _get(port, path, timeout=25):
    """(status, body); HTTP errors come back as (code, body), never raise."""
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}{path}",
                                    timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _connections(mock_port):
    """Distinct TCP connections the mock accepted since reset-log, excluding
    the control connection making this very query."""
    with urllib.request.urlopen(
            f"http://{HOST}:{mock_port}/ctl/connections", timeout=10) as r:
        return json.load(r)["connections"] - 1


def _fault(srv, mode, count, path, mock=0):
    srv.set_fault(mode, count, path_re=re.escape(path), mock=mock)


def _clear_fault(srv, mock=0):
    srv.set_fault("none", 0, mock=mock)


def _abort_get(port, path, after=0.5):
    """Start a GET and slam the client connection shut (detached-fill probe)."""
    s = socket.create_connection((HOST, port), timeout=10)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    time.sleep(after)
    s.close()


def _raw_get_clean(port, path, timeout=15):
    """GET over a raw socket, reading one full response. Returns (status,
    body_len, reset_seen): reset_seen is True iff the kernel surfaced
    ECONNRESET — the server must always FIN, never RST, whatever the origin
    did. Stops at Content-Length (the hold-expiry 504 deliberately keeps the
    connection alive for a same-socket retry, so EOF may never come)."""
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    raw, reset, need = b"", False, None
    try:
        while _expression_1(need, raw):
            part = s.recv(65536)
            if not part:
                break
            raw += part
            if _expression_2(need, raw):
                head, _, _ = raw.partition(b"\r\n\r\n")
                m = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
                _phase_raw_get_clean_1(m, head)
    except ConnectionResetError:
        reset = True
    except socket.timeout:
        pass                     # response boundary unknown; judge what we got
    finally:
        s.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].split(b" ")
    status = _expression_3(first)
    return status, len(body), reset


def _fetch_many(port, path, n, stagger=0.05, timeout=25):
    """N concurrent GETs (slightly staggered so waiters join a live fill)."""
    out = [None] * n

    def worker(i):
        try:
            out[i] = _get(port, path, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — recorded, asserted by caller
            out[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
        time.sleep(stagger)
    for t in threads:
        t.join()
    return out


# =========================================================================== #
# 1. Single-origin fault absorption (stall detection + fill retry)
# =========================================================================== #

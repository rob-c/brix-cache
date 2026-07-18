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
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, _spawn_mock, srv_instance

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
    origins = f"http://127.0.0.1:{pa}|http://127.0.0.1:{pb}"
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
    origins = f"http://127.0.0.1:{srv1.mock_ports[0]}"
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
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",
                                    timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _connections(mock_port):
    """Distinct TCP connections the mock accepted since reset-log, excluding
    the control connection making this very query."""
    with urllib.request.urlopen(
            f"http://127.0.0.1:{mock_port}/ctl/connections", timeout=10) as r:
        return json.load(r)["connections"] - 1


def _fault(srv, mode, count, path, mock=0):
    srv.set_fault(mode, count, path_re=re.escape(path), mock=mock)


def _clear_fault(srv, mock=0):
    srv.set_fault("none", 0, mock=mock)


def _abort_get(port, path, after=0.5):
    """Start a GET and slam the client connection shut (detached-fill probe)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    time.sleep(after)
    s.close()


def _raw_get_clean(port, path, timeout=15):
    """GET over a raw socket, reading one full response. Returns (status,
    body_len, reset_seen): reset_seen is True iff the kernel surfaced
    ECONNRESET — the server must always FIN, never RST, whatever the origin
    did. Stops at Content-Length (the hold-expiry 504 deliberately keeps the
    connection alive for a same-socket retry, so EOF may never come)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    raw, reset, need = b"", False, None
    try:
        while need is None or len(raw) < need:
            part = s.recv(65536)
            if not part:
                break
            raw += part
            if need is None and b"\r\n\r\n" in raw:
                head, _, _ = raw.partition(b"\r\n\r\n")
                m = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
                if m:
                    need = len(head) + 4 + int(m.group(1))
    except ConnectionResetError:
        reset = True
    except socket.timeout:
        pass                     # response boundary unknown; judge what we got
    finally:
        s.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].split(b" ")
    status = int(first[1]) if len(first) > 1 else 0
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
        with urllib.request.urlopen(f"http://127.0.0.1:{srv1.nginx_port}{path}",
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
    conn = http.client.HTTPConnection("127.0.0.1", srv1.nginx_port, timeout=30)
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


@pytest.mark.timeout(60)
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

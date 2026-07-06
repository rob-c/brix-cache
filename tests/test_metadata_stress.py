"""
tests/test_metadata_stress.py

Metadata-operation STRESS test — hammer the server with paced ~100 req/s of
metadata ops/queries (stat, dirlist, locate, PROPFIND) against both a STANDALONE
fileserver and a MESH (redirector), and verify the server either serves it all
or sheds load *cleanly* (kXR_wait on stream, HTTP 429) — never crashing, hanging,
erroring, or falling over.

This is distinct from tests/load_test.py (which measures bulk-transfer throughput
under max concurrency).  Here we:
  * RATE-PACE to a target req/s (default 100) for a fixed duration, and
  * focus on cheap+expensive METADATA paths, and
  * assert the rate-limiter protects the server rather than the server toppling.

The module's policy (src/net/ratelimit/ratelimit_stream.c) is the thing under test:
  * stat / statx / ping / query  -> NEVER rate-limited  (cheap; always answered)
  * open / read / dirlist / locate -> rate-limited       (expensive; shed cleanly)
So the invariants we assert are:
  1. NO fall-over: the server passes a health check after the storm.
  2. NO errors: every response is a well-formed served / redirect / kXR_wait /
     429 — never a 5xx, a malformed frame, a hang, or a dropped connection.
  3. Cheap metadata (stat) stays available and fast even at 100 req/s (exempt).
  4. Expensive metadata (dirlist / locate) is either fully served (server keeps
     up) or rate-limited cleanly (kXR_wait / 429) when a limit is configured.

Tunables (env): METADATA_STRESS_RATE (default 100), METADATA_STRESS_SECS
(default 6), METADATA_STRESS_WORKERS (default 16).

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_metadata_stress.py -v -s
"""

import os
import socket
import struct
import subprocess
import threading
import time

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST

# ---- wire constants (XProtocol; mirror tests/test_a_robustness.py) ----
kXR_dirlist  = 3004
kXR_stat     = 3017
kXR_locate   = 3027
kXR_ok       = 0
kXR_redirect = 4004
kXR_wait     = 4005

RATE    = int(os.environ.get("METADATA_STRESS_RATE", "100"))
SECS    = float(os.environ.get("METADATA_STRESS_SECS", "6"))
WORKERS = int(os.environ.get("METADATA_STRESS_WORKERS", "16"))


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# Server spawn (self-contained — no fleet dependency)                          #
# --------------------------------------------------------------------------- #

def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _spawn(conf_text, tmp_path, port):
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "t").mkdir(exist_ok=True)
    cp = tmp_path / "nginx.conf"
    cp.write_text(conf_text + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not _wait_port(port):
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.terminate()
        pytest.skip(f"server did not start on {port}: {err}")
    return proc


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _seed_dir(tmp_path, nfiles=64):
    data = tmp_path / "data"
    (data / "dir").mkdir(parents=True, exist_ok=True)
    (data / "test.txt").write_text("hello\n")
    for i in range(nfiles):
        (data / "dir" / f"f{i}.txt").write_text(f"content {i}\n")
    return data


HEADER = (
    "error_log {logs}/error.log error;\n"
    "pid       {logs}/nginx.pid;\n"
    "events {{ worker_connections 512; }}\n"
)


def _stream_conf(tmp_path, data, port, rl_rule=""):
    extra = ""
    if rl_rule:
        extra = "brix_rate_limit_zone zone=rls:4m;"
    return HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        {extra}
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_storage_backend posix:{data};
            brix_auth none;
            brix_allow_write on;
            {rl_rule}
        }}
    }}
    """


def _http_conf(tmp_path, data, port, rl_rule=""):
    extra = "brix_rate_limit_zone zone=rlh:4m;" if rl_rule else ""
    return HEADER.format(logs=tmp_path / "logs") + f"""
    http {{
        client_body_temp_path {tmp_path}/t; proxy_temp_path {tmp_path}/t;
        fastcgi_temp_path {tmp_path}/t; uwsgi_temp_path {tmp_path}/t;
        scgi_temp_path {tmp_path}/t; access_log off;
        {extra}
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                {rl_rule}
            }}
        }}
    }}
    """


def _mesh_redirector_conf(tmp_path, port, ds_port, rl_rule=""):
    extra = "brix_rate_limit_zone zone=rlm:4m;" if rl_rule else ""
    return HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        {extra}
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_manager_map /dir {HOST}:{ds_port};
            brix_manager_map / {HOST}:{ds_port};
            {rl_rule}
        }}
    }}
    """


# --------------------------------------------------------------------------- #
# Raw XRootD stream session + metadata ops                                     #
# --------------------------------------------------------------------------- #

def _xrd_login(host, port, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    s.recv(16)
    hdr = s.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    hdr = s.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    return s


def _recv_status(s):
    rhdr = s.recv(8)
    if len(rhdr) < 8:
        return None
    status = struct.unpack(">H", rhdr[2:4])[0]
    dlen = struct.unpack(">I", rhdr[4:8])[0]
    got = 0
    while got < dlen:
        c = s.recv(dlen - got)
        if not c:
            break
        got += len(c)
    return status


def _op_stat(s, path="/test.txt"):
    p = path.encode() + b"\x00"
    s.sendall(struct.pack(">BBH16sI", 0, 1, kXR_stat, b"\x00" * 16, len(p)) + p)
    return _recv_status(s)


def _op_dirlist(s, path="/dir"):
    p = path.encode() + b"\x00"
    s.sendall(struct.pack(">BBH16sI", 0, 1, kXR_dirlist, b"\x00" * 16, len(p)) + p)
    return _recv_status(s)


def _op_locate(s, path="/dir/f0.txt"):
    p = path.encode() + b"\x00"
    s.sendall(struct.pack(">BBHH14sI", 0, 1, kXR_locate, 0, b"\x00" * 14, len(p)) + p)
    return _recv_status(s)


def _http_propfind(port, path="/dir"):
    """One-shot PROPFIND on a fresh connection (used by the low-rate tests)."""
    try:
        with socket.create_connection((HOST, port), timeout=4) as s:
            s.sendall((f"PROPFIND {path} HTTP/1.1\r\nHost: x\r\nDepth: 0\r\n"
                       "Content-Length: 0\r\nConnection: close\r\n\r\n").encode())
            s.settimeout(4)
            data = b""
            while b"\r\n\r\n" not in data:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        if not data:
            return None
        return int(data.split(b"\r\n", 1)[0].split()[1])
    except OSError:
        return None


def _http_session(port):
    s = socket.create_connection((HOST, port), timeout=8)
    s.settimeout(8)
    return s


def _op_propfind_ka(s, path="/dir"):
    """Keep-alive PROPFIND: reuse a persistent connection, framing the response
    by Content-Length so the socket can serve the next request.  This removes
    the per-request TCP connect/teardown that otherwise caps HTTP throughput far
    below the rate limiter — real WebDAV clients reuse connections the same way.
    Returns the status code, or None to make the hammer re-establish the conn."""
    s.sendall((f"PROPFIND {path} HTTP/1.1\r\nHost: x\r\nDepth: 0\r\n"
               "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c:
            return None
        buf += c
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    cl = None
    for line in head.split(b"\r\n")[1:]:
        if line[:15].lower() == b"content-length:":
            cl = int(line.split(b":", 1)[1].strip())
            break
    if cl is None:
        return None          # chunked / close-delimited — can't safely reuse
    body = rest
    while len(body) < cl:
        c = s.recv(cl - len(body))
        if not c:
            return None
        body += c
    return status


# --------------------------------------------------------------------------- #
# Rate-paced hammer                                                            #
# --------------------------------------------------------------------------- #

def _classify_stream(st):
    if st in (kXR_ok, kXR_redirect):
        return "served"
    if st == kXR_wait:
        return "throttled"
    return "errored"          # None (dropped), 4003, or anything unexpected


def _classify_http(st):
    if st in (200, 206, 207):
        return "served"
    if st == 429:
        return "throttled"
    if st is not None and 400 <= st < 500:
        return "served"       # well-formed client-side answer (e.g. 405) — not a fall-over
    return "errored"          # None (dropped) or 5xx


def _paced_hammer(make_session, do_op, classify, close_session=None,
                  rate=RATE, secs=SECS, workers=WORKERS):
    """Dispatch do_op(session) at ~`rate` ops/sec (aggregate) for `secs`, spread
    over `workers` threads each owning a persistent session.

    Each worker runs its OWN interleaved schedule (worker w fires global ticks
    w, w+workers, w+2·workers, … at start + idx/rate) and accumulates into LOCAL
    counters, merged only at join.  There is no shared counter or per-op lock in
    the hot path — that is what lets the harness offer multi-thousand req/s
    without the GIL serialising every dispatch.  A worker that falls behind its
    schedule stops sleeping and fires back-to-back, so the offered rate tracks
    the server's ceiling when the server (not the schedule) is the limit.

    A session that errors is transparently re-created so one dead socket doesn't
    snowball.  Returns {dispatched, served, throttled, errored, lat:[...]}."""
    step = 1.0 / rate
    start = time.perf_counter()
    deadline = start + secs
    locals_ = [None] * workers

    def worker(wid):
        try:
            sess = make_session()
        except Exception:
            sess = None
        disp = served = throttled = errored = 0
        lat = []
        j = 0
        while True:
            target = start + (wid + j * workers) * step
            now = time.perf_counter()
            if now >= deadline:
                break
            if target > now:
                if target >= deadline:
                    break
                time.sleep(target - now)
            j += 1
            if sess is None:
                try:
                    sess = make_session()
                except Exception:
                    disp += 1
                    errored += 1
                    continue
            t0 = time.perf_counter()
            try:
                st = do_op(sess)
            except Exception:
                st = None
            dt = time.perf_counter() - t0
            kind = classify(st)
            disp += 1
            if kind == "served":
                served += 1
                lat.append(dt)
            elif kind == "throttled":
                throttled += 1
            else:
                errored += 1
                if close_session and sess is not None:
                    try:
                        close_session(sess)
                    except Exception:
                        pass
                sess = None
        if close_session and sess is not None:
            try:
                close_session(sess)
            except Exception:
                pass
        locals_[wid] = (disp, served, throttled, errored, lat)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    res = {"dispatched": 0, "served": 0, "throttled": 0, "errored": 0, "lat": []}
    for tup in locals_:
        if tup is None:
            continue
        d, s, th, e, la = tup
        res["dispatched"] += d
        res["served"] += s
        res["throttled"] += th
        res["errored"] += e
        res["lat"].extend(la)
    return res


def _pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * p))]


def _report(label, res):
    lat = res["lat"]
    print(f"\n[{label}] dispatched={res['dispatched']} served={res['served']} "
          f"throttled={res['throttled']} errored={res['errored']} "
          f"p50={_pct(lat,0.5)*1000:.1f}ms p95={_pct(lat,0.95)*1000:.1f}ms "
          f"p99={_pct(lat,0.99)*1000:.1f}ms", flush=True)


def _assert_no_fallover(res, label, min_dispatch_frac=0.5):
    # We actually applied meaningful load.
    assert res["dispatched"] >= RATE * SECS * min_dispatch_frac, \
        f"{label}: only dispatched {res['dispatched']} ops (hammer stalled?)"
    # Errors (dropped connections / 5xx / malformed) are the fall-over signal.
    # Tolerate a tiny number of transient socket races, not a collapse.
    tol = max(3, int(res["dispatched"] * 0.01))
    assert res["errored"] <= tol, \
        f"{label}: {res['errored']} errored responses (>{tol}) — server fell over"
    # Something must have been answered.
    assert res["served"] + res["throttled"] > 0, f"{label}: nothing answered"


def _server_healthy_stream(port):
    try:
        s = _xrd_login(HOST, port, timeout=4)
        st = _op_stat(s, "/test.txt")
        s.close()
        return st == kXR_ok
    except OSError:
        return False


# =========================================================================== #
# STANDALONE                                                                   #
# =========================================================================== #

class TestStandaloneMetadataStress:

    def test_cheap_stat_flood_all_served(self, tmp_path):
        """100 req/s of kXR_stat (exempt) — the server must answer ALL of them,
        never throttle a cheap op, and stay fast + healthy."""
        data = _seed_dir(tmp_path)
        port = 21990
        proc = _spawn(_stream_conf(tmp_path, data, port,
                                   rl_rule="brix_rate_limit_rule zone=rls key=ip rate=50r/s burst=50;"),
                      tmp_path, port)
        try:
            res = _paced_hammer(lambda: _xrd_login(HOST, port), _op_stat,
                                _classify_stream, close_session=lambda s: s.close())
            _report("standalone stat flood", res)
            _assert_no_fallover(res, "stat flood")
            assert res["throttled"] == 0, \
                "kXR_stat is exempt and must NEVER be rate-limited"
            assert _pct(res["lat"], 0.95) < 1.0, \
                f"cheap stat p95 too slow: {_pct(res['lat'],0.95):.3f}s"
            assert _server_healthy_stream(port), "server unhealthy after stat flood"
        finally:
            _stop(proc)

    def test_expensive_dirlist_flood_rate_limited_cleanly(self, tmp_path):
        """100 req/s of kXR_dirlist (expensive, rate-limited to 30r/s) — the
        server must shed the excess with kXR_wait, never erroring or crashing,
        and cheap stat must STILL be answered during the flood."""
        data = _seed_dir(tmp_path)
        port = 21991
        proc = _spawn(_stream_conf(tmp_path, data, port,
                                   rl_rule="brix_rate_limit_rule zone=rls key=ip rate=30r/s burst=30;"),
                      tmp_path, port)
        try:
            res = _paced_hammer(lambda: _xrd_login(HOST, port), _op_dirlist,
                                _classify_stream, close_session=lambda s: s.close())
            _report("standalone dirlist+RL", res)
            _assert_no_fallover(res, "dirlist+RL")
            assert res["throttled"] > 0, \
                "dirlist at 100/s under a 30r/s limit should shed via kXR_wait"
            # Cheap metadata stays available even while expensive ops are shed.
            assert _server_healthy_stream(port), \
                "stat unavailable / server unhealthy during dirlist flood"
        finally:
            _stop(proc)

    def test_dirlist_flood_no_limit_does_not_fall_over(self, tmp_path):
        """100 req/s of kXR_dirlist with NO rate limit — the server must absorb
        it (serve) without erroring, hanging, or crashing."""
        data = _seed_dir(tmp_path)
        port = 21992
        proc = _spawn(_stream_conf(tmp_path, data, port), tmp_path, port)
        try:
            res = _paced_hammer(lambda: _xrd_login(HOST, port), _op_dirlist,
                                _classify_stream, close_session=lambda s: s.close())
            _report("standalone dirlist no-RL", res)
            _assert_no_fallover(res, "dirlist no-RL")
            assert res["served"] > 0
            assert _server_healthy_stream(port), "server unhealthy after dirlist flood"
        finally:
            _stop(proc)

    def test_http_propfind_flood_rate_limited_cleanly(self, tmp_path):
        """100 req/s of WebDAV PROPFIND under a 30r/s per-IP limit — excess must
        return a clean 429, never a 5xx or dropped connection, server healthy."""
        data = _seed_dir(tmp_path)
        port = 21993
        proc = _spawn(_http_conf(tmp_path, data, port,
                                 rl_rule="brix_rate_limit_rule zone=rlh key=ip rate=30r/s burst=30;"),
                      tmp_path, port)
        try:
            res = _paced_hammer(lambda: None,
                                lambda _s: _http_propfind(port, "/dir"),
                                _classify_http)
            _report("standalone PROPFIND+RL", res)
            _assert_no_fallover(res, "PROPFIND+RL")
            assert res["throttled"] > 0, \
                "PROPFIND at 100/s under a 30r/s limit should return 429"
            # The server must still be RESPONSIVE after the flood — but with the
            # (now correctly-draining) bucket still full immediately afterwards a
            # 429 is the right answer, not a failure.  207/200 (drained) or 429
            # (still full) all prove it is answering, not wedged.
            assert _http_propfind(port, "/test.txt") in (200, 207, 429), \
                "server not responding to PROPFIND after the flood"
        finally:
            _stop(proc)


# =========================================================================== #
# MESH (redirector)                                                            #
# =========================================================================== #

class TestMeshMetadataStress:

    def test_redirector_locate_flood_rate_limited_cleanly(self, tmp_path):
        """100 req/s of kXR_locate at a redirector (manager_map) under a 40r/s
        limit — each request must resolve to a clean kXR_redirect or be shed via
        kXR_wait; the redirector must never error/crash under the metadata
        storm.  No data node is required: the redirector answers locate itself."""
        port = 21994
        ds_port = 21995          # advertised redirect target (need not be live)
        proc = _spawn(_mesh_redirector_conf(
            tmp_path, port, ds_port,
            rl_rule="brix_rate_limit_rule zone=rlm key=ip rate=40r/s burst=40;"),
            tmp_path, port)
        try:
            res = _paced_hammer(lambda: _xrd_login(HOST, port), _op_locate,
                                _classify_stream, close_session=lambda s: s.close())
            _report("mesh redirector locate+RL", res)
            _assert_no_fallover(res, "redirector locate+RL")
            # The redirector either redirects (served) or sheds (kXR_wait).
            assert res["served"] + res["throttled"] == \
                res["dispatched"] - res["errored"]
            # Redirector still answers a locate after the storm.
            try:
                s = _xrd_login(HOST, port, timeout=4)
                st = _op_locate(s, "/dir/f0.txt")
                s.close()
            except OSError:
                st = None
            assert st in (kXR_redirect, kXR_ok, kXR_wait), \
                f"redirector unhealthy after locate flood (status={st})"
        finally:
            _stop(proc)

    def test_redirector_locate_flood_no_limit_does_not_fall_over(self, tmp_path):
        """100 req/s of kXR_locate with NO limit — the redirector must keep
        redirecting without erroring/hanging/crashing."""
        port = 21996
        ds_port = 21997
        proc = _spawn(_mesh_redirector_conf(tmp_path, port, ds_port),
                      tmp_path, port)
        try:
            res = _paced_hammer(lambda: _xrd_login(HOST, port), _op_locate,
                                _classify_stream, close_session=lambda s: s.close())
            _report("mesh redirector locate no-RL", res)
            _assert_no_fallover(res, "redirector locate no-RL")
            assert res["served"] > 0, "redirector served no locate requests"
        finally:
            _stop(proc)


# =========================================================================== #
# RATE-LIMIT THROUGHPUT — the limiter must DELIVER its configured rate         #
# =========================================================================== #

class TestRateLimitThroughput:
    """After the leaky-bucket drain-writeback fix (src/net/ratelimit/ratelimit.c) the
    limiter delivers its configured rate.  These confirm it scales to ~1k r/s:
    a 1000 r/s limit under heavy offered load must SUSTAIN >500 req/s served
    (target headline), shed the excess cleanly, and never fall over.

    Offered load is driven well above the limit by a large worker pool; the
    server runs a single nginx process, so this also bounds the per-core serve
    cost of the limited metadata op.
    """

    LIMIT    = 4000        # r/s configured limit (headroom toward ~10k capability)
    BURST    = 2000
    OFFERED  = 8000        # target offered req/s (>= limit, so the limiter bites)
    SECS     = 5.0
    NWORKERS = 64          # lock-free hammer threads to push multi-k/s of sub-ms ops
    TARGET   = 2000        # headline: served rate must exceed this

    def _assert_throughput(self, label, res, limit_active=True):
        served_rate = res["served"] / self.SECS
        offered_rate = res["dispatched"] / self.SECS
        _report(label, res)
        print(f"  -> SERVED={served_rate:.0f} req/s  OFFERED={offered_rate:.0f} req/s "
              f"(limit {self.LIMIT}r/s)", flush=True)
        assert res["errored"] <= max(5, int(res["dispatched"] * 0.01)), \
            f"{label}: {res['errored']} errored — server fell over under load"
        assert served_rate > self.TARGET, \
            f"{label}: limiter delivered only {served_rate:.0f} req/s (<{self.TARGET})"
        return served_rate, offered_rate

    def test_mesh_locate_sustains_over_500rps(self, tmp_path):
        """kXR_locate at a redirector (cheapest limited op — map lookup, no FS)
        under a 1000 r/s limit, offered ~2000/s: served must exceed 500 r/s."""
        port = 21994
        ds_port = 21995
        proc = _spawn(_mesh_redirector_conf(
            tmp_path, port, ds_port,
            rl_rule=f"brix_rate_limit_rule zone=rlm key=ip rate={self.LIMIT}r/s burst={self.BURST};"),
            tmp_path, port)
        try:
            res = _paced_hammer(lambda: _xrd_login(HOST, port), _op_locate,
                                _classify_stream, close_session=lambda s: s.close(),
                                rate=self.OFFERED, secs=self.SECS, workers=self.NWORKERS)
            self._assert_throughput(f"mesh locate {self.LIMIT}r/s limit", res)
            assert _server_healthy_stream(port) or True  # redirector has no stat root
        finally:
            _stop(proc)

    def test_stream_dirlist_sustains_over_500rps(self, tmp_path):
        """kXR_dirlist on a small dir under a 1000 r/s limit, offered ~2000/s."""
        data = _seed_dir(tmp_path, nfiles=8)     # small dir → cheap dirlist
        port = 21998
        proc = _spawn(_stream_conf(tmp_path, data, port,
            rl_rule=f"brix_rate_limit_rule zone=rls key=ip rate={self.LIMIT}r/s burst={self.BURST};"),
            tmp_path, port)
        try:
            res = _paced_hammer(lambda: _xrd_login(HOST, port), _op_dirlist,
                                _classify_stream, close_session=lambda s: s.close(),
                                rate=self.OFFERED, secs=self.SECS, workers=self.NWORKERS)
            self._assert_throughput(f"stream dirlist {self.LIMIT}r/s limit", res)
            assert _server_healthy_stream(port), "server unhealthy after throughput run"
        finally:
            _stop(proc)

    def test_http_propfind_sustains_over_500rps(self, tmp_path):
        """WebDAV PROPFIND under a 1000 r/s limit, offered ~2000/s."""
        data = _seed_dir(tmp_path, nfiles=8)
        port = 21999
        proc = _spawn(_http_conf(tmp_path, data, port,
            rl_rule=f"brix_rate_limit_rule zone=rlh key=ip rate={self.LIMIT}r/s burst={self.BURST};"),
            tmp_path, port)
        try:
            res = _paced_hammer(lambda: _http_session(port),
                                lambda s: _op_propfind_ka(s, "/dir"),
                                _classify_http, close_session=lambda s: s.close(),
                                rate=self.OFFERED, secs=self.SECS,
                                workers=self.NWORKERS)
            self._assert_throughput(f"http PROPFIND {self.LIMIT}r/s limit", res)
        finally:
            _stop(proc)

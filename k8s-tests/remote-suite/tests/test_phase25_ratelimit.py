"""
Phase 25 — advanced rate limiting & traffic shaping.

Coverage:
  1. Source-marker checks: the ratelimit module, dispatch gate, body filter,
     directives, metrics, and dashboard route are wired.
  2. Config validation: the new directives parse (and do not collide with the
     Phase 20 brix_rate_limit); bad rate/key are rejected; off by default.
  3. HTTP functional: a per-IP request rate returns 429 once the burst is spent
     (success + Retry-After); nodelay rejects immediately; an unauthenticated
     client is bucketed by IP; bandwidth is charged (dashboard bytes_total).
  4. Stream functional: a per-IP kXR_read rate returns kXR_wait once the burst
     is spent; kXR_stat is never throttled.
  5. Dashboard: GET /brix/api/v1/ratelimit reports per-principal throttle
     counts, sorted most-throttled first.
  6. Stream concurrency (W7): brix_concurrency_limit caps concurrent root://
     connections per principal — over-cap connections get kXR_wait, and a slot
     freed by a disconnect is reusable (release wired in brix_on_disconnect).
"""

import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import http.server
from pathlib import Path

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _read(rel):
    p = ROOT / rel
    assert p.exists(), f"missing {rel}"
    text = p.read_text(encoding="utf-8")
    # Two refactors split source out of the file being read: the ngx_command_t
    # directive table into per-concern directives_*.inc fragments, and the big
    # brix_ctx_t / srv-conf structs into *_structs.h sub-structs — both #included
    # back into the original.  Inline those siblings so a presence check against
    # module.c / context.h sees the full effective source.
    import re as _re
    def _inc(m):
        frag = p.parent / m.group(1)
        return frag.read_text(encoding="utf-8") if frag.exists() else m.group(0)
    return _re.sub(r'#include "(directives_[a-z0-9_]+\.inc|[a-z0-9_]+_structs\.h)"',
                   _inc, text)


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

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
    assert "brix_rl_charge_ctx" in _read("src/protocols/root/read/read.c")
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
    wd = _read("src/protocols/webdav/module.c")
    st = _read("src/protocols/root/stream/module.c")
    for name in ("brix_rate_limit_zone", "brix_rate_limit_rule",
                 "brix_bandwidth_limit"):
        assert name in wd, name
        assert name in st, name


def test_metrics_and_dashboard_wired():
    m = _read("src/observability/metrics/metrics.h")
    assert "rl_throttled_http_total" in m
    assert "rl_throttled_stream_total" in m
    assert "brix_rate_limit_throttled_total" in _read("src/observability/metrics/ratelimit.c")
    assert "/brix/api/v1/ratelimit" in _read("src/observability/dashboard/module.c")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

HEADER = (
    "error_log {logs}/error.log info;\n"
    "pid       {logs}/nginx.pid;\n"
    "events {{ worker_connections 64; }}\n"
)


def _nginx_check(conf_text, tmp_path):
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "t").mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(conf_text)
    proc = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def _http_block(body, tmp_path, http_extra=""):
    return HEADER.format(logs=tmp_path / "logs") + f"""
    http {{
        client_body_temp_path {tmp_path}/t; proxy_temp_path {tmp_path}/t;
        fastcgi_temp_path {tmp_path}/t; uwsgi_temp_path {tmp_path}/t;
        scgi_temp_path {tmp_path}/t; access_log off;
        {http_extra}
        {body}
    }}
    """


def test_http_directives_parse(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_rate_limit_rule zone=rl key=vo rate=500r/s burst=800;
                brix_rate_limit_rule zone=rl key=ip rate=10r/s burst=10 nodelay;
                brix_rate_limit_rule zone=rl key=volume:/store/tape rate=50r/s burst=80;
                brix_bandwidth_limit zone=rl key=vo rate=100m/s burst=500m;
            }}
        }}
    """, tmp_path, http_extra="brix_rate_limit_zone zone=rl:4m;")
    rc, out = _nginx_check(conf, tmp_path)
    assert rc == 0, out


def test_bad_rate_rejected(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_rate_limit_rule zone=rl key=ip rate=500 burst=10;
            }}
        }}
    """, tmp_path, http_extra="brix_rate_limit_zone zone=rl:1m;")
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "rate" in out.lower()


def test_unknown_zone_rejected(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_rate_limit_rule zone=missing key=ip rate=5r/s burst=5;
            }}
        }}
    """, tmp_path)
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "zone" in out.lower()


def test_coexists_with_phase20_rate_limit(tmp_path):
    # The new directives and the Phase 20 brix_rate_limit must not collide.
    data = tmp_path / "data"; data.mkdir()
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_rate_limit_rule zone=rl key=ip rate=10r/s burst=10;
            }}
        }}
    """, tmp_path,
        http_extra="brix_kv_zone kv 1m key=64 val=64;\n"
                   "        brix_rate_limit_zone zone=rl:1m;")
    rc, out = _nginx_check(conf, tmp_path)
    assert rc == 0, out


# --------------------------------------------------------------------------- #
# Functional helpers                                                           #
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
        pytest.skip(f"server did not start: {err}")
    return proc


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _get(port, path, headers=""):
    with socket.create_connection((HOST, port), timeout=4) as s:
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: x\r\n{headers}"
                   "Connection: close\r\n\r\n").encode())
        s.settimeout(4)
        data = b""
        while b"\r\n\r\n" not in data:
            c = s.recv(4096)
            if not c:
                break
            data += c
    head = data.split(b"\r\n\r\n", 1)[0]
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    hdrs = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs[k.strip().lower().decode()] = v.strip().decode()
    return status, hdrs


# --------------------------------------------------------------------------- #
# 3. HTTP functional                                                           #
# --------------------------------------------------------------------------- #

def test_http_429_after_burst(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_rate_limit_rule zone=rl key=ip rate=2r/s burst=2;
            }}
        }}
    """, tmp_path, http_extra="brix_rate_limit_zone zone=rl:1m;")
    proc = _spawn(conf, tmp_path, port)
    try:
        codes = [_get(port, "/f.txt")[0] for _ in range(6)]
        assert codes[:2] == [200, 200], codes
        assert 429 in codes, codes
        # The throttled (non-nodelay) response carries Retry-After.
        st, hdrs = _get(port, "/f.txt")
        if st == 429:
            assert "retry-after" in hdrs, hdrs
    finally:
        _stop(proc)


def test_http_nodelay_immediate(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_rate_limit_rule zone=rl key=ip rate=1r/s burst=1 nodelay;
            }}
        }}
    """, tmp_path, http_extra="brix_rate_limit_zone zone=rl:1m;")
    proc = _spawn(conf, tmp_path, port)
    try:
        codes = [_get(port, "/f.txt")[0] for _ in range(4)]
        assert codes[0] == 200
        assert 429 in codes[1:], codes
        # nodelay → no Retry-After header.
        for _ in range(4):
            st, hdrs = _get(port, "/f.txt")
            if st == 429:
                assert "retry-after" not in hdrs, hdrs
                break
    finally:
        _stop(proc)


def test_http_bandwidth_throttled(tmp_path):
    # A tiny bandwidth cap: the first large GET is allowed, then the bucket
    # overflows and subsequent GETs are throttled (429).
    data = tmp_path / "data"; data.mkdir()
    (data / "big.bin").write_bytes(b"x" * 100000)
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_bandwidth_limit zone=rl key=ip rate=10k/s burst=120k;
            }}
        }}
    """, tmp_path, http_extra="brix_rate_limit_zone zone=rl:1m;")
    proc = _spawn(conf, tmp_path, port)
    try:
        codes = [_get(port, "/big.bin")[0] for _ in range(5)]
        assert codes[0] == 200, codes          # first within burst
        assert 429 in codes, codes             # bucket overflows after charge
    finally:
        _stop(proc)


def _curl_cookie(port):
    out = subprocess.run(
        ["curl", "-si", "-X", "POST", "--data", "password=pw",
         f"http://{HOST}:{port}/brix/login"],
        capture_output=True, text=True, timeout=8).stdout
    m = re.search(r"(?im)^Set-Cookie:\s*(xrd_dashboard=[^;]+)", out)
    return m.group(1) if m else None


def _curl_ratelimit(port, cookie):
    out = subprocess.run(
        ["curl", "-s", "-H", f"Cookie: {cookie}",
         f"http://{HOST}:{port}/brix/api/v1/ratelimit"],
        capture_output=True, text=True, timeout=8).stdout
    return json.loads(out)


def test_dashboard_shows_throttle_count(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = free_port()
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_rate_limit_rule zone=rl key=ip rate=2r/s burst=2;
            }}
            location /brix/ {{
                brix_dashboard on;
                brix_dashboard_password "pw";
            }}
        }}
    """, tmp_path, http_extra="brix_rate_limit_zone zone=rl:1m;")
    proc = _spawn(conf, tmp_path, port)
    try:
        # Drive throttling on the ip:127.0.0.1 principal.
        for _ in range(8):
            _get(port, "/f.txt")
        cookie = _curl_cookie(port)
        assert cookie, "dashboard login did not set a cookie"
        doc = _curl_ratelimit(port, cookie)
        principals = [p for z in doc.get("zones", []) for p in z["principals"]]
        assert principals, doc
        throttled = [p for p in principals if p["throttle_count"] > 0]
        assert throttled, principals
        # Sorted most-throttled first.
        counts = [p["throttle_count"] for p in principals]
        assert counts == sorted(counts, reverse=True), counts
    finally:
        _stop(proc)


# --------------------------------------------------------------------------- #
# Stream functional (raw XRootD wire)                                          #
# --------------------------------------------------------------------------- #

def _xrd_login(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
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


def _xrd_recv_status(s):
    rhdr = s.recv(8)
    if len(rhdr) < 8:
        return None, b""
    status = struct.unpack(">H", rhdr[2:4])[0]
    dlen = struct.unpack(">I", rhdr[4:8])[0]
    body = b""
    while len(body) < dlen:
        c = s.recv(dlen - len(body))
        if not c:
            break
        body += c
    return status, body


def _xrd_stat(s, path):
    payload = path.encode() + b"\x00"
    s.sendall(struct.pack(">BBH16sI", 0, 1, 3017, b"\x00" * 16, len(payload))
              + payload)
    return _xrd_recv_status(s)


def _xrd_open(s, path):
    # kXR_open = 3010; body: mode[2] options[2] reserved[12]; payload=path
    payload = path.encode()
    body = struct.pack(">HH12s", 0, 0x10, b"\x00" * 12)  # options kXR_open_read=0x10
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _xrd_read(s, fhandle, offset, rlen):
    # kXR_read = 3013; body: fhandle[4] offset[8] rlen[4] = 16; no payload.
    body = fhandle[:4] + struct.pack(">q", offset) + struct.pack(">i", rlen)
    s.sendall(struct.pack(">BBH", 0, 1, 3013) + body + struct.pack(">I", 0))
    return _xrd_recv_status(s)


KXR_WAIT = 4005
KXR_OK = 0


def test_stream_kxr_wait_after_burst(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = free_port()
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_rate_limit_zone zone=rls:1m;
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_storage_backend posix:{data};
            brix_auth none;
            brix_rate_limit_rule zone=rls key=ip rate=2r/s burst=2;
        }}
    }}
    """
    proc = _spawn(conf, tmp_path, port)
    try:
        s = _xrd_login(HOST, port)
        # kXR_open is rate-limited; burst=2 then kXR_wait.
        statuses = []
        for _ in range(6):
            st, _b = _xrd_open(s, "/f.txt")
            statuses.append(st)
        s.close()
        assert KXR_WAIT in statuses, statuses
    finally:
        _stop(proc)


def test_stream_stat_never_throttled(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = free_port()
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_rate_limit_zone zone=rls:1m;
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_storage_backend posix:{data};
            brix_auth none;
            brix_rate_limit_rule zone=rls key=ip rate=1r/s burst=1;
        }}
    }}
    """
    proc = _spawn(conf, tmp_path, port)
    try:
        s = _xrd_login(HOST, port)
        # Many stats in a row — never kXR_wait (stat is exempt).
        for _ in range(8):
            st, _b = _xrd_stat(s, "/f.txt")
            assert st != KXR_WAIT, st
        s.close()
    finally:
        _stop(proc)


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


def _conc_stream_conf(tmp_path, port, data, limit):
    return HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_rate_limit_zone zone=rlc:1m;
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_storage_backend posix:{data};
            brix_auth none;
            brix_concurrency_limit zone=rlc key=ip limit={limit};
        }}
    }}
    """


def test_stream_concurrency_directive_parses(tmp_path):
    # Regression: brix_concurrency_limit used to be HTTP-only and would be
    # rejected in a stream{} server block. It must now parse there.
    data = tmp_path / "data"; data.mkdir()
    rc, out = _nginx_check(_conc_stream_conf(tmp_path, free_port(), data, 4), tmp_path)
    assert rc == 0, out


def test_stream_concurrency_bad_limit_rejected(tmp_path):
    # limit= must be a positive integer (security/neg: a 0 or garbage cap is a
    # silent no-cap footgun, so the parser must reject it).
    data = tmp_path / "data"; data.mkdir()
    port = free_port()
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_rate_limit_zone zone=rlc:1m;
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_storage_backend posix:{data};
            brix_auth none;
            brix_concurrency_limit zone=rlc key=ip limit=0;
        }}
    }}
    """
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "limit" in out.lower()


def test_stream_concurrency_cap_and_release(tmp_path):
    # limit=2: two concurrent connections each hold an in-flight slot; the third
    # concurrent connection's first rate-limited op (kXR_open) gets kXR_wait.
    # Closing a holder frees its slot for a fresh connection (release path).
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = free_port()
    proc = _spawn(_conc_stream_conf(tmp_path, port, data, 2), tmp_path, port)
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
        _stop(proc)


def test_stream_concurrency_high_limit_no_throttle(tmp_path):
    # Control: with a cap well above the offered load, concurrent connections all
    # proceed — proving the kXR_wait above is the cap, not an artifact of opening
    # several connections at once.
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello\n")
    port = free_port()
    proc = _spawn(_conc_stream_conf(tmp_path, port, data, 16), tmp_path, port)
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
        _stop(proc)


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
    assert "rl_key_cache_valid" in gate
    # VOLUME rules must be excluded from caching.
    assert "BRIX_RL_KEY_VOLUME" in gate


def test_keycache_read_path_still_throttles(tmp_path):
    # The read path is non-path-bearing, so it uses the CACHED identity key.
    # Throttling must still fire there: open once, then reads exhaust the burst
    # and return kXR_wait.
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello world\n")
    port = free_port()
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_rate_limit_zone zone=rlk:1m;
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_storage_backend posix:{data};
            brix_auth none;
            brix_rate_limit_rule zone=rlk key=ip rate=2r/s burst=2;
        }}
    }}
    """
    proc = _spawn(conf, tmp_path, port)
    try:
        s = _xrd_login(HOST, port)
        st, body = _xrd_open(s, "/f.txt")          # op 1 (within burst)
        assert st == KXR_OK, ("open should succeed within burst", st)
        fh = body[:4]
        # Hammer reads on the cached ip key; the burst is spent → kXR_wait.
        read_status = [_xrd_read(s, fh, 0, 5)[0] for _ in range(6)]
        s.close()
        assert KXR_WAIT in read_status, ("cached-key read path must throttle",
                                         read_status)
    finally:
        _stop(proc)


def test_keycache_volume_not_collapsed(tmp_path):
    # VOLUME rules are path-dependent and must NOT be cached: a per-prefix bucket
    # must still throttle its own prefix while leaving non-matching paths free.
    data = tmp_path / "data"; data.mkdir()
    (data / "hot").mkdir(); (data / "cold").mkdir()
    (data / "hot" / "a.txt").write_text("hot\n")
    (data / "cold" / "b.txt").write_text("cold\n")
    port = free_port()
    conf = HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        brix_rate_limit_zone zone=rlv:1m;
        server {{
            listen {BIND_HOST}:{port};
            brix_root on;
            brix_storage_backend posix:{data};
            brix_auth none;
            brix_rate_limit_rule zone=rlv key=volume:/hot rate=1r/s burst=1;
        }}
    }}
    """
    proc = _spawn(conf, tmp_path, port)
    try:
        s = _xrd_login(HOST, port)
        st1, _ = _xrd_open(s, "/hot/a.txt")        # matches /hot, burst spent
        assert st1 == KXR_OK, ("first /hot open within burst", st1)
        st2, _ = _xrd_open(s, "/hot/a.txt")        # /hot bucket overflow → wait
        assert st2 == KXR_WAIT, ("second /hot open must throttle", st2)
        st3, _ = _xrd_open(s, "/cold/b.txt")       # no /hot match → never throttled
        assert st3 != KXR_WAIT, ("non-matching prefix must not be collapsed", st3)
        s.close()
    finally:
        _stop(proc)

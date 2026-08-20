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

Registry-backed: every nginx here is a throwaway instance provisioned through
the `lifecycle` harness (templates nginx_rl_http.conf + nginx_rl_stream.conf);
curl runs through the harness command runner.
"""

import json
import os
import re
import socket
import struct
import time
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST

# Every lifecycle-subject instance in this file draws a fixed exclusive-band port
# from the lifecycle ledger (lc-rl-*); xdist_group("lc-rl") serialises the whole
# family onto one worker so no fixed port ever has two concurrent drivers.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-rl")]

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
    # directive table into per-concern directives_*.h fragments, and the big
    # brix_ctx_t / srv-conf structs into *_structs.h sub-structs — both #included
    # back into the original.  Inline those siblings so a presence check against
    # module.c / context.h sees the full effective source.
    import re as _re
    def _inc(m):
        frag = p.parent / m.group(1)
        return frag.read_text(encoding="utf-8") if frag.exists() else m.group(0)
    return _re.sub(r'#include "(directives_[a-z0-9_]+\.h|[a-z0-9_]+_structs\.h)"',
                   _inc, text)


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

def _http_values(rl_knobs, http_extra="", extra_locations=""):
    return {"BIND_HOST": BIND_HOST, "RL_KNOBS": rl_knobs,
            "HTTP_EXTRA": http_extra, "EXTRA_LOCATIONS": extra_locations}


def _stream_values(rl_knobs, stream_extra):
    return {"BIND_HOST": BIND_HOST, "RL_KNOBS": rl_knobs,
            "STREAM_EXTRA": stream_extra}


def _parse_ok(lifecycle, name, template, values):
    lifecycle.register(NginxInstanceSpec(
        name=name, template=template, template_values=values,
        reason="phase-25 rate-limit directive parse coverage"))
    lifecycle.reconfigure(name)
    lifecycle.nginx_test(name)  # raises on parse failure


def _parse_fail(tmp_path, template, values):
    # Pure config-parse property: render + `nginx -t`, no server ever boots, so
    # the listen port is a non-binding placeholder (nginx -t never binds).
    data = tmp_path / "data"; data.mkdir(exist_ok=True)
    values = dict(values, PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                  LOG_DIR=str(tmp_path), TMP_DIR=str(tmp_path))
    result = nginx_t(template, tmp_path, **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")



def _start_http(lifecycle, tmp_path, name, rl_knobs, http_extra="",
                extra_locations="", seed_files=(), port=None):
    data = tmp_path / "data"; data.mkdir(exist_ok=True)
    for n, payload in seed_files:
        if isinstance(payload, bytes):
            (data / n).write_bytes(payload)
        else:
            (data / n).write_text(payload)
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_rl_http.conf",
        protocol="http",
        data_root=str(data),
        template_values=_http_values(rl_knobs, http_extra, extra_locations),
        port=port,
        reason="phase-25 HTTP rate-limit functional coverage"))
    return endpoint.port


def _start_stream(lifecycle, data, name, rl_knobs, stream_extra, port=None):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_rl_stream.conf",
        data_root=str(data),
        template_values=_stream_values(rl_knobs, stream_extra),
        port=port,
        reason="phase-25 stream rate-limit functional coverage"))
    return endpoint.port


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


def _curl_cookie(lifecycle, port):
    rc = lifecycle.run_cmd(
        ["curl", "-si", "-X", "POST", "--data", "password=pw",
         f"http://{HOST}:{port}/brix/login"], timeout=8)
    m = re.search(r"(?im)^Set-Cookie:\s*(xrd_dashboard=[^;]+)", rc.stdout)
    return m.group(1) if m else None


def _curl_ratelimit(lifecycle, port, cookie):
    rc = lifecycle.run_cmd(
        ["curl", "-s", "-H", f"Cookie: {cookie}",
         f"http://{HOST}:{port}/brix/api/v1/ratelimit"], timeout=8)
    return json.loads(rc.stdout)



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



def _conc_knobs(limit):
    return f"        brix_concurrency_limit zone=rlc key=ip limit={limit};\n"


_CONC_ZONE = "    brix_rate_limit_zone zone=rlc:1m;\n"

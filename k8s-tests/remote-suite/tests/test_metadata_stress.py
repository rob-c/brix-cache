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


from split_continuation import load as _load_continuation

_load_continuation(
    globals(),
    __file__,
    "_test_metadata_stress_runtime.py",
    "_test_metadata_stress_cases.py",
)


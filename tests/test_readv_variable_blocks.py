"""
tests/test_readv_variable_blocks.py

Verify THIS PROJECT'S native client (libxrdc, xrdc_file_readv) correctly handles
variably-sized kXR_readv response blocks — in particular blocks the server makes
SHORTER than requested by capping each element to brix_readv_segment_size. The
client must read each segment's actual returned length from the response (not
assume it equals the request) and deliver byte-exact data per segment.

A dedicated anonymous nginx is started with brix_readv_segment_size 1m over a
5 MiB random file, then a compiled libxrdc consumer (examples/xrdc_readv_demo.c)
issues one readv mixing tiny, mid, exactly-cap and over-cap (-> capped/short)
elements. The test checks each segment's reported `got` and its bytes.

Run:
    pytest tests/test_readv_variable_blocks.py -v
"""

import os
import socket
import subprocess
import tempfile
import time
import shutil

import pytest

# Reuse the proven static-link probes from the libxrdc test.
from test_libxrdc import _codec_link_libs, _krb5_link_libs, _uring_link_libs

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
SRC = os.path.join(REPO, "src")
SHARED = os.path.join(REPO, "shared", "xrdproto")
DEMO_SRC = os.path.join(CLIENT, "examples", "xrdc_readv_demo.c")
LIBXRDC = os.path.join(CLIENT, "libxrdc.a")
LIBXRDPROTO = os.path.join(SHARED, "libxrdproto.a")
NGINX_BIN = os.environ.get("RESIL_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
CC = os.environ.get("CC", "cc")

FILE_BYTES = 5 * 1024 * 1024
CAP = 1024 * 1024                 # brix_readv_segment_size 1m

_CONF = """\
worker_processes 1;
daemon off;
error_log {logs}/error.log error;
pid {logs}/nginx.pid;
events {{ worker_connections 1024; }}
stream {{
    server {{
        listen 127.0.0.1:{port};
        xrootd on;
        brix_storage_backend posix:{data};
        brix_readv_segment_size 1m;
        brix_access_log {logs}/access.log;
    }}
}}
"""


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def demo_bin(tmp_path_factory):
    if shutil.which(CC) is None:
        pytest.skip("no C compiler")
    for need in (DEMO_SRC, LIBXRDC, LIBXRDPROTO):
        if not os.path.isfile(need):
            pytest.skip(f"missing build artifact: {need}")
    out = str(tmp_path_factory.mktemp("readv_demo") / "demo")
    cmd = [CC, "-std=c11", "-O2",
           f"-I{os.path.join(CLIENT, 'lib')}", f"-I{SRC}", "-DXRDPROTO_NO_NGX",
           DEMO_SRC, LIBXRDC, LIBXRDPROTO,
           "-lssl", "-lcrypto", "-lz",
           *_codec_link_libs(), *_krb5_link_libs(), *_uring_link_libs(),
           "-lpthread", "-ldl", "-o", out]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        pytest.skip(f"demo build failed:\n{' '.join(cmd)}\n{proc.stderr}")
    return out


@pytest.fixture(scope="module")
def server1m():
    if not os.path.isfile(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    prefix = tempfile.mkdtemp(prefix="readv_var_")
    data, logs, confd = (os.path.join(prefix, d) for d in ("data", "logs", "conf"))
    for d in (data, logs, confd):
        os.makedirs(d, exist_ok=True)
    payload = os.urandom(FILE_BYTES)
    with open(os.path.join(data, "big.bin"), "wb") as fh:
        fh.write(payload)
    port = _free_port()
    with open(os.path.join(confd, "nginx.conf"), "w") as fh:
        fh.write(_CONF.format(port=port, data=data, logs=logs))
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    proc = subprocess.Popen([NGINX_BIN, "-p", prefix, "-c", "conf/nginx.conf"], env=env)
    up = False
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            up = True
            break
        except OSError:
            time.sleep(0.1)
    if not up:
        proc.terminate()
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.fail(f"nginx never came up on :{port}")
    try:
        yield {"url": f"root://127.0.0.1:{port}", "payload": payload}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(prefix, ignore_errors=True)


def _run_demo(demo_bin, url, segs, outfile):
    args = [demo_bin, url, "/big.bin", outfile] + [f"{o}:{l}" for (o, l) in segs]
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    return subprocess.run(args, capture_output=True, text=True, timeout=60, env=env)


def test_variable_and_capped_blocks(demo_bin, server1m, tmp_path):
    """One readv mixing tiny / mid / exactly-cap / over-cap (capped) elements,
    all within EOF and non-contiguous (no coalescing). Each block is verified for
    its actual length (got == min(req, cap)) and byte-exactness."""
    payload = server1m["payload"]
    # (offset, requested_len) — non-contiguous, all within the 5 MiB file.
    segs = [
        (100, 7),                 # tiny
        (5000, 65536),            # mid
        (200000, CAP),            # exactly the cap
        (1300000, 3 * 1024 * 1024),   # over cap -> capped/short
        (2500000, 200000),        # another size
        (3000000, 2 * 1024 * 1024),   # over cap -> capped/short
        (4194304, 1000000),       # ends at file end - within EOF
    ]
    outfile = str(tmp_path / "out.bin")
    r = _run_demo(demo_bin, server1m["url"], segs, outfile)
    assert r.returncode == 0, f"demo failed: {r.stderr}\n{r.stdout}"

    # Parse "seg <i> <off> <req> <got>" lines.
    got = {}
    for line in r.stdout.splitlines():
        f = line.split()
        if f and f[0] == "seg":
            got[int(f[1])] = (int(f[2]), int(f[3]), int(f[4]))  # off, req, got

    with open(outfile, "rb") as fh:
        blob = fh.read()

    cursor = 0
    for i, (off, req) in enumerate(segs):
        assert i in got, f"segment {i} missing from demo output"
        g_off, g_req, g_got = got[i]
        assert (g_off, g_req) == (off, req)
        expected_got = min(req, CAP)              # capped, never short of EOF here
        assert g_got == expected_got, (
            f"seg {i}: got {g_got} != expected {expected_got} (req {req}, cap {CAP})")
        block = blob[cursor:cursor + g_got]
        cursor += g_got
        assert block == payload[off:off + g_got], f"seg {i}: bytes not byte-exact"
    assert cursor == len(blob), "trailing/short data in demo output"


def test_short_eof_readv_is_a_clean_error(demo_bin, server1m, tmp_path):
    """A segment that runs short of EOF must surface as a clean client error
    (xrdc_file_readv returns -1 with status set), not a hang or partial garbage —
    the project's client correctly propagates the server's past-EOF rejection."""
    segs = [(FILE_BYTES - 1000, 65536)]   # 1000 bytes of file, 65536 requested
    outfile = str(tmp_path / "eof.bin")
    r = _run_demo(demo_bin, server1m["url"], segs, outfile)
    assert r.returncode != 0, f"expected readv error, got success:\n{r.stdout}"
    assert "readv" in (r.stderr + r.stdout).lower()

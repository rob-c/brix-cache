"""test_s3_native_authz.py — phase-101 W5.2c: native brix_authdb READ ACL on S3.

W5 unified brix_authdb onto the shared preamble but enforced it only on webdav,
leaving it accepted-but-inert on S3.  W5.2c closes that: the S3 access phase now
enforces the native u/g/p/h rules (from common.authdb_rules, deep-copied and
finalized against this export's own root) on the confined object path.

A rule-covered path is served; a path with no covering rule is default-denied
(403), and a host rule (`p <ip>`) matches on the peer — exactly like webdav and
root://.  Self-contained: spawns a single anonymous S3 server as a subprocess.

Run:  PYTHONPATH=. python3 -m pytest test_s3_native_authz.py -p no:xdist -q
"""

import os
import socket
import subprocess
import time
import urllib.request
import urllib.error

import pytest

from settings import NGINX_BIN
from ephemeral_port import free_port

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN),
    reason="nginx binary (set NGINX_BIN) not available",
)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", free_port()))  # net-literal-allow: loopback mock shim; leased mock-range port (never kernel-assigned)
    p = s.getsockname()[1]
    s.close()
    return p


def _http_code(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


@pytest.fixture()
def s3_authdb_server(tmp_path):
    data = tmp_path / "data"
    for sub in ("grant", "private", "host"):
        (data / sub).mkdir(parents=True)
        (data / sub / "f.txt").write_text(sub + "\n")
    authdb = tmp_path / "authdb"
    # u * grants /grant to anyone; a peer rule grants /host to loopback; /private
    # is covered by NO rule -> default-deny.
    authdb.write_text("u * /grant rl\np 127.0.0.1 /host r\np ::1 /host r\n")  # net-literal-allow: loopback literal is the subject under test

    port = _free_port()
    (tmp_path / "logs").mkdir()
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"worker_processes 1; daemon off; error_log {tmp_path}/logs/e.log info;\n"
        f"pid {tmp_path}/logs/p.pid;\n"
        "events { worker_connections 64; }\n"
        "http {\n"
        f"  access_log off; client_body_temp_path {tmp_path}/logs/cbt;\n"
        f"  server {{ listen 127.0.0.1:{port};\n"  # net-literal-allow: loopback literal is the subject under test
        "    location / { brix_s3 on; brix_s3_bucket b;\n"
        f"      brix_storage_backend posix:{data};\n"
        f"      brix_authdb {authdb}; }}\n"
        "  }\n"
        "}\n")

    proc = subprocess.Popen([NGINX_BIN, "-c", str(conf), "-p", str(tmp_path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # wait for the listener
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):  # net-literal-allow: probes the loopback mock shim
                break
        except OSError:
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.skip("s3 test server did not come up")
    yield f"http://127.0.0.1:{port}/b"  # net-literal-allow: URL targets the loopback mock shim
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_authdb_grants_rule_covered_path(s3_authdb_server):
    """`u * /grant rl` -> a GET under /grant is served."""
    assert _http_code(f"{s3_authdb_server}/grant/f.txt") == 200


def test_authdb_grants_host_rule_path(s3_authdb_server):
    """`p 127.0.0.1 /host r` -> the loopback peer is served under /host."""
    assert _http_code(f"{s3_authdb_server}/host/f.txt") == 200


def test_authdb_denies_uncovered_path(s3_authdb_server):
    """No rule covers /private -> default-deny (403), not a silent 200.

    This is the W5.2c guarantee: bare brix_authdb on S3 is ENFORCED, not an
    accepted-but-inert no-op."""
    assert _http_code(f"{s3_authdb_server}/private/f.txt") == 403

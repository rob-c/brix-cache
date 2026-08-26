"""
Native-client production transfer over web schemes (phase-37 §16 gap A):
xrdcp can now GET/PUT over davs:// / http(s):// (WebDAV) and s3:// (S3 REST,
AWS SigV4), not just root://.

  * WebDAV: streaming HTTP PUT/GET, bearer-token or anonymous.
  * S3:     SigV4-signed PUT (UNSIGNED-PAYLOAD) + GET (empty-body hash).

Each test self-hosts its own nginx (a WebDAV server + a SigV4-required S3 server)
on free loopback ports, so it never needs the shared fleet.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_web_transfer.py -v -p no:xdist
"""

import hashlib
import os
import socket
import subprocess
import threading
import time
from contextlib import contextmanager

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-client-web-transfer")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")
# Defined here (not only in the parent test module) so this helper's own
# functions resolve it: reexport copies helper->test, so a name the helper USES
# must live in the helper, not be stranded in the test's later top-level code.
VFS_S3_SMOKE = os.path.join(CLIENT_DIR, "bin", "vfs_s3_smoke")

S3_AK = "AKIDTESTCLIENT0001"
S3_SK = "c3RyZWFtaW5nLXNlY3JldC1rZXktZm9yLXRlc3Rpbmc="


def _free_port():
    from ephemeral_port import free_port
    return free_port(BIND_HOST)


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _md5(path):
    return hashlib.md5(path.read_bytes()).hexdigest()


def _build_tree(root):
    """Create a small nested local tree under `root`; return {rel: bytes}."""
    (root / "sub" / "deep").mkdir(parents=True)
    files = {
        "top.txt": b"top-level\n",
        "sub/mid.bin": os.urandom(2048),
        "sub/deep/leaf.dat": b"deep-leaf\n",
    }
    for rel, data in files.items():
        (root / rel).write_bytes(data)
    return files


@pytest.fixture(scope="module")
def _client_built():
    import shutil
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    r = subprocess.run(["make", "-C", CLIENT_DIR, "xrdcp"],
                       capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDCP):
        pytest.skip(f"xrdcp build failed:\n{r.stdout}\n{r.stderr}")


@pytest.fixture()
def web_servers(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    dav_data = tmp_path / "dav"
    s3_data = tmp_path / "s3"
    dav_data.mkdir()
    s3_data.mkdir()
    (s3_data / "testbucket").mkdir()

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-client-web-transfer",
        template="nginx_lc_client_web_transfer.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST,
                         "WEBDAV_DIR": str(dav_data),
                         "S3_DIR": str(s3_data),
                         "S3_ACCESS_KEY": S3_AK,
                         "S3_SECRET_KEY": S3_SK},
        reason="webdav+s3 client transfer"))
    s3_port = ep.extra_ports["S3_PORT"]

    # Harness waits on the WebDAV {PORT} only; poll the S3 port too.
    for _ in range(50):
        if _port_up(HOST, s3_port):
            break
        time.sleep(0.1)

    return {"dav_port": ep.port, "s3_port": s3_port, "root": tmp_path,
            "dav_data": dav_data}

def _mock_propfind_once(port, ready, body):
    """A throwaway HTTP server that answers one PROPFIND with `body` (207)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, port))
    srv.listen(1)
    srv.settimeout(20)
    ready.set()
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        srv.close()
        return
    try:
        conn.recv(65536)   # drain the request headers
        hdr = ("HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
        conn.sendall(hdr.encode() + body)
    except OSError:
        pass
    finally:
        conn.close()
        srv.close()


@contextmanager
def _mock_http_status(status="404 Not Found"):
    """Serve immediate empty HTTP errors until the client closes its relay."""
    port = _free_port()
    ready = threading.Event()
    stop = threading.Event()

    def serve():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((BIND_HOST, port))
        srv.listen(4)
        srv.settimeout(0.2)
        ready.set()
        try:
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                with conn:
                    try:
                        conn.recv(65536)
                        response = (f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n"
                                    "Connection: close\r\n\r\n")
                        conn.sendall(response.encode("ascii"))
                    except OSError:
                        pass
        finally:
            srv.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    if not ready.wait(5):
        raise RuntimeError("mock HTTP error server did not start")
    try:
        yield f"http://{HOST}:{port}"
    finally:
        stop.set()
        thread.join(2)



def _spool_env(tmp_path):
    """A subprocess env whose TMPDIR is an isolated dir, so we can assert the
    web->web relay leaves no staging temp behind."""
    spool = tmp_path / "spool"
    spool.mkdir(exist_ok=True)
    return dict(os.environ, TMPDIR=str(spool), XRDC_IO_TIMEOUT_MS="2000"), spool



def _build_vfs_s3_smoke():
    """Build the vfs_s3_smoke binary; skip if no C compiler or build fails."""
    import shutil
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    r = subprocess.run(["make", "-C", CLIENT_DIR, "vfs-s3-smoke"],
                       capture_output=True, text=True, timeout=300)
    if not os.path.exists(VFS_S3_SMOKE):
        pytest.skip(f"vfs-s3-smoke build failed:\n{r.stdout}\n{r.stderr}")

"""
The unified `xrd` git-style front-end: one command dispatching to xrdcp/xrdfs/xrddiag.

  xrd ls <endpoint>           -> xrdfs <endpoint> ls
  xrd get <url> [dst]         -> xrdcp <url> <dst>
  xrd put <local> <url>       -> xrdcp <local> <url>
  xrd cp ... / xrd diag ...   -> xrdcp / xrddiag

Self-hosts a writable root:// server.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_xrd_frontend.py -v -p no:xdist
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(120)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRD = os.path.join(CLIENT_DIR, "bin", "xrd")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def rw(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrd", "xrdfs", "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    for b in ("xrd", "xrdfs", "xrdcp"):
        if not os.path.exists(os.path.join(CLIENT_DIR, "bin", b)):
            pytest.skip(f"{b} build failed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("xrd")
    data = root / "data"
    data.mkdir()
    (data / "hello.bin").write_bytes(b"xrd-front-end\n")
    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
stream {{
    server {{ listen {BIND_HOST}:{port}; xrootd on; brix_storage_backend posix:{data};
             brix_auth none; brix_allow_write on; }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)
    yield {"port": port, "data": data}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _url(rw, path=""):
    return f"root://{HOST}:{rw['port']}/{path}"


def test_xrd_ls_dispatches_to_xrdfs(rw):
    p = subprocess.run([XRD, "ls", _url(rw, "/")], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "hello.bin" in p.stdout, p.stdout


def test_xrd_get(rw, tmp_path):
    out = tmp_path / "got.bin"
    p = subprocess.run([XRD, "get", _url(rw, "/hello.bin"), str(out)],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert out.read_bytes() == b"xrd-front-end\n"


def test_xrd_put_and_cp(rw, tmp_path):
    src = tmp_path / "up.bin"
    src.write_bytes(b"put-me\n")
    p = subprocess.run([XRD, "put", str(src), _url(rw, "/up.bin")],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert (rw["data"] / "up.bin").read_bytes() == b"put-me\n"
    # cp passes straight through to xrdcp (with -f)
    src2 = tmp_path / "cp.bin"
    src2.write_bytes(b"cp-me\n")
    p2 = subprocess.run([XRD, "cp", "-f", str(src2), _url(rw, "/cp.bin")],
                        capture_output=True, text=True, timeout=30)
    assert p2.returncode == 0, f"{p2.stdout}\n{p2.stderr}"
    assert (rw["data"] / "cp.bin").read_bytes() == b"cp-me\n"


def test_xrd_stat_dispatches(rw):
    p = subprocess.run([XRD, "stat", _url(rw, "/hello.bin")],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "Size:" in p.stdout, p.stdout


def test_xrd_mv_two_urls(rw):
    """Both URL operands of a 2-path verb are split to their paths (regression for the
    'only the first URL was rewritten' bug)."""
    (rw["data"] / "mvsrc.bin").write_bytes(b"move-me\n")
    p = subprocess.run([XRD, "mv", _url(rw, "/mvsrc.bin"), _url(rw, "/mvdst.bin")],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert (rw["data"] / "mvdst.bin").read_bytes() == b"move-me\n"
    assert not (rw["data"] / "mvsrc.bin").exists()


def test_xrd_mv_cross_endpoint_rejected(rw):
    """A 2-path verb spanning two different endpoints is rejected, not silently wrong."""
    p = subprocess.run([XRD, "mv", _url(rw, "/x"), "root://other.invalid:1094//y"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode != 0
    assert "same endpoint" in p.stderr, p.stderr


def test_xrd_version_and_unknown():
    v = subprocess.run([XRD, "version"], capture_output=True, text=True, timeout=10)
    assert v.returncode == 0 and "xrd" in v.stdout
    u = subprocess.run([XRD, "frobnicate"], capture_output=True, text=True, timeout=10)
    assert u.returncode != 0
    assert "unknown command" in u.stderr


def test_xrd_fs_verb_needs_endpoint():
    p = subprocess.run([XRD, "ls"], capture_output=True, text=True, timeout=10)
    assert p.returncode != 0
    assert "endpoint" in p.stderr

"""
Admin file browser/downloader on the monitoring dashboard
(GET /brix/api/v1/files + /download).

Self-contained: spins up its own nginx with a dashboard that has
brix_dashboard_browse_root pointed at a seeded tree, behind a password.

Verifies: authenticated listing (name/owner/size/mtime/btime), subdir nav,
byte-exact download, path-traversal confinement (403), 404s, auth gating (401),
and that the feature is hidden/404 when no browse_root is configured.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_dashboard_files.py -v -p no:xdist
"""

import hashlib
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from settings import HOST, BIND_HOST
from config_templates import render_config

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
DASH_PW = "files_admin_pw_42"

pytestmark = pytest.mark.timeout(120)


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("dashfiles")
    data = root / "data"
    (data / "sub").mkdir(parents=True)
    (data / "alpha.bin").write_bytes(os.urandom(1234))
    (data / "sub" / "note.txt").write_bytes(b"hello world\n")
    # a sensitive file OUTSIDE the browse root, used as the traversal target
    (root / "secret.txt").write_bytes(b"TOPSECRET\n")

    hp = _free_port()
    hp_off = _free_port()   # second server: dashboard WITHOUT browse_root
    conf = root / "nginx.conf"
    conf.write_text(render_config("nginx_dashboard_files.conf",
                                  BASE_DIR=root,
                                  BIND_HOST=BIND_HOST,
                                  PORT=hp,
                                  OFF_PORT=hp_off,
                                  PASSWORD=DASH_PW,
                                  DATA_DIR=data))
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    base = f"http://{HOST}:{hp}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/brix", timeout=2)
            break
        except Exception:
            time.sleep(0.1)
    yield {"base": base, "base_off": f"http://{HOST}:{hp_off}", "data": data,
           "alpha_md5": hashlib.md5((data / "alpha.bin").read_bytes()).hexdigest()}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "stop"], capture_output=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _login(base):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(base + "/brix/login",
                                 data=f"password={DASH_PW}".encode(), method="POST")
    try:
        hdrs = opener.open(req, timeout=5).headers
    except urllib.error.HTTPError as e:
        hdrs = e.headers
    sc = hdrs.get("Set-Cookie", "")
    return sc.split(";", 1)[0] if sc else None


def _get(base, path, cookie=None):
    req = urllib.request.Request(base + path)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.getcode(), r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def test_unauth_endpoints_are_401(server):
    for p in ("/brix/api/v1/files", "/brix/api/v1/download?path=/alpha.bin"):
        code, _, _ = _get(server["base"], p)
        assert code == 401, p


def test_list_root(server):
    cookie = _login(server["base"])
    assert cookie
    code, body, _ = _get(server["base"], "/brix/api/v1/files", cookie)
    assert code == 200
    d = json.loads(body)
    by = {e["name"]: e for e in d["entries"]}
    assert set(by) == {"alpha.bin", "sub"}
    assert by["sub"]["type"] == "dir"
    f = by["alpha.bin"]
    assert f["type"] == "file" and f["size"] == 1234
    # owner is the local account running nginx; metadata present
    assert f["owner"] and isinstance(f["uid"], int)
    assert f["mtime"] > 0 and f["btime"] >= 0


def test_list_subdir(server):
    cookie = _login(server["base"])
    code, body, _ = _get(server["base"], "/brix/api/v1/files?path=/sub", cookie)
    assert code == 200
    names = [e["name"] for e in json.loads(body)["entries"]]
    assert names == ["note.txt"]


def test_download_byte_exact(server):
    cookie = _login(server["base"])
    code, body, hdrs = _get(server["base"],
                            "/brix/api/v1/download?path=/alpha.bin", cookie)
    assert code == 200
    assert hashlib.md5(body).hexdigest() == server["alpha_md5"]
    assert "attachment" in hdrs.get("Content-Disposition", "")
    assert "alpha.bin" in hdrs.get("Content-Disposition", "")


@pytest.mark.parametrize("path", ["../secret.txt", "/../secret.txt",
                                  "/sub/../../secret.txt"])
def test_traversal_is_confined(server, path):
    cookie = _login(server["base"])
    code, body, _ = _get(server["base"],
                         "/brix/api/v1/download?path=" + path, cookie)
    assert code == 403
    assert b"TOPSECRET" not in body


def test_404s(server):
    cookie = _login(server["base"])
    assert _get(server["base"], "/brix/api/v1/download?path=/nope", cookie)[0] == 404
    # a directory is not a download
    assert _get(server["base"], "/brix/api/v1/download?path=/sub", cookie)[0] == 404


def test_disabled_without_browse_root(server):
    cookie = _login(server["base_off"])
    assert _get(server["base_off"], "/brix/api/v1/files", cookie)[0] == 404
    assert _get(server["base_off"],
                "/brix/api/v1/download?path=/x", cookie)[0] == 404


def test_page_has_file_viewer(server):
    cookie = _login(server["base"])
    code, body, _ = _get(server["base"], "/brix", cookie)
    assert code == 200
    assert b"files-section" in body and b"filesBrowse" in body

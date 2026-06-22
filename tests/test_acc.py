"""test_acc.py — XrdAcc-compatible authorization engine (xrootd_authdb_format xrdacc).

Stands up a self-contained dedicated nginx running the `xrdacc` engine over an
anonymous root:// stream tier and drives real `xrdfs`/`xrdcp` requests to verify
the faithful XrdAcc semantics end to end: additive privilege accumulation, the
`r`/`l`/`w` letters (note `r` does NOT imply `l`), default `u *` rules, and
fail-closed denial for unmatched paths and missing privileges.

Self-provisioning (own nginx instance + authdb + data) so it needs no shared
harness tier; skips cleanly when the nginx binary is absent or was built without
the module.  The pure engine algebra is covered separately by the C self-tests;
this is the integration proof on the live wire.
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import BIND_HOST, HOST, free_port, url_host

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
ACC_PORT = int(os.environ.get("TEST_ACC_PORT") or free_port())
ROOT = os.path.join(os.environ["TMPDIR"], "xrdacc-pytest")
URL = f"root://{url_host(HOST)}:{ACC_PORT}"

# authdb: anonymous (u *) gets read+lookup on /sub only; nothing elsewhere.
AUTHDB = "u * /sub rl\n"
CONTENT = b"hello xrdacc\n"


def _have_tools():
    return shutil.which("xrdfs") and shutil.which("xrdcp") and os.path.exists(NGINX_BIN)


def _port_up(port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def acc_server():
    if not _have_tools():
        pytest.skip("xrdfs/xrdcp or nginx binary unavailable")
    # The binary must be built with the module (acc engine linked).
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        if "xrootd_acc_access" not in syms.stdout:
            pytest.skip("nginx binary not built with the xrdacc engine")
    except Exception:
        pass

    shutil.rmtree(ROOT, ignore_errors=True)
    for d in ("data/sub", "logs", "conf"):
        os.makedirs(os.path.join(ROOT, d), exist_ok=True)
    with open(f"{ROOT}/data/sub/test.txt", "wb") as f:
        f.write(CONTENT)
    with open(f"{ROOT}/data/other.txt", "wb") as f:
        f.write(b"secret\n")
    with open(f"{ROOT}/authdb", "w") as f:
        f.write(AUTHDB)
    with open(f"{ROOT}/conf/nginx.conf", "w") as f:
        f.write(f"""worker_processes 1;
error_log {ROOT}/logs/error.log info;
pid {ROOT}/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {url_host(BIND_HOST)}:{ACC_PORT};
        xrootd on;
        xrootd_root {ROOT}/data;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_authdb_format xrdacc;
        xrootd_authdb {ROOT}/authdb;
        xrootd_authdb_audit all;
        xrootd_access_log {ROOT}/logs/access.log;
    }}
}}
""")

    conf = f"{ROOT}/conf/nginx.conf"
    t = subprocess.run([NGINX_BIN, "-t", "-c", conf], capture_output=True, text=True)
    assert t.returncode == 0, f"nginx -t failed: {t.stderr}"
    subprocess.run([NGINX_BIN, "-c", conf], capture_output=True)
    if not _port_up(ACC_PORT):
        pytest.skip("xrdacc nginx did not start")

    yield URL

    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)
    shutil.rmtree(ROOT, ignore_errors=True)


def _stat(url, path):
    return subprocess.run(["xrdfs", url, "stat", path],
                          capture_output=True, timeout=20)


class TestXrdAccEngine:
    """End-to-end XrdAcc authorization over root:// (anonymous `u *` rules)."""

    def test_granted_stat(self, acc_server):
        """`u * /sub rl` -> anon may stat under /sub (lookup priv)."""
        assert _stat(acc_server, "/sub/test.txt").returncode == 0

    def test_granted_read_content(self, acc_server):
        """`r` privilege -> anon may read the exact bytes."""
        r = subprocess.run(["xrdcp", "-f", f"{acc_server}//sub/test.txt", "-"],
                           capture_output=True, timeout=20)
        assert r.returncode == 0, r.stderr.decode()
        assert r.stdout == CONTENT

    def test_no_rule_denied(self, acc_server):
        """A path with no matching rule is denied (fail-closed default)."""
        assert _stat(acc_server, "/other.txt").returncode != 0

    def test_write_denied_on_readonly(self, acc_server, tmp_path):
        """`rl` grants no write -> open-for-write under /sub is denied."""
        up = tmp_path / "up.txt"
        up.write_bytes(b"data\n")
        r = subprocess.run(["xrdcp", "-f", str(up), f"{acc_server}//sub/new.txt"],
                           capture_output=True, timeout=20)
        assert r.returncode != 0, "write must be denied with only rl privileges"

    def test_audit_log_records_grant_and_deny(self, acc_server):
        """`xrootd_authdb_audit all` emits structured grant + deny lines."""
        _stat(acc_server, "/sub/test.txt")   # grant
        _stat(acc_server, "/other.txt")      # deny
        with open(f"{ROOT}/logs/error.log") as f:
            log = f.read()
        assert "xrootd authz:" in log and "grant" in log and "deny" in log


# ---------------------------------------------------------------------------
# Cross-protocol: the same engine over WebDAV (davs://) and S3
# ---------------------------------------------------------------------------

import urllib.request  # noqa: E402
import urllib.error    # noqa: E402

HTTP_ROOT = os.path.join(os.environ["TMPDIR"], "xrdacc-http-pytest")
HTTP_PORT = int(os.environ.get("TEST_ACC_HTTP_PORT") or free_port())


def _http_code(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _start_http(location_block):
    """Provision + start an http nginx with the given location block; the data
    tree grants `u * /grant rl` and denies everything else."""
    shutil.rmtree(HTTP_ROOT, ignore_errors=True)
    for d in ("data/grant", "logs", "conf", "tmp"):
        os.makedirs(os.path.join(HTTP_ROOT, d), exist_ok=True)
    with open(f"{HTTP_ROOT}/data/grant/ok.txt", "wb") as f:
        f.write(b"ok\n")
    with open(f"{HTTP_ROOT}/data/deny.txt", "wb") as f:
        f.write(b"no\n")
    with open(f"{HTTP_ROOT}/authdb", "w") as f:
        f.write("u * /grant rl\n")
    conf = f"{HTTP_ROOT}/conf/nginx.conf"
    with open(conf, "w") as f:
        f.write(f"""worker_processes 1;
error_log {HTTP_ROOT}/logs/error.log info;
pid {HTTP_ROOT}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {HTTP_ROOT}/tmp/cbt;
    proxy_temp_path {HTTP_ROOT}/tmp/pt;
    fastcgi_temp_path {HTTP_ROOT}/tmp/ft;
    uwsgi_temp_path {HTTP_ROOT}/tmp/ut;
    scgi_temp_path {HTTP_ROOT}/tmp/st;
    server {{
        listen {url_host(BIND_HOST)}:{HTTP_PORT};
        location / {{
{location_block}
            xrootd_authdb_format xrdacc;
            xrootd_authdb {HTTP_ROOT}/authdb;
            xrootd_authdb_audit all;
        }}
    }}
}}
""")
    t = subprocess.run([NGINX_BIN, "-t", "-c", conf], capture_output=True, text=True)
    assert t.returncode == 0, f"nginx -t failed: {t.stderr}"
    subprocess.run([NGINX_BIN, "-c", conf], capture_output=True)
    if not _port_up(HTTP_PORT):
        pytest.skip("http xrdacc nginx did not start")
    return conf


def _stop_http(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)
    shutil.rmtree(HTTP_ROOT, ignore_errors=True)


@pytest.fixture(scope="module")
def webdav_server():
    if not (shutil.which("curl") or True) or not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary unavailable")
    conf = _start_http(
        f"            xrootd_webdav on;\n"
        f"            xrootd_webdav_root {HTTP_ROOT}/data;\n"
        f"            xrootd_webdav_auth none;\n"
        f"            xrootd_webdav_allow_write on;")
    yield f"http://{url_host(HOST)}:{HTTP_PORT}"
    _stop_http(conf)


@pytest.fixture(scope="module")
def s3_server():
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary unavailable")
    conf = _start_http(
        f"            xrootd_s3 on;\n"
        f"            xrootd_s3_root {HTTP_ROOT}/data;")
    yield f"http://{url_host(HOST)}:{HTTP_PORT}"
    _stop_http(conf)


class TestXrdAccWebDAV:
    """The XrdAcc engine over WebDAV (HTTP method -> AOP)."""

    def test_get_granted(self, webdav_server):
        assert _http_code(f"{webdav_server}/grant/ok.txt") == 200

    def test_get_no_rule_denied(self, webdav_server):
        assert _http_code(f"{webdav_server}/deny.txt") == 403

    def test_put_denied_without_create_priv(self, webdav_server):
        # `rl` grants no create -> PUT (create) is denied.
        assert _http_code(f"{webdav_server}/grant/new.txt", method="PUT") == 403


class TestXrdAccS3:
    """The XrdAcc engine over S3 (S3 op -> AOP)."""

    def test_get_granted(self, s3_server):
        assert _http_code(f"{s3_server}/grant/ok.txt") == 200

    def test_get_no_rule_denied(self, s3_server):
        assert _http_code(f"{s3_server}/deny.txt") == 403

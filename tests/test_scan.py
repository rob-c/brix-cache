"""
Storage-scan engine (src/scan/) — phase-2 base engine.

This module currently covers the ngx-free, standalone-testable engine cores
(compiled + run outside the nginx module, like csi_unittest.c):

  * scan_record   — NDJSON record formatting (file / cursor / summary) + JSON
                    string escaping.
  * scan_throttle — token-bucket rate math, budget check, adaptive multiplier.
  * scan_emit     — ordered reorder buffer (out-of-order worker completion still
                    emits in walk order; window-overflow / late-seq rejected).

The HTTP-endpoint integration (dump/verify/fill/compare over chunked NDJSON)
lands with src/scan/scan_http.c and will add a live fixture here.

See docs/superpowers/specs/2026-06-29-storage-scan-verify-design.md and
docs/superpowers/specs/2026-06-29-client-backend-sysadmin-tooling-design.md.
"""
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import zlib

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN = os.path.join(REPO, "src", "scan")
SRCS = [
    os.path.join(SCAN, "scan_unittest.c"),
    os.path.join(SCAN, "scan_record.c"),
    os.path.join(SCAN, "scan_throttle.c"),
    os.path.join(SCAN, "scan_emit.c"),
    os.path.join(SCAN, "scan_drift.c"),
]


@pytest.fixture(scope="module")
def scan_core_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not all(os.path.exists(s) for s in SRCS):
        pytest.skip("src/scan sources missing")
    out = str(tmp_path_factory.mktemp("scan") / "ut")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", SCAN, "-o", out, *SRCS, "-lm"],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("scan cores failed to COMPILE (warnings are errors):\n%s"
                    % r.stderr)
    return out


def test_scan_core_suite(scan_core_bin):
    r = subprocess.run([scan_core_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        "scan core suite reported failures:\n%s\n%s" % (r.stdout, r.stderr)
    assert "all checks passed" in r.stdout


# --------------------------------------------------------------------------- #
# HTTP integration — GET /xrootd/api/v1/scan (dump/verify/fill) over a         #
# self-contained nginx with xrootd_scan_root on a seeded tree (mirrors         #
# test_dashboard_files.py's provisioning).                                     #
# --------------------------------------------------------------------------- #
from settings import HOST, BIND_HOST  # noqa: E402

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
SCAN_PW = "scan_admin_pw_42"

A_BYTES = b"A" * 1000
B_BYTES = b"B" * 2000


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _xattr_supported(path):
    try:
        os.setxattr(path, "user.scanprobe", b"1")
        os.removexattr(path, "user.scanprobe")
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def scan_server(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx not executable: %s" % NGINX_BIN)

    root = tmp_path_factory.mktemp("scansrv")
    data = root / "data"
    (data / "sub").mkdir(parents=True)
    (data / "a.bin").write_bytes(A_BYTES)
    (data / "sub" / "b.bin").write_bytes(B_BYTES)
    (root / "secret.txt").write_bytes(b"TOPSECRET\n")   # outside scan_root

    xattr_ok = _xattr_supported(str(data / "a.bin"))

    hp = _free_port()
    hp_off = _free_port()
    conf = root / "nginx.conf"
    conf.write_text("""
worker_processes 1;
pid %(root)s/nginx.pid;
error_log %(root)s/error.log info;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path %(root)s/tmp;
    proxy_temp_path %(root)s/tmp;
    fastcgi_temp_path %(root)s/tmp;
    uwsgi_temp_path %(root)s/tmp;
    scgi_temp_path %(root)s/tmp;
    server {
        listen %(bind)s:%(hp)d;
        location /xrootd { xrootd_dashboard on; xrootd_dashboard_password "%(pw)s";
                           xrootd_scan_root %(data)s; }
    }
    server {
        listen %(bind)s:%(hp_off)d;
        location /xrootd { xrootd_dashboard on; xrootd_dashboard_password "%(pw)s"; }
    }
}
""" % {"root": root, "bind": BIND_HOST, "hp": hp, "hp_off": hp_off,
       "pw": SCAN_PW, "data": data})

    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    base = "http://%s:%d" % (HOST, hp)
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/xrootd", timeout=2)
            break
        except Exception:
            time.sleep(0.1)
    yield {"base": base, "base_off": "http://%s:%d" % (HOST, hp_off),
           "data": data, "xattr_ok": xattr_ok}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "stop"], capture_output=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _login(base):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(base + "/xrootd/login",
                                 data=("password=%s" % SCAN_PW).encode(),
                                 method="POST")
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
        r = urllib.request.urlopen(req, timeout=15)
        return r.getcode(), r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def _ndjson(body):
    return [json.loads(ln) for ln in body.splitlines() if ln.strip()]


def _files(recs):
    return {r["path"].lstrip("/"): r for r in recs if r["t"] == "file"}


def _summary(recs):
    s = [r for r in recs if r["t"] == "summary"]
    assert len(s) == 1, "exactly one summary record"
    return s[0]


def test_scan_unauth_is_401(scan_server):
    code, _, _ = _get(scan_server["base"], "/xrootd/api/v1/scan?mode=dump")
    assert code == 401


def test_scan_disabled_is_404(scan_server):
    cookie = _login(scan_server["base_off"])
    code, _, _ = _get(scan_server["base_off"],
                      "/xrootd/api/v1/scan?mode=dump", cookie)
    assert code == 404


def test_scan_bad_mode_is_400(scan_server):
    cookie = _login(scan_server["base"])
    code, _, _ = _get(scan_server["base"],
                      "/xrootd/api/v1/scan?mode=bogus", cookie)
    assert code == 400


def test_scan_dump(scan_server):
    cookie = _login(scan_server["base"])
    code, body, hdrs = _get(scan_server["base"],
                            "/xrootd/api/v1/scan?mode=dump", cookie)
    assert code == 200, body
    assert "ndjson" in hdrs.get("Content-Type", "")
    recs = _ndjson(body)
    files = _files(recs)
    assert set(files) == {"a.bin", "sub/b.bin"}, files
    assert files["a.bin"]["size"] == 1000
    assert files["sub/b.bin"]["size"] == 2000
    assert _summary(recs)["files"] == 2


def test_scan_verify_fresh_tree_reports_missing(scan_server):
    """No stored checksums yet ⇒ verify recomputes and reports 'missing',
    with the freshly computed digest present. (xattr-independent.)"""
    cookie = _login(scan_server["base"])
    code, body, _ = _get(scan_server["base"],
                         "/xrootd/api/v1/scan?mode=verify&alg=adler32", cookie)
    assert code == 200, body
    files = _files(_ndjson(body))
    want_a = "%08x" % (zlib.adler32(A_BYTES) & 0xffffffff)
    assert files["a.bin"]["status"] == "missing"
    assert files["a.bin"]["computed"] == want_a
    assert _summary(_ndjson(body))["missing"] == 2


def test_scan_traversal_is_confined(scan_server):
    cookie = _login(scan_server["base"])
    code, body, _ = _get(scan_server["base"],
                         "/xrootd/api/v1/scan?mode=dump&path=../secret.txt",
                         cookie)
    # confined: the secret outside scan_root must never be reported
    assert code in (403, 404) or "secret" not in body, (code, body)


def test_scan_fill_then_verify_and_corruption(scan_server):
    if not scan_server["xattr_ok"]:
        pytest.skip("filesystem does not support user xattrs (no checksum-at-rest)")
    base, cookie = scan_server["base"], _login(scan_server["base"])

    # fill: persist checksums where none exist
    code, body, _ = _get(base, "/xrootd/api/v1/scan?mode=fill&alg=adler32", cookie)
    assert code == 200, body
    files = _files(_ndjson(body))
    assert files["a.bin"]["status"] in ("filled", "already")
    assert _summary(_ndjson(body))["filled"] >= 1 or \
        _summary(_ndjson(body))["already"] >= 1

    # verify: now everything matches
    cookie = _login(base)
    code, body, _ = _get(base, "/xrootd/api/v1/scan?mode=verify&alg=adler32", cookie)
    assert code == 200, body
    files = _files(_ndjson(body))
    assert files["a.bin"]["status"] == "ok"
    assert files["a.bin"]["stored"] == files["a.bin"]["computed"]

    # Simulate silent bit-rot: corrupt the bytes but PRESERVE mtime/size, so the
    # stored checksum is not treated as stale — verify must catch the mismatch.
    a = scan_server["data"] / "a.bin"
    pre = os.stat(a)
    a.write_bytes(b"X" * 1000)
    # restore mtime at NANOSECOND precision (the checksum-at-rest record pins
    # tv_sec AND tv_nsec; float os.utime would lose nsec and read as stale)
    os.utime(a, ns=(pre.st_atime_ns, pre.st_mtime_ns))
    cookie = _login(base)
    code, body, _ = _get(base, "/xrootd/api/v1/scan?mode=verify&alg=adler32", cookie)
    assert code == 200, body
    files = _files(_ndjson(body))
    assert files["a.bin"]["status"] == "mismatch", files["a.bin"]
    assert _summary(_ndjson(body))["mismatch"] == 1
    # restore for idempotent re-runs
    (scan_server["data"] / "a.bin").write_bytes(A_BYTES)


# --------------------------------------------------------------------------- #
# Client subcommands — xrdstorascan dump/verify/fill over the /scan endpoint.  #
# --------------------------------------------------------------------------- #
CLIENT_BIN = os.path.join(REPO, "client", "bin", "xrdstorascan")


def _storascan(*args, password=SCAN_PW):
    env = dict(os.environ)
    if password is not None:
        env["XRDSTORASCAN_PASSWORD"] = password
    else:
        env.pop("XRDSTORASCAN_PASSWORD", None)
    return subprocess.run([CLIENT_BIN, *args], capture_output=True, text=True,
                          env=env, timeout=60)


@pytest.fixture
def client(scan_server):
    if not os.path.exists(CLIENT_BIN):
        pytest.skip("xrdstorascan client not built")
    return scan_server["base"]


def test_client_dump(client):
    r = _storascan("dump", client, "--json")
    assert r.returncode == 0, r.stderr
    recs = [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]
    paths = {x["path"] for x in recs if x.get("t") == "file"}
    assert "/a.bin" in paths and "/sub/b.bin" in paths, r.stdout


def test_client_bad_password_fails(client):
    r = _storascan("dump", client, "--password", "wrong-pw", password=None)
    assert r.returncode != 0


def test_client_fill_verify_corruption(client, scan_server):
    if not scan_server["xattr_ok"]:
        pytest.skip("filesystem does not support user xattrs")

    # fill, then verify clean
    assert _storascan("fill", client, "--algo", "adler32").returncode == 0
    assert _storascan("verify", client, "--algo", "adler32").returncode == 0

    # silent bit-rot on a.bin (preserve mtime/size)
    a = scan_server["data"] / "a.bin"
    pre = os.stat(a)
    a.write_bytes(b"Z" * 1000)
    os.utime(a, ns=(pre.st_atime_ns, pre.st_mtime_ns))

    r = _storascan("verify", client, "--algo", "adler32")
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)  # SX_MISMATCH

    # restore + re-fill so the shared fixture is clean for later tests
    a.write_bytes(A_BYTES)
    _storascan("fill", client, "--algo", "adler32")


# --------------------------------------------------------------------------- #
# Phase 3 — inspect (A2) + health (C1) point queries.                          #
# --------------------------------------------------------------------------- #
def test_scan_inspect(scan_server):
    cookie = _login(scan_server["base"])
    code, body, _ = _get(scan_server["base"],
                         "/xrootd/api/v1/scan?mode=inspect&path=/a.bin", cookie)
    assert code == 200, body
    recs = _ndjson(body)
    insp = [r for r in recs if r.get("t") == "inspect"]
    assert len(insp) == 1, recs
    r = insp[0]
    assert r["path"] == "/a.bin"
    assert r["backend"] == "posix"
    assert r["namespace_consistent"] is True
    assert r["stored_src"] in ("none", "xattr")


def test_scan_health(scan_server):
    cookie = _login(scan_server["base"])
    code, body, _ = _get(scan_server["base"],
                         "/xrootd/api/v1/scan?mode=health", cookie)
    assert code == 200, body
    recs = _ndjson(body)
    h = [r for r in recs if r.get("t") == "health"]
    assert len(h) == 1, recs
    assert h[0]["backend"] == "posix"
    assert h[0]["total_bytes"] > 0
    assert h[0]["used_bytes"] + h[0]["free_bytes"] <= h[0]["total_bytes"]


def test_client_inspect(client):
    r = _storascan("inspect", client, "--path", "/a.bin", "--json")
    assert r.returncode == 0, r.stderr
    recs = [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]
    insp = [x for x in recs if x.get("t") == "inspect"]
    assert insp and insp[0]["backend"] == "posix", r.stdout


def test_client_health(client):
    r = _storascan("health", client, "--json")
    assert r.returncode == 0, r.stderr
    recs = [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]
    h = [x for x in recs if x.get("t") == "health"]
    assert h and h[0]["total_bytes"] > 0, r.stdout

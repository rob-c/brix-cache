"""
Storage-scan engine (src/fs/scan/) — phase-2 base engine.

This module currently covers the ngx-free, standalone-testable engine cores
(compiled + run outside the nginx module, like csi_unittest.c):

  * scan_record   — NDJSON record formatting (file / cursor / summary) + JSON
                    string escaping.
  * scan_throttle — token-bucket rate math, budget check, adaptive multiplier.
  * scan_emit     — ordered reorder buffer (out-of-order worker completion still
                    emits in walk order; window-overflow / late-seq rejected).

The HTTP-endpoint integration (dump/verify/fill/compare over chunked NDJSON)
lands with src/fs/scan/scan_http.c and will add a live fixture here.

See docs/superpowers/specs/2026-06-29-storage-scan-verify-design.md and
docs/superpowers/specs/2026-06-29-client-backend-sysadmin-tooling-design.md.
"""
import json
import os
import pathlib
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import zlib

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN = os.path.join(REPO, "src", "fs", "scan")
SRCS = [
    os.path.join(SCAN, "scan_unittest.c"),
    os.path.join(SCAN, "scan_record.c"),
    os.path.join(SCAN, "scan_throttle.c"),
    os.path.join(SCAN, "scan_emit.c"),
    os.path.join(SCAN, "scan_drift.c"),
]


@pytest.fixture(scope="module")
def scan_core_bin(tmp_path_factory):
    cc = _c_compiler()
    if cc is None:
        pytest.skip("no C compiler")
    if not _scan_sources_present():
        pytest.skip("src/fs/scan sources missing")
    out = str(tmp_path_factory.mktemp("scan") / "ut")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", SCAN, "-o", out, *SRCS, "-lm"],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("scan cores failed to COMPILE (warnings are errors):\n%s"
                    % r.stderr)
    return out


def _c_compiler():
    return shutil.which("gcc") or shutil.which("cc")


def _scan_sources_present():
    return all(os.path.exists(source) for source in SRCS)


def test_scan_core_suite(scan_core_bin):
    r = subprocess.run([scan_core_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        "scan core suite reported failures:\n%s\n%s" % (r.stdout, r.stderr)
    assert "all checks passed" in r.stdout


# --------------------------------------------------------------------------- #
# HTTP integration — GET /brix/api/v1/scan (dump/verify/fill) over a         #
# self-contained nginx with brix_dashboard_scan_root on a seeded tree (mirrors         #
# test_dashboard_files.py's provisioning).                                     #
# --------------------------------------------------------------------------- #
from settings import HOST, BIND_HOST, NGINX_BIN  # noqa: E402
from server_registry import NginxInstanceSpec  # noqa: E402

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-scan-dashboard")]

SCAN_PW = "scan_admin_pw_42"

A_BYTES = b"A" * 1000
B_BYTES = b"B" * 2000


def _xattr_supported(path):
    try:
        os.setxattr(path, "user.scanprobe", b"1")
        os.removexattr(path, "user.scanprobe")
        return True
    except OSError:
        return False


@pytest.fixture()
def scan_server(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx not executable: %s" % NGINX_BIN)

    # brix_dashboard_scan_root is validated at config-parse time, so the tree must exist
    # before start().  Seed it under tmp_path: scan_root = <root>/data, with a
    # secret one level up (outside scan_root) for the traversal probe.
    root = tmp_path / "scanroot"
    data = root / "data"
    (data / "sub").mkdir(parents=True)
    (data / "a.bin").write_bytes(A_BYTES)
    (data / "sub" / "b.bin").write_bytes(B_BYTES)
    (root / "secret.txt").write_bytes(b"TOPSECRET\n")   # outside scan_root

    xattr_ok = _xattr_supported(str(data / "a.bin"))

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-scan-dashboard",
        template="nginx_lc_scan_dashboard.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST, "PASSWORD": SCAN_PW,
                         "DATA_DIR": str(data)},
        reason="storage-scan dashboard endpoint over a seeded tree"))
    off_port = ep.extra_ports["OFF_PORT"]

    base = "http://%s:%d" % (HOST, ep.port)
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/brix", timeout=2)
            break
        except Exception:
            time.sleep(0.1)
    return {"base": base, "base_off": "http://%s:%d" % (HOST, off_port),
            "data": data, "xattr_ok": xattr_ok}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _login(base):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(base + "/brix/login",
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


def _records_of_type(records, kind):
    return [record for record in records if record.get("t") == kind]


def _single_record(records, kind):
    matches = _records_of_type(records, kind)
    assert len(matches) == 1, records
    return matches[0]


def _client_records(result):
    assert result.returncode == 0, result.stderr
    return _ndjson(result.stdout)


def _assert_inspect_record(record):
    actual = {key: record[key] for key in ("path", "backend", "namespace_consistent")}
    expected = {"path": "/a.bin", "backend": "posix", "namespace_consistent": True}
    assert actual == expected
    assert record["stored_src"] in ("none", "xattr")


def _assert_health_record(record):
    assert record["backend"] == "posix"
    assert record["total_bytes"] > 0
    used = record["used_bytes"] + record["free_bytes"]
    assert used <= record["total_bytes"]


def _scan_fill(base, cookie):
    code, body, _ = _get(base, "/brix/api/v1/scan?mode=fill&alg=adler32", cookie)
    assert code == 200, body
    assert _files(_ndjson(body))["a.bin"]["status"] in ("filled", "already")
    summary = _summary(_ndjson(body))
    assert summary["filled"] >= 1 or summary["already"] >= 1


def _scan_verify(base, cookie, expected):
    code, body, _ = _get(base, "/brix/api/v1/scan?mode=verify&alg=adler32", cookie)
    assert code == 200, body
    record = _files(_ndjson(body))["a.bin"]
    assert record["status"] == expected, record
    return record, _summary(_ndjson(body))


def test_scan_unauth_is_401(scan_server):
    code, _, _ = _get(scan_server["base"], "/brix/api/v1/scan?mode=dump")
    assert code == 401


def test_scan_disabled_is_404(scan_server):
    cookie = _login(scan_server["base_off"])
    code, _, _ = _get(scan_server["base_off"],
                      "/brix/api/v1/scan?mode=dump", cookie)
    assert code == 404


def test_scan_bad_mode_is_400(scan_server):
    cookie = _login(scan_server["base"])
    code, _, _ = _get(scan_server["base"],
                      "/brix/api/v1/scan?mode=bogus", cookie)
    assert code == 400


def test_scan_dump(scan_server):
    cookie = _login(scan_server["base"])
    code, body, hdrs = _get(scan_server["base"],
                            "/brix/api/v1/scan?mode=dump", cookie)
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
                         "/brix/api/v1/scan?mode=verify&alg=adler32", cookie)
    assert code == 200, body
    files = _files(_ndjson(body))
    want_a = "%08x" % (zlib.adler32(A_BYTES) & 0xffffffff)
    assert files["a.bin"]["status"] == "missing"
    assert files["a.bin"]["computed"] == want_a
    assert _summary(_ndjson(body))["missing"] == 2


def test_scan_traversal_is_confined(scan_server):
    cookie = _login(scan_server["base"])
    code, body, _ = _get(scan_server["base"],
                         "/brix/api/v1/scan?mode=dump&path=../secret.txt",
                         cookie)
    # confined: the secret outside scan_root must never be reported
    assert code in (403, 404) or "secret" not in body, (code, body)


def test_scan_fill_then_verify_and_corruption(scan_server):
    if not scan_server["xattr_ok"]:
        pytest.skip("filesystem does not support user xattrs (no checksum-at-rest)")
    base, cookie = scan_server["base"], _login(scan_server["base"])
    _scan_fill(base, cookie)
    record, _ = _scan_verify(base, _login(base), "ok")
    assert record["stored"] == record["computed"]

    # Simulate silent bit-rot: corrupt the bytes but PRESERVE mtime/size, so the
    # stored checksum is not treated as stale — verify must catch the mismatch.
    a = scan_server["data"] / "a.bin"
    pre = os.stat(a)
    a.write_bytes(b"X" * 1000)
    # restore mtime at NANOSECOND precision (the checksum-at-rest record pins
    # tv_sec AND tv_nsec; float os.utime would lose nsec and read as stale)
    os.utime(a, ns=(pre.st_atime_ns, pre.st_mtime_ns))
    _, summary = _scan_verify(base, _login(base), "mismatch")
    assert summary["mismatch"] == 1
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
    paths = {record["path"] for record in _records_of_type(_client_records(r), "file")}
    assert {"/a.bin", "/sub/b.bin"} <= paths, r.stdout


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
                         "/brix/api/v1/scan?mode=inspect&path=/a.bin", cookie)
    assert code == 200, body
    _assert_inspect_record(_single_record(_ndjson(body), "inspect"))


def test_scan_health(scan_server):
    cookie = _login(scan_server["base"])
    code, body, _ = _get(scan_server["base"],
                         "/brix/api/v1/scan?mode=health", cookie)
    assert code == 200, body
    _assert_health_record(_single_record(_ndjson(body), "health"))


def test_client_inspect(client):
    r = _storascan("inspect", client, "--path", "/a.bin", "--json")
    record = _single_record(_client_records(r), "inspect")
    assert record["backend"] == "posix", r.stdout


def test_client_health(client):
    r = _storascan("health", client, "--json")
    record = _single_record(_client_records(r), "health")
    assert record["total_bytes"] > 0, r.stdout

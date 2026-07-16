"""
Backend Storage observability tests (spec 2026-07-03).

Self-contained nginx: one default-POSIX WebDAV export + dashboard + /metrics,
plus a second export whose backend names a root:// origin (dead port — the
registry census is config-time, the origin is never contacted).

Asserts the five spec scenarios:
  1. capacity: storage.exports has backend "posix" with statvfs numbers, and
     /metrics carries brix_storage_bytes_total{...backend="posix"} — proving
     the default-POSIX census registration too;
  2. byte accounting: PUT then GET N bytes moves the posix written/read
     counters by >= N on BOTH surfaces;
  3. sendfile attribution: the GET above is the zero-copy path (cleartext
     posix) — the read counter movement guards the serve_file_ranged seam;
  4. remote export: the xroot-backed export reports remote:true and NO
     statvfs numbers, and nothing crashes;
  5. redaction: the anonymous snapshot's storage section carries no root/
     origin keys and no filesystem path; the authed one carries root.
"""

import json
import os
import time
import urllib.error
import urllib.request

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN, TEST_ROOT
from server_registry import NginxInstanceSpec

DASH_PW = "storage_panel_pw_1"
N = 4 * 1024 * 1024  # transfer size: large enough to dwarf noise


pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture
def server(lifecycle):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    # The xroot-backed export needs a real namespace dir at config-parse time
    # (its dead origin is never contacted); create it before render.
    remote_ns = os.path.join(TEST_ROOT, f"storpanel-remote-ns-{os.getpid()}")
    os.makedirs(remote_ns, exist_ok=True)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-storage-backend-panel",
        template="nginx_lc_storage_backend_panel.conf",
        protocol="webdav",
        template_values={"BIND_HOST": BIND_HOST, "PASSWORD": DASH_PW,
                         "REMOTE_NS": remote_ns},
        reason="backend storage observability panel coverage"))

    data = ep.data_root

    base = f"http://{HOST}:{ep.port}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/brix/api/v1/snapshot", timeout=2)
            break
        except Exception:
            time.sleep(0.1)
    yield {"base": base, "data": str(data)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop at the login 302 so its Set-Cookie header is observable."""

    def redirect_request(self, *args, **kwargs):
        return None


def _login(base):
    data = f"password={DASH_PW}".encode()
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(base + "/brix/login", data=data,
                                 method="POST")
    try:
        hdrs = opener.open(req, timeout=5).headers
    except urllib.error.HTTPError as e:
        hdrs = e.headers
    sc = hdrs.get("Set-Cookie", "")
    return sc.split(";", 1)[0] if sc else None


def _http(url, data=None, method=None, cookie=None):
    headers = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, r.read()


def _snapshot(server, cookie=None):
    _, body = _http(server["base"] + "/brix/api/v1/snapshot", cookie=cookie)
    return json.loads(body)


def _metrics(server):
    _, body = _http(server["base"] + "/metrics")
    return body.decode()


def _metric(text, name, **labels):
    """Sum all samples of `name` whose labels include **labels; None if absent."""
    total, found = 0, False
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        if all('%s="%s"' % kv in line for kv in labels.items()):
            total += int(float(line.rsplit(" ", 1)[1]))
            found = True
    return total if found else None


def test_capacity_and_census(server):
    text = _metrics(server)
    assert _metric(text, "brix_storage_bytes_total", backend="posix"), \
        "default-posix export missing from capacity gauges (census gap?)"

    snap = _snapshot(server)
    posix = [e for e in snap["storage"]["exports"] if e["backend"] == "posix"]
    assert posix, "posix export missing from snapshot storage census"
    assert posix[0]["bytes_total"] > 0
    assert posix[0]["remote"] is False


def test_byte_accounting_put_get_sendfile(server):
    before = _metrics(server)
    w0 = _metric(before, "brix_storage_io_bytes_written", backend="posix") or 0
    r0 = _metric(before, "brix_storage_io_bytes_read", backend="posix") or 0

    payload = os.urandom(N)
    status, _ = _http(server["base"] + "/acct.bin", data=payload, method="PUT")
    assert status in (201, 204)
    status, got = _http(server["base"] + "/acct.bin")
    assert status == 200 and got == payload      # zero-copy sendfile serve

    after = _metrics(server)
    w1 = _metric(after, "brix_storage_io_bytes_written", backend="posix")
    r1 = _metric(after, "brix_storage_io_bytes_read", backend="posix")
    assert w1 - w0 >= N, f"written moved {w1 - w0}, want >= {N}"
    assert r1 - r0 >= N, f"read (sendfile seam) moved {r1 - r0}, want >= {N}"

    snap = _snapshot(server)
    assert snap["storage"]["io"]["posix"]["bytes_read_total"] >= N
    assert snap["storage"]["io"]["posix"]["bytes_written_total"] >= N


def test_remote_export_census(server):
    snap = _snapshot(server)
    remote = [e for e in snap["storage"]["exports"] if e["backend"] == "xroot"]
    assert remote, "xroot-backed export missing from storage census"
    assert remote[0]["remote"] is True
    assert "bytes_total" not in remote[0]        # no statvfs for remote backends


def test_anonymous_redaction_vs_authed(server):
    snap = _snapshot(server)
    assert snap.get("anonymous") is True
    for e in snap["storage"]["exports"]:
        assert "root" not in e and "origin_host" not in e
    assert server["data"] not in json.dumps(snap["storage"])

    cookie = _login(server["base"])
    assert cookie, "dashboard login failed"
    authed = _snapshot(server, cookie=cookie)
    assert authed.get("anonymous") is not True
    roots = [e.get("root") for e in authed["storage"]["exports"]]
    assert server["data"] in roots               # authed view carries the path

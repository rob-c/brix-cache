"""
Dashboard config-download + anonymous-tier security tests.

Self-contained: spins up its own nginx (NGINX_BIN) with a minimal config that
carries KNOWN planted secrets and an anonymous-enabled dashboard, plus a stream
root:// server so a real transfer row can be exercised. Asserts:

  * config download is auth-required (401 unauthenticated, even with the
    anonymous tier on) and NEVER contains any planted secret (fail-closed
    redaction covers xrootd secrets, stock directives, and URL credentials);
  * the anonymous tier serves read endpoints without login, flagged
    "anonymous": true, while transfer-detail / config / admin stay auth-only;
  * a live transfer row is PII-redacted for anonymous viewers (client/identity/
    path) but full for authenticated viewers.

These are the security guarantees for "download the module config without
leaking secrets" and "anonymous stats without PII".
"""

import os
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN, free_port
from server_registry import NginxInstanceSpec

DASH_PW = "SECRET_DASH_PW_123"
MACAROON_HEX = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
SET_SECRET = "TOPSECRET_SET_VALUE"
HEADER_SECRET = "LEAKME_HEADER_TOKEN"
URL_CRED = "credpassLEAK"

PLANTED_SECRETS = [DASH_PW, MACAROON_HEX, SET_SECRET, HEADER_SECRET, URL_CRED]


pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture
def server(lifecycle):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root_port = free_port(BIND_HOST)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-dashboard-config-anon",
        template="nginx_lc_dashboard_config_anon.conf",
        protocol="webdav",
        extra_ports={"ROOT_PORT": root_port},
        template_values={"BIND_HOST": BIND_HOST, "URL_CRED": URL_CRED,
                         "PASSWORD": DASH_PW, "MACAROON_HEX": MACAROON_HEX,
                         "SET_SECRET": SET_SECRET, "HEADER_SECRET": HEADER_SECRET},
        reason="dashboard config-redaction + anonymous-tier PII coverage"))

    data = ep.data_root
    with open(os.path.join(data, "probe.txt"), "wb") as fh:
        fh.write(b"hello\n")
    with open(os.path.join(data, "big.bin"), "wb") as fh:
        fh.write(os.urandom(20 * 1024 * 1024))

    base = f"http://{HOST}:{ep.port}"
    # wait for readiness
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/brix/api/v1/snapshot", timeout=2)
            break
        except Exception:
            time.sleep(0.1)
    yield {"base": base, "root_url": f"root://{HOST}:{root_port}",
           "data": str(data)}


def _get(base, path, cookie=None):
    req = urllib.request.Request(base + path)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.getcode(), r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Suppress auto-redirect so the login 302's Set-Cookie is observable.

    A successful login replies 302 (post/redirect/get) to the dashboard with the
    session cookie on the *redirect* response.  The default urllib opener follows
    the 302 and returns the final GET's headers, dropping the Set-Cookie — so we
    must stop at the 302 and read its headers directly."""

    def redirect_request(self, *args, **kwargs):
        return None


def _login(base):
    data = f"password={DASH_PW}".encode()
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(base + "/brix/login", data=data, method="POST")
    try:
        # On a 2xx (e.g. wrong password re-renders the form) there is no cookie.
        hdrs = opener.open(req, timeout=5).headers
    except urllib.error.HTTPError as e:
        # Suppressed 302 surfaces here; its headers carry the Set-Cookie.
        hdrs = e.headers
    sc = hdrs.get("Set-Cookie", "")
    return sc.split(";", 1)[0] if sc else None


# ---------------------------------------------------------------- config download

def test_config_download_requires_auth_even_with_anonymous(server):
    code, _, _ = _get(server["base"], "/brix/api/v1/config")
    assert code == 401


def test_config_download_authed_is_text_attachment(server):
    cookie = _login(server["base"])
    assert cookie
    code, body, hdrs = _get(server["base"], "/brix/api/v1/config", cookie)
    assert code == 200
    assert hdrs.get("Content-Type", "").startswith("text/plain")
    assert "attachment" in hdrs.get("Content-Disposition", "")
    # the dump is real (a non-secret directive survives)
    assert "brix_dashboard on" in body


def test_config_download_leaks_no_secret(server):
    cookie = _login(server["base"])
    code, body, _ = _get(server["base"], "/brix/api/v1/config", cookie)
    assert code == 200
    for secret in PLANTED_SECRETS:
        assert secret not in body, f"config download LEAKED secret: {secret}"
    assert "[redacted]" in body            # fail-closed actually fired
    # fail-closed masks stock + unknown directives too
    assert "proxy_set_header [redacted]" in body


# ---------------------------------------------------------------- anonymous tier

@pytest.mark.parametrize("ep", ["snapshot", "transfers", "events", "history",
                                 "cluster", "cache", "ratelimit"])
def test_anonymous_read_endpoints_open_and_flagged(server, ep):
    code, body, _ = _get(server["base"], f"/brix/api/v1/{ep}")
    assert code == 200
    assert '"anonymous":true' in body.replace(" ", "")


@pytest.mark.parametrize("path", ["api/v1/transfers/1", "api/v1/config",
                                   "api/v1/admin/x"])
def test_anonymous_does_not_open_privileged_endpoints(server, path):
    code, _, _ = _get(server["base"], f"/brix/{path}")
    assert code in (401, 403)


def test_anonymous_page_served_not_redirected(server):
    code, body, _ = _get(server["base"], "/brix/")
    assert code == 200
    assert "BriX-Cache Dashboard" in body


def test_authed_snapshot_is_full(server):
    cookie = _login(server["base"])
    code, body, _ = _get(server["base"], "/brix/api/v1/snapshot", cookie)
    assert code == 200
    assert '"anonymous":false' in body.replace(" ", "")


# ---------------------------------------------------------------- live PII redaction

def test_live_transfer_row_pii_redacted_for_anonymous(server):
    """Throttle a root:// read so a transfer row lingers, then confirm the
    anonymous snapshot redacts client/identity/path while the authed one shows
    them in full."""
    if not (subprocess.run(["which", "xrdcp"], capture_output=True).returncode == 0):
        pytest.skip("xrdcp not available")

    cookie = _login(server["base"])
    obj = server["root_url"] + "//big.bin"
    # ~200 kB/s via a python pipe throttle (xrdcp --xrate pre-paces badly)
    throttle = (
        "import sys,time\n"
        "R=200000;CH=8192;i=sys.stdin.buffer;o=sys.stdout.buffer\n"
        "t=time.time();s=0\n"
        "while True:\n"
        " b=i.read(CH)\n"
        " if not b: break\n"
        " o.write(b);o.flush();s+=len(b)\n"
        " d=s/R-(time.time()-t)\n"
        " if d>0: time.sleep(d)\n"
    )
    reader = subprocess.Popen(
        f"xrdcp -f {obj} - 2>/dev/null | python3 -c '{throttle}' >/dev/null 2>&1",
        shell=True, preexec_fn=os.setsid)
    try:
        anon = authed = None
        for _ in range(60):
            _, b, _ = _get(server["base"], "/brix/api/v1/snapshot")
            if '"state":"active"' in b:
                anon = b
                _, authed, _ = _get(server["base"],
                                    "/brix/api/v1/snapshot", cookie)
                break
            time.sleep(0.1)
        assert anon is not None, "no active transfer row appeared"
        # anonymous row: PII scrubbed
        assert '"client":"[redacted]"' in anon.replace(" ", "")
        assert '"path":"[redacted]"' in anon.replace(" ", "")
        # the real client IP / file path must not appear anywhere in the anon body
        assert "127.0.0.1" not in anon
        assert "big.bin" not in anon
        assert server["data"] not in anon
        # authed row: full PII present
        assert authed and "big.bin" in authed
    finally:
        try:
            os.killpg(os.getpgid(reader.pid), 15)
        except Exception:
            pass

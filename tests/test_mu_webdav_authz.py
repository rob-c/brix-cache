"""No-root verification of FIX 3 — WebDAV native authdb read-authorization parity.

WebDAV GET/HEAD/PROPFIND previously enforced only xrdacc + token scope; native authdb (the
per-path/per-identity mechanism root:// uses) was skipped for reads, so a reader could obtain
data — including from the cache (the access-phase gate fronts a cached GET). This test stands
up a WebDAV server with `brix_webdav_authdb` (no impersonation — the gate is a worker-level
decision) and proves the native-authdb read gate now enforces: with `u * /cms rl` (grant the
/cms subtree only), an authenticated reader is served under /cms (200) but REFUSED elsewhere
(403), for GET, HEAD, and PROPFIND alike.

(Path-scoped authdb is used rather than VO ACL because the VOMS VO is not extracted over the
nginx-TLS WebDAV path here — a separate limitation from the authorization gate this verifies;
`brix_webdav_require_vo` is wired the same way for deployments where VOMS extraction is
available.)

Run: PYTHONPATH=tests pytest tests/test_mu_webdav_authz.py -v   (no root needed)
"""
import os
import socket
import subprocess
import time
from types import SimpleNamespace

import pytest

from mu_authz_lib import creds, fleet, ports, principals
from mu_authz_lib.adapters import measure_webdav

_PORT = ports.MU.WEBDAV_AUTHZ
_URL = f"https://{ports.MU.HOST}:{_PORT}"
_GRANTED = "/cms/secret.dat"       # under the granted subtree
_DENIED = "/private/secret.dat"    # outside it — must be refused


def _port_open(p):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((ports.MU.HOST, p))
        return True
    except OSError:
        return False
    finally:
        s.close()


@pytest.fixture(scope="module")
def webdav_authz_env():
    principals.build_cast()
    for sub in ("cms", "private"):
        d = os.path.join(ports.MU.DATA_ROOT, sub)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "secret.dat"), "wb") as f:
            f.write(b"S" * 4096)
    os.makedirs(ports.MU.MU_ROOT, exist_ok=True)
    with open(ports.MU.AUTHDB, "w") as f:
        f.write("u * /cms rl\n")            # any authenticated user may read /cms; nothing else
    for dd in (ports.MU.CONFIG_DIR, ports.MU.LOG_DIR, os.path.join(ports.MU.LOG_DIR, "nginx_tmp")):
        os.makedirs(dd, exist_ok=True)

    subst = fleet._base_subst()
    subst["{AUTHDB}"] = ports.MU.AUTHDB
    src = os.path.join(fleet._CFG_SRC, "webdav_authz_noimp.conf")
    text = open(src).read()
    for k, v in subst.items():
        text = text.replace(k, v)
    dst = os.path.join(ports.MU.CONFIG_DIR, "webdav_authz_noimp.conf")
    with open(dst, "w") as f:
        f.write(text)

    pidf = os.path.join(ports.MU.MU_ROOT, "webdav_authz.pid")
    subprocess.run([fleet.NGINX, "-c", dst, "-g", f"pid {pidf};"],
                   check=True, capture_output=True)
    deadline = time.time() + 15
    while time.time() < deadline and not _port_open(_PORT):
        time.sleep(0.2)
    if not _port_open(_PORT):
        raise TimeoutError(f"webdav authz server never listened on {_PORT}")
    try:
        yield _URL
    finally:
        try:
            os.kill(int(open(pidf).read().strip()), 15)
        except (ProcessLookupError, ValueError, FileNotFoundError):
            pass


def _proxy(name):
    cert = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_userkey.pem")
    proxy = creds.gen_gsi_proxy(cert, key, f"wdauthz_{name}")
    return SimpleNamespace(name=name, proxy=proxy, token="", s3_key="", s3_secret="")


@pytest.mark.parametrize("op", ["read", "stat", "list"])
def test_webdav_read_enforces_native_authdb(webdav_authz_env, op):
    """An authenticated reader is served under the granted /cms subtree but REFUSED (403)
    outside it — for GET, HEAD, and PROPFIND. This is the native-authdb read gate (FIX 3)
    that the pre-fix WebDAV read path lacked."""
    url = webdav_authz_env
    alice = _proxy("alice")

    v_granted = measure_webdav(url, _GRANTED, op, principal=alice)
    assert v_granted.decision == "ALLOW", f"{op} under granted /cms must be served: {v_granted}"

    v_denied = measure_webdav(url, _DENIED, op, principal=alice)
    assert v_denied.decision == "DENY", (
        f"LEAK: {op} of {_DENIED} (no authdb grant) was served: {v_denied}")

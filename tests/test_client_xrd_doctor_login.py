"""
`xrd doctor` + `xrd login` — cross-tool UX verbs on the unified front-end.

WHAT: `xrd doctor [endpoint]` summarises locally-discoverable credentials (bearer
      token + GSI proxy) and, if given an endpoint, whether we can connect + the
      TLS posture. `xrd login` best-effort acquires/refreshes a token/proxy.
WHY:  one command to answer "are my creds ok and can I reach the server".
HOW:  drive the real `xrd` binary with a controlled credential environment
      (BEARER_TOKEN + a non-existent X509_USER_PROXY so the host's real proxy
      can't perturb the test) and a self-hosted anon root:// server.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_xrd_doctor_login.py -p no:xdist -v
"""
import base64
import json as jsonlib
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrd-doctor-login")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRD = os.path.join(CLIENT_DIR, "bin", "xrd")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(claims):
    hdr = _b64url(jsonlib.dumps({"alg": "none", "typ": "JWT"}).encode())
    pay = _b64url(jsonlib.dumps(claims).encode())
    return f"{hdr}.{pay}.sig"


def _clean_env(**extra):
    """An env with NO ambient creds (no real proxy/token), plus `extra`."""
    env = dict(os.environ)
    env["X509_USER_PROXY"] = "/nonexistent/x509up_doctor_test"
    for k in ("BEARER_TOKEN", "BEARER_TOKEN_FILE"):
        env.pop(k, None)
    env.update(extra)
    return env


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrd"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRD):
        pytest.skip(f"xrd build failed:\n{proc.stdout}\n{proc.stderr}")


@pytest.fixture()
def server(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir()
    (data / "f.bin").write_bytes(os.urandom(4096))
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrd-doctor-login",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="xrd doctor/login against a writable anon root server"))
    return {"rport": ep.port}


def test_doctor_reports_discovered_token(server):
    """With a token in $BEARER_TOKEN, doctor explains it (not 'none discovered')
    and never echoes the raw token. Exit 0 with no endpoint problem."""
    tok = _jwt({"iss": "https://issuer.example", "sub": "alice",
                "exp": int(time.time()) + 3600, "scope": "storage.read:/"})
    r = subprocess.run([XRD, "doctor"], capture_output=True, text=True,
                       timeout=30, env=_clean_env(BEARER_TOKEN=tok))
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "none discovered" not in r.stdout, r.stdout
    assert "GSI proxy: none" in r.stdout
    # PII: the raw JWT must not be echoed back
    assert tok not in r.stdout and tok not in r.stderr


def test_doctor_endpoint_connect_ok(server):
    """doctor against a live anon endpoint reports connect OK + a TLS-posture line."""
    url = f"root://{HOST}:{server['rport']}/"
    r = subprocess.run([XRD, "doctor", url], capture_output=True, text=True,
                       timeout=30, env=_clean_env())
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "connect:" in r.stdout and "OK" in r.stdout
    assert "cleartext" in r.stdout or "TLS:" in r.stdout


def test_doctor_dead_endpoint_nonzero(server):
    """doctor against a closed port reports a connect failure and exits nonzero."""
    r = subprocess.run([XRD, "doctor", f"root://{HOST}:1/"],
                       capture_output=True, text=True, timeout=30, env=_clean_env())
    assert r.returncode != 0, f"{r.stdout}\n{r.stderr}"
    assert "FAILED" in r.stdout and "connect:" in r.stdout


def test_login_best_effort_no_creds(server):
    """`xrd login --read` with nothing configured is a clean no-op (exit 0) and
    leaks no secret."""
    r = subprocess.run([XRD, "login", "--read"], capture_output=True, text=True,
                       timeout=30, env=_clean_env())
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "credential(s) acquired/refreshed" in r.stdout

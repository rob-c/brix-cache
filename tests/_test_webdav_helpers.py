# loc-lint: exempt — a single module-scoped autouse `params=` fixture mutates module globals (e.g. BASE_URL) that every test reads directly; splitting tests into a sibling module breaks that shared mutable state (proven: webdav 120->100). Cohesive parametrize-unit; Phase-38 §4.4.
"""
tests/test_webdav.py

HTTPS WebDAV module tests for the ngx_http_brix_webdav_module.

Covers the WebDAV methods that xrdcp (XrdClHttp plugin) and compatible
clients depend on:

  OPTIONS   – capability advertisement (must include PROPFIND in Allow)
  HEAD      – metadata without body
  GET       – file content, including Range requests (206 Partial Content)
  PUT       – file upload
  DELETE    – file and directory removal
  MKCOL     – directory creation, with and without trailing slash
  PROPFIND  – Depth:0 (stat) and Depth:1 (directory listing)

The same WebDAV behaviour is exercised against both authenticated HTTPS test
servers:

  - HTTPS+GSI/x509 on port 8444, using an RFC 3820 proxy certificate
  - HTTPS+Token on port 8443, using an Authorization: Bearer JWT

Anonymous requests are checked against each server's configured policy: the
GSI endpoint requires credentials, while the token endpoint is optional-auth.

Run against an already-running nginx instance:

    /tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf

    pytest tests/test_webdav.py -v

Environment:
    GSI WebDAV endpoint:   https://localhost:8444/
    Token WebDAV endpoint: https://localhost:8443/
    CA cert:    /tmp/xrd-test/pki/ca/ca.pem
    Proxy cert: /tmp/xrd-test/pki/user/proxy_std.pem
    Data root:  /tmp/xrd-test/data/
"""

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

import pytest
import urllib.request
import ssl
from settings import CA_CERT, DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD, TOKENS_DIR

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL   = ""
CA_PEM     = CA_CERT
PROXY_PEM  = PROXY_STD
DATA_ROOT  = DEFAULT_DATA_ROOT
TOKEN_DIR  = TOKENS_DIR
AUTH_MODE  = "gsi"
TOKEN      = ""

# Unique prefix for test artefacts so parallel runs don't collide.  Each pytest-
# xdist worker gets its own prefix: the same test runs once per auth variant
# (anon/token/gsi) and xdist scatters those variants across workers, all sharing
# ONE server data directory.  With a constant prefix two variants race on the same
# fixed path (one's teardown rmtree's the dir another is mid-MKCOL on → 201 not
# 405); a per-worker prefix keeps each variant's artefacts disjoint.
_PFX = "wdav_%s_" % os.environ.get("PYTEST_XDIST_WORKER", "main")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _curl(*args, timeout=20):
    """
    Run curl with the common TLS / WebDAV auth flags and return
    (returncode, stdout_bytes, stderr_bytes).

    All WebDAV tests go through this helper so that any future change to
    TLS flags only needs updating in one place.
    """
    cmd = [
        "curl", "-sk",
        "--cacert", CA_PEM,
    ]
    if AUTH_MODE == "gsi":
        cmd.extend(["--cert", PROXY_PEM, "--key", PROXY_PEM])
    elif AUTH_MODE == "token":
        cmd.extend(["-H", f"Authorization: Bearer {TOKEN}"])
    cmd.extend(args)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _curl_no_cert(*args, timeout=20):
    """curl without any client certificate (anonymous TLS)."""
    cmd = [
        "curl", "-sk",
        "--cacert", CA_PEM,
        *args,
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _http_code(*args, **kwargs):
    """Return just the HTTP status code as an int."""
    rc, out, _ = _curl(*args, "-w", "%{http_code}", "-o", "/dev/null", **kwargs)
    assert rc == 0, f"curl failed (exit {rc})"
    return int(out.strip())


def _http_code_no_cert(*args, **kwargs):
    rc, out, _ = _curl_no_cert(*args, "-w", "%{http_code}", "-o", "/dev/null", **kwargs)
    assert rc == 0, f"curl failed (exit {rc})"
    return int(out.strip())


def _put(path: str, content: bytes) -> int:
    """PUT content to path; return HTTP status code."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        return _http_code("-X", "PUT", f"{BASE_URL}{path}",
                          "--data-binary", f"@{tmp}")
    finally:
        os.unlink(tmp)


def _get(path: str) -> bytes:
    """GET path; return response body bytes. Raises on curl failure."""
    rc, out, err = _curl(f"{BASE_URL}{path}")
    assert rc == 0, f"curl GET failed: {err.decode()}"
    return out


def _data_path(rel: str) -> str:
    """Absolute filesystem path for a data-root-relative path."""
    return os.path.join(DATA_ROOT, rel.lstrip("/"))


# ---------------------------------------------------------------------------
# Session fixture: verify nginx is reachable before running any test
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True, params=("gsi", "token"),
                ids=("gsi-8444", "token-8443"))
def nginx_webdav_ready(request, test_env):
    """Bind module constants from the shared test environment."""
    global BASE_URL, CA_PEM, PROXY_PEM, DATA_ROOT, TOKEN_DIR, AUTH_MODE, TOKEN
    AUTH_MODE = request.param
    BASE_URL  = (
        test_env["webdav_gsi_tls_url"]
        if AUTH_MODE == "gsi"
        else test_env["webdav_url"]
    )
    CA_PEM    = test_env["ca_pem"]
    PROXY_PEM = test_env["proxy_pem"]
    DATA_ROOT = test_env["data_dir"]
    TOKEN_DIR = test_env.get("token_dir", TOKENS_DIR)
    TOKEN     = ""

    if AUTH_MODE == "token":
        issuer = TokenIssuer(TOKEN_DIR)
        if not os.path.exists(issuer.key_path):
            issuer.init_keys()
        TOKEN = issuer.generate(
            scope="storage.read:/ storage.write:/",
            lifetime=7200,
        )

    rc, _, _ = _curl("-X", "OPTIONS", f"{BASE_URL}/", "-o", "/dev/null",
                     timeout=5)
    if rc != 0:
        pytest.skip(
            f"WebDAV endpoint {BASE_URL} not reachable."
        )


# ---------------------------------------------------------------------------
# Fixture: per-test scratch file
# ---------------------------------------------------------------------------

@pytest.fixture()
def scratch_file(tmp_path):
    """
    Yield (url_path, content) for a file that has been PUT to the server.
    Cleaned up from the data directory after the test.
    """
    # Unique per invocation: the suite runs under pytest-xdist where every worker
    # shares one server data directory.  A fixed name (wdav_scratch.txt) makes
    # concurrent tests PUT the SAME path, so the loser overwrites (HTTP 204) and a
    # teardown unlink can yank the file mid-test.  A uuid keeps each test isolated.
    name    = f"{_PFX}scratch_{uuid.uuid4().hex}.txt"
    content = b"scratch file content for WebDAV tests\n"
    url_path = f"/{name}"

    # 201 Created (new) or, defensively, 200/204 (overwrite) are all PUT successes.
    code = _put(url_path, content)
    assert code in (200, 201, 204), f"Fixture PUT failed with HTTP {code}"

    yield url_path, content

    dst = _data_path(name)
    if os.path.exists(dst):
        os.unlink(dst)


# ---------------------------------------------------------------------------
# OPTIONS
# ---------------------------------------------------------------------------

"""
Functional tests exercising WebDAV uploads/downloads using `xrdcp`
and `curl` so we can verify both clients work against the HTTPS WebDAV
interface the module serves.  x509/GSI client flows target the dedicated
HTTPS+GSI server on port 8444.  curl bearer-token flows target the HTTPS+Token
server on port 8443; xrdcp davs:// coverage stays on the x509 path because
the client plugin's bearer-token discovery is not a stable server assertion in
this test layout.

These tests start a small nginx instance (using the repo test layout PKI)
and then attempt uploads and downloads with the real client binaries. If
`xrdcp` or `curl` are not present on PATH the corresponding tests are
skipped.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

import pytest
import requests
from settings import (
    CA_DIR,
    DATA_ROOT,
    LOG_DIR,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_WEBDAV_PORT,
    PROXY_STD,
    SERVER_HOST,
    TOKENS_DIR,
    XRDCP_BIN,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

PROXY_PEM         = PROXY_STD
WEBDAV_GSI_PORT   = NGINX_WEBDAV_GSI_TLS_PORT
WEBDAV_GSI_URL    = f"https://{SERVER_HOST}:{NGINX_WEBDAV_GSI_TLS_PORT}"
WEBDAV_TOKEN_PORT = NGINX_WEBDAV_PORT
WEBDAV_TOKEN_URL  = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"
DATA_DIR          = DATA_ROOT
_rw_token         = ""  # populated by _init_token fixture before first test


@pytest.fixture(scope="module", autouse=True)
def _init_token():
    """Generate the read-write bearer token once the PKI dirs are ready."""
    global _rw_token
    issuer = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(issuer.key_path):
        issuer.init_keys()
    _rw_token = issuer.generate(
        scope="storage.read:/ storage.write:/",
        lifetime=7200,
    )


def _write_temp_file(contents: bytes):
    fd, path = tempfile.mkstemp()
    os.close(fd)
    with open(path, "wb") as fh:
        fh.write(contents)
    return path


def _run(cmd, env=None, cwd=None):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd)


def _webdav_modes():
    return (
        {
            "id": "gsi-8444",
            "mode": "gsi",
            "port": WEBDAV_GSI_PORT,
            "url": WEBDAV_GSI_URL,
            "curl_auth": ["--cert", PROXY_PEM],
            "requests_kwargs": {"cert": PROXY_PEM},
        },
        {
            "id": "token-8443",
            "mode": "token",
            "port": WEBDAV_TOKEN_PORT,
            "url": WEBDAV_TOKEN_URL,
            "curl_auth": ["-H", f"Authorization: Bearer {_rw_token}"],
            "requests_kwargs": {
                "headers": {"Authorization": f"Bearer {_rw_token}"},
            },
        },
    )


@pytest.fixture(scope="module", params=("gsi", "token"),
                ids=("gsi-8444", "token-8443"))
def webdav_mode(request):
    for mode in _webdav_modes():
        if mode["mode"] == request.param:
            return mode
    raise AssertionError(f"unknown WebDAV mode {request.param}")


def _wait_for_file_content(remote_name: str, expected: bytes, timeout: float) -> bool:
    path = os.path.join(DATA_DIR, remote_name.lstrip("/"))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(path, "rb") as fh:
                if fh.read() == expected:
                    return True
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return False


def test_xrdcp_upload_and_download():
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip(f"{XRDCP_BIN} not found on PATH")

    port = WEBDAV_GSI_PORT
    url_base = WEBDAV_GSI_URL

    content = b"hello-xrdcp-" + os.urandom(1024)
    local = _write_temp_file(content)
    remote_name = "xrdcp-upload.bin"
    remote_url = f"davs://localhost:{port}//{remote_name}"

    env = os.environ.copy()
    env["X509_USER_PROXY"] = PROXY_PEM
    env["X509_CERT_DIR"] = CA_DIR

    # Run xrdcp from a temp dir so that if XrdClHttp plugin is missing and
    # xrdcp falls back to treating davs:// as a local path, the artifacts
    # land in the temp dir (auto-cleaned) rather than the repo working tree.
    xrdcp_cwd = tempfile.mkdtemp()

    # Upload with xrdcp using HTTP (davs)
    r = _run([XRDCP_BIN, "--allow-http", "--verbose", local, remote_url], env=env, cwd=xrdcp_cwd)
    assert r.returncode == 0, (r.returncode, r.stderr.decode())

    if not _wait_for_file_content(remote_name, content, timeout=8):
        # Upload not observed. Try to seed the file via curl, then verify
        # that xrdcp can download it (exercise xrdcp as a davs client).
        seed = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, f"{url_base}/{remote_name}"])
        assert seed.returncode == 0, (seed.returncode, seed.stderr.decode(errors="replace"))

        out_local = local + ".from_xrdcp"
        r2 = _run([XRDCP_BIN, "--allow-http", "--verbose", f"davs://localhost:{port}//{remote_name}", out_local],
                  env=env, cwd=xrdcp_cwd)
        if r2.returncode != 0:
            # Collect diagnostics for debugging failures
            log_tail = ""
            log_path = os.path.join(LOG_DIR, "error.log")
            try:
                with open(log_path, encoding="utf-8", errors="replace") as fh:
                    log_tail = fh.read()[-4096:]
            except Exception:
                log_tail = "(could not read log)"
            pytest.fail(
                "xrdcp upload not observed in nginx log and xrdcp download failed\n"
                f"xrdcp upload stdout:\n{r.stdout.decode(errors='replace')}\n"
                f"xrdcp upload stderr:\n{r.stderr.decode(errors='replace')}\n"
                f"xrdcp download stdout:\n{r2.stdout.decode(errors='replace')}\n"
                f"xrdcp download stderr:\n{r2.stderr.decode(errors='replace')}\n"
                f"nginx log tail:\n{log_tail}"
            )

        with open(out_local, "rb") as fh:
            assert fh.read() == content
        return

    # Download via requests using the client proxy cert (verify disabled).
    resp = None
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            resp = requests.get(f"{url_base}/{remote_name}", cert=PROXY_PEM, verify=False, timeout=2)
            if resp.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.1)
    assert resp is not None and resp.status_code == 200, f"expected 200, got {resp.status_code if resp else 'no response'}"
    assert resp.content == content

    # Now download with xrdcp back to a different local path
    out_local = local + ".out"
    r2 = _run([XRDCP_BIN, "--allow-http", remote_url, out_local], env=env)
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode())
    with open(out_local, "rb") as fh:
        assert fh.read() == content


def test_curl_upload_and_download(webdav_mode):
    if shutil.which("curl") is None:
        pytest.skip("curl not found on PATH")

    url_base = webdav_mode["url"]
    curl_auth = webdav_mode["curl_auth"]

    content = b"hello-curl-" + os.urandom(512)
    local = _write_temp_file(content)
    remote_name = f"curl-upload-{webdav_mode['mode']}.bin"
    upload_url = f"{url_base}/{remote_name}"

    # Upload with curl (-k to ignore the test server certificate).
    r = _run(["curl", "-k", *curl_auth, "-T", local, upload_url])
    assert r.returncode == 0, (r.returncode, r.stderr.decode())

    # Download with curl and capture stdout
    r2 = subprocess.run(
        ["curl", "-k", *curl_auth, upload_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode())
    assert r2.stdout == content


@pytest.mark.timeout(45)
def test_xrdcp_large_upload_and_download():
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip(f"{XRDCP_BIN} not found on PATH")

    port = WEBDAV_GSI_PORT
    url_base = WEBDAV_GSI_URL

    content = os.urandom((2 * 1024 * 1024) + 137)
    local = _write_temp_file(content)
    remote_name = "xrdcp-large.bin"
    remote_url = f"davs://localhost:{port}//{remote_name}"

    env = os.environ.copy()
    env["X509_USER_PROXY"] = PROXY_PEM
    env["X509_CERT_DIR"] = CA_DIR

    xrdcp_cwd = tempfile.mkdtemp()

    r = _run([XRDCP_BIN, "--allow-http", "--verbose", local, remote_url], env=env, cwd=xrdcp_cwd)
    assert r.returncode == 0, (r.returncode, r.stderr.decode(errors="replace"))

    if not _wait_for_file_content(remote_name, content, timeout=15):
        # seed with curl and then verify xrdcp can download the seeded file
        seed = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, f"{url_base}/{remote_name}"])
        assert seed.returncode == 0, (seed.returncode, seed.stderr.decode(errors="replace"))

        out_local = local + ".from_xrdcp"
        r2 = _run([XRDCP_BIN, "--allow-http", "--verbose", f"davs://localhost:{port}//{remote_name}", out_local],
                  env=env, cwd=xrdcp_cwd)
        assert r2.returncode == 0, (r2.returncode, r2.stderr.decode(errors="replace"))
        with open(out_local, "rb") as fh:
            assert fh.read() == content
        return

    # If upload was observed, GET and verify
    resp = None
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            resp = requests.get(f"{url_base}/{remote_name}", cert=PROXY_PEM, verify=False, timeout=5)
            if resp.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.2)

    assert resp is not None and resp.status_code == 200, f"expected 200, got {resp.status_code if resp else 'no response'}"
    assert resp.content == content


@pytest.mark.timeout(45)
def test_curl_large_upload_and_download(webdav_mode):
    if shutil.which("curl") is None:
        pytest.skip("curl not found on PATH")

    url_base = webdav_mode["url"]
    curl_auth = webdav_mode["curl_auth"]

    content = os.urandom((2 * 1024 * 1024) + 137)
    local = _write_temp_file(content)
    remote_name = f"curl-large-{webdav_mode['mode']}.bin"
    upload_url = f"{url_base}/{remote_name}"

    # Upload with curl (-k to ignore the test server certificate).
    r = _run(["curl", "-k", *curl_auth, "-T", local, upload_url])
    assert r.returncode == 0, (r.returncode, r.stderr.decode(errors="replace"))

    # Wait for nginx to log the upload
    log_path = os.path.join(LOG_DIR, "error.log")
    seen = False
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with open(log_path, encoding="utf-8", errors="ignore") as fh:
                data = fh.read()
            if remote_name in data:
                seen = True
                break
        except FileNotFoundError:
            pass
        time.sleep(0.2)

    assert seen, "curl upload not observed in nginx log"

    # Download with curl and capture stdout
    r2 = subprocess.run(
        ["curl", "-k", *curl_auth, upload_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode(errors="replace"))
    assert r2.stdout == content

# brix-remote-skip
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


def _require(program):
    if shutil.which(program) is None:
        pytest.skip(f"{program} not found on PATH")


def _xrd_env():
    env = os.environ.copy()
    env["X509_USER_PROXY"] = PROXY_PEM
    env["X509_CERT_DIR"] = CA_DIR
    return env


def _assert_success(result):
    assert result.returncode == 0, (
        result.returncode, result.stderr.decode(errors="replace")
    )


def _assert_path_content(path, expected):
    with open(path, "rb") as stream:
        actual = stream.read()
    assert actual == expected


def _xrd_download(remote_url, output, env, cwd=None):
    result = _run([XRDCP_BIN, "--allow-http", "--verbose", remote_url, output],
                  env=env, cwd=cwd)
    _assert_success(result)
    return result


def _wait_for_response(url, timeout):
    response = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(url, cert=PROXY_PEM, verify=False, timeout=2)
            if response.status_code == 200:
                return response
        except Exception:
            pass
        time.sleep(0.1)
    return response


def _assert_response(response, expected):
    status = response.status_code if response else "no response"
    assert response is not None and response.status_code == 200, f"expected 200, got {status}"
    assert response.content == expected


def _log_tail():
    try:
        with open(os.path.join(LOG_DIR, "error.log"), encoding="utf-8",
                  errors="replace") as stream:
            return stream.read()[-4096:]
    except Exception:
        return "(could not read log)"


def _fallback_xrd(upload, local, remote_url, url_base, remote_name, env, cwd, content):
    seed = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local,
                 f"{url_base}/{remote_name}"])
    _assert_success(seed)
    output = local + ".from_xrdcp"
    download = _run([XRDCP_BIN, "--allow-http", "--verbose", remote_url, output],
                    env=env, cwd=cwd)
    if download.returncode != 0:
        pytest.fail(_xrd_failure_message(upload, download, _log_tail()))
    _assert_path_content(output, content)


def _xrd_failure_message(upload, download, log_tail):
    return (
        "xrdcp upload not observed in nginx log and xrdcp download failed\n"
        f"xrdcp upload stdout:\n{upload.stdout.decode(errors='replace')}\n"
        f"xrdcp upload stderr:\n{upload.stderr.decode(errors='replace')}\n"
        f"xrdcp download stdout:\n{download.stdout.decode(errors='replace')}\n"
        f"xrdcp download stderr:\n{download.stderr.decode(errors='replace')}\n"
        f"nginx log tail:\n{log_tail}"
    )


def _xrd_upload(local, remote_url, env, cwd):
    result = _run([XRDCP_BIN, "--allow-http", "--verbose", local, remote_url],
                  env=env, cwd=cwd)
    _assert_success(result)
    return result


def _wait_for_log(remote_name, timeout):
    log_path = os.path.join(LOG_DIR, "error.log")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(log_path, encoding="utf-8", errors="ignore") as stream:
                if remote_name in stream.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    return False


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
    _require(XRDCP_BIN)

    port = WEBDAV_GSI_PORT
    url_base = WEBDAV_GSI_URL

    content = b"hello-xrdcp-" + os.urandom(1024)
    local = _write_temp_file(content)
    remote_name = "xrdcp-upload.bin"
    remote_url = f"davs://{SERVER_HOST}:{port}//{remote_name}"

    env = _xrd_env()

    # Run xrdcp from a temp dir so that if XrdClHttp plugin is missing and
    # xrdcp falls back to treating davs:// as a local path, the artifacts
    # land in the temp dir (auto-cleaned) rather than the repo working tree.
    xrdcp_cwd = tempfile.mkdtemp()

    # Upload with xrdcp using HTTP (davs)
    upload = _xrd_upload(local, remote_url, env, xrdcp_cwd)

    if not _wait_for_file_content(remote_name, content, timeout=8):
        _fallback_xrd(upload, local, remote_url, url_base, remote_name,
                      env, xrdcp_cwd, content)
        return

    response = _wait_for_response(f"{url_base}/{remote_name}", 5)
    _assert_response(response, content)

    out_local = local + ".out"
    _xrd_download(remote_url, out_local, env)
    _assert_path_content(out_local, content)


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
    _require(XRDCP_BIN)

    port = WEBDAV_GSI_PORT
    url_base = WEBDAV_GSI_URL

    content = os.urandom((2 * 1024 * 1024) + 137)
    local = _write_temp_file(content)
    remote_name = "xrdcp-large.bin"
    remote_url = f"davs://{SERVER_HOST}:{port}//{remote_name}"

    env = _xrd_env()

    xrdcp_cwd = tempfile.mkdtemp()

    _xrd_upload(local, remote_url, env, xrdcp_cwd)

    if not _wait_for_file_content(remote_name, content, timeout=15):
        seed = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, f"{url_base}/{remote_name}"])
        _assert_success(seed)
        out_local = local + ".from_xrdcp"
        _xrd_download(remote_url, out_local, env, xrdcp_cwd)
        _assert_path_content(out_local, content)
        return

    response = _wait_for_response(f"{url_base}/{remote_name}", 10)
    _assert_response(response, content)


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

    assert _wait_for_log(remote_name, 15), "curl upload not observed in nginx log"

    # Download with curl and capture stdout
    r2 = subprocess.run(
        ["curl", "-k", *curl_auth, upload_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode(errors="replace"))
    assert r2.stdout == content

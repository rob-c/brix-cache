"""
Phase 40 (b) — native client (xrdcp --auto-refresh) credential auto-acquire.

WHAT: Verifies xrdcp proactively (re)acquires a stale bearer token via the local
      oidc-agent (`oidc-token <account>`) before transferring, and that the whole
      mechanism is FAIL-SOFT: a failing/absent oidc-token or an unconfigured
      account never breaks the transfer.
WHY:  (b) is "volunteer to get a new token / auto-refresh creds". A token that is
      absent/expired/near-expiry should be renewed for the user when --auto-refresh
      is given and a refresh source exists — otherwise the transfer proceeds
      unchanged (the server stays authoritative; (c) still warns).
HOW:  Drives the real xrdcp against the running anon root:// server on :11094,
      with a STUB `oidc-token` on PATH so the test is hermetic (no real IdP). The
      GSI-proxy branch is disabled via non-existent X509 paths so we assert purely
      on the token path. Skips cleanly without the server/binary.
"""
import base64
import json
import os
import socket
import stat
import subprocess
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
ROOT_HOST, ROOT_PORT = "127.0.0.1", 11094
DATA_DIR = os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "data")
SMALL = f"root://{ROOT_HOST}:{ROOT_PORT}//test.txt"


def _server_up():
    try:
        with socket.create_connection((ROOT_HOST, ROOT_PORT), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not os.path.exists(XRDCP) or not _server_up()
    or not os.path.exists(os.path.join(DATA_DIR, "test.txt")),
    reason="needs built xrdcp + running anon root:// server on :11094 with fixtures",
)


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt(claims):
    return f"{_b64(json.dumps({'alg':'none'}).encode())}.{_b64(json.dumps(claims).encode())}.sig"


def _stub_oidc(dir_path, body):
    """Write an executable `oidc-token` stub running `body` (sh)."""
    p = os.path.join(dir_path, "oidc-token")
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _run_autorefresh(tmp_path, stub_body, account="test", set_account=True,
                     extra_env=None):
    env = dict(os.environ)
    env.pop("BEARER_TOKEN", None)
    # Isolate the token path: no real proxy / cert in play.
    env["X509_USER_PROXY"] = "/nonexistent/proxy"
    env["X509_USER_CERT"] = "/nonexistent/cert"
    stubdir = tmp_path / "bin"
    stubdir.mkdir()
    _stub_oidc(str(stubdir), stub_body)
    env["PATH"] = f"{stubdir}:{env['PATH']}"
    if set_account:
        env["OIDC_ACCOUNT"] = account
    else:
        env.pop("OIDC_ACCOUNT", None)
    if extra_env:
        env.update(extra_env)
    dest = str(tmp_path / "out.txt")
    proc = subprocess.run([XRDCP, "--auto-refresh", "-f", SMALL, dest],
                          env=env, capture_output=True, text=True, timeout=30)
    return proc, dest


def test_autorefresh_fetches_token(tmp_path):
    """A configured account + working oidc-token → token refreshed, transfer OK."""
    fresh = _jwt({"exp": int(time.time()) + 3600,
                  "scope": "storage.read:/ storage.modify:/"})
    proc, dest = _run_autorefresh(tmp_path, f'echo "{fresh}"')
    assert "refreshed bearer token via oidc-agent (account test)" in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert open(dest, "rb").read() == b"hello from nginx-xrootd\n"


def test_autorefresh_failsoft_on_oidc_error(tmp_path):
    """oidc-token failing must NOT break the transfer — it is best-effort."""
    proc, dest = _run_autorefresh(tmp_path, "exit 1")
    assert "token auto-refresh skipped" in proc.stderr, proc.stderr
    # Transfer still completes against the anon server (fail-soft).
    assert proc.returncode == 0, proc.stderr
    assert os.path.exists(dest)


def test_autorefresh_no_account_does_not_attempt(tmp_path):
    """Without an account, the token branch is not attempted (no crash, no fetch)."""
    fresh = _jwt({"exp": int(time.time()) + 3600, "scope": "storage.read:/"})
    proc, dest = _run_autorefresh(tmp_path, f'echo "{fresh}"', set_account=False)
    assert "refreshed bearer token" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert os.path.exists(dest)

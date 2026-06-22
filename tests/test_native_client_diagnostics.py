"""
Native client diagnostics (phase-37 §15): --wire-trace, --timing, xrdfs explain.

These are always-available, OFF-by-default instrumentation hooks on the clean-room
xrdfs/xrdcp. They decode every frame, time each opcode, and narrate the connection
(caps / auth / TLS) — capabilities the stock terse tools structurally lack. All
diagnostic output goes to stderr (or, for `explain`, stdout); the normal command
output is unaffected, which these tests assert.

Run (serial, against a manually-started fleet):
    TEST_SKIP_SERVER_SETUP=1 TEST_XRDFS_BIN=$PWD/client/bin/xrdfs \
    PYTHONPATH=tests pytest tests/test_native_client_diagnostics.py -v -p no:xdist
"""

import os
import re
import shutil
import socket
import subprocess
import time

import pytest

from settings import (
    BIND_HOST,
    CA_DIR,
    HOST,
    NGINX_ANON_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
)

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

_CLEAN_ENV = {k: v for k, v in os.environ.items()}
_CLEAN_ENV.pop("X509_USER_PROXY", None)
_CLEAN_ENV.pop("X509_CERT_DIR", None)


@pytest.fixture(scope="module")
def native_xrdfs():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", os.path.join(REPO, "client")],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(NATIVE_XRDFS):
        pytest.skip(f"native client build failed:\n{proc.stdout}\n{proc.stderr}")
    return NATIVE_XRDFS


def _run(*args, env=None, timeout=20):
    return subprocess.run([NATIVE_XRDFS, *args], capture_output=True, text=True,
                          env=env or _CLEAN_ENV, timeout=timeout)


# --------------------------------------------------------------------------
# --wire-trace
# --------------------------------------------------------------------------

def test_wire_trace_decodes_frames(native_xrdfs):
    p = _run("--wire-trace", ANON_URL, "stat", "/test.txt")
    assert p.returncode == 0, p.stderr
    err = p.stderr
    # Decoded request + response lines for the login + stat exchange.
    assert "kXR_login" in err, err
    assert "kXR_stat" in err, err
    assert re.search(r"^> sid=\d+ kXR_stat", err, re.MULTILINE), err
    assert re.search(r"^< sid=\d+ ok", err, re.MULTILINE), err
    # The normal stat output still lands on stdout, uncorrupted by the trace.
    assert "Size:" in p.stdout, p.stdout
    assert "kXR_" not in p.stdout, "trace leaked onto stdout"


def test_wire_trace_hexdump(native_xrdfs):
    p = _run("--wire-trace=2", ANON_URL, "stat", "/test.txt")
    assert p.returncode == 0, p.stderr
    assert re.search(r"^\s+[0-9a-f]{4}: ([0-9a-f]{2} )+", p.stderr, re.MULTILINE), \
        "no hexdump rows at --wire-trace=2"


# --------------------------------------------------------------------------
# --timing
# --------------------------------------------------------------------------

def test_timing_summary(native_xrdfs):
    p = _run("--timing", ANON_URL, "stat", "/test.txt")
    assert p.returncode == 0, p.stderr
    assert "per-opcode RTT" in p.stderr, p.stderr
    assert re.search(r"kXR_stat\s+n=\d+", p.stderr), p.stderr
    assert "Size:" in p.stdout, "stat output missing under --timing"


# --------------------------------------------------------------------------
# off by default
# --------------------------------------------------------------------------

def test_diagnostics_off_by_default(native_xrdfs):
    p = _run(ANON_URL, "stat", "/test.txt")
    assert p.returncode == 0, p.stderr
    assert "per-opcode RTT" not in p.stderr, "timing printed without --timing"
    assert not re.search(r"^[<>] sid=", p.stderr, re.MULTILINE), \
        "wire-trace printed without --wire-trace"


# --------------------------------------------------------------------------
# xrdfs explain
# --------------------------------------------------------------------------

def test_explain_anon(native_xrdfs):
    p = _run(ANON_URL, "explain")
    assert p.returncode == 0, p.stderr
    out = p.stdout
    assert "Caps:" in out and "pgread/pgwrite=yes" in out, out
    assert re.search(r"Signing:\s+sec_level=\d", out), out
    assert "Session:" in out and re.search(r"Session:\s+[0-9a-f]{32}", out), out
    assert "Auth:" in out, out


@pytest.mark.skipif(not os.path.exists(PROXY_STD), reason="no GSI proxy available")
def test_explain_tls_reports_cipher(native_xrdfs):
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = PROXY_STD
    env["X509_CERT_DIR"] = CA_DIR
    p = _run(f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}", "explain",
             env=env, timeout=30)
    assert p.returncode == 0, p.stderr
    assert "TLS:      active" in p.stdout, p.stdout
    assert re.search(r"TLS:\s+active — TLSv1\.\d", p.stdout), p.stdout
    # GSI auth was actually used over TLS.
    assert "authenticated with: gsi" in p.stdout, p.stdout


# ==========================================================================
# WS-D: credential introspection (§15.2) + xrdgsitest (§14.3)
# Self-contained anon server so the token-claim tests run without the fleet.
# ==========================================================================

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
NATIVE_XRDGSITEST = os.path.join(REPO, "client", "bin", "xrdgsitest")


def _b64url(obj):
    import base64
    import json
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _jwt(exp):
    """A 3-segment 'none'-alg JWT (decoded for claims, never signature-verified)."""
    hdr = _b64url({"alg": "none", "typ": "JWT"})
    pay = _b64url({"iss": "https://issuer.example", "sub": "alice",
                   "aud": "xrootd", "scope": "storage.read:/", "exp": exp})
    return f"{hdr}.{pay}.sig"


@pytest.fixture(scope="module")
def anon_self(native_xrdfs, tmp_path_factory):
    """A throwaway anon nginx so `explain` (and its credential introspection) can
    run without depending on the shared fleet."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    root = tmp_path_factory.mktemp("diagcred")
    data = root / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"hi\n")
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        xrootd on;
        xrootd_root {data};
        xrootd_auth none;
    }}
}}
""")
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True)
    if t.returncode != 0:
        pytest.skip("nginx -t failed:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        try:
            with socket.create_connection((HOST, port), timeout=1):
                break
        except OSError:
            time.sleep(0.1)
    yield port
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _explain_with_token(port, token):
    env = dict(_CLEAN_ENV)
    env["BEARER_TOKEN"] = token
    return _run(f"root://{HOST}:{port}", "explain", env=env, timeout=20)


def test_explain_decodes_token_claims(native_xrdfs, anon_self):
    p = _explain_with_token(anon_self, _jwt(int(time.time()) + 99999))
    assert p.returncode == 0, p.stderr
    out = p.stdout
    assert "Credentials (in environment)" in out, out
    assert "iss:   https://issuer.example" in out, out
    assert "aud:   xrootd" in out and "scope: storage.read:/" in out, out
    assert "(valid)" in out, out


def test_explain_flags_expired_token(native_xrdfs, anon_self):
    """security-neg: an expired token is flagged EXPIRED, never silently valid."""
    p = _explain_with_token(anon_self, _jwt(int(time.time()) - 100))
    assert p.returncode == 0, p.stderr
    assert "EXPIRED" in p.stdout, p.stdout


def test_explain_malformed_token_no_crash(native_xrdfs, anon_self):
    """error: a non-JWT token yields a note, not a crash; rc stays 0."""
    p = _explain_with_token(anon_self, "not-a-jwt")
    assert p.returncode == 0, p.stderr
    assert "unparseable" in p.stdout, p.stdout


def test_xrdgsitest_built_clean(native_xrdfs):
    """Always-runnable: xrdgsitest builds, links no libXrd*, and forces GSI."""
    if not os.path.exists(NATIVE_XRDGSITEST):
        pytest.skip("xrdgsitest not built")
    ldd = subprocess.run(["ldd", NATIVE_XRDGSITEST], capture_output=True, text=True).stdout
    assert "libXrd" not in ldd, ldd
    h = subprocess.run([NATIVE_XRDGSITEST, "-h"], capture_output=True, text=True).stderr
    assert "GSI" in h or "gsi" in h, h


@pytest.mark.skipif(not os.path.exists(PROXY_STD), reason="no GSI proxy available")
def test_xrdgsitest_gsi_handshake(native_xrdfs):
    """GSI e2e (skips without the fleet/proxy): a valid proxy authenticates."""
    if not os.path.exists(NATIVE_XRDGSITEST):
        pytest.skip("xrdgsitest not built")
    s = socket.socket()
    try:
        s.connect((SERVER_HOST, NGINX_GSI_TLS_PORT))
    except OSError:
        pytest.skip("GSI+TLS server not running")
    finally:
        s.close()
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = PROXY_STD
    env["X509_CERT_DIR"] = CA_DIR
    p = subprocess.run([NATIVE_XRDGSITEST, "--tls",
                        f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "GSI OK" in p.stdout, p.stdout

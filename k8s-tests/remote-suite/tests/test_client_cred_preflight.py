"""
Phase 40 (c) — client-side credential pre-flight diagnostics.

WHAT: Verifies the native `xrdcp` warns the user about a locally-detectable
      credential problem (expired bearer token, or a read-only token used for a
      write) the instant it starts — BEFORE contacting the server — instead of
      leaving them to dig out the cause from a generic "permission denied".
WHY:  The whole point of (c) is "see the problem instantly". These cases need no
      server: `brix_cred_diagnose()` runs as pure local inspection at xrdcp
      start-up, so we drive the real binary against a refused address and assert
      on stderr. The connect failure afterwards is expected and ignored.
HOW:  Craft unsigned JWTs (alg=none; the diagnostic never verifies signatures —
      it is a hint, not a gate), hand them to xrdcp via $BEARER_TOKEN (first in
      the discovery order), and isolate the proxy branch with a non-existent
      $X509_USER_PROXY so only the token path is exercised.

3 cases: expired-token (error), read-only-on-write (error), valid-write-token
(security-negative: must NOT raise a false alarm).
"""
import base64
import json
import os
import subprocess
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

# A closed loopback port: connect() is refused instantly, so the copy fails fast
# right after the pre-flight line we care about is already on stderr.
DEAD_DST = "root://127.0.0.1:9//tmp/preflight_dst"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(claims: dict) -> str:
    """Unsigned 3-segment JWT carrying `claims` (signature is a placeholder)."""
    hdr = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    pay = _b64url(json.dumps(claims).encode())
    return f"{hdr}.{pay}.sig"


def _run_xrdcp_to_remote(token: str, src_file: str):
    """Run `xrdcp <src_file> <DEAD_DST>` with `token` discoverable; return stderr.

    The proxy branch is disabled via a non-existent X509_USER_PROXY so the test
    asserts purely on the token diagnostics (no interference from any real
    /tmp/x509up_u<uid> on the host)."""
    env = dict(os.environ)
    env["BEARER_TOKEN"] = token
    env["X509_USER_PROXY"] = "/nonexistent/x509up_for_preflight_test"
    # Don't let an unrelated discoverable token-file shadow BEARER_TOKEN.
    env.pop("BEARER_TOKEN_FILE", None)
    proc = subprocess.run(
        [XRDCP, "--retry", "0", src_file, DEAD_DST],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.stderr


@pytest.fixture(scope="module")
def src_file(tmp_path_factory):
    p = tmp_path_factory.mktemp("preflight") / "payload.dat"
    p.write_bytes(b"x" * 1024)
    return str(p)


@pytest.mark.skipif(not os.path.exists(XRDCP), reason="xrdcp not built")
def test_expired_token_warns_in_preflight(src_file):
    """Expired bearer token → instant, specific 'EXPIRED' warning at start-up."""
    token = _jwt({"exp": int(time.time()) - 600, "scope": "storage.read:/"})
    err = _run_xrdcp_to_remote(token, src_file)
    assert "bearer token has EXPIRED" in err, err


@pytest.mark.skipif(not os.path.exists(XRDCP), reason="xrdcp not built")
def test_readonly_token_on_write_warns(src_file):
    """A still-valid READ-only token used for an upload → scope-mismatch warning."""
    token = _jwt({"exp": int(time.time()) + 3600, "scope": "storage.read:/"})
    err = _run_xrdcp_to_remote(token, src_file)
    assert "READ scope only" in err, err


@pytest.mark.skipif(not os.path.exists(XRDCP), reason="xrdcp not built")
def test_valid_write_token_no_false_alarm(src_file):
    """A valid, write-capable, non-expiring token must NOT trigger any hint."""
    token = _jwt(
        {"exp": int(time.time()) + 3600, "scope": "storage.read:/ storage.modify:/"}
    )
    err = _run_xrdcp_to_remote(token, src_file)
    assert "EXPIRED" not in err, err
    assert "READ scope only" not in err, err
    assert "expires in" not in err, err


@pytest.mark.skipif(not os.path.exists(XRDCP), reason="xrdcp not built")
def test_s3_destination_skips_token_gsi_preflight(src_file):
    """Security-negative / UX: an s3:// transfer authenticates with AWS SigV4 keys,
    NOT a bearer token or GSI proxy — so an EXPIRED discoverable token (or proxy)
    must NOT raise a spurious 'GSI proxy expired' / 'bearer token' hint. The
    pre-flight only fires for the GSI/token credential family (root:// + non-s3
    web URLs)."""
    token = _jwt({"exp": int(time.time()) - 600, "scope": "storage.read:/"})
    env = dict(os.environ)
    env["BEARER_TOKEN"] = token
    env.pop("BEARER_TOKEN_FILE", None)
    proc = subprocess.run(
        [XRDCP, "--retry", "0", "--s3-access", "AK", "--s3-secret", "SK",
         src_file, "s3://127.0.0.1:9/bucket/obj"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert "bearer token has EXPIRED" not in proc.stderr, proc.stderr
    assert "GSI proxy has EXPIRED" not in proc.stderr, proc.stderr

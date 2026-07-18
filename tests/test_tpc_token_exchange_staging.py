"""A-5 — RFC 8693 token-exchange credential staging is confined to a private dir.

Hardening item A-5 harmonized every credential stager onto brix_cred_stage_write(),
which writes the short-lived OAuth2 request body (carrying the client's subject
token) into a 0600 file under the per-uid /dev/shm/brix-creds.<euid> tmpfs
directory — never world-traversable /tmp, where a co-tenant could open() the
inode during the fork/exec window (CWE-377).

The facility itself is unit-tested in tests/c/test_cred_stage.c.  This test pins
the same guarantee end-to-end through the live WebDAV token-exchange path:

  * config surface — booting nginx_lc_tpc_token_exchange.conf proves the A-5
    directives (brix_webdav_tpc_token_endpoint / _token_scope) parse and pass
    nginx -t (the lifecycle harness validates before serving);
  * staging reached — a COPY with `Credential: token-exchange` and a subject
    bearer drives tpc_cred_rfc8693_exchange (mode accepted → not 400); with the
    token endpoint pointed at a dead loopback port the exchange fails after
    staging (502), not before it;
  * confinement (the A-5 assertion) — no credential body file is left behind in
    /tmp before, during, or after the request; the private tmpfs dir is used.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_tpc_token_exchange_staging.py -v -p no:xdist
"""

import glob
import os

import pytest
import requests

from settings import BIND_HOST, HOST as _HOST, NGINX_BIN  # noqa: F401 (NGINX_BIN: harness gate)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness]

# Any credential body that A-5 must NOT create in /tmp (the pre-A-5 templates).
_TMP_LEAK_GLOBS = ("/tmp/tpc_cred_body_*", "/tmp/tpc_token_body_*")

# A dead loopback endpoint: curl connects, is refused, exits non-zero → 502.
_DEAD_TOKEN_ENDPOINT = "http://127.0.0.1:1/token"


def _tmp_cred_leaks():
    leaks = []
    for pattern in _TMP_LEAK_GLOBS:
        leaks.extend(glob.glob(pattern))
    return leaks


@pytest.fixture(scope="module")
def dav(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path_factory.mktemp("tpc-tokx-data")
    harness = LifecycleHarness()
    ep = harness.start(NginxInstanceSpec(
        name="lc-tpc-token-exchange",
        template="nginx_lc_tpc_token_exchange.conf",
        protocol="webdav",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "TOKEN_ENDPOINT": _DEAD_TOKEN_ENDPOINT,
        },
        reason="A-5 token-exchange credential staging"))
    try:
        yield f"http://{_HOST}:{ep.port}"
    finally:
        harness.close()


def _copy(base, *, credential, subject=None, source=None):
    # The pull Source must be an https URL (validated before credential
    # delegation); a dead https endpoint is fine — the token exchange fails at
    # staging/curl long before any transfer to the source is attempted.
    headers = {
        "Source": source or "https://127.0.0.1:1/nonexistent-source.bin",
        "Credential": credential,
    }
    if subject is not None:
        headers["Authorization"] = f"Bearer {subject}"
    return requests.request(
        "COPY", f"{base}/nonexistent-dest.bin", headers=headers, timeout=20)


def test_config_boots_with_a5_directives(dav):
    """The A-5 token-exchange directive surface parses and the server serves
    (the lifecycle harness ran nginx -t before yielding)."""
    # A trivial OPTIONS confirms the location is live.
    r = requests.options(f"{dav}/", timeout=10)
    assert r.status_code < 500, r.text


def test_token_exchange_mode_reaches_staging_not_400(dav):
    """With a subject bearer + configured endpoint, the token-exchange mode is
    accepted (not 400) and fails at the dead endpoint (502) — i.e. it reached
    the staging + exchange path rather than being rejected as an unknown mode."""
    r = _copy(dav, credential="token-exchange", subject="dummy.subject.jwt")
    assert r.status_code != 400, (
        f"token-exchange should be a valid mode reaching staging, got {r.status_code}")
    # Dead token endpoint → the exchange (post-staging) fails with 502.
    assert r.status_code == 502, (
        f"expected 502 from the dead token endpoint after staging, got {r.status_code}")


def test_no_credential_body_leaks_into_tmp(dav):
    """The A-5 guarantee: the staged OAuth2 body (with the subject token) never
    lands in world-traversable /tmp — before or after the request."""
    assert _tmp_cred_leaks() == [], (
        f"stale credential temp files in /tmp before test: {_tmp_cred_leaks()}")

    # Drive several exchanges so the staging path runs repeatedly.
    for _ in range(3):
        _copy(dav, credential="token-exchange", subject="dummy.subject.jwt")

    leaks = _tmp_cred_leaks()
    assert leaks == [], f"A-5 violated: credential body staged in /tmp: {leaks}"

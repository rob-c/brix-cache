"""
tests/test_token_cache_l1.py — per-worker L1 token-validation cache (phase-50).

These tests guard the always-on per-worker L1 bearer-token cache added to harden
token auth against "HTTP ReadTimeout under load" (src/token/worker_cache.c).  The
cache must make repeated token validation cheap WITHOUT changing any
authorization decision:

  * a token presented many times in quick succession is consistently authorized
    (the L1-hit path returns the same validated claims);
  * scope is still enforced through cached claims — a read-only token cached by a
    successful GET is still denied a PUT;
  * a write-scoped token works on the cache-hit (2nd) presentation too;
  * an invalid-signature token is rejected on every attempt (failures are never
    cached as valid);
  * many distinct valid tokens all authorize (no cross-token contamination in the
    direct-mapped cache).

Run:
    PYTHONPATH=tests pytest tests/test_token_cache_l1.py -v
"""

import os
import sys

import urllib3
import pytest
import requests

from settings import DATA_ROOT, NGINX_WEBDAV_PORT, SERVER_HOST, TOKENS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

WEBDAV_BASE = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"


@pytest.fixture(scope="module")
def issuer():
    ti = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(ti.key_path):
        ti.init_keys()
    return ti


def _get(token, path="/test.txt"):
    return requests.get(
        f"{WEBDAV_BASE}{path}",
        headers={"Authorization": f"Bearer {token}"},
        verify=False, timeout=10,
    )


def test_repeated_token_consistently_authorized(issuer):
    """A single valid token fired many times must always authorize with the same
    result — exercises the L1-hit path returning correct claims under repetition."""
    token = issuer.generate(scope="storage.read:/")
    for _ in range(60):
        resp = _get(token)
        assert resp.status_code == 200, f"unexpected {resp.status_code}"
        assert resp.content == b"hello from nginx-xrootd\n"


def test_cached_read_token_denied_write(issuer):
    """A read-only token cached by a successful GET must still be DENIED a PUT —
    proves the cache stores the real scopes and the write-scope check still runs."""
    token = issuer.generate(scope="storage.read:/")
    # Prime the cache with a successful read.
    assert _get(token).status_code == 200
    # Same token, now a write — must be refused for lack of write scope.
    resp = requests.put(
        f"{WEBDAV_BASE}/l1_should_not_exist.txt",
        data=b"nope\n",
        headers={"Authorization": f"Bearer {token}"},
        verify=False, timeout=10,
    )
    assert resp.status_code in (401, 403), \
        f"cached read token must not gain write access (got {resp.status_code})"
    # Make sure nothing was written.
    assert not os.path.exists(os.path.join(DATA_ROOT, "l1_should_not_exist.txt"))


def test_write_token_cached_allows_write(issuer):
    """A write-scoped token must work on the cache-hit (2nd) presentation too."""
    token = issuer.generate(scope="storage.read:/ storage.write:/")
    path = "/l1_write_cached.txt"
    local = os.path.join(DATA_ROOT, "l1_write_cached.txt")
    try:
        for i in range(2):
            resp = requests.put(
                f"{WEBDAV_BASE}{path}",
                data=b"cached-write\n",
                headers={"Authorization": f"Bearer {token}"},
                verify=False, timeout=10,
            )
            assert resp.status_code in (200, 201, 204), \
                f"PUT #{i} failed: {resp.status_code}"
    finally:
        try:
            os.unlink(local)
        except FileNotFoundError:
            pass


# NOTE: "a bad-signature token is never cached as valid" is asserted by the
# existing test_token_auth.py stream-port negative cases
# (test_bad_signature_rejected / test_wrong_issuer_rejected), which run through
# the SAME validate + L1-cache path (gsi/token.c) on a port where auth is
# mandatory.  It is intentionally NOT re-tested over HTTP here: the 8443 WebDAV
# is auth=optional with anonymous write enabled, so a rejected token falls
# through to the anonymous identity and the rejection is not observable at the
# HTTP status layer.  The L1 cache only ever stores SUCCESSFULLY validated
# claims, so the failure path is unchanged by this phase.


def test_distinct_tokens_all_authorize(issuer):
    """Many distinct valid tokens must each authorize — the direct-mapped L1 must
    not let one token's cached claims answer for a different token."""
    for i in range(25):
        # Vary subject so each token is byte-distinct (distinct fingerprints).
        token = issuer.generate(scope="storage.read:/", sub=f"user-{i}")
        resp = _get(token)
        assert resp.status_code == 200, \
            f"distinct token {i} failed: {resp.status_code}"

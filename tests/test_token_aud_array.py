"""
tests/test_token_aud_array.py

Coverage gap #30 (test-coverage-gap-audit): JWT `aud` claim as a JSON ARRAY.

RFC 7519 §4.1.3: `aud` MAY be a single string OR an array of strings.  WLCG and
many OIDC issuers routinely emit it as an array.  Before the fix, the gateway
extracted `aud` with json_get_string() (which only accepts a JSON string), so a
token whose `aud` is an array — even one that CONTAINS the configured audience —
was silently rejected (false-deny of an entire class of legitimate tokens).

These tests exercise the audience check end-to-end over a self-contained
token-auth WebDAV server (no fleet dependency): a valid token authenticates a
GET (200); an invalid/mismatched audience is rejected (403).
"""

import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer        # noqa: E402

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, HOST, BIND_HOST                    # noqa: E402
from server_registry import NginxInstanceSpec                      # noqa: E402

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-token-aud-array")]

AUDIENCE = "nginx-xrootd"
PORT = None                              # bound by the aud_server fixture


@pytest.fixture()
def aud_server(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    data = tmp_path / "data"
    data.mkdir()
    (data / "test.txt").write_text("hello-aud\n")
    cadir = tmp_path / "cadir"
    cadir.mkdir()                        # auth!=none requires a cadir (token-only is fine)

    issuer = TokenIssuer(str(tmp_path), audience=AUDIENCE)
    issuer.init_keys()                   # writes signing_key.pem + jwks.json

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-token-aud-array",
        template="nginx_lc_webdav_token_aud.conf",
        protocol="webdav",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "CADIR": str(cadir),
            "JWKS_PATH": issuer.jwks_path,
            "ISSUER": issuer.issuer,
            "AUDIENCE": AUDIENCE,
        },
        reason="webdav JWT audience-array auth"))

    global PORT
    PORT = ep.port
    yield issuer


def _sign(issuer, aud):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": TokenIssuer.DEFAULT_KID}
    payload = {
        "iss": issuer.issuer, "sub": "tester", "aud": aud,
        "exp": now + 3600, "iat": now, "nbf": now,
        "scope": "storage.read:/", "wlcg.ver": "1.0",
    }
    return issuer._sign_jwt(header, payload)


def _get(token):
    r = requests.get(f"http://{HOST}:{PORT}/test.txt",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10)
    return r.status_code


# --- positive controls: the audience check works for the scalar form --------

def test_scalar_aud_match_accepted(aud_server):
    assert _get(_sign(aud_server, AUDIENCE)) in (200, 206), \
        "scalar aud == expected should authenticate (oracle broken)"


def test_scalar_aud_mismatch_rejected(aud_server):
    assert _get(_sign(aud_server, "some-other-service")) == 403, \
        "scalar aud != expected must be rejected"


# --- the gap: aud as an ARRAY (RFC 7519 / WLCG / OIDC) ----------------------

def test_array_aud_containing_expected_accepted(aud_server):
    # aud is an array that CONTAINS the configured audience → must authenticate.
    tok = _sign(aud_server, [AUDIENCE, "https://other.example/aud"])
    assert _get(tok) in (200, 206), \
        "array aud containing the expected audience must be accepted (RFC 7519)"


def test_array_aud_expected_not_first_accepted(aud_server):
    # The match must not depend on array position.
    tok = _sign(aud_server, ["https://other.example/aud", "x", AUDIENCE])
    assert _get(tok) in (200, 206), \
        "array aud containing the expected audience (not first) must be accepted"


def test_array_aud_without_expected_rejected(aud_server):
    tok = _sign(aud_server, ["https://other.example/aud", "https://nope"])
    assert _get(tok) == 403, \
        "array aud NOT containing the expected audience must be rejected"


def test_empty_array_aud_rejected(aud_server):
    assert _get(_sign(aud_server, [])) == 403, \
        "empty aud array must be rejected"

"""tests/test_macaroon_delegation.py — Macaroon third-party delegation endpoint tests.

Tests the POST /.oauth2/token issuance endpoint and
GET /.well-known/oauth-authorization-server discovery endpoint.

Run against the plain HTTP WebDAV server (port 8080, anonymous+write) which
is configured with brix_webdav_macaroon_secret so the issuance path is active.

Success path:
  - Discovery returns a JSON document with token_endpoint pointing at /.oauth2/token
  - Authenticated POST issues a signed macaroon that can be validated with the same key

Error paths:
  - No auth → 401
  - Wrong grant_type → 400
  - Missing scope → 400
  - Unknown scope perm → 400

Run:
    PYTHONPATH=tests pytest tests/test_macaroon_delegation.py -v
"""

import base64
import hashlib
import hmac
import time

import pytest
import requests

from test_token_macaroon import make_macaroon


# ---------------------------------------------------------------------------
# Macaroon wire-format helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode_macaroon(token: str):
    """Decode a base64url macaroon into a list of (label, value) tuples."""
    raw = _b64url_decode(token)
    packets = []
    pos = 0
    while pos < len(raw):
        if pos + 4 > len(raw):
            break
        plen = int(raw[pos:pos + 4], 16)
        if plen < 4 or pos + plen > len(raw):
            break
        data = raw[pos + 4:pos + plen]
        if data and data[-1] == ord('\n'):
            data = data[:-1]
        sp = data.find(b' ')
        if sp >= 0:
            packets.append((data[:sp].decode(), data[sp + 1:]))
        pos += plen
    return packets


def validate_macaroon(token: str, root_key: bytes) -> dict:
    """Validate a macaroon's HMAC chain; return extracted first-party caveat values."""
    packets = decode_macaroon(token)
    sig = None
    caveats = {}
    provided_sig = None

    for label, value in packets:
        if label == "identifier":
            sig = hmac.new(root_key, value, hashlib.sha256).digest()
            break

    assert sig is not None, "No identifier packet found"

    for label, value in packets:
        if label == "cid":
            sig = hmac.new(sig, value, hashlib.sha256).digest()
            if b":" in value:
                k, v = value.split(b":", 1)
                caveats[k.decode()] = v.decode()
        elif label == "signature":
            provided_sig = value

    assert provided_sig == sig, (
        f"HMAC mismatch: expected {sig.hex()}, got {provided_sig.hex() if provided_sig else 'None'}"
    )
    return caveats


def parse_iso8601(s: str) -> float:
    """Parse 'YYYY-MM-DDTHH:MM:SSZ' → Unix timestamp."""
    import calendar
    from datetime import datetime
    dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    return float(calendar.timegm(dt.timetuple()))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MACAROON_SECRET_HEX = "deadbeef" * 8
MACAROON_SECRET     = bytes.fromhex(MACAROON_SECRET_HEX)
# Must match brix_webdav_token_issuer in the test config: the server pins a
# macaroon's "location" to the configured issuer (issuer-pinning, fail-closed),
# so a macaroon presented for auth must carry this exact location.
TOKEN_ISSUER        = "https://test.example.com"


@pytest.fixture(scope="module")
def base_url(test_env):
    return test_env["http_webdav_url"]


@pytest.fixture(scope="module")
def token_endpoint(base_url):
    return f"{base_url}/.oauth2/token"


@pytest.fixture(scope="module")
def discovery_url(base_url):
    return f"{base_url}/.well-known/oauth-authorization-server"


@pytest.fixture(scope="module")
def auth_token():
    """A valid macaroon token used to authenticate to the issuance endpoint."""
    return make_macaroon(
        MACAROON_SECRET,
        "test-delegation-subject",
        ["activity:DOWNLOAD", "before:2030-01-01T00:00:00Z"],
        location=TOKEN_ISSUER,
    )


# ---------------------------------------------------------------------------
# Discovery endpoint tests
# ---------------------------------------------------------------------------

class TestDiscovery:

    def test_discovery_returns_200(self, discovery_url):
        """GET /.well-known/oauth-authorization-server returns 200."""
        r = requests.get(discovery_url, timeout=10)
        assert r.status_code == 200

    def test_discovery_content_type_json(self, discovery_url):
        """Discovery response has application/json content type."""
        r = requests.get(discovery_url, timeout=10)
        assert "application/json" in r.headers.get("Content-Type", "")

    def test_discovery_token_endpoint_field(self, discovery_url):
        """Discovery JSON contains a token_endpoint pointing at /.oauth2/token."""
        r = requests.get(discovery_url, timeout=10)
        doc = r.json()
        assert "token_endpoint" in doc
        assert doc["token_endpoint"].endswith("/.oauth2/token")

    def test_discovery_grant_types_field(self, discovery_url):
        """Discovery JSON lists client_credentials in grant_types_supported."""
        r = requests.get(discovery_url, timeout=10)
        doc = r.json()
        assert "grant_types_supported" in doc
        assert "client_credentials" in doc["grant_types_supported"]

    def test_discovery_no_auth_required(self, discovery_url):
        """Discovery is accessible without authentication."""
        r = requests.get(discovery_url, timeout=10)
        assert r.status_code == 200

    def test_discovery_post_returns_405(self, discovery_url):
        """POST to discovery endpoint returns 405 (only GET/HEAD allowed)."""
        r = requests.post(discovery_url, timeout=10)
        assert r.status_code == 405


# ---------------------------------------------------------------------------
# Token issuance — error paths
# ---------------------------------------------------------------------------

class TestTokenEndpointErrors:

    def test_missing_auth_returns_401(self, token_endpoint):
        """POST without authentication returns 401 unauthorized."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read:/data",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        assert r.status_code == 401

    def test_wrong_grant_type_returns_400(self, token_endpoint, auth_token):
        """grant_type other than client_credentials returns 400."""
        r = requests.post(
            token_endpoint,
            data="grant_type=password&scope=storage.read:/data",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 400
        assert "unsupported_grant_type" in r.text

    def test_missing_scope_returns_400(self, token_endpoint, auth_token):
        """POST with grant_type but no scope returns 400."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 400
        assert "invalid_scope" in r.text

    def test_unknown_scope_permission_returns_400(self, token_endpoint, auth_token):
        """POST with an unrecognised scope permission returns 400."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.frob%3A%2Fdata",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 400
        assert "invalid_scope" in r.text


# ---------------------------------------------------------------------------
# Token issuance — success paths
# ---------------------------------------------------------------------------

class TestTokenIssuance:

    def test_issue_read_token_returns_200(self, token_endpoint, auth_token):
        """Authenticated POST with storage.read scope returns 200."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2Fdata",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"

    def test_issued_token_response_shape(self, token_endpoint, auth_token):
        """Issuance response has token, expires_in, and token_type fields."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2Fdata",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 200
        doc = r.json()
        assert "token" in doc
        assert "expires_in" in doc
        assert "token_type" in doc
        assert doc["token_type"] == "bearer"

    def test_issued_token_has_valid_hmac_chain(self, token_endpoint, auth_token):
        """The issued macaroon passes HMAC chain validation with the server's root key."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2Fdata",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 200
        caveats = validate_macaroon(r.json()["token"], MACAROON_SECRET)
        assert "activity" in caveats
        assert "DOWNLOAD" in caveats["activity"]

    def test_issued_token_has_path_caveat(self, token_endpoint, auth_token):
        """The issued macaroon contains a path: caveat matching the requested scope path."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2Fatlas",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 200
        caveats = validate_macaroon(r.json()["token"], MACAROON_SECRET)
        assert "path" in caveats
        assert caveats["path"] == "/atlas"

    def test_issued_token_has_expiry_caveat(self, token_endpoint, auth_token):
        """The issued macaroon has a before: caveat within expire_in seconds of now."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2Fdata&expire_in=7200",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 200
        doc = r.json()
        assert doc["expires_in"] == 7200
        caveats = validate_macaroon(doc["token"], MACAROON_SECRET)
        assert "before" in caveats
        expiry_ts = parse_iso8601(caveats["before"])
        # Should expire roughly 7200 seconds from now (allow 60s slack)
        assert expiry_ts > time.time() + 7000

    def test_write_scope_escalation_denied_for_read_token(self, token_endpoint, auth_token):
        """A read-only credential cannot obtain a write macaroon (privilege escalation denied).

        auth_token carries only activity:DOWNLOAD (storage.read scope).  Requesting
        storage.write:/data requires write authority the caller does not hold.
        The server must refuse with 403 to prevent scope escalation.
        """
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.write%3A%2Fdata",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 403, (
            f"Expected 403 (escalation denied) but got {r.status_code}: {r.text}"
        )
        assert "unauthorized" in r.text or "error" in r.text

    def test_issued_token_is_accepted_for_auth(self, base_url, token_endpoint, auth_token):
        """An issued delegation macaroon can authenticate a subsequent GET request."""
        import uuid
        fname = f"/.macaroon_delegation_test_{uuid.uuid4().hex}.txt"
        content = b"delegation test content"

        # Upload a test file (no auth needed on this anonymous write-enabled server)
        put_r = requests.put(f"{base_url}{fname}", data=content, timeout=10)
        assert put_r.status_code in (200, 201)

        # Obtain a delegation macaroon for storage.read:/
        issue_r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2F",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert issue_r.status_code == 200
        delegation_token = issue_r.json()["token"]

        # Use the delegation macaroon to GET the file
        get_r = requests.get(
            f"{base_url}{fname}",
            headers={"Authorization": f"Bearer {delegation_token}"},
            timeout=10,
        )
        assert get_r.status_code == 200
        assert get_r.content == content

        # Clean up
        requests.delete(f"{base_url}{fname}", timeout=10)

    def test_response_content_type_is_json(self, token_endpoint, auth_token):
        """Issuance response has Content-Type: application/json."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2Fdata",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 200
        assert "application/json" in r.headers.get("Content-Type", "")

    def test_response_cache_control_no_store(self, token_endpoint, auth_token):
        """Issuance response includes Cache-Control: no-store."""
        r = requests.post(
            token_endpoint,
            data="grant_type=client_credentials&scope=storage.read%3A%2Fdata",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {auth_token}",
            },
            timeout=10,
        )
        assert r.status_code == 200
        assert "no-store" in r.headers.get("Cache-Control", "")

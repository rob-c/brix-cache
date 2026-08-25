"""Managed OIDC discovery, JWKS, restart, and confinement contracts."""

import json
import urllib.error
import urllib.request

import pytest

from brixtest import token_auth
from brixtest.auth.store import AuthStore
from brixtest.errors import SpecError


def _json(url):
    with urllib.request.urlopen(url, timeout=1.0) as response:
        assert response.headers["Cache-Control"] == "no-store"
        return json.load(response)


def test_managed_oidc_serves_live_discovery_and_public_jwks(tmp_path):
    pytest.importorskip("cryptography")
    store = AuthStore(tmp_path / "auth")
    item = store.materialize(token_auth(
        algorithm="ES256", key_id="initial", managed=True,
    ))
    try:
        discovery = _json(item.test_env["BRIXTEST_TOKEN_DISCOVERY_URL"])
        jwks = _json(item.test_env["BRIXTEST_TOKEN_JWKS_URL"])

        assert item.available()
        assert discovery["issuer"] == "https://issuer.test"
        assert discovery["jwks_uri"] == item.metadata["jwks_url"]
        assert jwks["keys"][0]["kid"] == "initial"
        assert "d" not in jwks["keys"][0]
        assert item.path("authority_log").is_file()
    finally:
        store.close()
    assert not item.available()


def test_managed_oidc_restart_can_rotate_without_changing_endpoint(tmp_path):
    pytest.importorskip("cryptography")
    store = AuthStore(tmp_path / "auth")
    item = store.materialize(token_auth(
        algorithm="ES256", key_id="first", managed=True,
        rotate_on_restart=True,
    ))
    endpoint = item.metadata["authority_url"]
    first = _json(item.metadata["jwks_url"])["keys"][0]

    item.stop()
    assert not item.available()
    item.start()
    second = _json(item.metadata["jwks_url"])["keys"][0]

    assert item.available() and item.metadata["authority_url"] == endpoint
    assert first["kid"] != second["kid"]
    events = (item.root / "authority-events.jsonl").read_text()
    assert '"action": "rotated"' in events and '"action": "started"' in events
    store.close()


def test_managed_oidc_never_serves_private_material_or_mutating_methods(tmp_path):
    pytest.importorskip("cryptography")
    store = AuthStore(tmp_path / "auth")
    item = store.materialize(token_auth(algorithm="RS256", managed=True))
    base = item.metadata["authority_url"]
    try:
        with pytest.raises(urllib.error.HTTPError) as traversal:
            urllib.request.urlopen(base + "/signing.key", timeout=1.0)
        request = urllib.request.Request(base + "/rotate", method="POST")
        with pytest.raises(urllib.error.HTTPError) as mutation:
            urllib.request.urlopen(request, timeout=1.0)
        assert traversal.value.code == 404 and mutation.value.code == 405
        assert "PRIVATE KEY" not in json.dumps(_json(item.metadata["jwks_url"]))
    finally:
        store.close()


@pytest.mark.parametrize("managed,rotate", [("yes", False), (False, True), (True, 1)])
def test_token_authority_policy_rejects_invalid_or_ignored_controls(managed, rotate):
    with pytest.raises(SpecError, match="authority policy|requires managed"):
        token_auth(managed=managed, rotate_on_restart=rotate)

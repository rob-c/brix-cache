"""Live token rotation, issuance, TLS revocation, and audit contracts."""

import json
import shutil
import subprocess

import pytest

from brixtest import tls_auth, token_auth, verify_token
from brixtest.auth.store import AuthStore
from brixtest.errors import SpecError


def _events(item):
    return [
        json.loads(line)
        for line in (item.root / "authority-events.jsonl").read_text().splitlines()
    ]


def test_asymmetric_authority_rotates_issues_and_records_redacted_events(tmp_path):
    pytest.importorskip("cryptography")
    item = AuthStore(tmp_path / "auth").materialize(
        token_auth(algorithm="ES256", key_id="first"),
    )
    original_public = item.path("public_key").read_bytes()
    rotation = item.rotate(key_id="second")
    token = item.issue(subject="rotated-user", scopes=("storage.read:/data",))
    claims = verify_token(
        token, public_key=item.path("public_key").read_bytes(),
        algorithms=("ES256",), issuer="https://issuer.test", audience="brixtest",
    )

    assert item.path("public_key").read_bytes() != original_public
    assert rotation["version"] == 2 and rotation["key_id"] == "second"
    assert claims["sub"] == "rotated-user" and claims["scope"] == "storage.read:/data"
    events = _events(item)
    assert [event["action"] for event in events] == ["rotated", "issued"]
    assert token not in (item.root / "authority-events.jsonl").read_text()


def test_hmac_authority_rotation_invalidates_old_token(tmp_path):
    item = AuthStore(tmp_path / "auth").materialize(token_auth(secret="first-secret"))
    old_token = item.path("token").read_text()
    item.rotate()
    new_secret = item.path("secret").read_text()
    with pytest.raises(SpecError, match="signature"):
        verify_token(old_token, secret=new_secret)
    assert verify_token(item.issue(), secret=new_secret)["sub"] == "test-user"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is required")
def test_tls_authority_revokes_certificate_and_republishes_crl(tmp_path):
    item = AuthStore(tmp_path / "auth").materialize(tls_auth())
    before = item.path("crl").read_bytes()
    crl = item.revoke("client_cert")
    result = subprocess.run(
        [
            "openssl", "verify", "-CAfile", str(item.path("ca_cert")),
            "-CRLfile", str(crl), "-crl_check", str(item.path("client_cert")),
        ],
        capture_output=True, text=True, timeout=10.0, check=False,
    )

    assert crl.read_bytes() != before and result.returncode != 0
    assert "revoked" in (result.stdout + result.stderr).lower()
    assert _events(item)[0]["certificate"] == "client_cert"


def test_authority_controls_reject_wrong_stack_and_private_material(tmp_path):
    tokens = AuthStore(tmp_path / "tokens").materialize(token_auth(secret="secret"))
    with pytest.raises(SpecError, match="TLS or VOMS"):
        tokens.revoke()
    tls = AuthStore(tmp_path / "tls").materialize
    if shutil.which("openssl") is not None:
        with pytest.raises(SpecError, match="client_cert, host_cert, or voms_cert"):
            tls(tls_auth()).revoke("ca_cert")


def test_managed_authority_availability_can_be_injected_and_recovered(tmp_path):
    class Controller:
        running = False

        def available(self):
            return self.running

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

    item = AuthStore(tmp_path / "auth").materialize(token_auth(secret="secret"))
    controller = Controller()
    object.__setattr__(item, "_authority_controller", controller)

    assert not item.available()
    item.start()
    assert item.available()
    item.stop()
    assert not item.available()
    assert [event["action"] for event in _events(item)] == ["started", "stopped"]


def test_static_authority_rejects_unmanaged_availability_control(tmp_path):
    item = AuthStore(tmp_path / "auth").materialize(token_auth(secret="secret"))
    with pytest.raises(SpecError, match="managed service authorities only"):
        item.stop()

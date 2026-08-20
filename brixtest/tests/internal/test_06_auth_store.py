"""Authentication materialization and least-privilege handoff (051-060)."""

from pathlib import Path

import pytest

from brixtest import tls_auth, token_auth, voms_auth
from brixtest.auth.models import AuthRecipe
from brixtest.auth.store import AuthStore
from brixtest.errors import SpecError


def _fake_pki(root, **kwargs):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    trust = root / "certificates"
    trust.mkdir()
    names = (
        "ca_key", "ca_cert", "crl", "host_key", "host_cert",
        "client_key", "client_cert", "voms_key", "voms_cert",
    )
    files = {}
    for name in names:
        path = root / (name + ".pem")
        path.write_text(name)
        files[name] = path
    (trust / "hash.0").write_text("ca")
    files["trust_dir"] = trust
    return files


class SubjectOpenSSL:
    def run(self, *args, **kwargs):
        return "subject=/CN=BriXTest VOMS"


def test_051_token_stack_materializes_signed_token_and_secret(tmp_path):
    store = AuthStore(tmp_path / "auth")
    item = store.materialize(token_auth(secret="fixed-secret"))
    assert item.path("secret").read_text() == "fixed-secret"
    assert item.path("token").read_text().count(".") == 2


def test_052_token_server_receives_verifier_not_bearer(tmp_path):
    item = AuthStore(tmp_path / "auth").materialize(token_auth(secret="secret"))
    assert "BRIXTEST_TOKEN_SECRET_FILE" in item.server_env
    assert "BEARER_TOKEN" not in item.server_env


def test_053_token_client_receives_bearer_not_verifier(tmp_path):
    item = AuthStore(tmp_path / "auth").materialize(token_auth(secret="secret"))
    assert "BEARER_TOKEN" in item.client_env
    assert "BRIXTEST_TOKEN_SECRET_FILE" not in item.client_env


def test_054_tls_server_and_client_keys_are_separated(tmp_path, monkeypatch):
    monkeypatch.setattr("brixtest.auth.store.create_pki", _fake_pki)
    item = AuthStore(tmp_path / "auth").materialize(tls_auth())
    assert item.server_env["BRIXTEST_TLS_KEY"].endswith("host_key.pem")
    assert item.client_env["BRIXTEST_TLS_CLIENT_KEY"].endswith("client_key.pem")
    assert "BRIXTEST_TLS_KEY" not in item.client_env


def test_055_voms_server_never_receives_user_proxy(tmp_path, monkeypatch):
    monkeypatch.setattr("brixtest.auth.store.create_pki", _fake_pki)
    monkeypatch.setattr("brixtest.auth.store.OpenSSL", SubjectOpenSSL)

    def fake_command(argv, field):
        Path(argv[argv.index("-out") + 1]).write_text("proxy")
        return ""

    monkeypatch.setattr("brixtest.auth.store._command", fake_command)
    item = AuthStore(tmp_path / "auth").materialize(voms_auth(vo="atlas"))
    assert "X509_USER_PROXY" in item.client_env
    assert "X509_USER_PROXY" not in item.server_env


def test_056_multiple_active_stacks_cannot_collide_in_environment(tmp_path):
    store = AuthStore(tmp_path / "auth")
    store.materialize_all([
        token_auth("one", secret="one"), token_auth("two", secret="two"),
    ])
    with pytest.raises(SpecError, match="multiple active recipes"):
        store.environment("server")


def test_057_container_base_rewrites_auth_file_paths(tmp_path):
    store = AuthStore(tmp_path / "auth")
    store.materialize(token_auth(secret="secret"))
    environment = store.environment("server", Path("/brixtest/secure/auth"))
    assert environment["BRIXTEST_TOKEN_SECRET_FILE"] == "/brixtest/secure/auth/token/verification.key"


def test_058_server_file_export_excludes_bearer_token(tmp_path):
    store = AuthStore(tmp_path / "auth")
    store.materialize(token_auth(secret="secret"))
    files = store.files_for("server")
    assert "token/verification.key" in files
    assert "token/access.token" not in files


def test_059_auth_manifest_contains_hashes_not_secret_values(tmp_path):
    store = AuthStore(tmp_path / "auth")
    store.materialize_all([token_auth(secret="must-not-appear")])
    text = (store.root / "manifest.json").read_text()
    assert "must-not-appear" not in text and "sha256" in text


def test_060_unknown_auth_recipe_type_is_rejected(tmp_path):
    recipe = AuthRecipe("unknown", "unknown")
    with pytest.raises(SpecError, match="unsupported"):
        AuthStore(tmp_path / "auth").materialize(recipe)

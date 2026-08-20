"""Unified security resource access and cleanup contracts (081-090)."""

import os
from pathlib import Path

import pytest

from brixtest import credential, host_mapping, token_auth
from brixtest.errors import SpecError
from brixtest.runtime.artifacts import ArtifactStore
from brixtest.runtime.security import SecurityResources


def _security(tmp_path, *, credentials=(), auth=(), hosts=()):
    artifacts = ArtifactStore(tmp_path / "artifacts", tmp_path)
    artifacts.materialize_all([])
    return SecurityResources(
        tmp_path / "inputs", tmp_path, artifacts, credentials, auth, hosts,
    )


def test_081_security_materializes_credentials_and_auth(tmp_path):
    security = _security(
        tmp_path, credentials=[credential("custom", "value")],
        auth=[token_auth(secret="secret")],
    )
    security.materialize()
    assert security.credential("custom").content == "value"
    assert security.auth_stack("token").path("token").is_file()
    security.close()


def test_082_test_environment_is_activated_before_body(tmp_path, monkeypatch):
    monkeypatch.delenv("BRIXTEST_INTERNAL_KEY", raising=False)
    security = _security(
        tmp_path,
        credentials=[credential("key", "value", env="BRIXTEST_INTERNAL_KEY", env_value="content")],
    )
    security.materialize()
    assert os.environ["BRIXTEST_INTERNAL_KEY"] == "value"
    security.close()


def test_083_test_environment_is_restored_on_close(tmp_path, monkeypatch):
    monkeypatch.setenv("BRIXTEST_INTERNAL_KEY", "original")
    security = _security(
        tmp_path,
        credentials=[credential("key", "replacement", env="BRIXTEST_INTERNAL_KEY", env_value="content")],
    )
    security.materialize()
    security.close()
    assert os.environ["BRIXTEST_INTERNAL_KEY"] == "original"


def test_084_values_include_namespaced_credential_and_auth_paths(tmp_path):
    security = _security(
        tmp_path, credentials=[credential("custom", "value")],
        auth=[token_auth("tokens", secret="secret")],
    )
    security.materialize()
    values = security.values()
    assert Path(values["credential_custom"]).is_file()
    assert Path(values["auth_tokens_token"]).is_file()
    security.close()


def test_085_values_rewrite_secure_container_roots(tmp_path):
    security = _security(
        tmp_path, credentials=[credential("custom", "value")],
        auth=[token_auth("tokens", secret="secret")],
    )
    security.materialize()
    values = security.values(
        credential_base=Path("/secure/credentials"), auth_base=Path("/secure/auth"),
    )
    assert str(values["credential_custom"]).startswith("/secure/credentials/")
    assert str(values["auth_tokens_secret"]).startswith("/secure/auth/tokens/")
    security.close()


def test_086_resolve_accepts_alias_and_canonical_hostname(tmp_path):
    mapping = host_mapping("origin", "origin.test", address="127.0.0.8", aliases=("alias.test",))
    security = _security(tmp_path, hosts=[mapping])
    assert security.resolve("origin.test") == "127.0.0.8"
    assert security.resolve("alias.test.") == "127.0.0.8"


def test_087_reverse_requires_reverse_enabled_mapping(tmp_path):
    security = _security(
        tmp_path, hosts=[host_mapping("origin", "origin.test", address="127.0.0.8", reverse=False)],
    )
    with pytest.raises(SpecError, match="reverse lookup"):
        security.reverse("127.0.0.8")


def test_088_secure_server_files_exclude_test_only_credential(tmp_path):
    security = _security(
        tmp_path,
        credentials=[credential("test_only", "value", targets=("test",))],
        auth=[token_auth(secret="secret")],
    )
    security.materialize()
    files = security.secure_files("server")
    assert "auth/token/verification.key" in files
    assert not any("test_only" in name for name in files)
    security.close()


def test_089_security_summary_names_resources_without_secret_content(tmp_path):
    security = _security(
        tmp_path, credentials=[credential("custom", "do-not-export")],
        auth=[token_auth(secret="also-private")],
        hosts=[host_mapping("origin", "origin.test")],
    )
    security.materialize()
    summary = security.summary()
    assert set(summary) == {"credentials", "auth", "hosts"}
    assert "do-not-export" not in str(summary) and "also-private" not in str(summary)
    security.close()


def test_090_conflicting_test_environment_fails_before_test_body(tmp_path):
    security = _security(
        tmp_path,
        credentials=[credential("collision", "wrong", env="BEARER_TOKEN", env_value="content")],
        auth=[token_auth(secret="secret")],
    )
    with pytest.raises(SpecError, match="conflicting"):
        security.materialize()

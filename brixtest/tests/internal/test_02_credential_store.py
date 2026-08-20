"""Credential materialization and exposure contracts (011-020)."""

import base64

import pytest

from brixtest import checksum_credential, credential, noise, signed_credential
from brixtest.credentials import CredentialStore
from brixtest.errors import SpecError


def _store(tmp_path, artifact_store):
    return CredentialStore(tmp_path / "credentials", tmp_path, artifact_store)


def test_011_text_materializes_with_declared_mode(tmp_path, artifact_store):
    store = _store(tmp_path, artifact_store)
    item = store.materialize(credential("token", "value", mode=0o400))
    assert item.content == "value" and item.path.stat().st_mode & 0o777 == 0o400


def test_012_file_credential_is_copied(tmp_path, artifact_store, source_file):
    item = _store(tmp_path, artifact_store).materialize(credential("copy", source=source_file))
    assert item.path != source_file and item.content == source_file.read_text()


def test_013_checksum_uses_materialized_artifact(tmp_path, artifact_store):
    declaration = noise("payload", size=32, seed=3)
    payload = artifact_store.materialize(declaration)
    item = _store(tmp_path, artifact_store).materialize(checksum_credential("sum", declaration))
    assert item.content == "%s  %s\n" % (payload.sha256, payload.path.name)


def test_014_signed_credential_is_payload_and_hmac(tmp_path, artifact_store):
    item = _store(tmp_path, artifact_store).materialize(
        signed_credential("proof", "payload", secret="secret")
    )
    body, signature = item.content.split(".")
    assert base64.urlsafe_b64decode(body + "==") == b"payload"
    assert signature


def test_015_path_environment_points_at_materialized_file(tmp_path, artifact_store):
    store = _store(tmp_path, artifact_store)
    item = store.materialize(credential("key", "value", env="KEY_FILE"))
    assert store.environment("server")["KEY_FILE"] == str(item.path)


def test_016_content_environment_contains_the_credential(tmp_path, artifact_store):
    store = _store(tmp_path, artifact_store)
    store.materialize(credential("key", "value", env="KEY", env_value="content"))
    assert store.environment("client")["KEY"] == "value"


def test_017_target_filter_prevents_server_handoff(tmp_path, artifact_store):
    store = _store(tmp_path, artifact_store)
    store.materialize(credential("key", "value", env="KEY", targets=("test",)))
    assert store.environment("server") == {}
    assert store.environment("test")["KEY"].endswith("credentials/key.cred")


def test_018_container_base_rewrites_paths(tmp_path, artifact_store):
    store = _store(tmp_path, artifact_store)
    store.materialize(credential("key", "value", env="KEY_FILE"))
    assert store.environment("server", tmp_path / "mounted")["KEY_FILE"].endswith(
        "mounted/credentials/key.cred"
    )


def test_019_duplicate_credential_names_fail(tmp_path, artifact_store):
    store = _store(tmp_path, artifact_store)
    with pytest.raises(SpecError, match="more than once"):
        store.materialize_all([credential("same", "a"), credential("same", "b")])
    assert not store.root.exists()


def test_020_duplicate_destinations_fail_before_overwrite(tmp_path, artifact_store):
    store = _store(tmp_path, artifact_store)
    values = [credential("one", "a", destination="shared"), credential("two", "b", destination="shared")]
    with pytest.raises(SpecError, match="destination"):
        store.materialize_all(values)
    assert not store.root.exists()

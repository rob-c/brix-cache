"""Credential declaration success, error, and security boundaries (001-010)."""

import pytest

from brixtest import checksum_credential, credential, noise, signed_credential
from brixtest.errors import SpecError


def test_001_text_credential_has_confined_defaults():
    item = credential("api_key", "secret")
    assert item.kind == "text" and item.destination == "credentials/api_key.cred"


def test_002_file_credential_selects_file_kind(source_file):
    item = credential("host_key", source=source_file)
    assert item.kind == "file" and item.source == source_file


def test_003_value_and_source_are_mutually_exclusive(source_file):
    with pytest.raises(SpecError, match="mutually exclusive"):
        credential("bad", "value", source=source_file)


def test_004_checksum_credential_keeps_artifact_identity():
    payload = noise("payload", size=8)
    item = checksum_credential("digest", payload, algorithm="sha512")
    assert item.artifact is payload and item.algorithm == "sha512"


def test_005_signed_credential_defaults_to_content_environment():
    item = signed_credential("proof", "read:/", secret="key", env="PROOF")
    assert item.kind == "signed" and item.env_value == "content"


def test_006_credential_names_use_public_name_contract():
    with pytest.raises(SpecError, match="credential.name"):
        credential("UpperCase", "x")


def test_007_absolute_destination_is_rejected():
    with pytest.raises(SpecError, match="confined"):
        credential("escape", "x", destination="/tmp/escape")


def test_008_parent_destination_is_rejected():
    with pytest.raises(SpecError, match="confined"):
        credential("escape", "x", destination="../escape")


def test_009_environment_name_is_validated():
    with pytest.raises(SpecError, match="environment"):
        credential("bad_env", "x", env="BAD-NAME")


def test_010_world_writable_credentials_are_rejected():
    with pytest.raises(SpecError, match="writable"):
        credential("unsafe", "x", mode=0o606)

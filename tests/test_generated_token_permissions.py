"""The canonical token writer must satisfy the stock ztn private-file contract."""

import os
import stat

import pytest

from utils import make_token


def test_new_token_is_private_even_with_a_permissive_umask(tmp_path, capsys):
    destination = tmp_path / "issued.jwt"
    previous = os.umask(0)
    try:
        make_token._write_generated_token("owned-fixture-secret", destination)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.read_text() == "owned-fixture-secret"
    assert "owned-fixture-secret" not in capsys.readouterr().out


def test_existing_token_is_tightened_before_any_secret_write(tmp_path, monkeypatch):
    destination = tmp_path / "issued.jwt"
    destination.write_text("prior-fixture-content-that-is-longer")
    destination.chmod(0o666)
    original = os.fdopen
    observed = []

    def begin_write(descriptor, *args, **kwargs):
        observed.append(stat.S_IMODE(os.fstat(descriptor).st_mode))
        assert observed == [0o600]
        assert destination.read_text() == "prior-fixture-content-that-is-longer"
        return original(descriptor, *args, **kwargs)

    monkeypatch.setattr(make_token.os, "fdopen", begin_write)
    make_token._write_generated_token("replacement", destination)
    assert observed == [0o600]
    assert destination.read_text() == "replacement"


def test_permission_failure_preserves_content_and_closes_descriptor(tmp_path, monkeypatch):
    destination = tmp_path / "issued.jwt"
    destination.write_text("retained-content")
    descriptors = []

    def refuse_permission_change(descriptor, mode):
        descriptors.append(descriptor)
        raise PermissionError("owned fixture chmod failure")

    monkeypatch.setattr(make_token.os, "fchmod", refuse_permission_change)
    with pytest.raises(PermissionError, match="owned fixture chmod failure"):
        make_token._write_generated_token("must-not-be-written", destination)
    assert destination.read_text() == "retained-content"
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])

"""Checksum-loss accounting distinguishes application metadata from OS labels."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import test_audit15d_checksum_stage as subject


@pytest.mark.parametrize("attributes, refused", [
    ([], False),
    (["security.selinux"], False),
    (["security.selinux", "user.XrdCks.sha256"], True),
])
def test_checksum_pin_preserves_os_labels_and_rejects_user_metadata(
    monkeypatch, tmp_path, attributes, refused,
):
    """Execute the original assertion path using only test-owned fixture data."""
    origin, stage = tmp_path / "origin", tmp_path / "stage"
    (origin / "ck").mkdir(parents=True)
    stage.mkdir()
    (origin / "ck/pin.bin").write_bytes(subject.PAYLOAD)
    monkeypatch.setattr(subject.requests, "put", lambda *args, **kwargs:
                        SimpleNamespace(status_code=201, text=""))
    monkeypatch.setattr(subject, "_xattr", lambda path: None)
    monkeypatch.setattr(subject.os, "listxattr", lambda path: attributes)
    expectation = pytest.raises(AssertionError) if refused else nullcontext()
    with expectation:
        subject.test_checksum_lost_across_stage_flush_defect_pin((1, origin, stage))

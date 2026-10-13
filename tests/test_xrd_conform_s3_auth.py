"""Controlled positive and hostile S3 authentication-boundary fixtures."""
import pytest

from test_xrd_conform_http_semantics import _run, _run_cross_plane


def test_s3_presigned_expiry_and_path_binding_are_enforced(tmp_path):
    result, rows = _run(
        tmp_path, scheme="s3", with_s3_credentials=True
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-005"]["verdict"] == "conformant"
    assert rows["S3-006"]["verdict"] == "conformant"
    assert rows["S3-007"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour,row", [
    ("s3_tampered_signature_accepted", "S3-005"),
    ("s3_presign_expired_accepted", "S3-006"),
    ("s3_presign_path_accepted", "S3-007"),
])
def test_s3_presigned_authentication_fault_is_detected(
        tmp_path, behaviour, row):
    result, rows = _run(
        tmp_path, behaviour, scheme="s3", with_s3_credentials=True,
        verify_negative=row,
    )
    assert result.returncode == 1
    assert rows[row]["verdict"] == "divergent"


def test_cross_plane_authentication_confusion_is_rejected(tmp_path):
    result, rows = _run_cross_plane(
        tmp_path, with_s3_credentials=True, only_auth=True
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-008"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour", [
    "s3_bearer_accepted", "http_sigv4_accepted",
])
def test_cross_plane_authentication_confusion_is_detected(
        tmp_path, behaviour):
    result, rows = _run_cross_plane(
        tmp_path, behaviour, with_s3_credentials=True, only_auth=True,
        verify_negative="S3-008",
    )
    assert result.returncode == 1
    assert rows["S3-008"]["verdict"] == "divergent"

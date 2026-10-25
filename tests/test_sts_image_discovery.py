"""External STS oracle images can be pinned without silent substitution."""

import subprocess

import pytest

import test_sts_minio_live as oracle


def _listing(monkeypatch, text, rc=0):
    """Replace daemon discovery only; preserve the actual candidate selection."""
    monkeypatch.setattr(oracle, "run", lambda *args, **kw:
                        subprocess.CompletedProcess([], rc, text, ""))


def test_explicit_source_built_oracle_is_selected(monkeypatch):
    """A locally built, versioned image can supply the independent oracle."""
    image = "localhost/brix-validation-minio:pinned-release"  # net-literal-allow: cached OCI image name, not a network endpoint
    monkeypatch.setenv("BRIX_MINIO_IMAGE", image)
    _listing(monkeypatch, image + "\nquay.io/minio/minio:latest\n")
    assert oracle._pick_image("podman") == image


def test_missing_explicit_oracle_cannot_fall_back(monkeypatch):
    """An absent requested version must not silently use an old default."""
    monkeypatch.setenv("BRIX_MINIO_IMAGE", "localhost/brix-validation-minio:missing")  # net-literal-allow: nonexistent cached-image identity under test
    _listing(monkeypatch, "quay.io/minio/minio:latest\n")
    assert oracle._pick_image("podman") is None


def test_failed_runtime_output_cannot_select_an_image(monkeypatch):
    """Only a successful image listing can establish that an oracle exists."""
    monkeypatch.delenv("BRIX_MINIO_IMAGE", raising=False)
    _listing(monkeypatch, "quay.io/minio/minio:latest\n", rc=125)
    assert oracle._pick_image("podman") is None


@pytest.mark.parametrize("image", oracle.MINIO_IMAGES)
def test_default_official_image_spellings_remain_supported(monkeypatch, image):
    """Docker's short spelling and Podman's fully qualified spelling work."""
    monkeypatch.delenv("BRIX_MINIO_IMAGE", raising=False)
    _listing(monkeypatch, image + "\n")
    assert oracle._pick_image("podman") == image


def test_similar_untrusted_registry_is_not_an_official_default(monkeypatch):
    """A matching repository basename does not establish the image publisher."""
    monkeypatch.delenv("BRIX_MINIO_IMAGE", raising=False)
    _listing(monkeypatch, "unrelated.invalid/minio/minio:latest\n")
    assert oracle._pick_image("podman") is None

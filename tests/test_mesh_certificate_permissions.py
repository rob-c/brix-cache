"""Mesh TLS identities have deterministic permissions without changing umask."""

from pathlib import Path
import stat
import subprocess
import sys

import pytest

from brix_suite.mesh import cms_mesh_lib as subject


def _assert_modes(root):
    assert stat.S_IMODE((root / "cert.pem").stat().st_mode) == 0o644
    assert stat.S_IMODE((root / "key.pem").stat().st_mode) == 0o600


def test_generated_mesh_certificate_is_safe_under_permissive_umask(tmp_path):
    """Run the real OpenSSL generator with umask zero only in its child process."""
    script = ("import sys; from brix_suite.mesh.cms_mesh_lib import gen_cert; "
              "gen_cert(sys.argv[1])")
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True, text=True, umask=0, check=False, timeout=30)
    assert result.returncode == 0, result.stderr
    _assert_modes(tmp_path)
    parsed = subprocess.run(
        ["openssl", "x509", "-in", str(tmp_path / "cert.pem"), "-noout"],
        capture_output=True, text=True, check=False, timeout=10)
    assert parsed.returncode == 0, parsed.stderr


def test_existing_lax_mesh_identity_is_tightened_without_regeneration(monkeypatch, tmp_path):
    certificate = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    certificate.write_bytes(b"existing certificate bytes")
    key.write_bytes(b"existing private key bytes")
    certificate.chmod(0o666)
    key.chmod(0o666)

    def unexpected_generator(*args, **kwargs):
        pytest.fail("an existing identity must not be regenerated")

    monkeypatch.setattr(subject.subprocess, "run", unexpected_generator)
    assert subject.gen_cert(tmp_path) == (str(certificate), str(key))
    _assert_modes(tmp_path)
    assert certificate.read_bytes() == b"existing certificate bytes"
    assert key.read_bytes() == b"existing private key bytes"


def test_mesh_certificate_generation_failure_is_propagated(monkeypatch, tmp_path):
    def failed_generator(command, **options):
        assert options["check"] is True
        raise subprocess.CalledProcessError(1, command, stderr=b"fixture signing failed")

    monkeypatch.setattr(subject.subprocess, "run", failed_generator)
    with pytest.raises(subprocess.CalledProcessError) as failed:
        subject.gen_cert(tmp_path)
    assert failed.value.returncode == 1
    assert failed.value.stderr == b"fixture signing failed"
    assert not Path(tmp_path / "cert.pem").exists()

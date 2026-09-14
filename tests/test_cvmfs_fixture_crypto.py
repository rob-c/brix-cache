"""Exercise fixture signing with real OpenSSL and process-local policy."""

import os
import subprocess
from pathlib import Path

import pytest

from cvmfs.repo_forge import RepoForge


@pytest.fixture
def signing_keys(tmp_path):
    """Generate an ordinary RSA fixture key using the host's normal policy."""
    key = tmp_path / "key.pem"
    public_key = tmp_path / "public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
         "rsa_keygen_bits:2048", "-out", str(key)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public_key)],
        check=True, capture_output=True,
    )
    return key, public_key


@pytest.fixture
def restrictive_parent(tmp_path, monkeypatch):
    config = tmp_path / "parent.cnf"
    config.write_text(
        "openssl_conf = parent_init\n[parent_init]\n"
        "alg_section = parent_algorithms\n[parent_algorithms]\n"
        "rh-allow-sha1-signatures = no\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENSSL_CONF", str(config))
    return str(config)


def _verify(public_key, signature, message, tmp_path):
    signature_file = tmp_path / "signature.bin"
    signature_file.write_bytes(signature)
    config = Path(__file__).parent / "cvmfs" / "fixture-signing.cnf"
    return subprocess.run(
        ["openssl", "dgst", "-sha1", "-verify", str(public_key),
         "-signature", str(signature_file)],
        input=message, capture_output=True,
        env=dict(os.environ, OPENSSL_CONF=str(config.resolve())),
    )


def test_fixture_signing_preserves_parent_environment(
    signing_keys, restrictive_parent, tmp_path, monkeypatch,
):
    key, public_key = signing_keys
    monkeypatch.setenv("BRIX_FIXTURE_ENV_SENTINEL", "inherited")
    original_run = subprocess.run
    child_environments = []

    def observed_run(*args, **kwargs):
        child_environments.append(kwargs.get("env"))
        return original_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", observed_run)
    signature = RepoForge._rsa_sign_sha1(key, b"manifest hash line")
    assert len(signature) == 256
    assert child_environments[0]["BRIX_FIXTURE_ENV_SENTINEL"] == "inherited"
    assert child_environments[0]["OPENSSL_CONF"] != restrictive_parent
    assert os.environ["OPENSSL_CONF"] == restrictive_parent
    verified = _verify(public_key, signature, b"manifest hash line", tmp_path)
    assert verified.returncode == 0, verified.stderr.decode()


def test_fixture_signing_reports_invalid_key(restrictive_parent, tmp_path):
    key = tmp_path / "invalid.pem"
    key.write_text("not a PEM key", encoding="ascii")
    with pytest.raises(subprocess.CalledProcessError):
        RepoForge._rsa_sign_sha1(key, b"manifest hash line")
    assert os.environ["OPENSSL_CONF"] == restrictive_parent


def test_fixture_signature_rejects_changed_message(
    signing_keys, restrictive_parent, tmp_path,
):
    key, public_key = signing_keys
    signature = RepoForge._rsa_sign_sha1(key, b"manifest hash line")
    valid = _verify(public_key, signature, b"manifest hash line", tmp_path)
    assert valid.returncode == 0, valid.stderr.decode()
    changed = _verify(public_key, signature, b"different hash line", tmp_path)
    assert changed.returncode != 0
    assert os.environ["OPENSSL_CONF"] == restrictive_parent

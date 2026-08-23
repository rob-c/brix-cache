"""OpenSSL runner and disposable PKI construction contracts (041-050)."""

import subprocess
from pathlib import Path

import pytest

from brixtest.auth.pki import OpenSSL, _configuration, _safe_subject, create_pki
from brixtest.errors import SpecError


class FakeOpenSSL:
    def __init__(self):
        self.calls = []

    def run(self, *args, input_text=""):
        self.calls.append(args)
        self._write_key(args)
        self._write_output(args)
        if self._hash_requested(args, "x509"):
            return "cafebabe"
        if self._hash_requested(args, "crl"):
            return "cafebabe"
        if "-subject" in args:
            return "subject=/CN=BriXTest Test"
        return ""

    @staticmethod
    def _write_key(args):
        if "-keyout" in args:
            Path(args[args.index("-keyout") + 1]).write_text("PRIVATE KEY")

    @staticmethod
    def _write_output(args):
        if "-out" in args:
            Path(args[args.index("-out") + 1]).write_text("CERTIFICATE OR CRL")

    @staticmethod
    def _hash_requested(args, command):
        return args[0] == command and "-hash" in args


def test_041_openssl_configuration_has_ca_crl_and_san_sections(tmp_path):
    text = _configuration(tmp_path, ("one.test", "two.test"), 2)
    assert "database = $dir/index.txt" in text
    assert "default_crl_days = 2" in text
    assert "DNS.2 = two.test" in text


def test_042_safe_subject_accepts_plain_common_name():
    assert _safe_subject("BriXTest CA", "ca") == "BriXTest CA"


def test_043_safe_subject_rejects_subject_injection():
    with pytest.raises(SpecError, match=r"safe X\.509"):
        _safe_subject("name/CN=attacker", "ca")


def test_044_openssl_constructor_requires_executable(monkeypatch):
    monkeypatch.setattr("brixtest.auth.pki.shutil.which", lambda value: None)
    with pytest.raises(SpecError, match="not installed"):
        OpenSSL()


def test_045_openssl_runner_returns_stdout(monkeypatch):
    monkeypatch.setattr("brixtest.auth.pki.shutil.which", lambda value: "/openssl")
    monkeypatch.setattr(
        "brixtest.auth.pki.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="value\n", stderr=""),
    )
    assert OpenSSL().run("version") == "value"


def test_046_openssl_runner_preserves_failure_trace(monkeypatch):
    monkeypatch.setattr("brixtest.auth.pki.shutil.which", lambda value: "/openssl")
    monkeypatch.setattr(
        "brixtest.auth.pki.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, stdout="", stderr="bad config"),
    )
    with pytest.raises(SpecError, match="bad config"):
        OpenSSL().run("ca")


def test_047_openssl_timeout_becomes_spec_error(monkeypatch):
    monkeypatch.setattr("brixtest.auth.pki.shutil.which", lambda value: "/openssl")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("openssl", 30)

    monkeypatch.setattr("brixtest.auth.pki.subprocess.run", timeout)
    with pytest.raises(SpecError, match="timed out"):
        OpenSSL().run("ca")


def test_048_pki_requires_at_least_one_hostname(tmp_path):
    with pytest.raises(SpecError, match="at least one"):
        create_pki(
            tmp_path / "pki", authority_name="CA", hostnames=(),
            client_name="client", openssl=FakeOpenSSL(),
        )


def test_049_pki_builds_ca_crl_host_and_client_files(tmp_path):
    files = create_pki(
        tmp_path / "pki", authority_name="CA", hostnames=("server.test",),
        client_name="client", openssl=FakeOpenSSL(),
    )
    assert {"ca_cert", "crl", "host_cert", "host_key", "client_cert", "client_key"} <= set(files)
    assert all(files[name].is_file() for name in ("ca_cert", "crl", "host_cert", "client_cert"))


def test_050_pki_private_keys_and_hashed_trust_are_created(tmp_path):
    files = create_pki(
        tmp_path / "pki", authority_name="CA", hostnames=("server.test",),
        client_name="client", openssl=FakeOpenSSL(),
    )
    assert files["ca_key"].stat().st_mode & 0o777 == 0o600
    assert (files["trust_dir"] / "cafebabe.0").is_file()
    assert (files["trust_dir"] / "cafebabe.r0").is_file()

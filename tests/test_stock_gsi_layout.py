"""Reference security configuration follows its installed library ABI."""

import pytest

import stock_xrootd_owner as owner


@pytest.mark.parametrize("abi", [5, 6])
@pytest.mark.parametrize("protocol", ["gsi", "krb5"])
def test_matching_installed_gsi_plugin_is_selected(tmp_path, monkeypatch, abi, protocol):
    """RPM, Debian, Homebrew and Nix can use their actual library prefix."""
    security = tmp_path / f"libXrdSec-{abi}.so"
    security.touch()
    security.with_name(f"libXrdSec{protocol}-{abi}.so").touch()
    monkeypatch.setattr(owner, "find_xrd_sec_lib", lambda: security)
    assert getattr(owner, f"stock_{protocol}_layout")() == (security, tmp_path)


@pytest.mark.parametrize("protocol", ["gsi", "krb5"])
def test_missing_security_library_is_reported(monkeypatch, protocol):
    """A missing reference dependency is not replaced by a guessed path."""
    monkeypatch.setattr(owner, "find_xrd_sec_lib", lambda: None)
    assert getattr(owner, f"stock_{protocol}_layout")() is None


@pytest.mark.parametrize("protocol", ["gsi", "krb5"])
def test_another_gsi_abi_cannot_satisfy_the_selected_security_library(tmp_path, monkeypatch, protocol):
    """Never mix the reference server's ABI 5 with Python's ABI 6 plugin."""
    security = tmp_path / "libXrdSec-5.so"
    security.touch()
    (tmp_path / f"libXrdSec{protocol}-6.so").touch()
    monkeypatch.setattr(owner, "find_xrd_sec_lib", lambda: security)
    assert getattr(owner, f"stock_{protocol}_layout")() is None

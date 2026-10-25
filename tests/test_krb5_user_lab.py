"""The live Kerberos lab isolates realm state without requiring OS root."""

from types import SimpleNamespace
from pathlib import Path

import pytest

import test_krb5_forward_live as lab


def test_tool_discovery_uses_the_shared_mit_selector(monkeypatch):
    """Homebrew MIT tools must win over Apple's unrelated Heimdal binaries."""
    calls = []
    monkeypatch.setattr(lab, "krb5_tool", lambda name: calls.append(name) or "/mit/" + name)
    assert lab._which("krb5kdc") == "/mit/krb5kdc"
    assert calls == ["krb5kdc"]
    assert "unshare" not in lab.KRB5_TOOLS


def test_provisioning_runs_unprivileged_with_explicit_private_paths(monkeypatch, tmp_path):
    """The lab never creates a host realm or promotes the caller to root."""
    calls = []
    monkeypatch.setattr(lab, "_which", lambda name: "/mit/" + name)
    monkeypatch.setattr(lab, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    environment = {"KRB5_CONFIG": str(tmp_path / "krb5.conf"),
                   "KRB5_KDC_PROFILE": str(tmp_path / "kdc.conf")}
    lab._provision(tmp_path, environment)
    command, kwargs = calls[0]
    assert command[:2] == ["bash", "-c"]
    assert str(tmp_path / "origin.keytab") in command[2]
    assert str(tmp_path / "gateway.keytab") in command[2]
    assert kwargs["env"] is environment


def test_kdc_is_a_direct_user_owned_foreground_process(monkeypatch):
    """A platform without Linux namespaces can still run this exact KDC lab."""
    calls = []
    process = SimpleNamespace()
    monkeypatch.setattr(lab, "_which", lambda name: "/mit/" + name)
    monkeypatch.setattr(lab.subprocess, "Popen", lambda command, **kwargs:
                        calls.append((command, kwargs)) or process)
    assert lab._boot_kdc({"KRB5_CONFIG": "/private/test/krb5.conf"}) is process
    command, kwargs = calls[0]
    assert command == ["/mit/krb5kdc", "-n"]
    assert kwargs["env"]["KRB5_CONFIG"] == "/private/test/krb5.conf"


def test_origin_principal_compile_failure_is_not_an_unavailable_feature(monkeypatch, tmp_path):
    """Link the actual nginx formatter and preserve a failed harness as an error."""
    import test_krb5_origin_princ as origin

    calls = []
    monkeypatch.setattr(origin, '_gss_libs', lambda: [])
    monkeypatch.setattr(origin, '_FORWARD', tmp_path / 'forward.o')
    monkeypatch.setattr(origin, 'OBJS', tmp_path)
    monkeypatch.setattr(origin, 'run', lambda args, **kwargs:
                        calls.append(args) or SimpleNamespace(returncode=1,
                            stderr='deliberately missing symbol', stdout=''))
    factory = SimpleNamespace(mktemp=lambda _name: tmp_path)
    with pytest.raises(pytest.fail.Exception, match='deliberately missing symbol'):
        origin.harness.__wrapped__(factory)
    assert str(Path(tmp_path) / 'src/core/ngx_string.o') in calls[0]

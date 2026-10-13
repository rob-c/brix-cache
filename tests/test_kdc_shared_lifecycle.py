"""Ownership tests for the shared Kerberos test realm lifecycle."""

import pytest

from brix_suite.security import kdc


@pytest.fixture(autouse=True)
def reset_attachment_state(monkeypatch):
    monkeypatch.setattr(kdc, "_attached_realm", False)
    monkeypatch.setattr(kdc, "krb5_tools_available", lambda: True)
    monkeypatch.setattr(kdc, "_acquire_realm_lock", lambda: None)
    monkeypatch.setattr(kdc, "_release_realm_lock", lambda: None)


def test_up_attaches_to_complete_live_fleet_realm(monkeypatch):
    calls = []
    monkeypatch.setattr(kdc, "_reusable_realm_is_live", lambda: True)
    monkeypatch.setattr(kdc, "provision", lambda: calls.append("provision"))
    monkeypatch.setattr(kdc, "start_kdc", lambda: calls.append("start"))
    monkeypatch.setattr(kdc, "kinit_client", lambda: calls.append("kinit"))

    assert kdc.up() is True
    assert calls == ["kinit"]
    assert kdc._attached_realm is True


def test_down_never_stops_an_attached_fleet_realm(monkeypatch):
    calls = []
    monkeypatch.setattr(kdc, "_attached_realm", True)
    monkeypatch.setattr(kdc, "stop_kdc", lambda: calls.append("stop"))

    kdc.down()

    assert calls == []
    assert kdc._attached_realm is False


def test_standalone_realm_retains_start_stop_ownership(monkeypatch):
    calls = []
    monkeypatch.setattr(kdc, "_reusable_realm_is_live", lambda: False)
    monkeypatch.setattr(kdc, "provision", lambda: calls.append("provision"))
    monkeypatch.setattr(kdc, "start_kdc", lambda: calls.append("start"))
    monkeypatch.setattr(kdc, "kinit_client", lambda: calls.append("kinit"))
    monkeypatch.setattr(kdc, "stop_kdc", lambda: calls.append("stop"))

    assert kdc.up() is True
    kdc.down()

    assert calls == ["provision", "start", "kinit", "stop"]

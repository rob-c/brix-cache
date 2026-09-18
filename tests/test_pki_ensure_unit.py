"""``ensure_test_pki``: regenerate the shared test PKI only when it is
incomplete, so a test that merely needs *a* PKI never replaces the CA a
standing fleet was started against (the in-session ``blitz_test_pki`` that
turned every later GSI/VOMS test into a client-cert failure)."""
import os

import pytest

from brix_suite.security import pki


@pytest.fixture
def private_pki(tmp_path, monkeypatch):
    """Repoint every PKI path the generator writes at a private tree."""
    root = tmp_path / "pki"
    paths = {
        "PKI_DIR": str(root),
        "CA_DIR": str(root / "ca"),
        "CA_CERT": str(root / "ca" / "ca.pem"),
        "CA_KEY": str(root / "ca" / "ca.key"),
        "SERVER_CERT": str(root / "server" / "hostcert.pem"),
        "SERVER_KEY": str(root / "server" / "hostkey.pem"),
        "USER_CERT": str(root / "user" / "usercert.pem"),
        "USER_KEY": str(root / "user" / "userkey.pem"),
    }
    for name, value in paths.items():
        monkeypatch.setattr(pki, name, value)
    calls = []
    monkeypatch.setattr(pki, "blitz_test_pki", lambda: calls.append("blitz"))
    return paths, calls


def _touch_all(paths):
    for name, value in paths.items():
        if name.endswith(("_CERT", "_KEY")):
            os.makedirs(os.path.dirname(value), exist_ok=True)
            with open(value, "w", encoding="utf-8") as fh:
                fh.write("x")


def test_a_complete_pki_is_left_alone(private_pki):
    """success: the fleet's material stays byte-identical, no regeneration."""
    paths, calls = private_pki
    _touch_all(paths)
    assert pki.test_pki_complete()
    assert pki.ensure_test_pki() is False
    assert calls == []


def test_a_missing_credential_triggers_regeneration(private_pki):
    """error path: no user certificate ⇒ the generator runs once."""
    paths, calls = private_pki
    _touch_all(paths)
    os.unlink(paths["USER_CERT"])
    assert not pki.test_pki_complete()
    assert pki.ensure_test_pki() is True
    assert calls == ["blitz"]


def test_a_certificate_without_its_key_is_not_complete(private_pki):
    """security-negative: a CA certificate whose private key is gone cannot
    sign anything the fleet would trust — an orphan CA must not count as a
    usable PKI (it would leave every proxy mint failing while looking present)."""
    paths, calls = private_pki
    _touch_all(paths)
    os.unlink(paths["CA_KEY"])
    assert not pki.test_pki_complete()
    assert pki.ensure_test_pki() is True
    assert calls == ["blitz"]

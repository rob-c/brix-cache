"""Seed a bounded private archive while intercepting every readiness probe."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import zipfile

import pytest

from settings import TEST_PORT_START


@pytest.fixture
def zip_case(monkeypatch, tmp_path):
    settings = ModuleType("settings")
    settings.HOST = "zip-fixture.invalid"
    settings.TEST_ROOT = str(tmp_path / "test-root")
    settings.ZIP_ROOT_PORT = TEST_PORT_START
    settings.ZIP_WEBDAV_PORT = TEST_PORT_START + 1
    settings.ZIP_S3_PORT = TEST_PORT_START + 2
    monkeypatch.setitem(sys.modules, "settings", settings)
    path = Path(__file__).with_name("test_zip_member.py")
    spec = importlib.util.spec_from_file_location("zip_endpoint_subject", path)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    data = tmp_path / "selected-export"
    endpoint = SimpleNamespace(data_root=str(data))
    monkeypatch.setattr(subject, "get_server", lambda name: endpoint)
    ports = []

    def ready(port):
        ports.append(port)
        return True

    monkeypatch.setattr(subject, "_wait_listen", ready)
    return SimpleNamespace(subject=subject, data=data, ports=ports)


def test_fixture_uses_allocated_ports_and_registered_export(zip_case):
    subject = zip_case.subject
    fixture = subject.zipsrv.__wrapped__()
    try:
        info = next(fixture)
        assert info["data"] == str(zip_case.data)
        assert zip_case.ports == [TEST_PORT_START, TEST_PORT_START + 1, TEST_PORT_START + 2]
        assert subject.pytestmark.args == ("zip-member",)
        _check_archive(zip_case.data / "a.zip", subject)
    finally:
        fixture.close()


def _check_archive(path, subject):
    with zipfile.ZipFile(path) as archive:
        assert archive.read("stored.txt") == subject.STORED
        assert archive.read("sub/defl.bin") == subject.DEFL
        assert set(archive.namelist()) == {"stored.txt", "sub/defl.bin"}


@pytest.mark.parametrize("failure", ["not-ready", "error"])
def test_unavailable_selected_endpoint_preserves_outcome(zip_case, monkeypatch, failure):
    error = RuntimeError("deliberate offline readiness failure")

    def ready(port):
        if failure == "error":
            raise error
        return False

    monkeypatch.setattr(zip_case.subject, "_wait_listen", ready)
    kind = RuntimeError if failure == "error" else pytest.skip.Exception
    with pytest.raises(kind) as caught:
        next(zip_case.subject.zipsrv.__wrapped__())
    if failure == "error":
        assert caught.value is error
    else:
        assert str(TEST_PORT_START) in str(caught.value)


def test_archive_creation_failure_is_not_hidden_as_readiness_skip(zip_case, monkeypatch):
    error = OSError("deliberate offline archive creation failure")

    def refuse(*args, **kwargs):
        raise error

    monkeypatch.setattr(zip_case.subject.zipfile, "ZipFile", refuse)
    with pytest.raises(OSError) as caught:
        next(zip_case.subject.zipsrv.__wrapped__())
    assert caught.value is error
    assert zip_case.ports == []

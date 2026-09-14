"""Check memory-suite fixture timing using inert clients and no network."""

import hashlib
import importlib.util
from pathlib import Path
import socket
import sys
from types import ModuleType, SimpleNamespace

import pytest


@pytest.fixture
def memory_module(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline fixture test attempted network I/O")

    package, client, flags = (ModuleType(name) for name in
                              ("XRootD", "XRootD.client", "XRootD.client.flags"))
    client.File = forbidden
    package.client = client
    flags.OpenFlags = SimpleNamespace(READ=0)
    for module in (package, client, flags):
        monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.delenv("LARGE_FILE_MD5", raising=False)
    path = Path(__file__).with_name("test_phase31_memory.py")
    spec = importlib.util.spec_from_file_location("memory_readiness_subject", path)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    return subject


def test_import_defers_both_endpoint_probes(memory_module):
    assert memory_module.anon_only.name == "usefixtures"
    assert memory_module.anon_only.args == ("anon_server_ready",)
    assert memory_module.tls_only.args == ("tls_server_ready",)


@pytest.mark.parametrize("fixture_name", ["anon_server_ready", "tls_server_ready"])
@pytest.mark.parametrize("state", ["ready", "absent", "error"])
def test_runtime_readiness_preserves_each_endpoint_outcome(
        memory_module, monkeypatch, fixture_name, state):
    calls = []
    failure = RuntimeError("deliberate offline endpoint failure")

    def probe(host, port):
        calls.append((host, port))
        if state == "error":
            raise failure
        return state == "ready"

    monkeypatch.setattr(memory_module, "_reachable", probe)
    fixture = getattr(memory_module, fixture_name).__wrapped__
    _check_endpoint_outcome(fixture, state, failure)
    expected = (memory_module.NGINX_ANON_PORT if fixture_name == "anon_server_ready"
                else memory_module.NGINX_GSI_TLS_PORT)
    assert calls == [(memory_module.SERVER_HOST, expected)]


def _check_endpoint_outcome(fixture, state, failure):
    if state == "ready":
        assert fixture() is None
        return
    kind = RuntimeError if state == "error" else pytest.skip.Exception
    with pytest.raises(kind) as caught:
        fixture()
    if state == "error":
        assert caught.value is failure


@pytest.mark.parametrize("digest_state", ["current", "missing", "mismatch"])
def test_tls_body_uses_digest_published_after_collection(
        memory_module, monkeypatch, digest_state):
    payload = b"ordinary offline TLS fixture bytes"
    opened = []
    handle = _inert_handle(payload, opened)
    monkeypatch.setattr(memory_module.client, "File", lambda: handle)
    _set_digest(monkeypatch, payload, digest_state)
    body = memory_module.test_tls_large_read_trim_cycle_integrity
    if digest_state == "current":
        body()
        assert opened == [memory_module.GSI_TLS_URL + "//" + memory_module.LARGE_FILE]
        return
    kind = pytest.skip.Exception if digest_state == "missing" else AssertionError
    with pytest.raises(kind):
        body()
    if digest_state == "missing":
        assert opened == []


def _set_digest(monkeypatch, payload, state):
    if state != "missing":
        expected = hashlib.md5(payload if state == "current" else b"different fixture").hexdigest()
        monkeypatch.setenv("LARGE_FILE_MD5", expected)


def _inert_handle(payload, opened):
    status = SimpleNamespace(ok=True, message="inert client")

    def open_file(url, flags):
        opened.append(url)
        return status, None

    return SimpleNamespace(open=open_file, stat=lambda: (status, SimpleNamespace(size=len(payload))),
                           read=lambda offset, size: (status, payload[offset:offset + size]),
                           close=lambda: None)

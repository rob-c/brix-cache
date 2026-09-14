"""Validate reference readiness timing with no sockets or protocol requests."""

import importlib.util
from pathlib import Path
import socket
import sys
from types import ModuleType

import pytest


@pytest.fixture
def query_module(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline readiness test attempted network I/O")

    helper = ModuleType("_test_conf_pgio_helpers")
    for name in ("_handshake", "_login", "_open", "_read_response"):
        setattr(helper, name, forbidden)
    helper.kXR_ok, helper.kXR_error = 0, 4003
    monkeypatch.setitem(sys.modules, helper.__name__, helper)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    path = Path(__file__).with_name("test_query_by_fhandle.py")
    spec = importlib.util.spec_from_file_location("query_readiness_subject", path)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    return subject


def test_module_import_defers_reference_probe_to_fixture(query_module):
    test = query_module.TestQueryByFhandle.test_stock_refuses_pure_fhandle_query
    assert [mark.name for mark in test.pytestmark] == ["usefixtures"]
    assert test.pytestmark[0].args == ("stock_reference_ready",)


@pytest.mark.parametrize("ready", [True, False])
def test_runtime_fixture_uses_current_reference_state(query_module, monkeypatch, ready):
    calls = []

    def probe():
        calls.append("runtime readiness")
        return ready

    monkeypatch.setattr(query_module, "_stock_up", probe)
    fixture = query_module.stock_reference_ready.__wrapped__
    if ready:
        assert fixture() is None
    else:
        with pytest.raises(pytest.skip.Exception, match="stock reference not up"):
            fixture()
    assert calls == ["runtime readiness"]


def test_unexpected_readiness_error_is_not_hidden_as_skip(query_module, monkeypatch):
    error = RuntimeError("deliberate offline readiness failure")

    def probe():
        raise error

    monkeypatch.setattr(query_module, "_stock_up", probe)
    with pytest.raises(RuntimeError) as caught:
        query_module.stock_reference_ready.__wrapped__()
    assert caught.value is error

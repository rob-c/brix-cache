"""Native TPC readiness belongs to fixtures, never import-time socket probes."""

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


def _load_subject(monkeypatch, probe):
    exports = {"pytest": pytest, "_port_open": probe,
               "ROOT_TPC_NGINX_PORT": "nginx-fixture-port",
               "ROOT_TPC_REF_PORT": "reference-fixture-port"}
    monkeypatch.setitem(sys.modules, "split_continuation", SimpleNamespace(
        reexport=lambda namespace, name: namespace.update(exports)))
    monkeypatch.setitem(sys.modules, "official_interop_lib", SimpleNamespace())
    source = Path(__file__).with_name("test_native_xrdcp_xrdfs_b.py")
    spec = importlib.util.spec_from_file_location("native_tpc_readiness_subject", source)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    return subject


def test_ready_endpoints_are_checked_only_after_fixture_setup(monkeypatch):
    calls = []

    def ready(port):
        calls.append(port)
        return True

    subject = _load_subject(monkeypatch, ready)
    assert calls == [], "test collection must not connect to runtime listeners"
    subject._root_tpc_nginx_ready.__wrapped__()
    subject._root_tpc_pair_ready.__wrapped__(None)
    assert calls == [subject.ROOT_TPC_NGINX_PORT, subject.ROOT_TPC_REF_PORT]


def test_unavailable_managed_endpoints_fail_instead_of_skip(monkeypatch):
    calls = []

    def unavailable(port):
        calls.append(port)
        return False

    subject = _load_subject(monkeypatch, unavailable)
    assert calls == []
    with pytest.raises(pytest.fail.Exception, match="nginx.*not ready after fleet setup"):
        subject._root_tpc_nginx_ready.__wrapped__()
    with pytest.raises(pytest.fail.Exception, match="reference.*not ready after fleet setup"):
        subject._root_tpc_pair_ready.__wrapped__(None)
    assert calls == [subject.ROOT_TPC_NGINX_PORT, subject.ROOT_TPC_REF_PORT]


def test_readiness_errors_propagate_without_hiding_them_as_skips(monkeypatch):
    error = OSError("deliberate mocked readiness error")
    calls = []

    def failed(port):
        calls.append(port)
        raise error

    subject = _load_subject(monkeypatch, failed)
    assert calls == []
    with pytest.raises(OSError) as caught:
        subject._root_tpc_nginx_ready.__wrapped__()
    assert caught.value is error
    with pytest.raises(OSError) as caught:
        subject._root_tpc_pair_ready.__wrapped__(None)
    assert caught.value is error
    assert calls == [subject.ROOT_TPC_NGINX_PORT, subject.ROOT_TPC_REF_PORT]

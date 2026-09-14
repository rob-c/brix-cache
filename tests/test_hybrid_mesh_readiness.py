"""Hybrid readiness runs at fixture time, with no socket probe during import."""

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


def _load_subject(monkeypatch, probe):
    ports = {name: name for name in ("a_data", "g_data", "a_s3", "f_data", "g_http")}
    monkeypatch.setitem(sys.modules, "cms_mesh_lib", SimpleNamespace(port_open=probe))
    monkeypatch.setitem(sys.modules, "hybrid_mesh_lib", SimpleNamespace(
        PORTS=ports, HOST="mesh-fixture.invalid", EXPORT="/mesh", MESH_DIR="/unused-private-mesh"))
    monkeypatch.setitem(sys.modules, "settings", SimpleNamespace(ARTIFACTS_DIR="/unused-artifacts"))
    source = Path(__file__).with_name("test_hybrid_mesh.py")
    spec = importlib.util.spec_from_file_location("hybrid_readiness_subject", source)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    return subject, list(ports.values())


def test_ready_mesh_is_checked_only_when_fixture_runs(monkeypatch):
    calls = []

    def ready(port):
        calls.append(port)
        return True

    subject, ports = _load_subject(monkeypatch, ready)
    assert calls == [], "collection must not connect to any runtime listener"
    subject._require_hybrid_mesh.__wrapped__()
    assert calls == ports


def test_missing_front_door_fails_setup_instead_of_skipping_collection(monkeypatch):
    calls = []

    def not_ready(port):
        calls.append(port)
        return port != "g_http"

    subject, ports = _load_subject(monkeypatch, not_ready)
    assert calls == []
    with pytest.raises(pytest.fail.Exception, match="hybrid mesh not ready after fleet setup"):
        subject._require_hybrid_mesh.__wrapped__()
    assert calls == ports


def test_readiness_probe_error_is_propagated_unchanged(monkeypatch):
    error = OSError("fixture probe failed")
    calls = []

    def failed(port):
        calls.append(port)
        raise error

    subject, ports = _load_subject(monkeypatch, failed)
    assert calls == []
    with pytest.raises(OSError) as caught:
        subject._require_hybrid_mesh.__wrapped__()
    assert caught.value is error
    assert calls == ports[:1]

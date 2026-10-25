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


@pytest.mark.parametrize("host,family", [("127.0.0.1", "v4"), ("::1", "v6"),  # net-literal-allow: address-family classification corpus
                                        ("fixture.invalid", None)])  # net-literal-allow: configuration-only address-family vectors
def test_hybrid_reference_launch_matches_numeric_endpoint(tmp_path, monkeypatch,
                                                        host, family):
    """Both reference daemons use the same address family as their front doors."""
    from brix_suite.mesh import hybrid_mesh_lib as mesh
    calls = []
    monkeypatch.setattr(mesh, "HOST", host)
    monkeypatch.setattr(mesh, "CMSD_BIN", "/official/cmsd")
    monkeypatch.setattr(mesh, "BRIX_BIN", "/official/xrootd")
    monkeypatch.setattr(mesh, "runas_args", lambda _root: [])
    monkeypatch.setattr(mesh.subprocess, "run", lambda argv, **kw: calls.append((argv, kw)))

    def write(name, text):
        path = tmp_path / name
        path.write_text(text)
        return str(path)

    mesh.launch_xrootd(SimpleNamespace(root=str(tmp_path), write=write), "probe",
                       "fixture configuration\n")
    assert len(calls) == 2
    assert [argv[0] for argv, _kw in calls] == ["/official/cmsd", "/official/xrootd"]
    for argv, kwargs in calls:
        assert ("-I" in argv) == (family is not None)
        if family is not None:
            assert argv[argv.index("-I") + 1] == family
        assert kwargs == dict(check=False, start_new_session=True, cwd=str(tmp_path))
        assert Path(argv[argv.index("-c") + 1]).read_text() == "fixture configuration\n"


def test_hybrid_reference_launch_error_is_not_hidden(tmp_path, monkeypatch):
    """A missing reference daemon remains an error, not a ready topology."""
    from brix_suite.mesh import hybrid_mesh_lib as mesh
    error = FileNotFoundError("missing native reference")
    monkeypatch.setattr(mesh, "runas_args", lambda _root: [])

    def failed(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(mesh.subprocess, "run", failed)
    with pytest.raises(FileNotFoundError) as caught:
        mesh.launch_xrootd(SimpleNamespace(root=str(tmp_path), write=lambda *_: "unused"),
                           "probe", "fixture\n")
    assert caught.value is error

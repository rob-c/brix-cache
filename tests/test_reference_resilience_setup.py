"""Reference resilience fixtures keep native family, policy and child ownership."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from resilience import servers


@pytest.fixture(params=[servers.XrootdAnon, servers.XrootdGsi])
def reference_case(request, tmp_path, monkeypatch):
    calls, stopped = [], []
    child = SimpleNamespace(poll=lambda: None,
                            terminate=lambda: stopped.append("terminate"),
                            wait=lambda **kwargs: 0)

    def spawn(argv, **kwargs):
        calls.append(argv)
        return child

    monkeypatch.setattr(servers, "PREFIX", str(tmp_path))
    monkeypatch.setattr(servers, "BRIX_BIN", "/installed/official/xrootd")
    monkeypatch.setattr(servers.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(servers, "find_sec_lib", lambda: "/official/libXrdSec.so")
    monkeypatch.setattr(servers.subprocess, "Popen", spawn)
    monkeypatch.setattr(servers, "_wait_port", lambda *args, **kwargs: None)
    monkeypatch.setattr(servers, "reference_transport_directives",
                        lambda: "xrootd.async nosf\n")
    monkeypatch.setattr(servers.XrootdAnon, "_wait_ready", lambda self: None)
    monkeypatch.setattr(servers.XrootdGsi, "_wait_gsi_ready", lambda self: None)
    return request.param(port=12345), calls, stopped


@pytest.mark.parametrize("host,family", [("127.0.0.1", "v4"), ("::1", "v6"),  # net-literal-allow: address-family classification corpus
                                        ("fixture.invalid", None)])  # net-literal-allow: configuration-only endpoint vectors
def test_reference_fixture_matches_endpoint_without_resolving_names(
        reference_case, monkeypatch, host, family):
    server, calls, stopped = reference_case
    monkeypatch.setattr(servers, "HOST", host)
    with server:
        argv = calls[0]
        assert argv[0] == "/installed/official/xrootd"
        assert ("-I" in argv) == (family is not None)
        if family is not None:
            assert argv[argv.index("-I") + 1] == family
        assert "xrootd.async nosf\n" in Path(server.cfg).read_text()
    assert stopped == ["terminate"]


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_failed_entry_reaps_only_its_spawned_reference_and_preserves_verdict(
        reference_case, monkeypatch, failure):
    server, calls, stopped = reference_case
    verdict = failure("native readiness refused")

    def failed(*args, **kwargs):
        raise verdict

    monkeypatch.setattr(servers, "_wait_port", failed)
    with pytest.raises(failure) as caught:
        server.__enter__()
    assert caught.value is verdict
    assert len(calls) == 1 and stopped == ["terminate"]

import os
from pathlib import Path
import subprocess

import pytest

from cmdscripts import metadata_live_ports


def test_metadata_live_ports_are_importable():
    assert set(metadata_live_ports.SCENARIOS) == {
        "nonstaged-reap",
        "sd-s3-meta",
        "xfer-audit-sink",
        "xmeta",
    }


def test_metadata_live_ports_owns_one_unique_port_per_listener():
    assert len(metadata_live_ports._PORTS) == 4
    assert len(set(metadata_live_ports._PORTS)) == 4


@pytest.mark.parametrize("present,build_status", [(False, 0), (True, 0), (True, 2)])
def test_optional_smoke_build_refreshes_existing_binary(monkeypatch, tmp_path,
                                                       capsys, present, build_status):
    binary = tmp_path / "client/bin/sd_s3_meta_smoke"
    binary.parent.mkdir(parents=True)
    if present:
        binary.write_bytes(b"old SDK build")
    monkeypatch.setattr(metadata_live_ports, "REPO_ROOT", tmp_path)
    calls = []

    def build(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, build_status, "compiler output", "link error")

    monkeypatch.setattr(metadata_live_ports, "client_make", build)
    assert metadata_live_ports._build_s3_meta_smoke() == (build_status == 0)
    assert calls == [(tmp_path / "client", "sd-s3-meta-smoke")]
    output = capsys.readouterr().out
    assert ("link error" in output) == (build_status != 0)


def test_failed_smoke_build_stops_before_starting_server(monkeypatch):
    monkeypatch.setattr(metadata_live_ports, "_build_s3_meta_smoke", lambda: False)

    def refuse_server(*args):
        pytest.fail("a failed build must not launch the stale smoke binary")

    monkeypatch.setattr(metadata_live_ports, "LiveRun", refuse_server)
    assert metadata_live_ports.sd_s3_meta() == 1


@pytest.mark.optin
@pytest.mark.parametrize("scenario", sorted(metadata_live_ports.SCENARIOS))
def test_metadata_live_port_scenario(scenario: str):
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if scenario != "xmeta" and not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    assert metadata_live_ports.SCENARIOS[scenario](nginx) == 0

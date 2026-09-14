"""Hermetic raw fleet launch coverage for packaged nginx and startup failures."""

import importlib
import json
import os
from pathlib import Path
import subprocess

import pytest


def _config(root, relative="nginx.conf"):
    """Write a minimal caller-owned config without starting nginx."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("events {}\nstream {}\nhttp {}\n", encoding="utf-8")
    return path


@pytest.fixture(params=["server_launcher", "brix_suite.launcher"])
def raw_launcher(request, monkeypatch):
    """Exercise both public facades with real preparation and inert execution."""
    launcher = importlib.import_module(request.param)
    monkeypatch.setattr(launcher, "_nginx_bin", lambda: "/selected/frozen-nginx")
    monkeypatch.delenv("TEST_NGINX_LOAD_MODULES", raising=False)
    calls = []
    response = {"returncode": 0}

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        result = subprocess.CompletedProcess(argv, response["returncode"])
        if kwargs.get("check"):
            result.check_returncode()
        return result

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    return launcher.launch_fleet_nginx, calls, response


def _check_runtime_paths(body, root):
    """Every missing system default must become an absolute caller-owned path."""
    directives = {
        "pid": root / "logs/nginx.pid",
        "error_log": root / "logs/error.log",
        "access_log": root / "logs/access.log",
        "client_body_temp_path": root / "tmp/client-body",
        "proxy_temp_path": root / "tmp/proxy",
        "fastcgi_temp_path": root / "tmp/fastcgi",
        "uwsgi_temp_path": root / "tmp/uwsgi",
        "scgi_temp_path": root / "tmp/scgi",
    }
    for directive, path in directives.items():
        assert f"{directive} {json.dumps(str(path))}" in body, directive


def test_selected_modules_and_runtime_paths_reach_fleet_launch(
        raw_launcher, monkeypatch, tmp_path):
    """A packaged nginx receives all modules and writable per-fleet defaults."""
    launch, calls, _response = raw_launcher
    config = _config(tmp_path)
    modules = [tmp_path / name for name in (
        "ngx_stream_module.so", "ngx_stream_brix_module.so",
        "ngx_http_brix_xrdhttp_filter_module.so")]
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", os.pathsep.join(map(str, modules)))
    result = launch(str(config), cwd=str(tmp_path), env={"FLEET_TEST": "selected"})
    body = config.read_text()
    for module in modules:
        assert body.count(f"load_module {json.dumps(str(module))};") == 1
    _check_runtime_paths(body, tmp_path)
    assert result.returncode == 0, "successful launch did not return its result"
    assert calls[0][1]["env"]["FLEET_TEST"] == "selected", "caller env was lost"


def test_fleet_relaunch_is_idempotent(raw_launcher, monkeypatch, tmp_path):
    """Restarting an existing fleet config must not duplicate module directives."""
    launch, calls, _response = raw_launcher
    config = _config(tmp_path)
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", str(tmp_path / "brix.so"))
    launch(str(config), prefix=str(tmp_path))
    original = config.read_text()
    launch(str(config), prefix=str(tmp_path))
    assert config.read_text() == original, "relaunch changed the prepared config"
    assert len(calls) == 2, "both requested launches must execute"


def test_failed_nginx_launch_is_reported(raw_launcher, tmp_path):
    """A rejected configuration aborts setup rather than waiting for dead ports."""
    launch, _calls, response = raw_launcher
    config = _config(tmp_path)
    response["returncode"] = 1
    with pytest.raises(subprocess.CalledProcessError) as failure:
        launch(str(config), cwd=str(tmp_path))
    assert failure.value.returncode == 1, "daemon failure code was lost"
    assert failure.value.cmd[-1] == str(config), "failed config was not identified"


def test_missing_config_cannot_launch_a_daemon(raw_launcher, tmp_path):
    """A stale requested path fails before any server process can be spawned."""
    launch, calls, _response = raw_launcher
    with pytest.raises(FileNotFoundError):
        launch(str(tmp_path / "absent.conf"), cwd=str(tmp_path))
    assert not calls, "missing config reached process execution"


def test_relative_config_uses_prefix_and_child_cwd(raw_launcher, tmp_path):
    """HA-style relative config paths are resolved exactly under their prefix."""
    launch, calls, _response = raw_launcher
    prefix = tmp_path / "member"
    config = _config(prefix, "conf/nginx.conf")
    launch("conf/nginx.conf", prefix="member", cwd=str(tmp_path))
    argv, options = calls[0]
    assert argv[-1] == str(config), "relative config resolved outside its prefix"
    assert options["cwd"] == str(tmp_path), "child working directory changed"
    _check_runtime_paths(config.read_text(), prefix)


def test_plain_launch_keeps_output_inherited(raw_launcher, tmp_path):
    """Static launches inject no modules and leave daemon/broker streams unpiped."""
    launch, calls, _response = raw_launcher
    config = _config(tmp_path)
    launch(str(config))
    options = calls[0][1]
    assert "load_module" not in config.read_text(), "unselected modules were loaded"
    assert not {"stdout", "stderr", "capture_output"} & options.keys(), \
        "captured pipes can remain open in a detached broker"
    assert options["start_new_session"], "fleet daemon did not get its own session"
    _check_runtime_paths(config.read_text(), Path(config).parent)

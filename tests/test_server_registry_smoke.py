import json
import os
import subprocess
import time
from pathlib import Path

import pytest

import settings

from config_templates import render_config_to_path
from cmdscripts import main as cmd_main, run as cmd_run
from server_launcher import RegistryCommandFailure, RegistryLauncher
from server_registry import (
    CommandSpec,
    NginxInstanceSpec,
    clear_registry,
    endpoint_for,
    get_server,
    manifest_read,
    manifest_write,
    register_command_suite,
    register_nginx,
    register_xrootd,
    registered_command_suites,
    selected_specs,
    server,
    write_manifest,
)


def test_registry_manifest_round_trip(tmp_path, monkeypatch):
    clear_registry()
    monkeypatch.setattr("server_registry.REGISTRY_ROOT", str(tmp_path / "registry"))
    monkeypatch.setattr("server_registry.REGISTRY_MANIFEST", str(tmp_path / "manifest.json"))
    spec = NginxInstanceSpec(
        name="smoke",
        template="nginx_registry_smoke.conf",
        port=12345,
        data_root=str(tmp_path / "data"),
        reason="registry smoke",
    )
    register_nginx(spec)

    manifest_path = tmp_path / "manifest.json"
    manifest = write_manifest(path=str(manifest_path))
    alias_manifest_path = tmp_path / "manifest-alias.json"
    alias_manifest = manifest_write(manifest, path=str(alias_manifest_path))
    loaded = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["servers"]["smoke"]["endpoint"]["port"] == 12345
    assert alias_manifest["servers"]["smoke"]["endpoint"]["port"] == 12345
    assert loaded["servers"]["smoke"]["url"] == "root://127.0.0.1:12345/"
    assert get_server("smoke").data_root == str(tmp_path / "data")
    assert server("smoke").port == 12345
    assert manifest_read(str(manifest_path))["version"] == 1
    clear_registry()


def test_registry_reserves_missing_ports_stably(monkeypatch):
    clear_registry()
    ports = iter([23456, 23457])
    monkeypatch.setattr("server_registry.free_port", lambda host="127.0.0.1": next(ports))
    spec = register_nginx(
        NginxInstanceSpec(name="dynamic", template="nginx_registry_smoke.conf")
    )

    first = endpoint_for(spec)
    second = endpoint_for(spec)

    assert first.port == 23456
    assert second.port == 23456
    clear_registry()


def test_registry_duplicate_error_names_first_registration_site():
    clear_registry()
    register_nginx(NginxInstanceSpec(name="dup", template="nginx_registry_smoke.conf"))

    try:
        register_nginx(NginxInstanceSpec(name="dup", template="nginx_registry_smoke.conf"))
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("duplicate registration unexpectedly succeeded")

    assert "server already registered: dup" in message
    assert "test_server_registry_smoke.py" in message
    clear_registry()


def test_registry_xrootd_alias_command_specs_and_selected_dependencies():
    clear_registry()
    parent = register_nginx(
        NginxInstanceSpec(name="parent", template="nginx_registry_smoke.conf", port=12340)
    )
    child = register_xrootd(
        NginxInstanceSpec(
            name="child",
            template="nginx_registry_smoke.conf",
            port=12341,
            requires=("parent",),
        )
    )
    command = register_command_suite(
        CommandSpec(name="probe", argv=("xrdcp", "--version"), requires=("child",))
    )

    class Item:
        def get_closest_marker(self, name):
            if name == "registry_server":
                class Marker:
                    args = ("child",)
                return Marker()
            return None

    assert child.requires == ("parent",)
    assert command.argv == ("xrdcp", "--version")
    assert registered_command_suites() == [command]
    assert [spec.name for spec in selected_specs([Item()])] == ["parent", "child"]
    assert [spec.name for spec in selected_specs([])] == [parent.name, child.name]
    clear_registry()


def test_registry_manifest_can_be_limited_to_selected_specs():
    from server_registry import build_manifest

    clear_registry()
    first = register_nginx(
        NginxInstanceSpec(name="first", template="nginx_registry_smoke.conf", port=12400)
    )
    register_nginx(
        NginxInstanceSpec(name="second", template="nginx_registry_smoke.conf", port=12401)
    )

    manifest = build_manifest(specs=[first])

    assert sorted(manifest["servers"]) == ["first"]
    clear_registry()


def test_render_config_to_path_writes_parent_dirs(tmp_path):
    target = tmp_path / "nested" / "nginx.conf"
    render_config_to_path(
        "nginx_registry_smoke.conf",
        target,
        strict=True,
        PORT=34567,
        DATA_ROOT=str(tmp_path / "data"),
        LOG_DIR=str(tmp_path / "logs"),
    )

    text = target.read_text(encoding="utf-8")
    assert "listen 34567;" in text
    assert str(tmp_path / "data") in text


def test_launcher_render_nginx_and_structured_failure(tmp_path, monkeypatch):
    clear_registry()
    monkeypatch.setattr("server_registry.REGISTRY_ROOT", str(tmp_path / "registry"))
    monkeypatch.setattr("server_launcher.REGISTRY_STRICT_TEMPLATES", True)
    spec = register_nginx(
        NginxInstanceSpec(
            name="launch",
            template="nginx_registry_smoke.conf",
            port=12450,
            data_root=str(tmp_path / "data"),
        )
    )
    launcher = RegistryLauncher()

    endpoint = launcher.render_nginx(spec)
    result = subprocess.CompletedProcess(
        args=["nginx", "-t"],
        returncode=1,
        stdout="bad stdout",
        stderr="bad stderr",
    )
    monkeypatch.setattr("server_launcher.subprocess.run", lambda *args, **kwargs: result)

    try:
        launcher.nginx_test(spec)
    except RegistryCommandFailure as exc:
        message = str(exc)
    else:
        raise AssertionError("nginx_test unexpectedly succeeded")

    assert endpoint.config.endswith("nginx.conf")
    assert "listen 12450;" in open(endpoint.config, encoding="utf-8").read()
    assert "config:" in message
    assert endpoint.config in message
    assert "bad stderr" in message
    clear_registry()


def test_launcher_readiness_aliases_and_command_runner(monkeypatch):
    launcher = RegistryLauncher()

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr("server_launcher.socket.create_connection", lambda *args, **kwargs: Conn())
    launcher._wait_ready("127.0.0.1", 1, "webdav")
    launcher._wait_ready("127.0.0.1", 1, "metrics")

    result = subprocess.CompletedProcess(args=["tool"], returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr("server_launcher.subprocess.run", lambda *args, **kwargs: result)

    assert launcher.run_cmd(["tool"]).stdout == "ok"


def test_cmdscripts_helpers_are_importable(monkeypatch):
    result = subprocess.CompletedProcess(args=["client"], returncode=0, stdout="client-ok", stderr="")
    monkeypatch.setattr("cmdscripts.subprocess.run", lambda *args, **kwargs: result)

    assert cmd_run(["client"]).stdout == "client-ok"
    assert cmd_main(lambda argv: 7, ["--flag"]) == 7
    assert cmd_main(lambda argv: None, []) == 0


@pytest.mark.uses_lifecycle_harness
def test_lifecycle_harness_drives_throwaway_instance(lifecycle, tmp_path):
    if not os.access(settings.NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {settings.NGINX_BIN}")

    endpoint = lifecycle.start(
        NginxInstanceSpec(
            name="lc-smoke",
            template="nginx_registry_smoke.conf",
            data_root=str(tmp_path / "data"),
            reason="lifecycle harness smoke",
        )
    )
    assert Path(endpoint.pidfile).exists()

    snapshot = lifecycle.process_snapshot("lc-smoke")
    assert any("master" in command for _, command in snapshot)
    assert any("worker" in command for _, command in snapshot)

    lifecycle.reconfigure("lc-smoke")
    lifecycle.reload("lc-smoke")
    lifecycle.reopen("lc-smoke")
    lifecycle.restart("lc-smoke")
    assert Path(endpoint.pidfile).exists()

    lifecycle.stop("lc-smoke")
    deadline = time.time() + 10
    while Path(endpoint.pidfile).exists() and time.time() < deadline:
        time.sleep(0.1)
    assert not Path(endpoint.pidfile).exists()


def test_registry_settings_exports_phase_env_knobs():
    assert settings.REGISTRY_ROOT.endswith("registry")
    assert settings.REGISTRY_MANIFEST.endswith("manifest.json")
    assert isinstance(settings.REGISTRY_START, bool)
    assert isinstance(settings.REGISTRY_KEEP_LOGS, bool)
    assert settings.REGISTRY_PORT_BASE is None or isinstance(settings.REGISTRY_PORT_BASE, str)

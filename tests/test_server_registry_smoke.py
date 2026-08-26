import json
import os
import subprocess
import time
from pathlib import Path

import pytest

import settings
from settings import HOST

from config_templates import render_config_to_path
from cmdscripts import main as cmd_main, run as cmd_run
from server_launcher import (
    RegistryCommandFailure,
    RegistryLauncher,
    _inject_nginx_load_modules,
    _inject_nginx_runtime_paths,
)
from server_registry import (
    CommandSpec,
    NginxInstanceSpec,
    clear_registry,
    endpoint_for,
    get_server,
    manifest_read,
    manifest_owns_test_root,
    fleet_ready_for_test_root,
    manifest_write,
    register_command_suite,
    register_nginx,
    register_xrootd,
    registered_command_suites,
    selected_specs,
    server,
    write_manifest,
)


def _check_test_lifecycle_harness_drives_throwaway_instance_1(endpoint):
    assert Path(endpoint.pidfile).exists()

def _check_test_lifecycle_harness_drives_throwaway_instance_2(endpoint):
    assert Path(endpoint.pidfile).exists()

def _check_test_lifecycle_harness_drives_throwaway_instance_3(endpoint):
    assert not Path(endpoint.pidfile).exists()

def _check_test_ipv6_fleet_specs_declare_host6_4(v6):
    assert len(v6) >= 6, "ipv6 tier missing from the fleet catalogue"

def _check_test_ipv6_fleet_specs_declare_host6_5(wrong):
    assert not wrong, f"ipv6 specs probing the wrong family: {wrong}"


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
    assert loaded["servers"]["smoke"]["url"] == "root://127.0.0.1:12345/"  # net-literal-allow: registry URL-construction assertion
    assert get_server("smoke").data_root == str(tmp_path / "data")
    assert server("smoke").port == 12345
    assert manifest_read(str(manifest_path))["version"] == 1
    clear_registry()


def test_dynamic_module_directives_are_injected_before_config(monkeypatch, tmp_path):
    core = tmp_path / "stream core.so"
    brix = tmp_path / "brix.so"
    config = tmp_path / "nginx.conf"
    config.write_text("events {}\n", encoding="utf-8")
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", os.pathsep.join((str(core), str(brix))))

    _inject_nginx_load_modules(str(config))

    lines = config.read_text(encoding="utf-8").splitlines()
    assert lines[:2] == [
        f'load_module "{core}";',
        f'load_module "{brix}";',
    ]
    assert lines[3] == "events {}"


def test_dynamic_module_injection_is_idempotent(monkeypatch, tmp_path):
    module = tmp_path / "brix.so"
    config = tmp_path / "nginx.conf"
    config.write_text("events {}\n", encoding="utf-8")
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", str(module))

    _inject_nginx_load_modules(str(config))
    _inject_nginx_load_modules(str(config))

    assert config.read_text(encoding="utf-8").count("load_module ") == 1


def test_stop_registered_visits_every_spec_after_one_stop_failure(monkeypatch):
    specs = [
        NginxInstanceSpec(name="first", template="unused", port=12341),
        NginxInstanceSpec(name="second", template="unused", port=12342),
    ]
    launcher = RegistryLauncher()
    visited = []

    def stop(name):
        visited.append(name)
        if name == "second":
            raise FileNotFoundError("launch binary disappeared")

    monkeypatch.setattr(launcher, "stop", stop)
    # A host without `ss` (snapshot None) keeps the exact per-spec path: every
    # spec is visited even though nothing is listening.
    monkeypatch.setattr("lib_py.util.listening_port_pids", lambda: None)
    with pytest.raises(RuntimeError, match="second: launch binary disappeared"):
        launcher.stop_registered(specs)
    assert visited == ["second", "first"]


def test_stop_registered_skips_quiescent_specs(monkeypatch):
    # No in-memory handle, no pidfile, no listener on the declared port: the
    # snapshot proves stop() would be a pure no-op, so the sweep skips it.
    specs = [
        NginxInstanceSpec(name="idle-a", template="unused", port=12346),
        NginxInstanceSpec(name="idle-b", template="unused", port=12347),
    ]
    launcher = RegistryLauncher()
    visited = []
    monkeypatch.setattr(launcher, "stop", lambda name: visited.append(name))
    monkeypatch.setattr("lib_py.util.listening_port_pids", lambda: {})
    launcher.stop_registered(specs)
    assert visited == []


def test_stop_registered_stops_spec_with_live_listener(monkeypatch):
    # A listener on any declared port — even one whose PIDs are unreadable
    # (empty set) — keeps the full stop path; only its idle peer is skipped.
    specs = [
        NginxInstanceSpec(name="live", template="unused", port=12348),
        NginxInstanceSpec(name="idle", template="unused", port=12349),
    ]
    launcher = RegistryLauncher()
    visited = []
    monkeypatch.setattr(launcher, "stop", lambda name: visited.append(name))
    monkeypatch.setattr("lib_py.util.listening_port_pids", lambda: {12348: set()})
    launcher.stop_registered(specs)
    assert visited == ["live"]


def test_stop_registered_stops_spec_with_pidfile_but_no_listener(monkeypatch):
    # A crashed master can leave its pidfile with no LISTEN socket; the pidfile
    # alone must defeat the quiescence proof so stop() still reaps it.
    spec = NginxInstanceSpec(name="halfdead-pidfile", template="unused", port=12350)
    endpoint = endpoint_for(spec)
    pidfile = Path(endpoint.pidfile)
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    pidfile.write_text("999999\n", encoding="utf-8")
    try:
        launcher = RegistryLauncher()
        visited = []
        monkeypatch.setattr(launcher, "stop", lambda name: visited.append(name))
        monkeypatch.setattr("lib_py.util.listening_port_pids", lambda: {})
        launcher.stop_registered([spec])
        assert visited == ["halfdead-pidfile"]
    finally:
        pidfile.unlink(missing_ok=True)


def test_disk_teardown_treats_a_zombie_as_exited() -> None:
    """A SIGTERM'd reference server can be a zombie before its Popen reaps it.

    ``os.kill(pid, 0)`` still succeeds then, but a zombie owns no listener.  The
    stateless complete-fleet stopper must advance instead of waiting its full
    five-second grace interval for each already-dead xrootd process.
    """
    proc = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
    deadline = time.monotonic() + 3.0
    try:
        while time.monotonic() < deadline:
            try:
                stat = Path(f"/proc/{proc.pid}/stat").read_text(encoding="utf-8")
            except OSError:
                break
            if stat.rsplit(")", 1)[1].lstrip().startswith("Z"):
                break
            time.sleep(0.01)
        assert RegistryLauncher._process_exited(proc.pid)
    finally:
        proc.wait(timeout=3)


def test_orphan_worker_reaper_uses_only_declared_ports(monkeypatch, tmp_path):
    spec = NginxInstanceSpec(name="orphan", template="unused", port=12343)
    proc = tmp_path / "proc"
    (proc / "701").mkdir(parents=True)
    (proc / "702").mkdir(parents=True)
    (proc / "701" / "cmdline").write_bytes(b"nginx: worker process\0")
    (proc / "702" / "cmdline").write_bytes(b"unrelated-server\0")
    killed = []

    monkeypatch.setattr("lib_py.util.pids_on_port", lambda port: [701, 702])
    monkeypatch.setattr("lib_py.util.kill_pid_list", lambda pids: killed.extend(pids))
    real_path = Path

    def fake_path(value):
        text = str(value)
        if text.startswith("/proc/"):
            return proc / text.split("/")[2] / "cmdline"
        return real_path(value)

    # the reaper lives in the mixinb shard — its Path binding is THAT module's
    monkeypatch.setattr("_server_launcher_part2_mixinb.Path", fake_path)
    RegistryLauncher._reap_orphan_nginx_workers(spec)
    assert killed == [701]


def test_packaged_nginx_defaults_are_confined_to_instance_prefix(tmp_path):
    prefix = tmp_path / "instance"
    config = tmp_path / "nginx.conf"
    config.write_text("events {}\nhttp { server {} }\n", encoding="utf-8")

    _inject_nginx_runtime_paths(str(config), str(prefix))

    text = config.read_text(encoding="utf-8")
    assert f'pid "{prefix}/logs/nginx.pid";' in text
    assert f'access_log "{prefix}/logs/access.log";' in text
    assert f'client_body_temp_path "{prefix}/tmp/client-body";' in text
    assert "/run/nginx.pid" not in text
    assert "/var/log/nginx" not in text


def test_explicit_runtime_paths_are_not_duplicated(tmp_path):
    prefix = tmp_path / "instance"
    config = tmp_path / "nginx.conf"
    config.write_text(
        "pid /chosen/nginx.pid;\nerror_log stderr;\n"
        "events {}\nhttp { access_log off; server {} }\n",
        encoding="utf-8",
    )

    _inject_nginx_runtime_paths(str(config), str(prefix))

    text = config.read_text(encoding="utf-8")
    assert text.count("pid ") == 1
    assert text.count("error_log ") == 1
    assert text.count("access_log ") == 1


def test_stream_only_config_gets_no_http_directives(tmp_path):
    config = tmp_path / "nginx.conf"
    config.write_text("events {}\nstream { server {} }\n", encoding="utf-8")

    _inject_nginx_runtime_paths(str(config), str(tmp_path / "instance"))

    text = config.read_text(encoding="utf-8")
    assert "access_log" not in text
    assert "client_body_temp_path" not in text


def test_manifest_ownership_accepts_matching_normalized_root(tmp_path, monkeypatch):
    root = tmp_path / "suite-root"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "version": 1, "test_root": str(root / ".." / "suite-root"),
        "servers": {},
    }))
    monkeypatch.setattr("server_registry.TEST_ROOT", str(root))
    assert manifest_owns_test_root(str(manifest))


def test_manifest_ownership_rejects_different_root(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "version": 1, "test_root": str(tmp_path / "lane-a"), "servers": {},
    }))
    monkeypatch.setattr("server_registry.TEST_ROOT", str(tmp_path / "lane-b"))
    assert not manifest_owns_test_root(str(manifest))


def test_fleet_ready_marker_requires_matching_completed_root(tmp_path, monkeypatch):
    marker = tmp_path / ".fleet-ready"
    monkeypatch.setattr("server_registry.TEST_ROOT", str(tmp_path / "lane-a"))
    assert not fleet_ready_for_test_root(str(marker))
    marker.write_text(str(tmp_path / "lane-b") + "\n")
    assert not fleet_ready_for_test_root(str(marker))
    marker.write_text(str(tmp_path / "lane-a") + "\n")
    assert fleet_ready_for_test_root(str(marker))


@pytest.mark.parametrize("payload", ["not-json", '{"version": 1, "servers": {}}'])
def test_manifest_ownership_rejects_invalid_or_rootless_manifest(
        tmp_path, monkeypatch, payload):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(payload)
    monkeypatch.setattr("server_registry.TEST_ROOT", str(tmp_path / "lane"))
    assert not manifest_owns_test_root(str(manifest))


def test_registry_rejects_a_portless_spec():
    """Phase 5 removed the dynamic free_port fallback: a spec with no port is a
    hard error, so every registered server must declare a fixed port (settings
    constant, fleet_ports ledger, or explicit ``port=``)."""
    clear_registry()
    spec = register_nginx(
        NginxInstanceSpec(name="portless", template="nginx_registry_smoke.conf")
    )
    try:
        endpoint_for(spec)
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("portless spec unexpectedly resolved to an endpoint")

    assert "portless" in message
    assert "no port" in message
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
    launcher._wait_ready(HOST, 1, "webdav")
    launcher._wait_ready(HOST, 1, "metrics")

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
@pytest.mark.xdist_group("lc-smoke")  # fixed-port lc-smoke → one driver at a time
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
    _check_test_lifecycle_harness_drives_throwaway_instance_1(endpoint)

    snapshot = lifecycle.process_snapshot("lc-smoke")
    def _assert_test_lifecycle_harness_drives_throwaway_instance_1():
        assert any("master" in command for _, command in snapshot)
        assert any("worker" in command for _, command in snapshot)

    _assert_test_lifecycle_harness_drives_throwaway_instance_1()

    lifecycle.reconfigure("lc-smoke")
    lifecycle.reload("lc-smoke")
    lifecycle.reopen("lc-smoke")
    lifecycle.restart("lc-smoke")
    _check_test_lifecycle_harness_drives_throwaway_instance_2(endpoint)

    lifecycle.stop("lc-smoke")
    deadline = time.time() + 10
    while Path(endpoint.pidfile).exists() and time.time() < deadline:
        time.sleep(0.1)
    _check_test_lifecycle_harness_drives_throwaway_instance_3(endpoint)


def test_registry_settings_exports_phase_env_knobs():
    assert settings.REGISTRY_ROOT.endswith("registry")
    assert settings.REGISTRY_MANIFEST.endswith("manifest.json")
    assert isinstance(settings.REGISTRY_START, bool)
    assert isinstance(settings.REGISTRY_KEEP_LOGS, bool)
    assert isinstance(settings.TEST_PORT_START, int)


def test_endpoint_honours_spec_host_and_brackets_ipv6_url():
    """A spec that declares a host gets it verbatim on the endpoint (this is
    the address the readiness probe dials) and IPv6 literals are bracketed in
    the URL."""
    spec = NginxInstanceSpec(name="v6-probe-smoke", template="unused.conf",
                             port=19321, host="::1")  # net-literal-allow: IPv6 endpoint construction under test
    endpoint = endpoint_for(spec)
    assert endpoint.host == "::1"  # net-literal-allow: IPv6 endpoint host under test
    assert endpoint.url == "root://[::1]:19321/"  # net-literal-allow: IPv6 endpoint URL formatting under test


def test_endpoint_defaults_to_settings_host_without_spec_host():
    """No declared host -> settings.HOST, unbracketed (the pre-existing
    contract for the v4 fleet must not shift)."""
    spec = NginxInstanceSpec(name="v4-probe-smoke", template="unused.conf",
                             port=19322)
    endpoint = endpoint_for(spec)
    assert endpoint.host == settings.HOST
    assert endpoint.url == f"root://{settings.HOST}:19322/"


def test_ipv6_fleet_specs_declare_host6():
    """Every [::1]-tier fleet spec must carry host=HOST6 — a 127.0.0.1 TCP
    probe against a v6-only listener can never succeed, so a missing host
    silently reports the instance as failed-to-start every boot."""
    from fleet_specs import dedicated_specs

    v6 = [s for s in dedicated_specs() if s.name.startswith("ipv6-")]
    _check_test_ipv6_fleet_specs_declare_host6_4(v6)
    wrong = [s.name for s in v6 if s.host != settings.HOST6]
    _check_test_ipv6_fleet_specs_declare_host6_5(wrong)

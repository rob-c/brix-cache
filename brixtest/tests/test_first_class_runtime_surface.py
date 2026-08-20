"""Contract tests for typed references, launchers, bounded IO, and Minikube."""

from __future__ import annotations

import json
import hashlib
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import (
    LogPolicy, MiB, Placement, ResourceLimits, ServerLaunchContext,
    ServerLaunchRequest, SpecError, case, credential, endpoint, execution,
    binary, client, get_case, param, probe, run_root_ref, server, server_config, text_artifact,
    workspace_ref,
)
from brixtest.design import Artifact
from brixtest.minikube import MinikubeConfig, minikube_status
from brixtest.cli.main import _parser
from brixtest.runtime.backends import LocalCaseBackend, MinikubeCaseBackend
from brixtest.runtime.binaries import BinaryStore, CapturedBinary
from brixtest.runtime.commands import CommandRunner
from brixtest.runtime.executors import tool_executor
from brixtest.runtime.launchers import server_launcher
from brixtest.runtime.logcapture import BoundedLogPump
from brixtest.runtime.manager import CaseManager
from brixtest.testing import check_launcher_contract


def _definition(*resources, keep="always"):
    @case(*resources, observe=[], keep=keep)
    def managed(run):
        pass

    return get_case(managed)


def test_declarations_own_discoverable_typed_references():
    payload = text_artifact("payload", "hello")
    secret = credential("proof", "signed")
    origin = server(
        "origin", execution=execution("daemon", "{port}"),
        endpoints=[endpoint("http", scheme="http")],
    )

    assert payload.ref().key == "artifact_payload"
    assert payload.ref(directory=True).key == "artifact_payload_dir"
    assert secret.ref().key == "credential_proof"
    assert origin.host.key == "server_origin_host"
    assert origin.port("http").key == "server_origin_http_port"
    assert origin.url("http").key == "server_origin_http_url"
    assert origin.config_path.key == "server_origin_config"
    assert origin.log_path.key == "server_origin_log"
    assert param("size").key == "param_size"
    assert workspace_ref().key == "workspace"
    assert run_root_ref().key == "run_root"


@pytest.mark.parametrize("name", ["", "not-valid", "two words"])
def test_parameter_references_reject_ambiguous_placeholder_names(name):
    with pytest.raises(SpecError, match="runtime placeholder identifier"):
        param(name)


def test_reference_helpers_cannot_forge_unknown_server_roles():
    origin = server("origin", execution=execution("daemon"))
    with pytest.raises(SpecError, match="reference.role"):
        origin.url("Invalid.Role")


def test_process_launcher_preserves_the_rendered_supervised_plan(tmp_path):
    declaration = server("origin", execution=execution("daemon", "--serve"))
    context = ServerLaunchContext("unit::origin", tmp_path, tmp_path / "workspace")
    request = ServerLaunchRequest(
        declaration, ("daemon", "--serve"), {"MODE": "test"},
        tmp_path / "runtime" / "instances" / "origin",
    )
    launcher = server_launcher("process")
    plan = launcher.prepare(context, request)

    assert plan.argv == ("daemon", "--serve")
    assert plan.env == {"MODE": "test"}
    assert plan.launcher == "process" and not plan.cleanup_argv
    assert check_launcher_contract(launcher, declaration, context, request) == []


def test_process_launcher_refuses_a_working_directory_outside_the_run(tmp_path):
    declaration = server("origin", execution=execution("daemon"))
    context = ServerLaunchContext("unit::escape", tmp_path / "run", tmp_path / "run/workspace")
    request = ServerLaunchRequest(declaration, ("daemon",), {}, tmp_path / "outside")
    with pytest.raises(SpecError, match="confined below the run root"):
        server_launcher("process").prepare(context, request)


@pytest.mark.parametrize(
    "placement, message",
    [
        (Placement(image="example/image@sha256:" + "a" * 64), "does not consume"),
        (Placement(resources=ResourceLimits(cpu=1)), "cannot enforce"),
        (Placement(options={"unknown": True}), "has no options"),
    ],
)
def test_process_launcher_refuses_silently_ignored_placement(placement, message):
    declaration = server("origin", execution=execution("daemon"), placement=placement)
    with pytest.raises(SpecError, match=message):
        server_launcher("process").validate(declaration)


def test_docker_launcher_uses_pinned_image_mode_0600_env_and_resource_limits(
    tmp_path, monkeypatch,
):
    image = "registry.example/server@sha256:" + "b" * 64
    declaration = server(
        "origin", execution=execution("/opt/server", "--port", "1234"),
        placement=Placement(
            backend="docker", image=image, labels={"suite": "unit"},
            resources=ResourceLimits(cpu=1.5, memory_bytes=64 * MiB, pids=32),
        ),
    )
    context = ServerLaunchContext("unit::docker", tmp_path, tmp_path / "workspace")
    request = ServerLaunchRequest(
        declaration, declaration.command, {"TOKEN": "not-in-argv"},
        tmp_path / "runtime" / "instances" / "origin",
    )
    monkeypatch.setattr("brixtest.runtime.launchers.shutil.which", lambda name: "/usr/bin/" + name)
    cleanup = []
    monkeypatch.setattr(
        "brixtest.runtime.launchers.subprocess.run",
        lambda argv, **kwargs: cleanup.append(tuple(argv))
        or subprocess.CompletedProcess(argv, 0),
    )

    launcher = server_launcher("docker")
    plan = launcher.prepare(context, request)
    env_file = Path(plan.metadata["env_file"])

    assert plan.argv[:2] == ("docker", "run")
    assert image in plan.argv and "not-in-argv" not in plan.argv
    assert ("--cpus", "1.5") == plan.argv[plan.argv.index("--cpus"):][:2]
    assert "--memory" in plan.argv and "--pids-limit" in plan.argv
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert env_file.read_text() == "TOKEN=not-in-argv\n"
    launcher.cleanup(context, plan)
    assert cleanup == [plan.cleanup_argv]


@pytest.mark.parametrize("backend", ["docker", "podman"])
def test_container_launchers_reject_mutable_images_by_default(backend):
    declaration = server(
        "origin", execution=execution("daemon"),
        placement=Placement(backend=backend, image="example/server:latest"),
    )
    with pytest.raises(SpecError, match="image@sha256"):
        server_launcher(backend).validate(declaration)


def test_container_launcher_rejects_multiline_secret_before_runtime_spawn(
    tmp_path, monkeypatch,
):
    declaration = server(
        "origin", execution=execution("daemon"),
        placement=Placement(
            backend="docker", image="example/server@sha256:" + "c" * 64,
        ),
    )
    context = ServerLaunchContext("unit::newline", tmp_path, tmp_path / "workspace")
    request = ServerLaunchRequest(
        declaration, ("daemon",), {"TOKEN": "line-one\nline-two"}, tmp_path,
    )
    monkeypatch.setattr("brixtest.runtime.launchers.shutil.which", lambda name: "/usr/bin/docker")
    with pytest.raises(SpecError, match="cannot contain newlines"):
        server_launcher("docker").prepare(context, request)


@pytest.mark.parametrize(
    "unsafe",
    ["--privileged", "--volume=/:/host", "-v", "--cap-add=SYS_ADMIN", "-p8080:80"],
)
def test_container_launcher_runtime_args_cannot_bypass_boundaries(unsafe):
    declaration = server(
        "origin", execution=execution("daemon"),
        placement=Placement(
            backend="docker", image="example/server@sha256:" + "e" * 64,
            options={"runtime_args": (unsafe,)},
        ),
    )
    with pytest.raises(SpecError, match="cannot override privilege"):
        server_launcher("docker").validate(declaration)


def test_container_server_launcher_refuses_unreachable_bridge_network():
    declaration = server(
        "origin", execution=execution("daemon"),
        placement=Placement(
            backend="docker", image="example/server@sha256:" + "f" * 64,
            options={"network": "bridge"},
        ),
    )
    with pytest.raises(SpecError, match="allocated loopback ports"):
        server_launcher("docker").validate(declaration)


def test_container_tool_network_cannot_attach_an_unmanaged_container_namespace():
    declaration = client(
        "reader", execution=execution("reader"),
        placement=Placement(
            backend="docker", image="example/client@sha256:" + "a" * 64,
            options={"network": "container:privileged-neighbour"},
        ),
    )
    with pytest.raises(SpecError, match="simple named container network"):
        tool_executor("docker").validate(declaration)


def test_local_backend_accepts_mixed_process_and_container_server_placements():
    image = "example/server@sha256:" + "d" * 64
    native = server("native", execution=execution("daemon"))
    boxed = server(
        "boxed", execution=execution("daemon"),
        placement=Placement(backend="docker", image=image),
    )
    definition = _definition(native, boxed)
    LocalCaseBackend().validate(definition)


def test_local_backend_rejects_unknown_server_launcher_during_planning():
    declaration = server(
        "origin", execution=execution("daemon"),
        placement=Placement(backend="not-installed"),
    )
    with pytest.raises(SpecError, match="launcher extension"):
        LocalCaseBackend().validate(_definition(declaration))


def test_command_capture_is_bounded_while_draining_large_parallel_streams(tmp_path):
    result = CommandRunner(tmp_path / "logs", cwd=tmp_path).run(
        sys.executable, "-c",
        "import sys;sys.stdout.write('o'*2000000);sys.stderr.write('e'*2000000)",
        output_limit=1024,
    )
    assert len(result.stdout.encode()) <= 1024
    assert len(result.stderr.encode()) <= 1024
    assert result.stdout_truncated and result.stderr_truncated
    assert "BriXTest output truncated" in result.stdout
    assert "BriXTest output truncated" in result.stderr


def test_command_timeout_retains_partial_output_and_terminates_process_group(tmp_path):
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        CommandRunner(tmp_path / "logs", cwd=tmp_path).run(
            sys.executable, "-c",
            "import time;print('before-timeout',flush=True);time.sleep(30)",
            timeout=0.1, output_limit=1024,
        )
    assert "before-timeout" in str(raised.value.output)
    metadata = json.loads((tmp_path / "logs" / "0001.json").read_text())
    assert metadata["error"] == "TimeoutExpired"


def test_server_log_is_capped_during_execution(tmp_path):
    noisy = server(
        "noisy",
        execution=execution(
            sys.executable, "-c",
            "import sys;sys.stdout.write('x'*200000);sys.stdout.flush()",
        ),
        logs=LogPolicy(max_bytes=2048),
        probe=probe("none"),
    )
    manager = CaseManager(_definition(noisy), "unit::noisy", root=tmp_path / "run")
    run = manager.start()
    run.server(noisy).wait(timeout=5.0)
    manager.set_outcome("passed")
    manager.close()
    log = tmp_path / "run" / "runtime" / "logs" / "noisy.log"
    assert log.stat().st_size <= 2048
    assert b"log limit reached" in log.read_bytes()


def test_server_log_pump_publishes_short_lines_before_process_exit(tmp_path):
    process = subprocess.Popen(
        [
            sys.executable, "-u", "-c",
            "import time;print('ready', flush=True);time.sleep(30)",
        ],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert process.stdout is not None
    log = tmp_path / "live.log"
    pump = BoundedLogPump(process.stdout, log, 1024)
    pump.start()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and "ready" not in (
        log.read_text(errors="replace") if log.exists() else ""
    ):
        time.sleep(0.01)
    try:
        assert log.read_text() == "ready\n"
    finally:
        process.terminate()
        process.wait(timeout=2.0)
        assert pump.join(timeout=1.0)


def test_service_controls_restart_health_command_signal_and_wait(tmp_path):
    code = (
        "import http.server,sys;"
        "http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),"
        "http.server.SimpleHTTPRequestHandler).serve_forever()"
    )
    origin = server(
        "origin", execution=execution(sys.executable, "-u", "-c", code, "{port}"),
        config=server_config("served=true\n"),
    )
    manager = CaseManager(_definition(origin), "unit::controls", root=tmp_path / "run")
    service = manager.start().server(origin)

    assert service.is_ready()
    assert service.wait(timeout=0.0) is None
    assert service.command(sys.executable, "-c", "print('inside')").stdout == "inside\n"
    service.signal("TERM")
    assert service.wait(timeout=5.0) is not None
    restarted = service.restart()
    assert restarted.wait_ready(timeout=5.0).port() == service.port()
    assert restarted.read_config() == "served=true\n"
    manager.set_outcome("passed")
    manager.close()


def test_detached_service_control_and_invalid_udp_health_fail_clearly(tmp_path):
    from brixtest.runtime.api import Service

    log = tmp_path / "server.log"
    log.write_text("line\n")
    value = Service(
        "detached", "127.0.0.1", {"primary": 12345}, tmp_path / "c",
        log, tmp_path, protocols={"primary": "udp"},
    )
    with pytest.raises(SpecError, match="detached Service"):
        value.restart()
    with pytest.raises(SpecError, match="TCP endpoint"):
        value.is_ready()
    with pytest.raises(SpecError, match="integer >= 0"):
        value.tail_log(-1)


def test_service_follow_log_is_incremental_and_deadline_bounded(tmp_path):
    from brixtest.runtime.api import Service

    log = tmp_path / "server.log"
    log.write_text("old\n")
    value = Service(
        "detached", "127.0.0.1", {"primary": 12345}, tmp_path / "c", log, tmp_path,
    )

    def append():
        time.sleep(0.08)
        with log.open("a") as handle:
            handle.write("new\n")

    worker = threading.Thread(target=append)
    worker.start()
    assert list(value.follow_log(timeout=0.3, interval=0.01)) == ["new"]
    worker.join()


def test_minikube_defaults_are_docker_only_and_reproducible():
    config = MinikubeConfig()
    assert config.profile == "brixtest"
    assert "--driver=docker" in config.start_argv()
    assert "--container-runtime=docker" in config.start_argv()
    with pytest.raises(SpecError, match="uses Docker"):
        MinikubeConfig(driver="podman")


def test_minikube_cli_preserves_environment_defaults_until_dispatch(monkeypatch):
    monkeypatch.setenv("BRIXTEST_MINIKUBE_PROFILE", "isolated-profile")
    monkeypatch.setenv("BRIXTEST_MINIKUBE_CPUS", "3")
    monkeypatch.setenv("BRIXTEST_MINIKUBE_MEMORY_MB", "6144")
    args = _parser().parse_args(["minikube", "status"])
    defaults = MinikubeConfig.from_environment()
    assert args.profile is None and args.cpus is None and args.memory is None
    assert (defaults.profile, defaults.cpus, defaults.memory_mb) == (
        "isolated-profile", 3, 6144,
    )


def test_minikube_environment_rejects_non_numeric_capacity(monkeypatch):
    monkeypatch.setenv("BRIXTEST_MINIKUBE_CPUS", "many")
    with pytest.raises(SpecError, match="must be integers"):
        MinikubeConfig.from_environment()


def test_minikube_status_normalizes_missing_binary(monkeypatch):
    monkeypatch.setattr(
        "brixtest.minikube.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("minikube")),
    )
    result = minikube_status(MinikubeConfig())
    assert result["ok"] is False
    assert result["profile"] == "brixtest"
    assert "FileNotFoundError" in result["error"]


def test_minikube_status_requires_all_control_plane_components(monkeypatch):
    monkeypatch.setattr(
        "brixtest.minikube.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0,
            json.dumps({"Host": "Running", "Kubelet": "Stopped", "APIServer": "Running"}),
            "",
        ),
    )
    result = minikube_status(MinikubeConfig())
    assert result["ok"] is False and result["running"] is False


def test_minikube_backend_selects_explicit_context_for_docker_profile(monkeypatch):
    profile = {
        "valid": [{"Name": "brixtest", "Config": {"Driver": "docker"}}],
    }
    monkeypatch.setattr("brixtest.runtime.backends.shutil.which", lambda name: "/usr/bin/" + name)
    def run(argv, **kwargs):
        payload = (
            {"Host": "Running", "Kubelet": "Running", "APIServer": "Running"}
            if "status" in argv else profile
        )
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    monkeypatch.setattr("brixtest.runtime.backends.subprocess.run", run)

    class Context:
        selected = ""

        def set_kubernetes_context(self, value):
            self.selected = value

    context = Context()
    backend = MinikubeCaseBackend()
    backend.validate(SimpleNamespace(servers=(), clients=()))
    backend.prepare(context)
    assert context.selected == "brixtest"
    assert backend.plan(context) == {
        "backend": "minikube", "profile": "brixtest",
        "driver": "docker", "context": "brixtest",
    }


@pytest.mark.parametrize("driver", ["podman", "kvm2"])
def test_minikube_backend_refuses_non_docker_profiles(driver, monkeypatch):
    profile = {"valid": [{"Name": "brixtest", "Config": {"Driver": driver}}]}
    monkeypatch.setattr("brixtest.runtime.backends.shutil.which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        "brixtest.runtime.backends.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, json.dumps(profile), "",
        ),
    )
    with pytest.raises(SpecError, match="requires the Docker driver"):
        MinikubeCaseBackend().prepare(SimpleNamespace(set_kubernetes_context=lambda value: None))


def test_minikube_backend_refuses_stopped_docker_profile(monkeypatch):
    profile = {"valid": [{"Name": "brixtest", "Config": {"Driver": "docker"}}]}
    monkeypatch.setattr("brixtest.runtime.backends.shutil.which", lambda name: "/usr/bin/" + name)

    def run(argv, **kwargs):
        payload = (
            {"Host": "Stopped", "Kubelet": "Stopped", "APIServer": "Stopped"}
            if "status" in argv else profile
        )
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    monkeypatch.setattr("brixtest.runtime.backends.subprocess.run", run)
    with pytest.raises(SpecError, match="profile is not ready"):
        MinikubeCaseBackend().prepare(SimpleNamespace(set_kubernetes_context=lambda value: None))


def test_artifact_reference_method_is_present_on_custom_provider_declarations():
    value = Artifact("generated", "custom-kind", filename="input.bin")
    assert value.ref().key == "artifact_generated"


def test_captured_binary_verifies_every_library_checksum(tmp_path):
    executable = tmp_path / "daemon"
    library = tmp_path / "libdaemon.so"
    executable.write_bytes(b"executable")
    library.write_bytes(b"library")
    value = CapturedBinary(
        "daemon", executable, tmp_path,
        hashlib.sha256(executable.read_bytes()).hexdigest(),
        (library,),
    )
    assert value.verify()
    assert value.as_dict()["library_sha256"][str(library)] \
        == hashlib.sha256(b"library").hexdigest()
    library.write_bytes(b"rebuild-blatted-library")
    assert value.verify() is False


def test_binary_capture_discovers_transitive_dynamic_library_graph(tmp_path, monkeypatch):
    executable = tmp_path / "daemon"
    first = tmp_path / "libfirst.so"
    second = tmp_path / "libsecond.so"
    for path, content in ((executable, b"exe"), (first, b"one"), (second, b"two")):
        path.write_bytes(content)
    executable.chmod(0o700)

    def dependencies(path):
        return {executable: (first,), first: (second,)}.get(path, ())

    monkeypatch.setattr("brixtest.runtime.binaries._ldd_libraries", dependencies)
    captured = BinaryStore(tmp_path / "capture", tmp_path).capture(
        binary("daemon", executable),
    )
    assert {path.name for path in captured.libraries} == {"libfirst.so", "libsecond.so"}
    assert captured.verify()


def test_binary_capture_rejects_different_libraries_with_same_runtime_name(tmp_path):
    executable = tmp_path / "daemon"
    executable.write_bytes(b"exe")
    executable.chmod(0o700)
    left = tmp_path / "left/libsame.so"
    right = tmp_path / "right/libsame.so"
    left.parent.mkdir()
    right.parent.mkdir()
    left.write_bytes(b"left")
    right.write_bytes(b"right")
    declaration = binary(
        "daemon", executable, libraries=(left, right), discover_libraries=False,
    )
    with pytest.raises(SpecError, match="same basename"):
        BinaryStore(tmp_path / "capture", tmp_path).capture(declaration)

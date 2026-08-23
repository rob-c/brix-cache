"""Contract tests for typed references, launchers, bounded IO, and Minikube."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from brixtest import (
    SpecError,
    binary,
    case,
    execution,
    get_case,
    server,
    server_config,
)
from brixtest.cli.main import _parser
from brixtest.design import Artifact
from brixtest.minikube import MinikubeConfig, minikube_status
from brixtest.runtime.backends import MinikubeCaseBackend
from brixtest.runtime.binaries import BinaryStore, CapturedBinary
from brixtest.runtime.manager import CaseManager


def _definition(*resources, keep="always"):
    @case(*resources, observe=[], keep=keep)
    def managed(run):
        pass

    return get_case(managed)



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


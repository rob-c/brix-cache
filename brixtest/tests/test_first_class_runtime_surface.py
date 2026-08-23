"""Contract tests for typed references, launchers, bounded IO, and Minikube."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from brixtest import (
    LogPolicy,
    MiB,
    Placement,
    ResourceLimits,
    ServerLaunchContext,
    ServerLaunchRequest,
    SpecError,
    case,
    client,
    credential,
    endpoint,
    execution,
    get_case,
    param,
    probe,
    run_root_ref,
    server,
    text_artifact,
    workspace_ref,
)
from brixtest.runtime.backends import LocalCaseBackend
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
    with pytest.raises(SpecError, match=r"reference\.role"):
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

    observed = (
        plan.argv[:2], image in plan.argv, "not-in-argv" in plan.argv,
        plan.argv[plan.argv.index("--cpus"):][:2], "--memory" in plan.argv,
        "--pids-limit" in plan.argv, stat.S_IMODE(env_file.stat().st_mode),
        env_file.read_text(),
    )
    assert observed == (
        ("docker", "run"), True, False, ("--cpus", "1.5"), True, True,
        0o600, "TOKEN=not-in-argv\n",
    )
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

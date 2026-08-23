"""Tests for resource backends and test-author extensions."""

from __future__ import annotations

import json
import sys

import pytest

from brixtest import (
    CaseManager,
    ExtensionRegistry,
    Placement,
    ResourceLimits,
    Service,
    case,
    collector,
    endpoint,
    http_endpoint,
    http_probe,
    probe,
    register_extension,
    server,
    server_config,
)
from brixtest.config.lanes import Lane
from brixtest.deploy.local import LocalBackend
from brixtest.errors import SpecError
from brixtest.evidence.collectors import CollectorManager
from brixtest.fleet.kinds import KindProfile, known_kinds, register_kind
from brixtest.fleet.probes import ExtensionProbe, probe_from_declaration
from brixtest.fleet.registry import InstanceSpec, Registry, ServerEndpoint
from brixtest.runtime.api import Run
from brixtest.runtime.commands import CommandRunner
from brixtest.runtime.kubernetes import server_resources
from brixtest.testing import assert_extension_contract


def test_service_uses_endpoint_schemes_and_reads_named_configs(tmp_path):
    main = tmp_path / "main.conf"
    extra = tmp_path / "extra.conf"
    log = tmp_path / "server.log"
    main.write_text("main\n")
    extra.write_text("extra\n")
    log.write_text("ready\n")
    service = Service(
        "origin", "::1", {"primary": 8443, "admin": 9000}, main, log, tmp_path,
        configs={"main.conf": main, "extra.conf": extra},
        schemes={"primary": "https"},
    )
    assert service.url(path="status") == "https://[::1]:8443/status"
    assert service.endpoint("admin") == {
        "role": "admin", "host": "::1", "port": 9000, "scheme": "",
        "protocol": "tcp",
    }
    assert service.read_config("extra.conf") == "extra\n"
    assert service.read_log() == "ready\n"


def test_kubernetes_resources_translate_limits_probes_and_mounts():
    digest = "example.test/origin@sha256:" + "a" * 64
    declaration = server(
        "origin", command=["/opt/origin"], config=server_config("ready=true\n"),
        endpoints=[http_endpoint()], probe=http_probe(path="/ready"),
        image=digest,
        placement=Placement(
            backend="kubernetes", image=digest, labels={"role": "origin"},
            resources=ResourceLimits(cpu=1, memory_bytes=64 << 20, pids=32),
        ),
    )
    _, deployment, _ = server_resources(
        declaration, namespace="brixtest-unit", command=["/opt/origin"], env={},
        ports={"http": 8080, "primary": 8080}, config_text="ready=true\n",
        mount_secret="origin-mounts", mount_items=[{"key": "file-0000", "path": "input"}],
        temporary_mounts=("scratch",),
    )
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["readinessProbe"]["httpGet"] == {
        "path": "/ready", "port": 8080, "scheme": "HTTP",
    }
    assert container["resources"]["limits"]["memory"] == str(64 << 20)
    assert {item["mountPath"] for item in container["volumeMounts"]} >= {
        "/brixtest/mounts", "/brixtest/mounts/scratch",
    }


def test_kubernetes_backend_refuses_udp_that_port_forward_cannot_publish(tmp_path):
    declaration = server(
        "dns", command=["dns"], config=server_config("port={port}\n"),
        endpoints=[endpoint("dns", protocol="udp")], probe=probe("none"),
        image="example.test/dns@sha256:" + "a" * 64,
        placement=Placement(backend="kubernetes"),
    )

    @case(servers=[declaration], backend="kubernetes", observe=[])
    def managed(run):
        pass

    with pytest.raises(SpecError, match="cannot publish UDP"):
        CaseManager(managed.__brixtest_case__, "unit::udp", root=tmp_path / "run")


def test_local_backend_refuses_kubernetes_only_placement_instead_of_ignoring_it(tmp_path):
    declaration = server(
        "origin", command=["origin"], config=server_config("ready=true\n"),
        placement=Placement(resources=ResourceLimits(memory_bytes=1024)),
    )

    @case(servers=[declaration], backend="local", observe=[])
    def managed(run):
        pass

    with pytest.raises(SpecError, match="requires Kubernetes"):
        CaseManager(managed.__brixtest_case__, "unit::limits", root=tmp_path / "run")


def test_command_runner_accepts_expected_nonzero_and_bounds_output(tmp_path):
    result = CommandRunner(tmp_path / "logs", cwd=tmp_path).run(
        sys.executable, "-c", "import sys;print('x'*100);sys.exit(7)",
        expected_exit_codes=(7,), output_limit=40,
    )
    assert result.returncode == 7 and result.stdout_truncated
    assert len(result.stdout.encode()) <= 40
    assert json.loads((tmp_path / "logs" / "0001.json").read_text())["expected_exit_codes"] == [7]


def test_command_runner_retries_until_an_expected_exit(tmp_path):
    marker = tmp_path / "attempt"
    code = (
        "import pathlib,sys;p=pathlib.Path(sys.argv[1]);"
        "n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n));"
        "sys.exit(0 if n==2 else 9)"
    )
    result = CommandRunner(None, cwd=tmp_path).run(
        sys.executable, "-c", code, marker, retries=1,
    )
    assert result.ok and result.attempts == 2 and marker.read_text() == "2"


def _process_backend(tmp_path):
    kind = "unit-resource-process"
    if kind not in known_kinds():
        register_kind(KindProfile(
            name=kind, pidfile=None, stop="process-group", command=None,
            default_probe="none", ports_only_quiescence=True,
        ))
    registry = Registry()
    lane = Lane(tmp_path / "lane", port_base=31000, port_span=100)
    backend = LocalBackend(registry, lane)
    backend.prepare(lane, None)
    return kind, registry, backend


def test_foreground_lifecycle_waits_for_a_successful_command(tmp_path):
    kind, registry, backend = _process_backend(tmp_path)
    spec = InstanceSpec(
        "foreground", kind, command=(sys.executable, "-c", "print('complete')"),
        readiness="none", background=False, expected_exit=True,
    )
    registry.register(spec)
    registry.freeze()
    endpoint_value = backend.start(spec)
    assert "complete" in endpoint_value.log_path.read_text()
    backend.stop(spec.name)


def test_shutdown_command_runs_before_the_selected_signal(tmp_path):
    kind, registry, backend = _process_backend(tmp_path)
    marker = tmp_path / "shutdown-marker"
    spec = InstanceSpec(
        "background", kind,
        command=(sys.executable, "-c", "import time;time.sleep(30)"),
        readiness="none", shutdown_signal="INT",
        shutdown_command=(
            sys.executable, "-c", "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('done')",
            str(marker),
        ),
    )
    registry.register(spec)
    registry.freeze()
    backend.start(spec)
    backend.stop(spec.name)
    assert marker.read_text() == "done"


class _ProbeDriver:
    def __init__(self):
        self.validated = None

    def validate(self, declaration):
        self.validated = declaration

    def wait(self, declaration, endpoint, timeout):
        assert declaration is self.validated and endpoint.name == "origin"
        return timeout / 2


def test_custom_probe_extension_is_bound_and_executed(tmp_path, monkeypatch):
    from brixtest.extensions import extension_registry

    driver = _ProbeDriver()
    extension_registry.register("probe", "grpc", driver, replace=True)
    declaration = probe("grpc", timeout=4)
    runtime = probe_from_declaration(declaration)
    endpoint_value = ServerEndpoint(
        "origin", "custom", "127.0.0.1", {"primary": 1}, tmp_path,
        tmp_path / "log", None,
    )
    assert isinstance(runtime, ExtensionProbe)
    assert runtime.wait(endpoint_value, 4) == 2


class _FullDriver:
    def validate(self, *args): pass
    def plan(self, *args): return {}
    def prepare(self, *args): pass
    def start(self, *args): pass
    def stop(self, *args): pass
    def collect(self, *args): return {}
    def execute(self, *args): pass
    def run(self, *args): pass
    def wait(self, *args): return 0
    def materialize(self, *args): pass
    def redact(self, *args): return "[redacted]"


@pytest.mark.parametrize("kind", ["probe", "backend", "executor", "provider"])
def test_stateful_extension_kinds_have_reusable_conformance_checks(kind):
    result = assert_extension_contract(kind, "example", _FullDriver())
    assert result["kind"] == kind and result["api_version"] == 1


@pytest.mark.parametrize("kind", ["collector", "analyzer", "exporter"])
def test_callable_extension_kinds_have_reusable_conformance_checks(kind):
    result = assert_extension_contract(kind, "example", lambda *args: None)
    assert result["kind"] == kind


def test_collector_extension_runs_through_the_shared_validated_registry(tmp_path):
    calls = []

    def collect(manager, declaration):
        calls.append((manager.root, declaration.name, dict(declaration.options)))

    register_extension("collector", "unit-sample", collect, replace=True)
    declaration = collector("unit-sample", answer=42)
    manager = CollectorManager(
        [declaration], root=tmp_path, pid_provider=dict,
        metric=lambda *args, **kwargs: None,
        event=lambda *args, **kwargs: None,
        namespace_provider=lambda: "",
    )
    manager._sample(declaration)
    assert calls == [(tmp_path, "unit-sample", {"answer": 42})]


def test_extension_registry_reports_duplicates_versions_and_missing_methods():
    registry = ExtensionRegistry()
    registry.register("backend", "example", _FullDriver())
    with pytest.raises(SpecError, match="already registered"):
        registry.register("backend", "example", _FullDriver())
    with pytest.raises(SpecError, match="supports version"):
        registry.register("backend", "v2", _FullDriver(), api_version=2)
    with pytest.raises(SpecError, match="must implement"):
        registry.register("backend", "broken", object())


def test_custom_case_backend_runs_through_the_complete_lifecycle(tmp_path):
    events = []

    class Backend:
        def validate(self, declaration):
            events.append("validate")

        def plan(self, context):
            events.append("plan")
            return {"portable": True}

        def prepare(self, context):
            events.append("prepare")

        def start(self, context):
            events.append("start")
            return context.run

        def stop(self, context):
            events.append("stop")

        def collect(self, context):
            events.append("collect")
            return {"events": list(events)}

    register_extension("backend", "unit-backend", Backend(), replace=True)

    @case(backend="unit-backend", observe=[], keep="always")
    def managed(run):
        pass

    manager = CaseManager(managed.__brixtest_case__, "unit::backend", root=tmp_path / "run")
    value = manager.start()
    assert isinstance(value, Run) and events == ["validate", "plan", "prepare", "start"]
    manager.set_outcome("passed")
    manager.close()
    assert events == ["validate", "plan", "prepare", "start", "stop", "collect"]
    assert any(
        item["name"] == "backend-result.json"
        for item in manager.evidence.snapshot()["artifacts"]
    )

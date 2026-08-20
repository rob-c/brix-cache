"""Contract tests for the composable 0.14 test-author surface."""

from __future__ import annotations

import ast
import dataclasses
import json
import sys
import pytest

from brixtest import (
    Command,
    Execution,
    Reference,
    CaseManager,
    client,
    ConfigSet,
    Endpoint,
    ExtensionRegistry,
    Lifecycle,
    LogPolicy,
    Mount,
    Placement,
    Probe,
    ResourceLimits,
    Service,
    command,
    collector,
    execution,
    configs,
    endpoint,
    exec_probe,
    http_endpoint,
    http_probe,
    mount,
    probe,
    server,
    server_config,
    case,
    register_extension,
    artifact_ref,
    binary,
    binary_ref,
    config_ref,
    credential,
    credential_ref,
    server_ref,
    text_artifact,
    tool,
)
from brixtest.errors import SpecError
from brixtest.fleet.probes import ExtensionProbe, probe_from_declaration
from brixtest.fleet.kinds import KindProfile, known_kinds, register_kind
from brixtest.fleet.registry import InstanceSpec, Registry, ServerEndpoint
from brixtest.config.lanes import Lane
from brixtest.deploy.local import LocalBackend
from brixtest.runtime.commands import CommandRunner
from brixtest.runtime.api import Run
from brixtest.runtime.kubernetes import server_resources
from brixtest.testing import assert_extension_contract
from brixtest.cli.main import main as cli_main
from brixtest.evidence.collectors import CollectorManager


def test_command_factory_accepts_vector_or_varargs_and_freezes_values():
    env = {"MODE": "test"}
    left = command("tool", "--flag", env=env, expected_exit_codes=(0, 7), retries=2)
    right = command(["tool", "--flag"])
    env["MODE"] = "changed"
    assert left.argv == right.argv == ("tool", "--flag")
    assert left.env == {"MODE": "test"}
    assert left.expected_exit_codes == (0, 7) and left.retries == 2


def test_execution_is_the_canonical_distinct_command_declaration():
    value = execution("reader", "--json", timeout=7)
    assert isinstance(value, Execution)
    assert isinstance(value, Command)
    assert type(command("reader")) is Command
    assert value.argv == ("reader", "--json") and value.timeout == 7


def test_tool_and_server_share_one_execution_vocabulary():
    invocation = execution("reader", "--url", server_ref("origin"), timeout=4)
    reader = tool("reader", execution=invocation)
    origin = server(
        "origin", execution=execution("origin", "--config", config_ref("origin.conf")),
        config=server_config("ready=true\n", "origin.conf"),
    )
    assert reader.execution == invocation
    assert origin.execution.argv == origin.command


def test_typed_reference_factories_are_explicit_and_placeholder_compatible():
    executable = binary("reader", sys.executable)
    payload = text_artifact("payload", "hello")
    proof = credential("proof", "signed")
    values = (
        artifact_ref(payload), binary_ref(executable), config_ref("conf.d/Origin.conf"),
        credential_ref(proof), server_ref("origin", role="http"),
    )
    assert all(isinstance(value, Reference) for value in values)
    assert [value.key for value in values] == [
        "artifact_payload", "binary_reader", "config_conf_d_Origin_conf",
        "credential_proof", "server_origin_http_url",
    ]
    assert [str(value) for value in values] == ["{%s}" % value.key for value in values]


@pytest.mark.parametrize("operation,field", [
    (lambda: Reference("unknown", "thing"), "reference.kind"),
    (lambda: Reference("artifact", "Bad"), "reference.name"),
    (lambda: Reference("server", "origin", "path"), "reference.attribute"),
    (lambda: Reference("artifact", "payload", role="http"), "reference.role"),
])
def test_typed_references_reject_ambiguous_or_invalid_targets(operation, field):
    with pytest.raises(SpecError, match=field):
        operation()


def test_case_positional_resources_infer_kinds_and_transitive_inputs():
    executable = binary("reader", sys.executable)
    payload = text_artifact("payload", "hello")
    proof = credential("proof", "secret")
    origin = server(
        "origin", binary=executable, config=server_config("ready=true\n"),
        mounts=[mount(payload, "inputs/payload"), mount(proof, "secure/proof")],
    )
    reader = tool("reader", command=[executable, "--version"])

    @case(origin, reader, observe=[])
    def managed(run):
        pass

    definition = managed.__brixtest_case__
    assert definition.servers == (origin,) and definition.tools == (reader,)
    assert definition.binaries == (executable,)
    assert definition.artifacts == (payload,) and definition.credentials == (proof,)


def test_cli_scaffolds_generic_and_nginx_cases_without_overwriting(tmp_path):
    assert cli_main(["--project", str(tmp_path), "new", "tests/test_feature.py"]) == 0
    generic = tmp_path / "tests/test_feature.py"
    ast.parse(generic.read_text())
    original = generic.read_text()
    assert cli_main(["--project", str(tmp_path), "new", "tests/test_feature.py"]) == 1
    assert generic.read_text() == original

    assert cli_main([
        "--project", str(tmp_path), "new", "tests/test_nginx.py", "--nginx",
    ]) == 0
    nginx = tmp_path / "tests/test_nginx.py"
    config = tmp_path / "tests/configs/nginx.conf.in"
    ast.parse(nginx.read_text())
    assert "server_ref(ORIGIN" in nginx.read_text()
    assert "listen {host}:{port}" in config.read_text()


def test_server_command_rejects_client_only_execution_policy():
    with pytest.raises(SpecError, match="server command policy"):
        server(
            "origin", command=command("origin", retries=1),
            config=server_config("ready=true\n"),
        )


def test_client_inherits_every_reusable_command_policy():
    declaration = client(
        "reader",
        command=command(
            "reader", input="request", encoding="latin-1", timeout=7,
            expected_exit_codes=(0, 4), output_limit=99, retries=2,
        ),
    )
    assert declaration.input == "request" and declaration.encoding == "latin-1"
    assert declaration.timeout == 7 and declaration.expected_exit_codes == (0, 4)
    assert declaration.output_limit == 99 and declaration.retries == 2


@pytest.mark.parametrize("field,value", [
    ("argv", []),
    ("argv", "shell command"),
    ("env", {"NAME": 3}),
    ("cwd", "../escape"),
    ("input", b"bytes"),
    ("encoding", ""),
    ("timeout", 0),
    ("expected_exit_codes", ()),
    ("output_limit", 0),
    ("mode", "shell"),
    ("retries", -1),
])
def test_command_rejects_invalid_policy_fields(field, value):
    values = {"argv": ("tool",), field: value}
    with pytest.raises(SpecError, match="command"):
        Command(**values)


def test_endpoint_factories_capture_transport_and_scheme():
    assert endpoint("rpc", protocol="udp", port=9000) == Endpoint("rpc", "udp", 9000)
    assert http_endpoint().scheme == "http"
    assert http_endpoint("admin", tls=True).scheme == "https"


@pytest.mark.parametrize("operation,field", [
    (lambda: endpoint("Bad"), "endpoint.name"),
    (lambda: endpoint(protocol="sctp"), "endpoint.protocol"),
    (lambda: endpoint(port=0), "endpoint.port"),
    (lambda: endpoint(scheme="1http"), "endpoint.scheme"),
    (lambda: endpoint(metadata=[]), "endpoint.metadata"),
])
def test_endpoint_security_boundaries_are_structured(operation, field):
    with pytest.raises(SpecError, match=field):
        operation()


def test_probe_factories_cover_builtin_readiness_kinds():
    assert probe().kind == "tcp"
    assert http_probe().kind == "http"
    assert http_probe(tls=True).kind == "https"
    assert exec_probe("tool", "ready").command == ("tool", "ready")
    assert probe("log", pattern="ready").kind == "log"


@pytest.mark.parametrize("values,field", [
    ({"kind": "Bad"}, "probe.kind"),
    ({"endpoint": "Bad"}, "probe.endpoint"),
    ({"timeout": 0}, "probe.timeout"),
    ({"interval": 0}, "probe.interval"),
    ({"path": "relative"}, "probe.path"),
    ({"kind": "exec", "command": ()}, "probe.command"),
    ({"statuses": (99,)}, "probe.statuses"),
    ({"pattern": 3}, "probe.pattern"),
])
def test_probe_rejects_malformed_fields(values, field):
    with pytest.raises(SpecError, match=field):
        Probe(**values)


def test_mount_factory_is_confined_and_immutable(tmp_path):
    value = mount(tmp_path / "source", "etc/server.conf", kind="path")
    assert value == Mount(tmp_path / "source", "etc/server.conf", True, "path")
    assert dataclasses.is_dataclass(value) and value.__dataclass_params__.frozen


@pytest.mark.parametrize("values,field", [
    ({"source": None, "target": "x"}, "mount.source"),
    ({"source": "x", "target": "/etc/x"}, "mount.target"),
    ({"source": "x", "target": "../x"}, "mount.target"),
    ({"source": "x", "target": "x", "read_only": 1}, "mount.read_only"),
    ({"source": "x", "target": "x", "kind": "device"}, "mount.kind"),
])
def test_mount_refuses_unsafe_or_ambiguous_declarations(values, field):
    with pytest.raises(SpecError, match=field):
        Mount(**values)


def test_resource_policies_are_composable_and_frozen():
    limits = ResourceLimits(cpu=1.5, memory_bytes=64 << 20, pids=32)
    placement = Placement(
        backend="kubernetes", image="example.test/server@sha256:" + "a" * 64,
        labels={"role": "origin"}, resources=limits,
    )
    lifecycle = Lifecycle(shutdown_signal="INT", shutdown_command=("ctl", "stop"))
    logs = LogPolicy(max_bytes=1024, tail_lines=5, redact=("secret",))
    assert placement.resources is limits and placement.labels == {"role": "origin"}
    assert lifecycle.shutdown_command == ("ctl", "stop")
    assert logs.redact == ("secret",)


def test_server_log_policy_bounds_and_redacts_before_archival(tmp_path):
    path = tmp_path / "server.log"
    path.write_text("old-data\n" * 20 + "token=secret\n")
    CaseManager._apply_log_policy(
        path, LogPolicy(max_bytes=80, redact=("secret",)),
    )
    content = path.read_text()
    assert "earlier log bytes omitted" in content
    assert "secret" not in content and "[REDACTED]" in content


@pytest.mark.parametrize("operation,field", [
    (lambda: ResourceLimits(cpu=0), "resources.cpu"),
    (lambda: ResourceLimits(memory_bytes=0), "resources.memory_bytes"),
    (lambda: ResourceLimits(pids=True), "resources.pids"),
    (lambda: Placement(backend="Unknown"), "placement.backend"),
    (lambda: Placement(labels={"x": 1}), "placement.labels"),
    (lambda: Lifecycle(shutdown_signal="HUP"), "shutdown_signal"),
    (lambda: Lifecycle(stop_timeout=0), "stop_timeout"),
    (lambda: LogPolicy(max_bytes=0), "logs.max_bytes"),
    (lambda: LogPolicy(tail_lines=-1), "logs.tail_lines"),
    (lambda: LogPolicy(redact=("",)), "logs.redact"),
])
def test_resource_policies_fail_at_declaration_time(operation, field):
    with pytest.raises(SpecError, match=field):
        operation()


def test_multi_config_set_selects_primary_and_server_endpoints():
    main = server_config("listen={port}\n", "main.conf")
    policy = server_config("allow=all\n", "conf.d/policy.conf", template=False)
    selected = configs(policy, main, primary="main.conf")
    declaration = server(
        "origin", command=["origin", "-c", "{config}"], configs=selected,
        endpoints=[http_endpoint()], probe=http_probe(),
    )
    assert isinstance(selected, ConfigSet) and selected.primary_file is main
    assert declaration.config is main and declaration.configs.files == (policy, main)
    assert declaration.ports == {"http": None}
    assert declaration.probe.endpoint == "http"


def test_multi_config_set_rejects_duplicates_and_unknown_primary():
    first = server_config("one", "same.conf")
    second = server_config("two", "same.conf")
    with pytest.raises(SpecError, match="destinations must be unique"):
        configs(first, second)
    with pytest.raises(SpecError, match="must name a declared"):
        configs(first, primary="missing.conf")


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
        [declaration], root=tmp_path, pid_provider=lambda: {},
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

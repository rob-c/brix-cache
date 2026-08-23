"""Tests for resources and extension contracts."""

from __future__ import annotations

import ast
import dataclasses
import sys

import pytest

from brixtest import (
    CaseManager,
    Command,
    ConfigSet,
    Endpoint,
    Execution,
    Lifecycle,
    LogPolicy,
    Mount,
    Placement,
    Probe,
    Reference,
    ResourceLimits,
    artifact_ref,
    binary,
    binary_ref,
    case,
    client,
    command,
    config_ref,
    configs,
    credential,
    credential_ref,
    endpoint,
    exec_probe,
    execution,
    http_endpoint,
    http_probe,
    mount,
    probe,
    server,
    server_config,
    server_ref,
    text_artifact,
    tool,
)
from brixtest.cli.main import main as cli_main
from brixtest.errors import SpecError


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

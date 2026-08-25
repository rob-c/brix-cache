"""Exhaustive contracts for BriXTest's stable test-author API."""

import dataclasses
import hashlib
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import brixtest
from brixtest import (  # noqa: F401 -- importing every public type is the contract
    Artifact,
    ArtifactProviderContext,
    AuthRecipe,
    BackendContext,
    Binary,
    BriXTestError,
    CapturedBinary,
    CaseDefinition,
    CaseManager,
    CaseRunError,
    Client,
    CollectorSpec,
    CommandResult,
    ConfigFile,
    ConfigTemplate,
    ConfiguredClient,
    ConfiguredTool,
    Credential,
    ExtensionRegistry,
    HelperProcessError,
    HostMapping,
    Isolation,
    KerberosAuth,
    MaterializedArtifact,
    MaterializedAuth,
    MaterializedCredential,
    MetricRecorder,
    MetricSample,
    MetricTimer,
    Readiness,
    Run,
    Server,
    Service,
    SpecError,
    TemplateError,
    TLSAuth,
    TokenAuth,
    ToolExecutionContext,
    ToolExecutionRequest,
    VOMSAuth,
)
from brixtest._api import (
    PUBLIC_METHODS,
)
from brixtest.clients.configured import ClientSpec

_VALUE_EXPORTS = {"GB", "GiB", "KB", "KiB", "MB", "MiB", "__version__"}

_PUBLIC_METHODS = {
    getattr(brixtest, name): set(members)
    for name, members in PUBLIC_METHODS.items()
}


def _visible_methods(value):
    return {
        name for name, member in inspect.getmembers(value)
        if not name.startswith("_")
        and name not in {"add_note", "with_traceback"}
        and (callable(member) or isinstance(member, property))
    }


def _call_shape(value, strip_owner=False):
    parameters = _visible_parameters(value, strip_owner)
    result = [_parameter_label(parameter) for parameter in parameters]
    boundary = _keyword_boundary(parameters)
    if boundary is not None:
        result.insert(boundary, "*")
    return tuple(result)


def _visible_parameters(value, strip_owner):
    return [
        parameter for parameter in inspect.signature(value).parameters.values()
        if not strip_owner or parameter.name not in ("self", "cls")
    ]


def _parameter_label(parameter):
    if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
        return "*" + parameter.name
    if parameter.kind is inspect.Parameter.VAR_KEYWORD:
        return "**" + parameter.name
    suffix = "?" if parameter.default is not inspect.Parameter.empty else ""
    return parameter.name + suffix


def _keyword_boundary(parameters):
    if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters):
        return None
    return next(
        (index for index, parameter in enumerate(parameters)
         if parameter.kind is inspect.Parameter.KEYWORD_ONLY),
        None,
    )
def test_case_decorator_produces_a_complete_immutable_definition():
    def body(run):
        return None

    decorated = brixtest.case(
        trials=2, warmup=1, backend="local", isolation=brixtest.process(),
        timeout=9, keep="always", observe=[],
    )(body)
    definition = brixtest.get_case(decorated)
    assert brixtest.is_case(decorated) and not brixtest.is_case(body.__name__)
    assert isinstance(definition, brixtest.CaseDefinition)
    assert (definition.trials, definition.warmup, definition.timeout) == (2, 1, 9)
    assert definition.backend == "local" and definition.keep == "always"
    assert definition.resource_names == {
        "servers": (), "clients": (), "artifacts": (), "binaries": (),
        "credentials": (), "auth": (), "hosts": (), "observe": (),
        "environments": (), "volumes": (), "identities": (), "tasks": (),
        "managed_resources": (),
    }
    assert json.loads(json.dumps(definition.as_dict()))["backend"] == "local"
    with pytest.raises(dataclasses.FrozenInstanceError):
        definition.timeout = 1
    with pytest.raises(SpecError, match=r"case\.trials"):
        dataclasses.replace(definition, trials=0)
    with pytest.raises(SpecError, match="decorated"):
        brixtest.get_case(lambda: None)


def test_readiness_and_service_cover_endpoint_config_and_log_access(tmp_path):
    config = tmp_path / "origin.conf"
    log = tmp_path / "origin.log"
    config.write_text("listen 43123\n")
    log.write_text("ready\n")
    service = Service(
        "origin", "127.0.0.1", {"http": 43123, "primary": 43123},
        config, log, tmp_path,
    )
    assert brixtest.tcp("http", timeout=3).kind == "tcp"
    assert brixtest.immediate().kind == "none"
    assert service.port("http") == 43123
    assert service.address("http") == ("127.0.0.1", 43123)
    assert service.url(role="http", path="status") == "http://127.0.0.1:43123/status"
    assert service.read_config() == "listen 43123\n"
    assert service.read_log() == "ready\n"
    assert json.loads(json.dumps(service.as_dict()))["ports"]["http"] == 43123
    assert dataclasses.replace(service, host="::1").url(path="health") \
        == "http://[::1]:43123/health"
    with pytest.raises(SpecError, match="declares"):
        service.port("missing")
    with pytest.raises(SpecError, match="URI scheme"):
        service.url("not a scheme")
    with pytest.raises(SpecError, match="TCP port"):
        dataclasses.replace(service, ports={"primary": 0})


def test_command_result_has_standard_and_fluent_output_helpers():
    result = CommandResult(("tool",), 0, "a\nb\n", "warn\n", 0.1)
    assert result.ok and result.args == ("tool",)
    assert result.output == "a\nb\nwarn\n"
    assert result.stdout_lines == ["a", "b"] and result.stderr_lines == ["warn"]
    assert json.loads(json.dumps(result.as_dict()))["ok"] is True
    assert CommandResult(("tool",), 0, '{"ok": true}', "", 0).json() == {"ok": True}
    with pytest.raises(SpecError, match="valid JSON"):
        result.json()
    assert result.check() is result and result.check_returncode() is None
    failed = CommandResult(("tool",), 7, "", "bad", 0.1)
    with pytest.raises(subprocess.CalledProcessError) as raised:
        failed.check()
    assert raised.value.stderr == "bad"
    for values in (
        ((), 0, "", "", 0), (("tool",), True, "", "", 0),
        (("tool",), 0, b"bytes", "", 0), (("tool",), 0, "", "", -1),
    ):
        with pytest.raises(SpecError):
            CommandResult(*values)


def test_configured_client_exposes_identity_timeout_command_and_text_output(tmp_path):
    client = ConfiguredClient(ClientSpec(
        "reader", (sys.executable, "-c", "print('hello')"), cwd=str(tmp_path), timeout=5,
    ), {})
    assert client.name == "reader" and client.timeout == 5
    assert client.command[0] == sys.executable
    result = client.run()
    assert isinstance(result, CommandResult) and result.stdout == "hello\n"
    assert client.cwd == tmp_path
    assert json.loads(json.dumps(client.as_dict()))["name"] == "reader"
    with pytest.raises(SpecError, match="timeout"):
        client.run(timeout=0)
    with pytest.raises(SpecError, match="must map strings"):
        client.run(env={"BAD": 1})
    with pytest.raises(SpecError, match="NUL-free"):
        client.run("bad\x00arg")


def test_metrics_cover_every_numeric_operation_timer_tags_snapshot_and_sink():
    events = []
    metrics = MetricRecorder(lambda event, row: events.append((event, dict(row))))
    gauge = metrics.gauge("queue.depth", 3, unit="items")
    metrics.count("requests", labels={"route": "read"})
    metrics.observe("latency", 0.2, unit="s")
    with metrics.timer("operation") as timer:
        pass
    metrics.tag("build", "asan")
    snapshot = metrics.snapshot()
    assert gauge.as_dict()["kind"] == "gauge"
    assert timer.elapsed >= 0 and len(snapshot["samples"]) == 4
    assert snapshot["tags"] == {"build": "asan"}
    replayed = []
    metrics.set_sink(lambda event, row: replayed.append(event), replay=True)
    assert replayed.count("metric") == 4 and replayed.count("tag") == 1
    assert {event for event, _ in events} == {"metric", "tag"}


def test_isolation_factories_cover_every_supported_backend(tmp_path):
    digest = "registry.test/brixtest@sha256:" + "a" * 64
    values = (
        brixtest.process(), brixtest.nsenter(12, namespaces=("mount", "net")),
        brixtest.docker(digest), brixtest.podman(digest), brixtest.runc(tmp_path),
        brixtest.kubernetes(digest),
    )
    assert [item.kind for item in values] == [
        "process", "nsenter", "docker", "podman", "runc", "kubernetes",
    ]
    assert all(isinstance(item, brixtest.Isolation) for item in values)
    assert "--brixtest-isolation" in values[0].cli_args()


def test_credential_factories_and_materialized_io_cover_all_public_forms(tmp_path):
    payload = brixtest.text_artifact("payload", "content")
    values = (
        brixtest.credential("plain", "secret"),
        brixtest.checksum_credential("checksum", payload),
        brixtest.signed_credential("signed", "scope", secret="key"),
    )
    assert [item.kind for item in values] == ["text", "checksum", "signed"]
    path = tmp_path / "credential"
    path.write_text("secret")
    materialized = MaterializedCredential(
        "plain", path, hashlib.sha256(b"secret").hexdigest(), "text",
        "credentials/plain", "TOKEN", "content",
        ("test",),
    )
    assert os.fspath(materialized) == str(path)
    assert materialized.content == materialized.read_text() == "secret"
    assert materialized.read_bytes() == b"secret"
    assert "secret" not in json.dumps(materialized.as_dict())
    assert materialized.verify()
    with materialized.open("r") as handle:
        assert handle.read() == "secret"
    path.write_text("tampered")
    assert not materialized.verify()


def test_auth_recipe_token_and_materialized_surfaces_are_complete(tmp_path):
    recipes = (
        brixtest.token_auth(), brixtest.tls_auth(), brixtest.voms_auth(),
        brixtest.kerberos_auth(),
    )
    assert [item.kind for item in recipes] == ["token", "tls", "voms", "kerberos"]
    token = brixtest.issue_token(
        secret="secret", issuer="https://issuer.test", audience="storage",
        subject="user", scopes=("read:/",), now=100, lifetime=50,
    )
    header, payload = brixtest.decode_token(token)
    assert header["alg"] == "HS256" and payload["scope"] == "read:/"
    assert brixtest.verify_token(
        token, secret="secret", issuer="https://issuer.test", audience="storage", now=101,
    )["sub"] == "user"
    token_path = tmp_path / "token"
    token_path.write_text(token)
    auth = MaterializedAuth(
        "token", "token", tmp_path, {"token": token_path},
        {"TOKEN": "test"}, {"TOKEN": "server"}, {"TOKEN": "client"}, {},
    )
    assert auth.path("token") == token_path
    assert auth.environment() == {"TOKEN": "test"}
    assert auth.environment("server") == {"TOKEN": "server"}
    serialized = json.dumps(auth.as_dict())
    assert '"TOKEN": "test"' not in serialized and "TOKEN" in serialized
    with pytest.raises(SpecError, match="must be test"):
        auth.environment("other")


def test_direct_token_api_rejects_claim_override_and_untyped_time_values():
    common = {
        "secret": "secret", "issuer": "https://issuer.test", "audience": "storage",
        "subject": "user", "now": 100,
    }
    with pytest.raises(SpecError, match="cannot override"):
        brixtest.issue_token(**common, claims={"exp": 999})
    with pytest.raises(SpecError, match="positive integer"):
        brixtest.issue_token(**common, lifetime=0)
    with pytest.raises(SpecError, match="JSON serializable"):
        brixtest.issue_token(**common, claims={"custom": object()})
    token = brixtest.issue_token(**common)
    with pytest.raises(SpecError, match="integer timestamp"):
        brixtest.verify_token(token, secret="secret", now=True)


def test_network_and_collector_factories_cover_every_public_kind():
    host = brixtest.host_mapping(
        "origin", "Origin.Test.", aliases=("Alias.Test.",), address="127.0.0.8",
    )
    assert host.hostnames == ("origin.test", "alias.test")
    collectors = (
        brixtest.process_tree(interval=0.1),
        brixtest.prometheus("{server_origin_url}/metrics", allow=("requests",)),
        brixtest.structured_logs("runtime/*.jsonl"),
        brixtest.kubernetes_events(),
        brixtest.collector("custom", option="value"),
    )
    assert [item.kind for item in collectors] == [
        "process", "prometheus", "structured-logs", "kubernetes", "plugin",
    ]
    assert all(isinstance(item, brixtest.CollectorSpec) for item in collectors)


def test_run_facade_delegates_every_resource_and_evidence_convenience(tmp_path):
    artifact_path = tmp_path / "artifact.txt"
    artifact_path.write_text('{"message": "hello"}')
    artifact = MaterializedArtifact(
        "message", artifact_path, artifact_path.stat().st_size,
        hashlib.sha256(artifact_path.read_bytes()).hexdigest(), "text",
    )
    binary = CapturedBinary("tool", Path(sys.executable), tmp_path, "b" * 64, ())
    credential_path = tmp_path / "credential"
    credential_path.write_text("proof")
    credential = MaterializedCredential(
        "proof", credential_path, "c" * 64, "text", "proof", None, "path", ("test",),
    )
    auth = MaterializedAuth("auth", "token", tmp_path, {}, {}, {}, {}, {})
    service = Service(
        "origin", "127.0.0.1", {"primary": 43123}, artifact_path,
        artifact_path, tmp_path,
    )
    client = ConfiguredClient(ClientSpec("reader", (sys.executable, "--version")), {})
    configured_tool = ConfiguredTool(
        ClientSpec("inspect", (sys.executable, "--version")), {},
    )
    calls = []

    class Commands:
        def run(self, *argv, **options):
            calls.append((argv, options))
            return CommandResult(tuple(str(item) for item in argv), 0, "ok", "", 0)

    class Store:
        def __init__(self, value):
            self.value = value
            self._items = {value.name: value}
            self._captured = self._items

        def get(self, name):
            calls.append(("get", name))
            return self.value

    class Evidence:
        def __init__(self):
            self.spans = SimpleNamespace(span=lambda name, **attrs: (name, attrs))

        def attach(self, path, **metadata):
            return {"path": path, **metadata}

        def attach_text(self, name, text, **metadata):
            return {"name": name, "text": text, **metadata}

        def attach_json(self, name, value, **metadata):
            return {"name": name, "value": value, **metadata}

    manager = SimpleNamespace(
        root=tmp_path, workspace=tmp_path, backend_name="local", metrics=MetricRecorder(),
        commands=Commands(), artifact_store=Store(artifact), binary_store=Store(binary),
        _services={"origin": service},
        _clients={"reader": client, "inspect": configured_tool},
        service=lambda name: service,
        client=lambda name: {
            "reader": client, "inspect": configured_tool,
        }[name],
            security=SimpleNamespace(
            credential=lambda name: credential, auth_stack=lambda name: auth,
            resolve=lambda hostname: "127.0.0.8", reverse=lambda address: "origin.test",
            credentials=SimpleNamespace(_items={"proof": credential}),
            auth=SimpleNamespace(_items={"auth": auth}),
            ),
            _managed=SimpleNamespace(volumes=SimpleNamespace(_items={}), tasks={}),
            _providers=SimpleNamespace(instances={}),
            evidence=Evidence(),
    )
    run = Run(manager)
    _assert_run_commands(run)
    _assert_run_clients(run, service, client, configured_tool)
    _assert_run_artifacts(run, artifact, artifact_path)
    _assert_run_resources(run, binary, credential, auth)
    _assert_run_evidence(run, artifact_path)
    _assert_run_collections(run)
    _assert_invalid_run_values(run)


def _assert_run_commands(run):
    observed = (
        run.command("tool", check=False).stdout,
        run.execute(brixtest.execution("tool", "--version")).stdout,
    )
    assert observed == ("ok", "ok")


def _assert_run_clients(run, service, client, configured_tool):
    assert (
        run.server("origin") is service,
        run.client("reader") is client,
        run.tool("inspect") is configured_tool,
    ) == (True, True, True)
    _assert_legacy_execution(run)
    _assert_client_compatibility(run, client)


def _assert_legacy_execution(run):
    with pytest.warns(DeprecationWarning, match="run.execute"):
        assert run.tool(brixtest.execution("tool"), check=False).stdout == "ok"


def _assert_client_compatibility(run, client):
    with pytest.warns(DeprecationWarning, match="compatibility path"):
        assert run.tool("reader") is client


def _assert_run_artifacts(run, artifact, artifact_path):
    observed = (
        run.artifact("message") is artifact,
        run.artifact_text("message"), run.artifact_bytes("message"),
        run.artifact_json("message"), run.artifact_file("message"),
        run.artifact_path("message"),
    )
    expected = (
        True, '{"message": "hello"}', b'{"message": "hello"}',
        {"message": "hello"}, artifact_path, artifact_path,
    )
    assert observed == expected
    with run.open_artifact("message", "r") as handle:
        assert handle.read() == '{"message": "hello"}'


def _assert_run_resources(run, binary, credential, auth):
    assert (
        run.binary("tool") is binary, run.credential("proof") is credential,
        run.auth("auth") is auth, run.resolve("origin.test"),
        run.reverse("127.0.0.8"),
    ) == (True, True, True, "127.0.0.8", "origin.test")


def _assert_run_evidence(run, artifact_path):
    assert (
        run.attach_text("x", "text")["text"],
        run.attach_json("x", {"ok": True})["value"],
        run.attach(artifact_path, role="output")["role"],
        run.step("transfer", bytes=5),
    ) == ("text", {"ok": True}, "output", ("transfer", {"bytes": 5}))


def _assert_run_collections(run):
    observed = (
        set(run.servers), set(run.clients), set(run.tools), set(run.artifacts),
        set(run.binaries), set(run.credentials), set(run.auth_stacks),
        set(run.volumes), set(run.tasks), set(run.resources),
        json.loads(json.dumps(run.as_dict()))["backend"],
    )
    expected = (
        {"origin"}, {"reader", "inspect"}, {"inspect"}, {"message"},
        {"tool"}, {"proof"}, {"auth"}, set(), set(), set(), "local",
    )
    assert observed == expected
    snapshot = run.servers
    snapshot.clear()
    assert set(run.servers) == {"origin"}


def _assert_invalid_run_values(run):
    for operation in (
        lambda: run.server([]), lambda: run.client(None), lambda: run.artifact(3),
        lambda: run.binary({}), lambda: run.credential(object()), lambda: run.auth(()),
        lambda: run.volume([]), lambda: run.task(None), lambda: run.resource({}),
        lambda: run.resolve(None), lambda: run.reverse(""),
    ):
        with pytest.raises(SpecError):
            operation()

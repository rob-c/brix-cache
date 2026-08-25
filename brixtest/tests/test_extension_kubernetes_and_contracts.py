"""Tests for Kubernetes extensions and runtime contracts."""

from __future__ import annotations

import dataclasses
import json
from types import SimpleNamespace

import pytest

from brixtest import (
    CommandResult,
    Placement,
    ResourceLimits,
    SpecError,
    ToolExecutionContext,
    ToolExecutionRequest,
    artifact,
    identity,
    register_extension,
    server,
    tool,
)
from brixtest.cli.metrics import _analyze, _export
from brixtest.runtime.artifacts import ArtifactProviderContext
from brixtest.runtime.executors import _tool_pod, tool_executor
from brixtest.runtime.kubernetes import _secret_environment, secure_secret_resource
from brixtest.testing import (
    check_case_backend_contract,
    check_executor_contract,
    check_provider_contract,
)


class _TextProvider:
    def __init__(self) -> None:
        self.seen = None

    def validate(self, declaration) -> None:
        self.seen = declaration

    def materialize(self, declaration, destination, context):
        assert declaration is self.seen
        assert context.root == destination.parent.resolve()
        return str(declaration.options["message"])



class _RecordingExecutor:
    def __init__(self) -> None:
        self.requests = []

    def validate(self, declaration) -> None:
        assert declaration.placement.backend == "unit-executor"

    def execute(self, context, request):
        self.requests.append((context, request))
        return CommandResult(request.argv, 0, "extension-output\n", "", 0.01)



def _request(tmp_path, *, backend="docker", env=None, resources=None):
    digest = "registry.test/tools@sha256:" + "a" * 64
    placement = Placement(
        backend=backend, image=digest,
        resources=resources or ResourceLimits(),
    )
    return ToolExecutionRequest(
        "reader", ("reader", "--json"), env or {"TOKEN": "sensitive"},
        tmp_path / "workspace", 5.0, None, (0,), 1024, "capture", 0,
        "utf-8", False, placement, digest,
    )



def test_kubernetes_tool_manifest_translates_resources_mounts_dns_and_security(tmp_path):
    request = dataclasses.replace(
        _request(
            tmp_path, backend="kubernetes",
            resources=ResourceLimits(cpu=1.5, memory_bytes=64 << 20),
        ),
        metadata={
            "secure_secret": "client-secure",
            "secure_items": ({"key": "file-0000", "path": "token"},),
            "secret_environment": {"BEARER_TOKEN": "file-0000"},
            "mount_secret": "client-mounts",
            "mount_items": ({"key": "file-0000", "path": "input"},),
            "temporary_mounts": ("scratch",),
            "host_aliases": ({"ip": "127.0.0.8", "hostnames": ["origin.test"]},),
        },
    )
    request = dataclasses.replace(
        request,
        placement=dataclasses.replace(
            request.placement,
            node_selector={"pool": "tests"},
            security_context={"runAsNonRoot": True},
        ),
    )
    manifest = _tool_pod("brixtest-reader", "brixtest-unit", request)
    spec = manifest["spec"]
    container = spec["containers"][0]
    bearer = next(item for item in container["env"] if item["name"] == "BEARER_TOKEN")
    observed = (
        container["command"], container["resources"]["limits"],
        container["securityContext"], bearer["valueFrom"]["secretKeyRef"],
        "sensitive" in json.dumps(bearer), spec["nodeSelector"],
        spec["hostAliases"][0]["hostnames"], {item["name"] for item in spec["volumes"]},
    )
    expected = (
        ["reader", "--json"], {"cpu": "1.5", "memory": str(64 << 20)},
        {"runAsNonRoot": True}, {"name": "client-secure", "key": "file-0000"},
        False, {"pool": "tests"}, ("origin.test",),
        {"workspace", "secure", "declared-mounts", "temporary-0"},
    )
    assert observed == expected


def test_kubernetes_tool_manifest_applies_declared_identity(tmp_path):
    runner = identity(
        "runner", uid=1001, gid=1002, groups=(1003,),
        capabilities=("net-bind-service",), permissions={"pods": ("get",)},
    )
    request = dataclasses.replace(
        _request(tmp_path, backend="kubernetes"), metadata={"identity": runner},
    )
    manifest = _tool_pod("brixtest-reader", "brixtest-unit", request)
    pod = manifest["spec"]
    assert pod["serviceAccountName"] == "brixtest-runner"
    assert pod["securityContext"] == {
        "runAsUser": 1001, "runAsGroup": 1002, "supplementalGroups": [1003],
    }
    capabilities = pod["containers"][0]["securityContext"]["capabilities"]
    assert capabilities == {"add": ["NET_BIND_SERVICE"]}


def test_kubernetes_content_credentials_use_secret_keys_not_plain_env(tmp_path):
    token = tmp_path / "access.token"
    token.write_text("secret-token")
    secret, items = secure_secret_resource(
        "brixtest-unit", {"auth/token/access.token": token},
    )
    mapped = _secret_environment(
        {"auth/token/access.token": token}, items,
        {"BEARER_TOKEN": "secret-token", "BEARER_TOKEN_FILE": "/secure/access.token"},
    )
    assert mapped == {"BEARER_TOKEN": "file-0000"}
    assert "secret-token" not in json.dumps(items)
    assert "secret-token" not in json.dumps(mapped)
    assert secret["data"]["file-0000"] != "secret-token"


@pytest.mark.parametrize("relative", ["../escape", "/absolute", ""])
def test_kubernetes_secret_projection_rejects_unconfined_paths(tmp_path, relative):
    source = tmp_path / "source"
    source.write_text("secret")
    with pytest.raises(SpecError, match="Kubernetes secret path"):
        secure_secret_resource("brixtest-unit", {relative: source})


def test_kubernetes_secret_projection_rejects_symlink_sources(tmp_path):
    source = tmp_path / "source"
    source.write_text("secret")
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(SpecError, match="non-symlink"):
        secure_secret_resource("brixtest-unit", {"credential": link})


def test_kubernetes_executor_accepts_pty_but_rejects_unportable_policy(tmp_path):
    executor = tool_executor("kubernetes")
    digest = "registry.test/tools@sha256:" + "a" * 64
    base = SimpleNamespace(
        name="reader", placement=Placement(backend="kubernetes", image=digest),
        command=(), binaries=(), mode="capture",
    )
    executor.validate(base)
    with pytest.raises(SpecError, match="digest pinned"):
        executor.validate(SimpleNamespace(**{**vars(base), "placement": Placement(backend="kubernetes", image="latest")}))
    executor.validate(SimpleNamespace(**{**vars(base), "mode": "pty"}))
    with pytest.raises(SpecError, match="PID limit"):
        executor.validate(SimpleNamespace(**{
            **vars(base),
            "placement": Placement(
                backend="kubernetes", image=digest,
                resources=ResourceLimits(pids=8),
            ),
        }))


def test_server_config_is_optional_but_still_captured_as_provenance():
    declaration = server("daemon", command=["daemon"])
    assert declaration.config.content == ""
    assert declaration.config.filename == "daemon.conf"
    assert declaration.metadata["brixtest.synthetic_config"] is True
    assert declaration.configs.primary_file is declaration.config
    direct = declaration.__class__("direct", ("daemon",))
    assert direct.config.filename == "direct.conf"
    assert direct.metadata["brixtest.synthetic_config"] is True


def test_client_and_tool_have_explicit_resource_identity():
    actor = tool("inspect", command=["inspect"])
    assert actor.resource_kind == "tool"
    assert actor.execution.argv == ("inspect",)
    from brixtest import client

    reader = client("reader", command=["reader"])
    assert reader.resource_kind == "client"


def test_metrics_analyzer_and_exporter_extensions_receive_json_options(tmp_path, capsys):
    calls = []

    def analyze(payload, context):
        calls.append(("analyze", payload, context))
        return {"score": context["options"]["confidence"]}

    def export(payload, destination, context):
        destination.write_text(json.dumps(payload))
        calls.append(("export", payload, context))
        return {"stored": True}

    register_extension("analyzer", "unit-analysis", analyze, replace=True)
    register_extension("exporter", "unit-export", export, replace=True)
    payload = {"aggregates": [{"name": "latency", "mean": 1.0}]}
    analyze_args = SimpleNamespace(
        plugin="unit-analysis", option=["confidence=0.99"], json=True,
    )
    assert _analyze(analyze_args, payload, tmp_path) == 0
    assert json.loads(capsys.readouterr().out) == {"score": 0.99}
    output = tmp_path / "export.json"
    export_args = SimpleNamespace(
        format="plugin", plugin="unit-export", option=["batch=10"],
        out=str(output), json=True,
    )
    assert _export(export_args, payload, tmp_path) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["result"] == {"stored": True} and output.is_file()
    assert [call[0] for call in calls] == ["analyze", "export"]


@pytest.mark.parametrize("kind", ["analyzer", "exporter"])
def test_metrics_extensions_reject_non_json_results(tmp_path, kind):
    register_extension(kind, "unit-invalid-result", lambda *args: {1, 2}, replace=True)
    args = SimpleNamespace(
        plugin="unit-invalid-result", option=[], json=True,
        format="plugin", out=str(tmp_path / "output"),
    )
    with pytest.raises(SpecError, match="must be JSON-safe"):
        (_analyze if kind == "analyzer" else _export)(args, {}, tmp_path)


def test_public_extension_contract_helpers_report_success_error_and_escape(tmp_path):
    provider = _TextProvider()
    declaration = artifact("contract", "unit-contract", message="ok")
    context = ArtifactProviderContext(tmp_path, tmp_path)
    assert check_provider_contract(
        provider, declaration, tmp_path / "contract.bin", context,
    ) == []

    class BadExecutor:
        def validate(self, declaration) -> None:
            pass

        def execute(self, context, request):
            return object()

    request = _request(tmp_path)
    assert check_executor_contract(
        BadExecutor(), SimpleNamespace(),
        ToolExecutionContext("unit::contract", tmp_path, tmp_path, "local"),
        request,
    ) == ["execute: must return brixtest.CommandResult"]

    class EscapingProvider:
        def validate(self, declaration) -> None:
            pass

        def materialize(self, declaration, destination, context):
            outside = tmp_path.parent / "outside-contract"
            outside.write_text("bad")
            return outside

    violations = check_provider_contract(
        EscapingProvider(), declaration, tmp_path / "unused", context,
    )
    assert "materialize: result escaped its confined root" in violations


def test_tool_request_and_context_reject_invalid_public_values(tmp_path):
    request = _request(tmp_path)
    assert request.cwd == tmp_path / "workspace"
    with pytest.raises(SpecError, match="output limit"):
        dataclasses.replace(request, output_limit=0)
    with pytest.raises(SpecError, match="expected exits"):
        dataclasses.replace(request, expected_exit_codes=())
    with pytest.raises(SpecError, match="metadata"):
        dataclasses.replace(request, metadata=[])
    with pytest.raises(SpecError, match="local_execute"):
        ToolExecutionContext("unit::bad", tmp_path, tmp_path, "local", local_execute=3)


def test_backend_contract_helper_requires_mapping_run_and_collection(tmp_path):
    run = SimpleNamespace(root=tmp_path, workspace=tmp_path, backend_name="local", metrics=None)

    class Backend:
        def validate(self, declaration) -> None:
            pass

        def plan(self, context):
            return []

        def prepare(self, context) -> None:
            pass

        def start(self, context):
            return object()

        def stop(self, context) -> None:
            pass

        def collect(self, context):
            return []

    violations = check_case_backend_contract(Backend(), object(), run)
    assert violations == [
        "plan: must return a mapping", "start: must return brixtest.Run",
        "collect: must return a mapping",
    ]

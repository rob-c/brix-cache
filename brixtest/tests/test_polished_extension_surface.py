"""Focused obligations for BriXTest 0.14's first-class extension surface."""

from __future__ import annotations

import dataclasses
import json
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import (
    CommandResult, Placement, ResourceLimits, SpecError, ToolExecutionContext,
    ToolExecutionRequest, artifact, case, execution, register_extension, server,
    tool,
)
from brixtest.cli.metrics import _analyze, _export
from brixtest.cli.main import main as cli_main
from brixtest.runtime.artifacts import ArtifactProviderContext, ArtifactStore
from brixtest.runtime.executors import _tool_pod, tool_executor
from brixtest.runtime.kubernetes import _secret_environment, secure_secret_resource
from brixtest.runtime.manager import CaseManager
from brixtest.testing import (
    check_case_backend_contract, check_executor_contract, check_provider_contract,
)
from brixtest.extensions import (
    Analyzer, CaseBackend, Collector, ENTRY_POINT_GROUPS, Exporter, ProbeDriver,
    ResourceProvider, ServerLauncher, ToolExecutor,
)


class _EntryPoints:
    def __init__(self, rows):
        self.rows = rows

    def select(self, *, group):
        return tuple(row for row in self.rows if row.group == group)


class _EntryPoint:
    def __init__(self, group, name, target):
        self.group = group
        self.name = name
        self.value = "external_package:extension"
        self.target = target

    def load(self):
        return self.target


def test_extension_protocols_and_entry_point_groups_are_complete():
    class Backend:
        def validate(self, declaration): pass
        def plan(self, context): return {}
        def prepare(self, context): pass
        def start(self, context): pass
        def stop(self, context): pass
        def collect(self, context): return {}

    class Probe:
        def validate(self, declaration): pass
        def wait(self, declaration, endpoint, timeout): pass

    class Launcher:
        def validate(self, declaration): pass
        def prepare(self, context, request): pass
        def cleanup(self, context, plan): pass

    assert isinstance(Backend(), CaseBackend)
    assert isinstance(_RecordingExecutor(), ToolExecutor)
    assert isinstance(_TextProvider(), ResourceProvider)
    assert isinstance(Probe(), ProbeDriver)
    assert isinstance(Launcher(), ServerLauncher)
    assert isinstance(lambda *args: None, (Collector, Analyzer, Exporter))
    assert set(ENTRY_POINT_GROUPS) == {
        "backend", "executor", "probe", "provider", "collector", "analyzer", "exporter",
        "launcher",
    }


class _TextProvider:
    def __init__(self) -> None:
        self.seen = None

    def validate(self, declaration) -> None:
        self.seen = declaration

    def materialize(self, declaration, destination, context):
        assert declaration is self.seen
        assert context.root == destination.parent.resolve()
        return str(declaration.options["message"])


def test_packaged_extension_discovery_is_lazy_versioned_and_refreshable(monkeypatch):
    from brixtest.extensions import ExtensionRegistry

    target = _RecordingExecutor()
    target.brixtest_api_version = 1
    target.brixtest_capabilities = ("remote", "capture")
    rows = [_EntryPoint("brixtest.executors", "external-executor", target)]
    monkeypatch.setattr(
        "brixtest.extensions.metadata.entry_points", lambda: _EntryPoints(rows),
    )
    registry = ExtensionRegistry()
    discovered = registry.discover()
    assert discovered[0].loaded is False
    assert registry.load("executor", "external-executor") is target
    info = registry.describe("executor")[0]
    assert info.loaded and info.capabilities == ("capture", "remote")
    refresh_registry = ExtensionRegistry()
    assert refresh_registry.discover()[0].loaded is False
    rows.clear()
    assert refresh_registry.discover(refresh=True) == ()


def test_packaged_extension_rejects_incompatible_or_malformed_metadata(monkeypatch):
    from brixtest.extensions import ExtensionInfo, ExtensionRegistry

    target = _RecordingExecutor()
    target.brixtest_api_version = 2
    target.brixtest_capabilities = ("capture",)
    rows = [_EntryPoint("brixtest.executors", "future-executor", target)]
    monkeypatch.setattr(
        "brixtest.extensions.metadata.entry_points", lambda: _EntryPoints(rows),
    )
    registry = ExtensionRegistry()
    with pytest.raises(SpecError, match="supports version 1"):
        registry.load("executor", "future-executor")
    with pytest.raises(SpecError, match="extension name"):
        registry.register("executor", "Invalid.Name", _RecordingExecutor())
    with pytest.raises(SpecError, match="capabilities"):
        ExtensionInfo("executor", "valid-name", capabilities=(["not-hashable"],))


def test_plugin_cli_lists_every_builtin_runtime_seam(capsys):
    assert cli_main(["--json", "plugins"]) == 0
    payload = json.loads(capsys.readouterr().out)
    rows = {(row["kind"], row["name"]) for row in payload["extensions"]}
    assert {
        ("backend", "local"), ("backend", "kubernetes"),
        ("backend", "minikube"),
        ("executor", "local"), ("executor", "kubernetes"),
        ("executor", "docker"), ("executor", "podman"),
        ("provider", "noise"), ("provider", "file"), ("provider", "text"),
        ("launcher", "process"), ("launcher", "docker"), ("launcher", "podman"),
    } <= rows


def test_custom_artifact_provider_materializes_through_the_real_store(tmp_path):
    provider = _TextProvider()
    register_extension("provider", "unit-generated", provider, replace=True)
    declaration = artifact(
        "generated", "unit-generated", filename="message.txt", message="hello",
    )
    store = ArtifactStore(tmp_path / "store", tmp_path)
    result = store.materialize_all((declaration,))["generated"]
    assert result.read_text() == "hello"
    assert result.verify() and provider.seen is declaration
    manifest = json.loads((tmp_path / "store" / "manifest.json").read_text())
    assert manifest["artifacts"]["generated"]["sha256"] == result.sha256


@pytest.mark.parametrize("result_kind", ["escape", "symlink", "invalid"])
def test_artifact_provider_output_is_confined_regular_and_typed(tmp_path, result_kind):
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")

    class Provider:
        def validate(self, declaration) -> None:
            pass

        def materialize(self, declaration, destination, context):
            if result_kind == "escape":
                return outside
            if result_kind == "symlink":
                destination.symlink_to(outside)
                return None
            return object()

    register_extension("provider", "unit-unsafe", Provider(), replace=True)
    declaration = artifact("unsafe", "unit-unsafe")
    with pytest.raises(SpecError, match="artifact provider result"):
        ArtifactStore(tmp_path / "store", tmp_path).materialize(declaration)


class _RecordingExecutor:
    def __init__(self) -> None:
        self.requests = []

    def validate(self, declaration) -> None:
        assert declaration.placement.backend == "unit-executor"

    def execute(self, context, request):
        self.requests.append((context, request))
        return CommandResult(request.argv, 0, "extension-output\n", "", 0.01)


def test_custom_executor_runs_a_first_class_tool_without_ambient_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BRIXTEST_UNIT_AMBIENT_SECRET", "do-not-copy")
    executor = _RecordingExecutor()
    register_extension("executor", "unit-executor", executor, replace=True)
    declaration = tool(
        "remote-tool", execution=execution("remote", "--check"),
        env={"DECLARED": "yes"}, placement=Placement(backend="unit-executor"),
    )

    @case(declaration, observe=[], keep="always")
    def managed(run):
        pass

    manager = CaseManager(
        managed.__brixtest_case__, "unit::custom-executor", root=tmp_path / "run",
    )
    run = manager.start()
    result = run.tool(declaration).run()
    manager.set_outcome("passed")
    manager.close()
    context, request = executor.requests[-1]
    assert result.stdout == "extension-output\n"
    assert request.env == {"DECLARED": "yes"}
    assert "BRIXTEST_UNIT_AMBIENT_SECRET" not in request.env
    assert context.nodeid == "unit::custom-executor"
    assert (tmp_path / "run" / "runtime" / "client-logs" / "remote-tool" / "0001.json").is_file()


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


def test_docker_executor_uses_mode_0600_env_file_and_never_secret_argv(tmp_path, monkeypatch):
    (tmp_path / "workspace").mkdir()
    observed = {}

    def completed(self, *argv, **options):
        argv = list(argv)
        env_file = Path(argv[argv.index("--env-file") + 1])
        observed["argv"] = tuple(argv)
        observed["env"] = env_file.read_text()
        observed["mode"] = stat.S_IMODE(env_file.stat().st_mode)
        return CommandResult(tuple(argv), 0, "ok\n", "", 0.01)

    monkeypatch.setattr("brixtest.runtime.executors.CommandRunner.run", completed)
    context = ToolExecutionContext(
        "unit::docker", tmp_path, tmp_path / "workspace", "local",
    )
    result = tool_executor("docker").execute(context, _request(tmp_path))
    assert result.stdout == "ok\n" and observed["mode"] == 0o600
    assert observed["env"] == "TOKEN=sensitive\n"
    assert "sensitive" not in observed["argv"]
    env_file = Path(observed["argv"][observed["argv"].index("--env-file") + 1])
    assert not env_file.exists()


def test_container_executor_rejects_unrepresentable_environment_before_spawn(
    tmp_path, monkeypatch,
):
    request = _request(tmp_path, env={"VALUE": "line-one\nline-two"})
    monkeypatch.setattr(
        "brixtest.runtime.executors.CommandRunner.run",
        lambda *args, **kwargs: pytest.fail("container runtime must not be invoked"),
    )
    context = ToolExecutionContext("unit::docker", tmp_path, tmp_path, "local")
    with pytest.raises(SpecError, match="newlines or NUL"):
        tool_executor("docker").execute(context, request)


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
    assert container["command"] == ["reader", "--json"]
    assert container["resources"]["limits"] == {"cpu": "1.5", "memory": str(64 << 20)}
    assert container["securityContext"] == {"runAsNonRoot": True}
    bearer = next(item for item in container["env"] if item["name"] == "BEARER_TOKEN")
    assert bearer["valueFrom"]["secretKeyRef"] == {
        "name": "client-secure", "key": "file-0000",
    }
    assert "sensitive" not in json.dumps(bearer)
    assert spec["nodeSelector"] == {"pool": "tests"}
    assert spec["hostAliases"][0]["hostnames"] == ("origin.test",)
    assert {item["name"] for item in spec["volumes"]} == {
        "workspace", "secure", "declared-mounts", "temporary-0",
    }


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


def test_kubernetes_executor_rejects_mutable_images_pty_and_unsupported_pid_limit(tmp_path):
    executor = tool_executor("kubernetes")
    digest = "registry.test/tools@sha256:" + "a" * 64
    base = SimpleNamespace(
        name="reader", placement=Placement(backend="kubernetes", image=digest),
        command=(), binaries=(), mode="capture",
    )
    executor.validate(base)
    with pytest.raises(SpecError, match="digest pinned"):
        executor.validate(SimpleNamespace(**{**vars(base), "placement": Placement(backend="kubernetes", image="latest")}))
    with pytest.raises(SpecError, match="capture or stream"):
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

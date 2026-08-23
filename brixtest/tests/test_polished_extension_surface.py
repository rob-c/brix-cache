"""Tests for the public extension API."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from brixtest import (
    CommandResult,
    Placement,
    ResourceLimits,
    SpecError,
    ToolExecutionContext,
    ToolExecutionRequest,
    artifact,
    case,
    execution,
    register_extension,
    tool,
)
from brixtest.cli.main import main as cli_main
from brixtest.extensions import (
    ENTRY_POINT_GROUPS,
    Analyzer,
    CaseBackend,
    Collector,
    Exporter,
    ProbeDriver,
    ResourceProvider,
    ServerLauncher,
    ToolExecutor,
)
from brixtest.runtime.artifacts import ArtifactStore
from brixtest.runtime.executors import tool_executor
from brixtest.runtime.manager import CaseManager


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


class _ContractBackend:
    def validate(self, declaration):
        pass

    def plan(self, context):
        return {}

    def prepare(self, context):
        pass

    def start(self, context):
        pass

    def stop(self, context):
        pass

    def collect(self, context):
        return {}


class _ContractProbe:
    def validate(self, declaration):
        pass

    def wait(self, declaration, endpoint, timeout):
        pass


class _ContractLauncher:
    def validate(self, declaration):
        pass

    def prepare(self, context, request):
        pass

    def cleanup(self, context, plan):
        pass


def test_extension_protocols_and_entry_point_groups_are_complete():
    assert isinstance(_ContractBackend(), CaseBackend)
    assert isinstance(_RecordingExecutor(), ToolExecutor)
    assert isinstance(_TextProvider(), ResourceProvider)
    assert isinstance(_ContractProbe(), ProbeDriver)
    assert isinstance(_ContractLauncher(), ServerLauncher)
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

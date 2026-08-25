"""Stable capability publication and adapter conformance contracts."""

import pytest

from brixtest.extensions import ExtensionRegistry, get_extension, installed_extensions
from brixtest.planning.capabilities import backend_capabilities
from brixtest.runtime.backends import case_backend
from brixtest.runtime.executors import tool_executor
from brixtest.runtime.filesystem import NativeFilesystem
from brixtest.runtime.images import OCIImageStore
from brixtest.runtime.launchers import server_launcher
from brixtest.testing import check_extension_capabilities


class _Executor:
    brixtest_api_version = 1
    brixtest_capabilities = ("execution.capture", "network.tcp")

    def validate(self, declaration):
        return None

    def execute(self, context, request):
        return None


def test_programmatic_registration_derives_declared_capabilities():
    registry = ExtensionRegistry()
    info = registry.register("executor", "unit", _Executor())
    assert info.capabilities == ("execution.capture", "network.tcp")


def test_capability_conformance_reports_missing_requirement():
    assert check_extension_capabilities(
        "executor", _Executor(), ("execution.capture",),
    ) == []
    assert check_extension_capabilities(
        "executor", _Executor(), ("execution.pty",),
    ) == ["capabilities: missing execution.pty"]


def test_capability_conformance_requires_version_and_declaration():
    assert check_extension_capabilities("executor", object()) == [
        "api_version: must equal 1",
    ]
    target = type("Target", (), {"brixtest_api_version": 1})()
    assert check_extension_capabilities("executor", target) == [
        "capabilities: must be declared",
    ]


@pytest.mark.parametrize("kind,name,target", [
    ("backend", "local", lambda: case_backend("local")),
    ("backend", "kubernetes", lambda: case_backend("kubernetes")),
    ("backend", "minikube", lambda: case_backend("minikube")),
    ("launcher", "process", lambda: server_launcher("process")),
    ("launcher", "docker", lambda: server_launcher("docker")),
    ("launcher", "podman", lambda: server_launcher("podman")),
    ("executor", "local", lambda: tool_executor("local")),
    ("executor", "docker", lambda: tool_executor("docker")),
    ("executor", "podman", lambda: tool_executor("podman")),
    ("executor", "kubernetes", lambda: tool_executor("kubernetes")),
    ("provider", "noise", lambda: get_extension("provider", "noise")),
    ("provider", "text", lambda: get_extension("provider", "text")),
    ("provider", "file", lambda: get_extension("provider", "file")),
])
def test_every_builtin_extension_has_versioned_capabilities(kind, name, target):
    selected = target()
    expected = backend_capabilities(name, kind)
    assert check_extension_capabilities(kind, selected, expected) == []
    info = next(item for item in installed_extensions(kind) if item.name == name)
    assert frozenset(info.capabilities) == expected


def test_builtin_transport_and_image_pipeline_publish_narrow_capabilities():
    assert check_extension_capabilities(
        "transport", NativeFilesystem,
        backend_capabilities("native-filesystem", "transport"),
    ) == []
    assert check_extension_capabilities(
        "image", OCIImageStore, backend_capabilities("oci", "image"),
    ) == []
    assert "execution.stdin" in backend_capabilities("kubernetes", "executor")
    assert "execution.pty" in backend_capabilities("kubernetes", "executor")
    assert "workload.task" not in backend_capabilities("process", "launcher")

"""Consumer-specific typed-reference projection contracts."""

from pathlib import Path

import pytest

from brixtest import (
    Placement,
    Service,
    binary,
    case,
    client,
    endpoint,
    server,
    task,
    text_artifact,
)
from brixtest.errors import SpecError
from brixtest.runtime.kubernetes import KubernetesCaseManager
from brixtest.runtime.manager import CaseManager


_IMAGE = "registry.test/runtime@sha256:" + "a" * 64


def _definition(*resources, backend="kubernetes"):
    @case(*resources, backend=backend, observe=())
    def declared(run):
        return None

    return declared.__brixtest_case__


def _manager(tmp_path, *resources):
    return CaseManager(
        _definition(*resources), "references::consumer", root=tmp_path / "run",
    )


def test_kubernetes_named_endpoint_references_use_cluster_dns(tmp_path):
    origin = server(
        "origin", command=("/server",), image=_IMAGE,
        endpoints=(
            endpoint("primary", scheme="http"),
            endpoint("admin", scheme="https"),
        ),
    )
    manager = _manager(tmp_path, origin)
    backend = KubernetesCaseManager.from_manager(manager)
    values, _secure = backend._case_values(
        (origin,), {"origin": {"primary": 18000, "admin": 18001}},
    )
    assert values["server_origin_admin_host"] == "origin"
    assert values["server_origin_admin_url"] == "https://origin:18001"
    assert manager._render_part(
        origin.url("admin"), values, "consumer reference",
    ) == "https://origin:18001"


def test_controller_consumer_uses_forwarded_service_not_cluster_address(tmp_path):
    origin = server("origin", command=("/server",), image=_IMAGE)
    manager = _manager(tmp_path, origin)
    manager._services["origin"] = Service(
        "origin", "127.0.0.1", {"primary": 39001},
        tmp_path / "origin.conf", tmp_path / "origin.log", tmp_path / "origin",
        schemes={"primary": "http"}, protocols={"primary": "tcp"},
    )
    values = manager._global_values({})
    assert values["server_origin_host"] == "127.0.0.1"
    assert values["server_origin_url"] == "http://127.0.0.1:39001/"


def test_kubernetes_server_binary_reference_resolves_to_image_path(tmp_path):
    executable = binary(
        "server-bin", image=_IMAGE, image_path="/opt/bin/server",
    )
    origin = server(
        "origin", command=("/launcher",), image=_IMAGE,
        env={"SERVER_BINARY": executable.ref()},
    )
    manager = _manager(tmp_path, executable, origin)
    backend = KubernetesCaseManager.from_manager(manager)
    backend._generated_binary_paths = {}
    common, _secure = backend._case_values(
        (origin,), {"origin": {"primary": 18000}},
    )
    values = backend._server_values(origin, common, {"primary": 18000})
    assert backend._render_server_environment(
        origin, values, Path("/brixtest/secure"),
    )["SERVER_BINARY"] == "/opt/bin/server"


def test_kubernetes_server_artifact_reference_is_projected(tmp_path):
    payload = text_artifact("payload", "content")
    origin = server(
        "origin", command=("/server",), image=_IMAGE,
        env={"PAYLOAD": payload.ref()},
    )
    manager = _manager(tmp_path, payload, origin)
    manager.artifact_store.materialize_all((payload,))
    backend = KubernetesCaseManager.from_manager(manager)
    backend._generated_binary_paths = {}
    values = backend._server_values(origin, {}, {"primary": 18000})
    files, _temporary, _managed = backend._mount_files(origin, (), values)
    assert values["artifact_payload"].as_posix().startswith(
        "/brixtest/mounts/auto/artifacts/payload/"
    )
    assert next(iter(files.values())).read_text() == "content"


def test_kubernetes_legacy_artifact_dir_placeholder_is_projected(tmp_path):
    payload = text_artifact("payload", "content")
    origin = server(
        "origin", command=("/server",), image=_IMAGE,
        env={"PAYLOAD_DIR": "{artifact_payload_dir}"},
    )
    manager = _manager(tmp_path, payload, origin)
    manager.artifact_store.materialize_all((payload,))
    backend = KubernetesCaseManager.from_manager(manager)
    backend._generated_binary_paths = {}
    values = backend._server_values(origin, {}, {"primary": 18000})
    files, _temporary, _managed = backend._mount_files(origin, (), values)
    assert values["artifact_payload_dir"].as_posix().startswith(
        "/brixtest/mounts/auto/artifacts/payload"
    )
    assert next(iter(files.values())).read_text() == "content"


def test_kubernetes_client_rejects_host_only_binary_before_mutation(tmp_path):
    executable = binary("reader", tmp_path / "reader")
    reader = client(
        "reader", command=("/launcher",), env={"READER": executable.ref()},
        placement=Placement(backend="kubernetes", image=_IMAGE),
    )
    root = tmp_path / "run"
    with pytest.raises(SpecError, match="require image_path"):
        CaseManager(
            _definition(executable, reader), "references::host-path", root=root,
        )
    assert not root.exists()


def test_kubernetes_task_rejects_unprojected_artifact_before_mutation(tmp_path):
    payload = text_artifact("payload", "content")
    prepare = task(
        "prepare", command=("/prepare", payload.ref()),
        placement=Placement(backend="kubernetes", image=_IMAGE),
    )
    root = tmp_path / "run"
    with pytest.raises(SpecError, match="provider-backed mount"):
        CaseManager(
            _definition(payload, prepare), "references::task-artifact", root=root,
        )
    assert not root.exists()


def test_missing_consumer_representation_has_a_precise_error(tmp_path):
    payload = text_artifact("payload", "content")
    manager = _manager(tmp_path, payload)
    with pytest.raises(SpecError, match="consuming resource's environment"):
        manager._render_part(payload.ref(), {}, "consumer reference")

"""Deterministic local-binary to Minikube image pipeline contracts."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import CapturedBinary, CommandResult, SpecError, binary, server
from brixtest.runtime.images import OCIImageStore
from brixtest.runtime.kubernetes_images import prepare_server_images
from brixtest.runtime.kubernetes_manifests import server_resources
from brixtest.pytest_profile import validate_profile


class _Evidence:
    def __init__(self):
        self.events = []
        self.attachments = []

    def event(self, name, value):
        self.events.append((name, value))

    def attach_json(self, name, value, **metadata):
        self.attachments.append((name, value, metadata))


class _Commands:
    def __init__(self):
        self.calls = []

    def run(self, *argv, **options):
        self.calls.append((argv, options))
        stdout = ""
        if argv[:3] == ("docker", "image", "inspect"):
            stdout = json.dumps([{
                "Id": "sha256:" + "b" * 64,
                "RootFS": {"Layers": ["sha256:" + "c" * 64]},
            }])
        return CommandResult(tuple(argv), 0, stdout, "", 0.01)


def _captured(tmp_path: Path, name: str = "nginx") -> CapturedBinary:
    tmp_path.mkdir(parents=True, exist_ok=True)
    executable = tmp_path / name
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    library_dir = tmp_path / "lib"
    library_dir.mkdir()
    return CapturedBinary(name, executable, library_dir, digest, ())


def _owner(tmp_path):
    return SimpleNamespace(
        root=tmp_path / "run", commands=_Commands(), evidence=_Evidence(),
    )


def test_image_store_builds_content_addressed_rootfs_sbom_and_loads_minikube(tmp_path):
    owner = _owner(tmp_path)
    item = OCIImageStore(owner, "brixtest").build(
        "origin", (_captured(tmp_path),),
    )
    _assert_generated_image(item)
    _assert_image_commands_and_evidence(owner)


def _assert_generated_image(item):
    assert item.tag.startswith("brixtest.local/origin:sha256-")
    assert item.paths == {"nginx": "/opt/brixtest/bin/nginx"}
    assert item.image_id == "sha256:" + "b" * 64
    assert item.layers == ("sha256:" + "c" * 64,)
    assert len(item.files[0]["sha256"]) == 64
    assert (item.context / "Dockerfile").read_text() == (
        "FROM scratch\nCOPY rootfs/ /\nENV LD_LIBRARY_PATH=/opt/brixtest/lib\n"
    )
    assert (item.context / "rootfs/opt/brixtest/bin/nginx").read_bytes().startswith(b"#!")


def _assert_image_commands_and_evidence(owner):
    commands = [row[0] for row in owner.commands.calls]
    _assert_image_commands(commands)
    _assert_image_evidence(owner.evidence)


def _assert_image_commands(commands):
    assert any(row[:4] == ("docker", "build", "--pull=false", "--network=none") for row in commands)
    assert any(row[:4] == ("minikube", "--profile", "brixtest", "image") for row in commands)


def _assert_image_evidence(evidence):
    assert set(evidence.events[0][1]["tool_versions"]) == {"docker", "minikube"}
    assert evidence.events[0][0] == "generated-oci-image"
    assert evidence.attachments[0][1]["sbom"][0]["path"].endswith("/nginx")


def test_image_store_reuses_identical_capture_without_rebuilding(tmp_path):
    owner = _owner(tmp_path)
    store = OCIImageStore(owner, "brixtest")
    captured = _captured(tmp_path)
    assert store.build("origin", (captured,)) is store.build("other", (captured,))
    assert sum(call[0][:2] == ("docker", "build") for call in owner.commands.calls) == 1


def test_image_store_rejects_dockerfile_injection_and_unsafe_binary_name(tmp_path):
    owner = _owner(tmp_path)
    store = OCIImageStore(owner, "brixtest")
    with pytest.raises(SpecError, match="generated image base"):
        store.build("origin", (_captured(tmp_path),), base_image="busybox\nRUN bad")
    unsafe = _captured(tmp_path / "other", name="unsafe")
    object.__setattr__(unsafe, "name", "../unsafe")
    with pytest.raises(SpecError, match="safe BriXTest binary name"):
        OCIImageStore(_owner(tmp_path / "unsafe"), "brixtest").build("origin", (unsafe,))


def test_server_manifest_accepts_only_content_addressed_generated_tag():
    declaration = server("origin", command=("/opt/brixtest/bin/nginx",))
    tag = "brixtest.local/origin:sha256-" + "a" * 64
    documents = server_resources(
        declaration, namespace="case", command=declaration.command, env={},
        ports={"primary": 8080}, config_text="", image=tag,
        image_pull_policy="Never",
    )
    container = next(row for row in documents if row["kind"] == "Deployment")[
        "spec"
    ]["template"]["spec"]["containers"][0]
    assert (container["image"], container["imagePullPolicy"]) == (tag, "Never")
    with pytest.raises(SpecError, match="content-addressed image"):
        server_resources(
            declaration, namespace="case", command=declaration.command, env={},
            ports={"primary": 8080}, config_text="", image="latest",
        )


def test_remote_kubernetes_rejects_local_binary_before_image_build(tmp_path):
    declared = binary("nginx", tmp_path / "nginx")
    captured = _captured(tmp_path)
    owner = _owner(tmp_path)
    owner.backend_name = "kubernetes"
    owner.binary_store = SimpleNamespace(get=lambda name: captured)
    backend = SimpleNamespace(owner=owner, context="remote")
    origin = server("origin", command=(declared,))
    with pytest.raises(SpecError, match="configured BriXTest OCI registry"):
        prepare_server_images(backend, (origin,))
    assert owner.commands.calls == []


def test_remote_kubernetes_pushes_capture_to_configured_registry(
    tmp_path, monkeypatch,
):
    digest = "registry.test/base@sha256:" + "d" * 64
    monkeypatch.setenv("BRIXTEST_OCI_REGISTRY", "registry.test/team")
    monkeypatch.setenv("BRIXTEST_OCI_BASE_IMAGE", digest)
    declared = binary("nginx", tmp_path / "nginx")
    captured = _captured(tmp_path)
    owner = _owner(tmp_path)
    owner.backend_name = "kubernetes"
    owner.binary_store = SimpleNamespace(get=lambda name: captured)
    backend = SimpleNamespace(owner=owner, context="remote")

    images, paths = prepare_server_images(
        backend, (server("origin", command=(declared,)),),
    )

    _assert_registry_capture(owner, images, paths, digest)


def _assert_registry_capture(owner, images, paths, digest):

    assert images["origin"].startswith("registry.test/team/origin:sha256-")
    assert paths["origin"] == {"nginx": "/opt/brixtest/bin/nginx"}
    image_root = next((owner.root / "runtime/images").iterdir())
    assert (image_root / "Dockerfile").read_text().startswith("FROM " + digest)
    commands = [row[0] for row in owner.commands.calls]
    assert ("docker", "push") in [row[:2] for row in commands]
    assert "minikube" not in [row[0] for row in commands]
    assert owner.evidence.events[0][1]["delivery"] == "registry-push"


def test_image_profile_rejects_mutable_base_and_unsafe_registry():
    with pytest.raises(SpecError, match="digest-pinned"):
        validate_profile({"images": {"base_image": "python:latest"}})
    with pytest.raises(SpecError, match="registry host"):
        validate_profile({"images": {"registry": "https://registry.test/team"}})


def test_explicit_digest_pinned_server_image_is_preserved():
    image = "registry.test/server@sha256:" + "e" * 64
    declaration = server("origin", command=("/server",), image=image)
    documents = server_resources(
        declaration, namespace="case", command=declaration.command, env={},
        ports={"primary": 8080}, config_text="",
    )
    container = next(row for row in documents if row["kind"] == "Deployment")[
        "spec"
    ]["template"]["spec"]["containers"][0]
    assert container["image"] == image
    assert container["imagePullPolicy"] == "IfNotPresent"

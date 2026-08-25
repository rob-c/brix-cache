"""Cross-backend contracts for the public service filesystem facade."""

from __future__ import annotations

import os
import subprocess

import pytest

from brixtest import Placement, identity, server
from brixtest.errors import SpecError
from brixtest.runtime.filesystem import ServiceFilesystem
from brixtest.runtime.filesystem_remote import RemoteFilesystem
from brixtest.runtime.kubernetes_manifests import server_resources

_SERVER_IMAGE = "registry.test/server@sha256:" + "a" * 64
_HELPER_IMAGE = "registry.test/helper@sha256:" + "b" * 64


def _remote(root, observed=None) -> ServiceFilesystem:
    callback = None if observed is None else lambda operation, payload: observed.append(
        (operation, payload),
    )
    return ServiceFilesystem(RemoteFilesystem(
        ("env",), (str(root),), observer=callback, timeout=5.0,
    ))


def _deployment(documents):
    return next(item for item in documents if item["kind"] == "Deployment")


def test_remote_transport_supports_the_complete_binary_safe_facade(tmp_path):
    observed = []
    filesystem = _remote(tmp_path, observed)
    filesystem.mkdir("state")
    filesystem.write_bytes("state/payload", b"\x00\xffBriX")
    assert filesystem.read_bytes("state/payload") == b"\x00\xffBriX"
    assert filesystem.read_text("state/payload", errors="replace").endswith("BriX")
    assert filesystem.list("state") == ("payload",)
    assert filesystem.stat("state/payload")["size"] == 6
    filesystem.chmod("state/payload", 0o640)
    filesystem.chown("state/payload", -1, os.getgid())
    filesystem.symlink("payload", "state/alias")
    assert filesystem.stat("state/alias", follow_symlinks=False)["is_symlink"] is True
    filesystem.setxattr("state/payload", "user.brixtest", b"\x00attribute")
    assert filesystem.getxattr("state/payload", "user.brixtest") == b"\x00attribute"
    assert "user.brixtest" in filesystem.listxattr("state/payload")
    filesystem.removexattr("state/payload", "user.brixtest")
    filesystem.remove("state", recursive=True)
    assert observed[-1][0] == "remove"
    assert observed[1][1]["sha256"]


def test_remote_transport_rejects_errors_and_escape_attempts(tmp_path):
    filesystem = _remote(tmp_path)
    with pytest.raises(SpecError, match="escapes"):
        filesystem.read_bytes("../outside")
    with pytest.raises(SpecError, match="must remain"):
        filesystem.symlink("/etc/passwd", "escape")
    with pytest.raises(SpecError, match="cannot mutate a service root"):
        filesystem.remove(".", recursive=True)
    with pytest.raises(SpecError, match=r"user\.\*"):
        filesystem.getxattr("missing", "security.invalid")
    with pytest.raises(SpecError, match="FileNotFoundError"):
        filesystem.read_bytes("missing")


def test_remote_transport_rejects_unframed_backend_output(tmp_path, monkeypatch):
    monkeypatch.setattr(
        subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, b"not-a-frame", b"bad"),
    )
    with pytest.raises(SpecError, match="invalid framing"):
        _remote(tmp_path).read_bytes("payload")


def test_kubernetes_manifest_adds_a_restricted_shared_volume_sidecar():
    runner = identity(
        "runner", uid=1200, gid=1300, groups=(1400,), capabilities=("chown",),
    )
    origin = server(
        "origin", command=("/server",), image=_SERVER_IMAGE,
        placement=Placement(backend="kubernetes", identity=runner),
    )
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="", identity=runner,
        filesystem_image=_HELPER_IMAGE,
    )
    pod = _deployment(documents)["spec"]["template"]["spec"]
    server_container, helper = pod["containers"]
    assert helper["name"] == "brixtest-filesystem"
    assert helper["image"] == _HELPER_IMAGE
    assert helper["volumeMounts"] == server_container["volumeMounts"]
    assert helper["securityContext"]["readOnlyRootFilesystem"] is True
    assert helper["securityContext"]["allowPrivilegeEscalation"] is False
    assert helper["securityContext"]["capabilities"] == {
        "drop": ["ALL"], "add": ["CHOWN"],
    }
    assert pod["securityContext"] == {
        "runAsUser": 1200, "runAsGroup": 1300, "supplementalGroups": [1400],
    }


def test_kubernetes_filesystem_helper_requires_an_immutable_image():
    origin = server("origin", command=("/server",), image=_SERVER_IMAGE)
    with pytest.raises(SpecError, match="immutable image digest"):
        server_resources(
            origin, namespace="case", command=("/server",), env={},
            ports={"primary": 18000}, config_text="",
            filesystem_image="registry.test/helper:latest",
        )

"""Explicit physical libc/NSS mapping contracts."""

import pytest

from brixtest import Placement, docker, execution, host_mapping, process, server
from brixtest.errors import SpecError
from brixtest.isolation import build_launch
from brixtest.runtime.launchers import ServerLaunchContext, ServerLaunchRequest, server_launcher


def _launch(tmp_path, isolation, mapping):
    control = tmp_path / "control"
    control.mkdir()
    return build_launch(
        isolation, ("python3", "-m", "pytest"), {}, cwd=tmp_path,
        readonly_roots=(tmp_path,), writable_root=tmp_path,
        control_dir=control, validate_executable=False,
        host_aliases=(mapping,),
    )


def test_libc_mapping_rejects_process_isolation_before_launch(tmp_path):
    mapping = host_mapping("origin", "origin.test", libc=True, targets=("test",))
    with pytest.raises(SpecError, match="Docker, Podman, or Kubernetes"):
        _launch(tmp_path, process(), mapping)


def test_libc_mapping_rejects_unrepresentable_forward_only_policy():
    with pytest.raises(SpecError, match="forward-only"):
        host_mapping("origin", "origin.test", reverse=False, libc=True)


def test_framework_only_mapping_is_not_silently_promoted_to_container_nss(tmp_path):
    mapping = host_mapping("origin", "origin.test")
    launch = _launch(
        tmp_path, docker("example/image@sha256:" + "a" * 64), mapping,
    )
    assert "--add-host" not in launch.argv


def test_libc_mapping_validates_consumer_roles():
    with pytest.raises(SpecError, match="server, client, or test"):
        host_mapping("origin", "origin.test", libc=True, targets=("unknown",))
    with pytest.raises(SpecError, match="at least one consumer"):
        host_mapping("origin", "origin.test", libc=True, targets=())


def test_managed_container_server_receives_server_targeted_aliases(tmp_path, monkeypatch):
    mapping = host_mapping(
        "origin", "origin.test", address="127.0.0.9", aliases=("alias.test",),
        libc=True, targets=("server",),
    )
    declaration = server(
        "origin", execution=execution("daemon"), placement=Placement(
            backend="docker", image="example/server@sha256:" + "a" * 64,
        ),
    )
    request = ServerLaunchRequest(
        declaration, ("daemon",), {}, tmp_path, host_aliases=(mapping,),
    )
    context = ServerLaunchContext("unit::hosts", tmp_path, tmp_path / "workspace")
    monkeypatch.setattr("brixtest.runtime.launchers.shutil.which", lambda _: "/usr/bin/docker")

    argv = server_launcher("docker").prepare(context, request).argv
    assert "origin.test:127.0.0.9" in argv
    assert "alias.test:127.0.0.9" in argv

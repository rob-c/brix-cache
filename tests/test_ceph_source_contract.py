"""Live Ceph drivers follow the canonical client graph instead of stale lists."""

import subprocess
import shlex

import pytest

from cmdscripts import ceph_sources
from cmdscripts import ceph_operator


def test_real_ceph_source_graph_contains_complete_backend_and_rescue_closures():
    """Both new batch operations and shared name translation reach every driver."""
    core = ceph_sources.backend_sources()
    assert "src/fs/backend/rados/sd_ceph_batch.c" in core
    assert "src/fs/path/site_n2n.c" in core
    assert "src/fs/backend/rados/sd_ceph_striper.c" not in core
    cephfs = ceph_sources.backend_sources(cephfs=True)
    assert set(core) < set(cephfs)
    assert "src/fs/backend/rados/sd_cephfs_ro.c" in cephfs
    assert len(cephfs) == len(set(cephfs))


def test_failed_make_cannot_supply_a_partial_ceph_source_graph(monkeypatch):
    """A broken graph query must fail rather than compiling fewer functions."""
    monkeypatch.setattr(ceph_sources, "client_make", lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 2, "CEPH_CORE_SRCS=partial", "bad graph"))
    with pytest.raises(subprocess.CalledProcessError):
        ceph_sources.backend_sources()


def test_source_graph_cannot_copy_paths_outside_the_repository():
    """Even a plausible C suffix cannot turn metadata into an arbitrary host copy."""
    with pytest.raises(ValueError):
        ceph_sources._sources_from_metadata("CEPH_CORE_SRCS=/outside/fixture.c", "CEPH_CORE_SRCS")
    with pytest.raises(ValueError, match="did not report"):
        ceph_sources._sources_from_metadata("", "CEPH_CORE_SRCS")


@pytest.mark.parametrize("legacy,expected", [(None, "fixture-cluster"),
                                           ("legacy-cluster", "legacy-cluster")])
def test_credential_oracle_uses_the_harness_cluster_name(monkeypatch, tmp_path, legacy, expected):
    """Custom cluster names must not silently turn the credential test into a skip."""
    monkeypatch.setenv("CEPH_CONTAINER", "fixture-cluster")
    monkeypatch.setenv("WORK", "fixture-work")
    monkeypatch.delenv("DEMO", raising=False)
    if legacy is not None:
        monkeypatch.setenv("DEMO", legacy)
    names = []
    monkeypatch.setattr(ceph_operator, "_need_docker", lambda: (True, ""))

    def running(name):
        names.append(name)
        return name == "fixture-work"

    monkeypatch.setattr(ceph_operator, "_container_running", running)
    ceph_operator.sd_ceph_cred_live(tmp_path)
    assert names == ["fixture-work", expected]


def test_native_driver_command_preserves_literal_path_arguments(monkeypatch):
    """Shell metacharacters in a caller path must remain one quoted argument."""
    monkeypatch.setattr(ceph_sources, "backend_sources", lambda _: ["src/fixture.c"])
    output = "/tmp/fixture output; inert-command"
    command = shlex.split(ceph_sources.driver_command("tests/fixture.c", output))
    assert command[-2:] == ["-o", output]
    assert command.count("&&") == 1

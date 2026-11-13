import os
from contextlib import contextmanager
from types import SimpleNamespace
import uuid

import pytest

from cmdscripts import ceph_harness


@contextmanager
def _owned_ceph_lifecycle(monkeypatch, directory):
    """A suite job owns its lab and always releases its host-network sockets."""
    with monkeypatch.context() as environment:
        environment.setenv('CEPH_CONTAINER', 'brix-ceph-lifecycle-' + uuid.uuid4().hex)
        environment.setenv('CEPH_DIR', str(directory))
        environment.setenv('CEPH_POOL', 'brix-lifecycle')
        try:
            yield
        finally:
            if ceph_harness.cmd_stop() != 0:
                raise RuntimeError('could not remove the owned Ceph lifecycle lab')


def test_ceph_harness_commands_are_importable():
    assert set(ceph_harness.COMMANDS) == {"start", "stop", "status", "env", "pool-reset"}
    assert ceph_harness.cidr_net("192.168.65.3/24") == "192.168.65.0/24"
    assert ceph_harness.cidr_ip("192.168.65.3/24") == "192.168.65.3"


def _require_ceph_runtime():
    """Retain the live lab's existing explicit opt-out and runtime checks."""
    if os.environ.get("PHASE81_RUN_CEPH_PORTS") == "0":
        pytest.skip("PHASE81_RUN_CEPH_PORTS=0 set — skipping the Docker Ceph harness")
    if not ceph_harness.have_docker():
        pytest.skip("docker not found")
    # Rootless podman/docker can exist on PATH yet be unable to RUN containers
    # for this user (no subuid/subgid mapping, no session runtime dir).  The
    # harness's own probe distinguishes that: it must yield a CIDR before the
    # lab can start, so treat a dead probe as "no usable container runtime".
    if not os.environ.get("MON_IP") and not ceph_harness.detect_container_cidr():
        pytest.skip("container runtime cannot run containers as this user "
                    "(rootless subuid/subgid missing?) — Docker Ceph lab unavailable")


@pytest.mark.optin
@pytest.mark.suite_job
@pytest.mark.timeout(600)
def test_ceph_harness_lifecycle(monkeypatch, tmp_path):
    """Run start/env/status/reset, then release this suite job's owned lab.

    Cold image pulls and single-OSD placement-group startup retain the original
    600-second budget. The CLI's separately invoked start command stays persistent.
    """
    _require_ceph_runtime()
    with _owned_ceph_lifecycle(monkeypatch, tmp_path / 'ceph'):
        assert ceph_harness.cmd_start() == 0
        assert ceph_harness.cmd_env() == 0
        assert ceph_harness.cmd_status() == 0
        assert ceph_harness.cmd_pool_reset() == 0


def _assert_private_lifecycle_environment(directory):
    """Require private identities before exercising success or failed work."""
    owned = ceph_harness.ceph_container()
    assert owned.startswith('brix-ceph-lifecycle-')
    assert ceph_harness.ceph_dir() == directory
    assert ceph_harness.ceph_pool() == 'brix-lifecycle'
    return owned


@pytest.fixture
def lifecycle_cleanup(monkeypatch):
    """Observe container removal while retaining a foreign ambient identity."""
    monkeypatch.setenv('CEPH_CONTAINER', 'foreign-lab')
    monkeypatch.setenv('CEPH_DIR', '/foreign-credentials')
    removed = []
    monkeypatch.setattr(ceph_harness, '_docker', lambda arguments:
        removed.append(arguments) or SimpleNamespace(returncode=0))
    return removed


def _assert_foreign_lab_preserved(removed, owned):
    """Teardown addresses exactly the private lab and restores ambient paths."""
    assert removed == [['rm', '-f', owned]]
    assert ceph_harness.ceph_container() == 'foreign-lab'
    assert ceph_harness.ceph_dir().as_posix() == '/foreign-credentials'


def test_lifecycle_releases_only_its_private_lab(monkeypatch, tmp_path, lifecycle_cleanup):
    """Successful test work releases its lab without touching foreign resources."""
    with _owned_ceph_lifecycle(monkeypatch, tmp_path):
        owned = _assert_private_lifecycle_environment(tmp_path)
    _assert_foreign_lab_preserved(lifecycle_cleanup, owned)


def test_failed_lifecycle_still_releases_only_its_private_lab(
        monkeypatch, tmp_path, lifecycle_cleanup):
    """An assertion failure cannot leak the monitor into the next CI phase."""
    with pytest.raises(ValueError, match='test operation failed'):
        with _owned_ceph_lifecycle(monkeypatch, tmp_path):
            owned = _assert_private_lifecycle_environment(tmp_path)
            raise ValueError('test operation failed')
    _assert_foreign_lab_preserved(lifecycle_cleanup, owned)


def test_lifecycle_cleanup_failure_cannot_pass(monkeypatch, tmp_path):
    """Failed owned teardown must remain a failed suite job."""
    monkeypatch.setattr(ceph_harness, '_docker', lambda _arguments:
        SimpleNamespace(returncode=7, stderr='owned container removal failed'))
    with pytest.raises(RuntimeError, match='could not remove the owned'):
        with _owned_ceph_lifecycle(monkeypatch, tmp_path):
            pass

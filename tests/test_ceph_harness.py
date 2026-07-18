import os

import pytest

from cmdscripts import ceph_harness


def test_ceph_harness_commands_are_importable():
    assert set(ceph_harness.COMMANDS) == {"start", "stop", "status", "env", "pool-reset"}
    assert ceph_harness.cidr_net("192.168.65.3/24") == "192.168.65.0/24"
    assert ceph_harness.cidr_ip("192.168.65.3/24") == "192.168.65.3"


@pytest.mark.optin
@pytest.mark.timeout(600)
def test_ceph_harness_lifecycle():
    """Opt-in Docker lab lifecycle: start -> env -> status -> pool-reset.

    Deliberately leaves the demo container running (like the shell harness);
    stop it with `python3 -m cmdscripts.ceph_harness stop`.

    Overrides the 30s global default: a cold start pulls/boots the demo
    MON/MGR/OSD and waits for HEALTH, and pool-reset recreates 32 PGs against a
    single-OSD cluster still settling -- comfortably past 30s on the first run.
    """
    if os.environ.get("PHASE81_RUN_CEPH_PORTS") == "0":
        pytest.skip("PHASE81_RUN_CEPH_PORTS=0 set — skipping the Docker Ceph harness")
    if not ceph_harness.have_docker():
        pytest.skip("docker not found")
    assert ceph_harness.cmd_start() == 0
    assert ceph_harness.cmd_env() == 0
    assert ceph_harness.cmd_status() == 0
    assert ceph_harness.cmd_pool_reset() == 0

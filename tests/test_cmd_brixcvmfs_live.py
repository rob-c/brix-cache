"""Collector for the brixMount/brixcvmfs/scvmfs live scenario ports.

Every scenario mounts FUSE or contacts live upstreams. They run by default;
set PHASE81_RUN_LIVE_PORTS=0 to skip them. The importability test always runs.
"""

import os

import pytest

from cmdscripts import brixcvmfs_live


def test_brixcvmfs_live_scenarios_are_importable():
    assert set(brixcvmfs_live.SCENARIOS) == {
        "mount-cvmfs-live",
        "brixmount-live",
        "brixcvmfs-live",
        "atlas-live",
        "clever-live",
        "overlay",
        "scvmfs",
    }
    assert all(callable(fn) for fn in brixcvmfs_live.SCENARIOS.values())


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(brixcvmfs_live.SCENARIOS))
def test_brixcvmfs_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip FUSE-mounting/live-network brixcvmfs ports")
    try:
        rc = brixcvmfs_live.SCENARIOS[scenario]()
    except brixcvmfs_live.LiveSkip as exc:
        pytest.skip(str(exc))
    assert rc == 0

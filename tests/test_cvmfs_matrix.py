"""Collector for the CVMFS comparison-matrix scenario ports.

matrix and netem-lab need root plus ip/tc (network-namespace netem lab);
spike-cas-hash contacts a real Stratum-1; cvmfs-baselines needs squid or
varnish installed. They run by default; set PHASE81_RUN_LIVE_PORTS=0 to skip
them. The importability test always runs.
"""

import os

import pytest

from cmdscripts import cvmfs_matrix
from cmdscripts.brixcvmfs_live import LiveSkip


def test_cvmfs_matrix_scenarios_are_importable():
    assert set(cvmfs_matrix.SCENARIOS) == {
        "matrix",
        "cvmfs-baselines",
        "spike-cas-hash",
        "netem-lab",
    }
    assert all(callable(fn) for fn in cvmfs_matrix.SCENARIOS.values())
    assert set(cvmfs_matrix.NETEM_PROFILES) == {"clean", "loss", "reorder", "corrupt", "jitter", "site"}


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(cvmfs_matrix.SCENARIOS))
def test_cvmfs_matrix_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip the netem/live-network CVMFS matrix ports")
    try:
        rc = cvmfs_matrix.SCENARIOS[scenario]()
    except LiveSkip as exc:
        pytest.skip(str(exc))
    assert rc == 0

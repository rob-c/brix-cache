"""Pytest wrapper for the remote cache/stage tier live scenarios.

`cmdscripts/tier_remote.py` was reachable only by hand (audit §3): it is the only
coverage of a cache node whose STORE is itself remote (root://) — remote stage
flush, remote eviction + refill, remote cinfo metadata in both xattr and sidecar
mode, and sparse slice fills.
"""

import os

import pytest

from cmdscripts import tier_remote
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-tier_remote")


def test_tier_remote_scenarios_are_importable():
    assert set(tier_remote.SCENARIOS) == {
        "remote-stage",
        "remote-evict",
        "remote-store",
        "sidecar-meta",
        "slice-fill",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(tier_remote.SCENARIOS))
def test_tier_remote_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    assert tier_remote.SCENARIOS[scenario](NGINX_BIN) == 0

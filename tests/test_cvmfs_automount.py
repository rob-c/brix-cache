"""Collector for the brixMount autofs automount-umbrella live scenarios.

Every scenario mounts FUSE (umbrella + nested child mounts). They run by
default; set PHASE81_RUN_LIVE_PORTS=0 to skip them. The importability test
always runs.
"""

import os

import pytest

from cmdscripts import brixautofs_live


def test_brixautofs_live_scenarios_are_importable():
    assert set(brixautofs_live.SCENARIOS) == {"automount", "automount-strict"}
    assert all(callable(fn) for fn in brixautofs_live.SCENARIOS.values())


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(brixautofs_live.SCENARIOS))
def test_brixautofs_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip FUSE-mounting brixautofs ports")
    try:
        rc = brixautofs_live.SCENARIOS[scenario]()
    except brixautofs_live.LiveSkip as exc:
        pytest.skip(str(exc))
    assert rc == 0

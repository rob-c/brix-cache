import os
from pathlib import Path

import pytest

from cmdscripts import tier_stage_live


def test_tier_stage_live_are_importable():
    assert set(tier_stage_live.SCENARIOS) == {
        "root-slice-fill",
        "root-stage-writeback",
        "stage-async-remote-flush",
        "tier-instance-lifetime",
    }


@pytest.mark.optin
@pytest.mark.parametrize("scenario", sorted(tier_stage_live.SCENARIOS))
def test_tier_stage_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") != "1":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=1 to run live port scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    for client in tier_stage_live.CLIENT_REQUIREMENTS[scenario]:
        if not client.exists():
            pytest.skip(f"client binary not built: {client}")
    assert tier_stage_live.SCENARIOS[scenario](nginx) == 0

import os
from pathlib import Path

import pytest

from cmdscripts import gsi_trust_live

pytestmark = pytest.mark.xdist_group("cmd-gsi_trust_live")


def test_gsi_trust_live_are_importable():
    assert set(gsi_trust_live.SCENARIOS) == {
        "csi-trust",
        "delegation-upload",
        "gsi-intermediate-ca",
        "gsi-store-memo",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(gsi_trust_live.SCENARIOS))
def test_gsi_trust_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live GSI/trust scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    assert gsi_trust_live.SCENARIOS[scenario](nginx) == 0

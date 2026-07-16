import os
from pathlib import Path

import pytest

from cmdscripts import pblock_live


def test_pblock_live_are_importable():
    assert set(pblock_live.SCENARIOS) == {
        "pblock-meta-gsi",
        "pblock-root",
        "pblock-webdav",
        "pblock-writethrough",
    }


@pytest.mark.optin
@pytest.mark.parametrize("scenario", sorted(pblock_live.SCENARIOS))
def test_pblock_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") != "1":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=1 to run live port scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    for client in pblock_live.CLIENT_REQUIREMENTS[scenario]:
        if not client.exists():
            pytest.skip(f"client binary not built: {client}")
    assert pblock_live.SCENARIOS[scenario](nginx) == 0

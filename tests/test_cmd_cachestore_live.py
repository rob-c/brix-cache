import os
from pathlib import Path

import pytest

from cmdscripts import cachestore_live

pytestmark = pytest.mark.xdist_group("cmd-cachestore_live")


def test_cachestore_live_are_importable():
    assert set(cachestore_live.SCENARIOS) == {
        "cache-xroot-webdav-offload",
        "cachestore-sidecar",
        "xroot-cachestore-serve",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(cachestore_live.SCENARIOS))
def test_cachestore_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    for client in cachestore_live.CLIENT_REQUIREMENTS[scenario]:
        if not client.exists():
            pytest.skip(f"client binary not built: {client}")
    assert cachestore_live.SCENARIOS[scenario](nginx) == 0

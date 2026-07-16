import os
from pathlib import Path

import pytest

from cmdscripts import tap_proxy_live


def test_tap_proxy_live_are_importable():
    assert set(tap_proxy_live.SCENARIOS) == {
        "proxy-env-live",
        "tap-proxy",
        "tap-proxy-gsi",
        "tap-proxy-gsi-hybrid",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(tap_proxy_live.SCENARIOS))
def test_tap_proxy_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") != "1":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=1 to run live tap-proxy scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if scenario != "proxy-env-live" and not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    assert tap_proxy_live.SCENARIOS[scenario](nginx) == 0

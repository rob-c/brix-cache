import os
from pathlib import Path

import pytest

from cmdscripts import cache_passthrough

def _check_test_cache_passthrough_scenario_1(nginx, scenario):
    assert cache_passthrough.SCENARIOS[scenario](nginx) == 0


pytestmark = pytest.mark.xdist_group("cmd-cache_passthrough")


def test_cache_passthrough_scenarios_are_importable():
    assert set(cache_passthrough.SCENARIOS) == {"serve-evict", "disabled-declines"}


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(cache_passthrough.SCENARIOS))
def test_cache_passthrough_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    for client in cache_passthrough.CLIENT_REQUIREMENTS[scenario]:
        if not client.exists():
            pytest.skip(f"client binary not built: {client}")
    _check_test_cache_passthrough_scenario_1(nginx, scenario)

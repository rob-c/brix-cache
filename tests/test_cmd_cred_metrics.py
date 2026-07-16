import os
from pathlib import Path

import pytest

from cmdscripts import cred_metrics


def test_cred_metrics_scenarios_are_importable():
    assert set(cred_metrics.SCENARIOS) == {"counters"}


@pytest.mark.optin
@pytest.mark.timeout(300)
@pytest.mark.parametrize("scenario", sorted(cred_metrics.SCENARIOS))
def test_cred_metrics_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") != "1":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=1 to run live credential-metrics scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    rc = cred_metrics.SCENARIOS[scenario](nginx)
    if rc == cred_metrics.SKIP:
        pytest.skip("scenario prerequisites unavailable (see stdout for the SKIP reason)")
    assert rc == 0

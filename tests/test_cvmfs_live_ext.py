import os
from pathlib import Path

import pytest

from cmdscripts import cvmfs_live_ext

pytestmark = pytest.mark.xdist_group("cmd-cvmfs_live_ext")


def test_cvmfs_live_ext_is_importable():
    assert set(cvmfs_live_ext.SCENARIOS) == {
        "bench",
        "brix-all",
        "evict",
        "faultproxy-bench",
        "holdopen",
        "logging",
        "proxy",
        "resilience",
        "reverse",
        "select",
        "selectlog",
        "stock",
        "unified-origin",
        "upstream-metrics",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(cvmfs_live_ext.SCENARIOS))
def test_cvmfs_live_ext_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live cvmfs scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    try:
        rc = cvmfs_live_ext.SCENARIOS[scenario](nginx)
    except cvmfs_live_ext.LiveSkip as exc:
        pytest.skip(str(exc))
    assert rc == 0

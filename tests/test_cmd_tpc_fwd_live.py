"""Collector for the TPC credential-forwarding live scenario ports.

Python ports of run_tpc_fwd_root.sh, run_tpc_fwd_webdav.sh, and
run_tpc_delegation_nginx.sh (tests/cmdscripts/tpc_fwd_live.py).  The live
scenarios spin up real nginx/xrootd fleets and run by default; set
PHASE81_RUN_LIVE_PORTS=0 to skip them.
"""

import os
from pathlib import Path

import pytest

from cmdscripts import tpc_fwd_live


def test_tpc_fwd_live_is_importable():
    assert set(tpc_fwd_live.SCENARIOS) == {
        "tpc-fwd-root",
        "tpc-fwd-webdav",
        "tpc-delegation-nginx",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(tpc_fwd_live.SCENARIOS))
def test_tpc_fwd_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live TPC forwarding scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not os.access(tpc_fwd_live.BRIX_XRDCP, os.X_OK):
        pytest.skip(f"repo xrdcp not built: {tpc_fwd_live.BRIX_XRDCP}")
    assert tpc_fwd_live.SCENARIOS[scenario](nginx) == 0

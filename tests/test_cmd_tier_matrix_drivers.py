"""Pytest wrapper for the stage_store driver-matrix live scenario.

`cmdscripts/tier_matrix_drivers.py` was reachable only by hand (audit §3): it
drives the same stage-then-flush PUT through every writable stage_store driver
(posix, pblock, xroot; rados when BRIX_TEST_RADOS_POOL names a pool), which is
the only cross-driver comparison of that path.
"""

import os

import pytest

from cmdscripts import tier_matrix_drivers
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-tier_matrix_drivers")


def test_tier_matrix_drivers_is_importable():
    assert callable(tier_matrix_drivers.run_port)


@pytest.mark.optin
@pytest.mark.timeout(900)
def test_tier_matrix_drivers_flow():
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    assert tier_matrix_drivers.run_port(NGINX_BIN) == 0

"""Pytest wrapper for the CVMFS fill-verification live scenario.

`cmdscripts/cvmfs_verify.py` was reachable only by hand (audit §3): it is the
only end-to-end proof that a corrupted origin fill is refused (502), quarantined
and counted, that a clean retry still succeeds — and, as the security-negative
half, that `brix_cvmfs_verify off` DOES admit and then re-serve the corruption,
which is why the default must stay on.
"""

import os

import pytest

from cmdscripts import cvmfs_verify
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-cvmfs_verify")


def test_cvmfs_verify_is_importable():
    assert callable(cvmfs_verify.run_port)


@pytest.mark.optin
@pytest.mark.timeout(600)
def test_cvmfs_verify_flow():
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    assert cvmfs_verify.run_port(NGINX_BIN) == 0

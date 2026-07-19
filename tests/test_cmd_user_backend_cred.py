import os
from pathlib import Path

import pytest

from cmdscripts import user_backend_cred


def test_user_backend_cred_scenarios_are_importable():
    assert set(user_backend_cred.SCENARIOS) == {
        "base",
        "root",
        "ns",
        "p2",
        "multiuser-authz",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(user_backend_cred.SCENARIOS))
def test_user_backend_cred_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live per-user credential scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if scenario == "multiuser-authz":
        # This scenario re-drives the ENTIRE multi-user authz suite (14 test_mu_*
        # modules) as a NESTED pytest — minutes of work, and the fast lane's worst
        # hang.  It duplicates its own dedicated lane (tests/run_multiuser_authz.sh),
        # so it must never run inline in the parallel fast lane: skip unless root
        # AND explicitly opted in.
        if os.geteuid() != 0:
            pytest.skip("multiuser-authz requires root (real accounts + setfsuid)")
        if os.environ.get("PHASE81_RUN_MULTIUSER") != "1":
            pytest.skip("multiuser-authz drives the heavy nested mu suite — set "
                        "PHASE81_RUN_MULTIUSER=1 (or use run_multiuser_authz.sh) to run it")
    rc = user_backend_cred.SCENARIOS[scenario](nginx)
    if rc == user_backend_cred.SKIP:
        pytest.skip("scenario prerequisites unavailable (see stdout for the SKIP reason)")
    assert rc == 0

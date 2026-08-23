import os
import shutil

import pytest

from cmdscripts import dashboard_demo_live


def _guard_test_dashboard_demo_live_flow_1():
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip the live dashboard demo")

def _guard_test_dashboard_demo_live_flow_2():
    if shutil.which("xrdcp") is None:
        pytest.skip("xrdcp not found (install xrootd-client)")

def _guard_test_dashboard_demo_live_flow_3(gateway_up, startable):
    if not gateway_up and not startable:
        pytest.skip("no gateway on :11094 and no prepared /tmp/xrd-test config to start one")

def _check_test_dashboard_demo_live_flow_1():
    assert dashboard_demo_live.demo(live_minutes=float(os.environ.get("LIVE_MINUTES", "1"))) == 0


def test_dashboard_demo_scenarios_are_importable():
    assert set(dashboard_demo_live.SCENARIOS) == {"demo"}
    assert callable(dashboard_demo_live.throttled_put)
    assert callable(dashboard_demo_live.throttled_get)
    assert callable(dashboard_demo_live.generate)


@pytest.mark.optin
@pytest.mark.timeout(600)
def test_dashboard_demo_live_flow():
    _guard_test_dashboard_demo_live_flow_1()
    _guard_test_dashboard_demo_live_flow_2()
    gateway_up = dashboard_demo_live._listening(dashboard_demo_live.ROOT_PORT)
    startable = (
        dashboard_demo_live.NGINX_BIN.exists()
        and dashboard_demo_live.TEST_CONF.is_file()
        and dashboard_demo_live.TEST_PKI_CERT.is_file()
    )
    _guard_test_dashboard_demo_live_flow_3(gateway_up, startable)
    # Keep the sustained-traffic window short under pytest; the demo leaves a
    # detached generator running for LIVE_MINUTES by design.
    _check_test_dashboard_demo_live_flow_1()

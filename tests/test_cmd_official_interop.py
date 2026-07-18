import os
import shutil
import socket

import pytest

from cmdscripts import official_interop


def test_official_interop_scenarios_are_importable():
    assert set(official_interop.SCENARIOS) == {
        "all",
        "cross-compatible",
        "host",
        "noauth",
        "stress",
    }


def _fleet_anon_listening() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", official_interop.anon_port()), timeout=1):
            return True
    except OSError:
        return False


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", ["noauth", "host", "stress"])
def test_official_interop_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip official interop live scenarios")
    missing = official_interop._missing_tools()
    if missing:
        pytest.skip(f"XRootD client tools missing: {', '.join(missing)}")
    if not _fleet_anon_listening():
        pytest.skip(f"no nginx anon listener on :{official_interop.anon_port()}")
    assert official_interop.SCENARIOS[scenario]() == 0


@pytest.mark.optin
@pytest.mark.timeout(600)
def test_cross_compatible_lanes():
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip the cross-compatible pytest lanes")
    if shutil.which("xrootd") is None:
        pytest.skip("stock xrootd server not installed (needed for the xrootd backend lane)")
    assert official_interop.cross_compatible() == 0

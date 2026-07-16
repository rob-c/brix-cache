import os
from pathlib import Path

import pytest

from cmdscripts import system_live_ports


def test_system_live_ports_are_importable():
    assert set(system_live_ports.SCENARIOS) == {
        "cache-af-family",
        "io-uring-backend",
        "ktls",
        "proxy-metadata-phase",
    }


@pytest.mark.optin
@pytest.mark.parametrize("scenario", sorted(system_live_ports.SCENARIOS))
def test_system_live_port_scenario(scenario: str):
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    assert system_live_ports.SCENARIOS[scenario](nginx) == 0

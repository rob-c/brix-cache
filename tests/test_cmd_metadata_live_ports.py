import os
from pathlib import Path

import pytest

from cmdscripts import metadata_live_ports


def test_metadata_live_ports_are_importable():
    assert set(metadata_live_ports.SCENARIOS) == {
        "nonstaged-reap",
        "sd-s3-meta",
        "xfer-audit-sink",
        "xmeta",
    }


def test_metadata_live_ports_owns_one_unique_port_per_listener():
    assert len(metadata_live_ports._PORTS) == 4
    assert len(set(metadata_live_ports._PORTS)) == 4


@pytest.mark.optin
@pytest.mark.parametrize("scenario", sorted(metadata_live_ports.SCENARIOS))
def test_metadata_live_port_scenario(scenario: str):
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if scenario != "xmeta" and not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    assert metadata_live_ports.SCENARIOS[scenario](nginx) == 0

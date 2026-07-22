import os
from pathlib import Path

import pytest

from cmdscripts import tape_live

pytestmark = pytest.mark.xdist_group("cmd-tape_live")


def test_tape_live_are_importable():
    assert set(tape_live.SCENARIOS) == {
        "s3-tape-residency",
        "tape-exec-adapter",
        "tape-recall-async",
        "tape-recall-stream",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(tape_live.SCENARIOS))
def test_tape_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    for client in tape_live.CLIENT_REQUIREMENTS[scenario]:
        if not client.exists():
            pytest.skip(f"client binary not built: {client}")
    assert tape_live.SCENARIOS[scenario](nginx) == 0

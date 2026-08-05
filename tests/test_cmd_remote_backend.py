"""Pytest wrapper for the remote-backend (pass-through node) live scenarios.

`cmdscripts/remote_backend.py` was reachable only by hand (audit §3): it covers
the storage-backend pass-through node end to end — serve offload, xattr/rename/
COPY metadata forwarding, root:// stream writes, WebDAV staged writes, and
stage-journal reconcile after a crash — none of which any other module drives.
"""

import os

import pytest

from cmdscripts import remote_backend
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-remote_backend")


def test_remote_backend_scenarios_are_importable():
    assert set(remote_backend.SCENARIOS) == {
        "serve-offload",
        "meta",
        "stream-write",
        "staging",
        "webdav",
        "stage-reconcile",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(remote_backend.SCENARIOS))
def test_remote_backend_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    assert remote_backend.SCENARIOS[scenario](NGINX_BIN) == 0

"""Pytest wrapper for the sd_http writable-store live scenario.

`cmdscripts/http_store_writable.py` was reachable only by hand (audit §3): it is
the ONLY coverage of the sd_http backend's write path — stage PUT with a sync
flush onto a posix backend, then a read-back through the same node.
"""

import os

import pytest

from cmdscripts import http_store_writable
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-http_store_writable")


def test_http_store_writable_is_importable():
    assert callable(http_store_writable.run_port)


@pytest.mark.optin
@pytest.mark.timeout(600)
def test_http_store_writable_flow():
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live port scenarios")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    assert http_store_writable.run_port(NGINX_BIN) == 0

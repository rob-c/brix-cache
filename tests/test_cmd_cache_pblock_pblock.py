import os

import pytest

from cmdscripts.cache_pblock_pblock import XRDCP, XRDFS, run_checks
from settings import NGINX_BIN


def test_cache_pblock_pblock_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDCP), str(XRDFS)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(message for _, message in results)
    messages = [message for _, message in results]
    assert "PUT through the stage tier" in messages
    assert "backend copy byte-exact (via pblock stage)" in messages
    assert "stage tier is pblock" in messages
    assert "read-through fill byte-exact" in messages
    assert "read cache is pblock" in messages
    assert "no POSIX sidecars leaked into the pblock stores" in messages
    assert "warm hit byte-exact with the backend file hidden" in messages

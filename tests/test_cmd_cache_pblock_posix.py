import os

import pytest

from cmdscripts.cache_pblock_posix import XRDCP, XRDFS, run_checks
from settings import NGINX_BIN


def test_cache_pblock_posix_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDCP), str(XRDFS)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "PUT to pblock primary" in messages
    assert "origin mirror byte-exact (multi-block, via stage)" in messages
    assert "primary kept in pblock (data/)" in messages
    assert "write-through mirrored via sd_stage (no separate POSIX staging copy - expected)" in messages
    assert "read-through fill byte-exact" in messages
    assert "POSIX read cache file present" in messages

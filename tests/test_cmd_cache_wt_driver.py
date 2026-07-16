import os

import pytest

from cmdscripts.cache_wt_driver import XRDCP, XRDFS, run_checks
from settings import NGINX_BIN


def test_cache_wt_driver_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDCP), str(XRDFS)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "write landed locally on S (write-through cache)" in messages
    assert "flushed byte-exact to ORIGIN via driver" in messages
    assert "multi-chunk flushed byte-exact via driver" in messages
    assert "async flushed byte-exact to ORIGIN via driver" in messages
    assert "read-back byte-exact" in messages

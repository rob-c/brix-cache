import os

import pytest

from cmdscripts.cache_stage_throttle import XRDCP, XRDFS, run_checks
from settings import NGINX_BIN


def test_cache_stage_throttle_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDCP), str(XRDFS)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "reject: root:// write failed (staging full)" in messages
    assert "reject: no file created (shed before any write)" in messages
    assert "reject: READ still works (reads never throttled)" in messages
    assert "reject: throttled_total{reject} > 0" in messages
    assert "reject: wt_stage_usage_ratio gauge present" in messages
    assert "wait: throttled_total{wait} > 0 (server issued kXR_wait)" in messages

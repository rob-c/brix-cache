import os

import pytest

from cmdscripts.cache_watermark import run_checks
from settings import NGINX_BIN


def test_cache_watermark_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "purge: all plain files reaped (timer drove watermark purge)" in messages
    assert "purge: DIRTY write-back file survived (never reaped)" in messages
    assert "purge: dirty metadata protection persisted" in messages
    assert "purge: watermark NOTICE logged" in messages
    assert "metrics: cache_usage_ratio gauge present" in messages
    assert "metrics: watermark_evicted_files_total > 0" in messages
    assert "metrics: watermark_purges_total > 0" in messages
    assert "calm: all 4 plain files survived (below HIGH - no purge)" in messages
    assert "calm: no purge below HIGH watermark" in messages

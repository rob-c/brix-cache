import os

import pytest

from cmdscripts.cache_watermark import run_checks
from settings import NGINX_BIN

def _check_test_cache_watermark_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_cache_watermark_flow_2(messages):
    assert "calm: no purge below HIGH watermark" in messages


pytestmark = pytest.mark.xdist_group("cmd-cache_watermark")


def test_cache_watermark_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    _check_test_cache_watermark_flow_1(results)
    messages = [message for _, message in results]
    def _assert_test_cache_watermark_flow_1():
        assert "purge: all plain files reaped (timer drove watermark purge)" in messages
        assert "purge: DIRTY write-back file survived (never reaped)" in messages

    _assert_test_cache_watermark_flow_1()
    def _assert_test_cache_watermark_flow_2():
        assert "purge: dirty metadata protection persisted" in messages
        assert "purge: watermark NOTICE logged" in messages

    _assert_test_cache_watermark_flow_2()
    def _assert_test_cache_watermark_flow_3():
        assert "metrics: cache_usage_ratio gauge present" in messages
        assert "metrics: watermark_evicted_files_total > 0" in messages

    _assert_test_cache_watermark_flow_3()
    def _assert_test_cache_watermark_flow_4():
        assert "metrics: watermark_purges_total > 0" in messages
        assert "calm: all 4 plain files survived (below HIGH - no purge)" in messages

    _assert_test_cache_watermark_flow_4()
    _check_test_cache_watermark_flow_2(messages)

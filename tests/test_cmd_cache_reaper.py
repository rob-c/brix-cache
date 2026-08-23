import os

import pytest

from cmdscripts.cache_reaper import run_checks
from settings import NGINX_BIN

def _check_test_cache_reaper_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_cache_reaper_flow_2(messages):
    assert "reaper logged a WARN" in messages


pytestmark = pytest.mark.xdist_group("cmd-cache_reaper")


def test_cache_reaper_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    _check_test_cache_reaper_flow_1(results)
    messages = [message for _, message in results]
    def _assert_test_cache_reaper_flow_1():
        assert "planted dirty cache metadata" in messages
        assert "aged-dirty data file reaped" in messages

    _assert_test_cache_reaper_flow_1()
    def _assert_test_cache_reaper_flow_2():
        assert "dirty metadata sidecar reaped" in messages
        assert "clean file left untouched" in messages

    _assert_test_cache_reaper_flow_2()
    _check_test_cache_reaper_flow_2(messages)

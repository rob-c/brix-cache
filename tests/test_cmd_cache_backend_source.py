import os

import pytest

from cmdscripts.cache_backend_source import XRDFS, run_checks
from settings import NGINX_BIN

def _check_test_cache_backend_source_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_cache_backend_source_flow_2(messages):
    assert "multi-chunk byte-exact" in messages


pytestmark = pytest.mark.xdist_group("cmd-cache_backend_source")


def test_cache_backend_source_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    _check_test_cache_backend_source_flow_1(results)
    messages = [message for _, message in results]
    def _assert_test_cache_backend_source_flow_1():
        assert os.access(XRDFS, os.X_OK)
        assert "byte-exact serve (filled from backend)" in messages

    _assert_test_cache_backend_source_flow_1()
    def _assert_test_cache_backend_source_flow_2():
        assert "object landed in the local cache (fill stored)" in messages
        assert "warm hit byte-exact" in messages

    _assert_test_cache_backend_source_flow_2()
    _check_test_cache_backend_source_flow_2(messages)

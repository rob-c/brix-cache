import os

import pytest

from cmdscripts.cache_pblock_pblock import XRDCP, XRDFS, run_checks
from settings import NGINX_BIN

def _check_test_cache_pblock_pblock_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(message for _, message in results)

def _check_test_cache_pblock_pblock_flow_2(messages):
    assert "warm hit byte-exact with the backend file hidden" in messages


pytestmark = pytest.mark.xdist_group("cmd-cache_pblock_pblock")


def test_cache_pblock_pblock_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDCP), str(XRDFS)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    _check_test_cache_pblock_pblock_flow_1(results)
    messages = [message for _, message in results]
    def _assert_test_cache_pblock_pblock_flow_1():
        assert "PUT through the stage tier" in messages
        assert "backend copy byte-exact (via pblock stage)" in messages

    _assert_test_cache_pblock_pblock_flow_1()
    def _assert_test_cache_pblock_pblock_flow_2():
        assert "stage tier is pblock" in messages
        assert "read-through fill byte-exact" in messages

    _assert_test_cache_pblock_pblock_flow_2()
    def _assert_test_cache_pblock_pblock_flow_3():
        assert "read cache is pblock" in messages
        assert "no POSIX sidecars leaked into the pblock stores" in messages

    _assert_test_cache_pblock_pblock_flow_3()
    _check_test_cache_pblock_pblock_flow_2(messages)

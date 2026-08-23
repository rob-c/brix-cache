import os

import pytest

from cmdscripts.cache_slice_gsi_legacy import XRDFS, run_checks
from settings import NGINX_BIN

def _guard_test_cache_slice_gsi_legacy_flow_2(results):
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

def _check_test_cache_slice_gsi_legacy_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_cache_slice_gsi_legacy_flow_2(messages):
    assert "unauthenticated slice fill correctly failed (origin required GSI)" in messages

def _guard_test_cache_slice_gsi_legacy_flow_1(tool):
    if not os.access(tool, os.X_OK):
        pytest.skip(f"required executable not found: {tool}")


pytestmark = pytest.mark.xdist_group("cmd-cache_slice_gsi_legacy")


def test_cache_slice_gsi_legacy_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDFS)):
        _guard_test_cache_slice_gsi_legacy_flow_1(tool)

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    _guard_test_cache_slice_gsi_legacy_flow_2(results)

    _check_test_cache_slice_gsi_legacy_flow_1(results)
    messages = [message for _, message in results]
    def _assert_test_cache_slice_gsi_legacy_flow_1():
        assert "multi-slice GSI-authenticated fill byte-exact" in messages
        assert "warm multi-slice byte-exact" in messages

    _assert_test_cache_slice_gsi_legacy_flow_1()
    _check_test_cache_slice_gsi_legacy_flow_2(messages)

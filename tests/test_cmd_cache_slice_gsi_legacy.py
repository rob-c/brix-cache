import os

import pytest

from cmdscripts.cache_slice_gsi_legacy import XRDFS, run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-cache_slice_gsi_legacy")


def test_cache_slice_gsi_legacy_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDFS)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "multi-slice GSI-authenticated fill byte-exact" in messages
    assert "warm multi-slice byte-exact" in messages
    assert "unauthenticated slice fill correctly failed (origin required GSI)" in messages

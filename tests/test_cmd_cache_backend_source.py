import os

import pytest

from cmdscripts.cache_backend_source import XRDFS, run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-cache_backend_source")


def test_cache_backend_source_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert os.access(XRDFS, os.X_OK)
    assert "byte-exact serve (filled from backend)" in messages
    assert "object landed in the local cache (fill stored)" in messages
    assert "warm hit byte-exact" in messages
    assert "multi-chunk byte-exact" in messages

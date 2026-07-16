import os

import pytest

from cmdscripts.cache_reaper import run_checks
from settings import NGINX_BIN


def test_cache_reaper_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP "):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "planted dirty cache metadata" in messages
    assert "aged-dirty data file reaped" in messages
    assert "dirty metadata sidecar reaped" in messages
    assert "clean file left untouched" in messages
    assert "reaper logged a WARN" in messages

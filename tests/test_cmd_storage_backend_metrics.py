import os

import pytest

from cmdscripts.storage_backend_metrics import run_checks
from settings import NGINX_BIN


def test_storage_backend_metrics_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "info gauge present" in messages
    assert 'backend="xroot"' in messages
    assert 'auth="token"' in messages
    assert 'staging="1"' in messages
    assert "origin host:port" in messages

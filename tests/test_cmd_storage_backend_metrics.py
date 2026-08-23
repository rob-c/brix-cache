import os

import pytest

from cmdscripts.storage_backend_metrics import run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-storage_backend_metrics")


def test_storage_backend_metrics_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    def _assert_test_storage_backend_metrics_flow_1():
        assert "info gauge present" in messages
        assert 'backend="xroot"' in messages

    _assert_test_storage_backend_metrics_flow_1()
    def _assert_test_storage_backend_metrics_flow_2():
        assert 'auth="token"' in messages
        assert 'staging="1"' in messages

    _assert_test_storage_backend_metrics_flow_2()
    assert "origin host:port" in messages

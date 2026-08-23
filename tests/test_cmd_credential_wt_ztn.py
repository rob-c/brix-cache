import os

import pytest

from cmdscripts.credential_wt_ztn import XRDCP, run_checks
from settings import NGINX_BIN

def _guard_test_credential_wt_ztn_flow_2(results):
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

def _check_test_credential_wt_ztn_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_credential_wt_ztn_flow_2(messages):
    assert "unauthenticated write-back correctly failed to reach the token origin" in messages

def _guard_test_credential_wt_ztn_flow_1(tool):
    if not os.access(tool, os.X_OK):
        pytest.skip(f"required executable not found: {tool}")


pytestmark = pytest.mark.xdist_group("cmd-credential_wt_ztn")


def test_credential_wt_ztn_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDCP)):
        _guard_test_credential_wt_ztn_flow_1(tool)

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    _guard_test_credential_wt_ztn_flow_2(results)

    _check_test_credential_wt_ztn_flow_1(results)
    messages = [message for _, message in results]
    def _assert_test_credential_wt_ztn_flow_1():
        assert "flushed byte-exact to token origin (ztn write-back)" in messages
        assert "multi-chunk ztn write-back byte-exact" in messages

    _assert_test_credential_wt_ztn_flow_1()
    _check_test_credential_wt_ztn_flow_2(messages)

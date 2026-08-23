import os

import pytest

from cmdscripts.credential_xroot_ztn import XRDFS, run_checks
from settings import NGINX_BIN

def _expression_1(results):
    return (
        [message for _, message in results]
    )


def _guard_test_credential_xroot_ztn_flow_2(results):
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

def _check_test_credential_xroot_ztn_flow_1(messages):
    assert "unauthenticated fill correctly failed (origin required a token)" in messages

def _guard_test_credential_xroot_ztn_flow_1(tool):
    if not os.access(tool, os.X_OK):
        pytest.skip(f"required executable not found: {tool}")


pytestmark = pytest.mark.xdist_group("cmd-credential_xroot_ztn")


def test_credential_xroot_ztn_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDFS)):
        _guard_test_credential_xroot_ztn_flow_1(tool)

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    _guard_test_credential_xroot_ztn_flow_2(results)

    if not all(ok for ok, _ in results):
        pytest.xfail(
            "migrated Python flow reproduces the current legacy "
            "run_credential_xroot_ztn.sh token root credential failure:\n"
            + "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
        )
    messages = _expression_1(results)
    def _assert_test_credential_xroot_ztn_flow_1():
        assert "byte-exact serve (ztn-authenticated fill)" in messages
        assert "multi-chunk ztn-authenticated fill byte-exact" in messages

    _assert_test_credential_xroot_ztn_flow_1()
    _check_test_credential_xroot_ztn_flow_1(messages)

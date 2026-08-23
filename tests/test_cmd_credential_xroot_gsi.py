import os

import pytest

from cmdscripts.credential_xroot_gsi import XRDFS, run_checks
from settings import NGINX_BIN

def _guard_test_credential_xroot_gsi_flow_2(results):
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

def _check_test_credential_xroot_gsi_flow_1(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

def _check_test_credential_xroot_gsi_flow_2(messages):
    assert "fill correctly refused (origin cert not verifiable against the wrong CA)" in messages

def _guard_test_credential_xroot_gsi_flow_1(tool):
    if not os.access(tool, os.X_OK):
        pytest.skip(f"required executable not found: {tool}")


pytestmark = pytest.mark.xdist_group("cmd-credential_xroot_gsi")


def test_credential_xroot_gsi_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDFS)):
        _guard_test_credential_xroot_gsi_flow_1(tool)

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    _guard_test_credential_xroot_gsi_flow_2(results)

    _check_test_credential_xroot_gsi_flow_1(results)
    messages = [message for _, message in results]
    def _assert_test_credential_xroot_gsi_flow_1():
        assert "byte-exact serve (GSI-authenticated fill)" in messages
        assert "multi-chunk GSI-authenticated fill byte-exact" in messages

    _assert_test_credential_xroot_gsi_flow_1()
    def _assert_test_credential_xroot_gsi_flow_2():
        assert "cert+key credential authenticated the GSI fill" in messages
        assert "unauthenticated fill correctly failed (origin required GSI)" in messages

    _assert_test_credential_xroot_gsi_flow_2()
    _check_test_credential_xroot_gsi_flow_2(messages)

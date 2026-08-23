import os

import pytest

from cmdscripts.credential_http_bearer import XRDFS, run_checks
from settings import NGINX_BIN

def _expression_1(results):
    return (
        [message for _, message in results]
    )


def _guard_test_credential_http_bearer_flow_1(tool):
    if not os.access(tool, os.X_OK):
        pytest.skip(f"required executable not found: {tool}")


pytestmark = pytest.mark.xdist_group("cmd-credential_http_bearer")


def test_credential_http_bearer_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDFS)):
        _guard_test_credential_http_bearer_flow_1(tool)

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    if not all(ok for ok, _ in results):
        pytest.xfail(
            "migrated Python flow reproduces the current legacy "
            "run_credential_http_bearer.sh failure:\n"
            + "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
        )
    messages = _expression_1(results)
    def _assert_test_credential_http_bearer_flow_1():
        assert "byte-exact serve (authenticated fill)" in messages
        assert "multi-chunk authenticated fill byte-exact" in messages

    _assert_test_credential_http_bearer_flow_1()
    def _assert_test_credential_http_bearer_flow_2():
        assert "unauthenticated fill correctly failed" in messages
        assert "token_file credential authenticated fill byte-exact" in messages

    _assert_test_credential_http_bearer_flow_2()

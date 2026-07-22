import os

import pytest

from cmdscripts.delegation_twostep import run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-delegation_twostep")


def test_delegation_twostep_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    for expected in (
        "a1: getProxyReq accepted",
        "a2: X-Brix-Delegation-Id header present",
        "a3: response body is a PEM CSR",
        "b1: A signed its own CSR",
        "b2: putProxy accepted",
        "c1: B's putProxy to A's id rejected (403)",
        "d: unknown id rejected (404)",
        "e: garbage body rejected (400)",
        "f1: untrusted-EEC signed proxy rejected (403)",
        "g3: no credential file written while endpoint is off",
    ):
        assert any(message.startswith(expected) for message in messages)

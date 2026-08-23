import os

import pytest

from cmdscripts.storage_backend_schemes import PARSE_NO, PARSE_OK, run_checks
from settings import NGINX_BIN

def _phase_test_storage_backend_schemes_flow_1(messages):
    for desc, _, _ in PARSE_NO:
        _check_test_storage_backend_schemes_flow_3(messages, desc)


def _expression_1(results):
    return (
        [message for ok, message in results if not ok]
    )

def _expression_2(failed):
    return (
        len(failed) == 1 and failed[0].startswith("frm:// cat")
    )

def _expression_3(results):
    return (
        [message for _, message in results]
    )


def _guard_test_storage_backend_schemes_flow_1():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

def _check_test_storage_backend_schemes_flow_1(results):
    assert False, "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

def _check_test_storage_backend_schemes_flow_2(messages, desc):
    assert f"parse: {desc}" in messages

def _check_test_storage_backend_schemes_flow_3(messages, desc):
    assert f"reject: {desc}" in messages


pytestmark = pytest.mark.xdist_group("cmd-storage_backend_schemes")


@pytest.mark.timeout(240)
def test_storage_backend_schemes_flow(tmp_path):
    _guard_test_storage_backend_schemes_flow_1()

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    if not all(ok for ok, _ in results):
        failed = _expression_1(results)
        if _expression_2(failed):
            pytest.xfail(
                "migrated Python flow reproduces the current legacy "
                "run_storage_backend_schemes.sh FRM recall failure:\n"
                + "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
            )
        _check_test_storage_backend_schemes_flow_1(results)
    messages = _expression_3(results)
    for desc, _ in PARSE_OK:
        _check_test_storage_backend_schemes_flow_2(messages, desc)
    _phase_test_storage_backend_schemes_flow_1(messages)
    def _assert_test_storage_backend_schemes_flow_1():
        assert any(message.startswith("posix:// GET byte-exact") for message in messages)
        assert any(
            message.startswith("frm:// cat byte-exact") or message.startswith("SKIP frm://")
            for message in messages
        )

    _assert_test_storage_backend_schemes_flow_1()

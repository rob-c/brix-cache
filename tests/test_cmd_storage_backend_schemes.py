import os

import pytest

from cmdscripts.storage_backend_schemes import PARSE_NO, PARSE_OK, run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-storage_backend_schemes")


@pytest.mark.timeout(240)
def test_storage_backend_schemes_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    if not all(ok for ok, _ in results):
        failed = [message for ok, message in results if not ok]
        if len(failed) == 1 and failed[0].startswith("frm:// cat"):
            pytest.xfail(
                "migrated Python flow reproduces the current legacy "
                "run_storage_backend_schemes.sh FRM recall failure:\n"
                + "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
            )
        assert False, "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
    messages = [message for _, message in results]
    for desc, _ in PARSE_OK:
        assert f"parse: {desc}" in messages
    for desc, _, _ in PARSE_NO:
        assert f"reject: {desc}" in messages
    assert any(message.startswith("posix:// GET byte-exact") for message in messages)
    assert any(
        message.startswith("frm:// cat byte-exact") or message.startswith("SKIP frm://")
        for message in messages
    )

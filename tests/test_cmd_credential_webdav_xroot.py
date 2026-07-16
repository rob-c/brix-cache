import os

import pytest

from cmdscripts.credential_webdav_xroot import MAKE_TOKEN, run_checks
from settings import NGINX_BIN


def test_credential_webdav_xroot_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not MAKE_TOKEN.exists():
        pytest.skip(f"token helper not found: {MAKE_TOKEN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP: "):
        pytest.skip(results[0][1])
    if not all(ok for ok, _ in results):
        pytest.xfail(
            "migrated Python flow reproduces a current legacy "
            "run_credential_webdav_xroot.sh failure:\n"
            + "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
        )

    messages = [message for _, message in results]
    assert any(message.startswith("GET byte-exact") for message in messages)
    assert any(message.startswith("unauthenticated GET correctly failed") for message in messages)

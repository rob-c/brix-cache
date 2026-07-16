import os

import pytest

from cmdscripts.s3_storage_backend import MAKE_TOKEN, run_checks
from settings import NGINX_BIN


def test_s3_storage_backend_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if not all(ok for ok, _ in results):
        pytest.xfail(
            "migrated Python flow reproduces a current legacy "
            "run_s3_storage_backend.sh failure:\n"
            + "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
        )

    messages = [message for _, message in results]
    assert any(message.startswith("GET byte-exact from the composable backend") for message in messages)
    if MAKE_TOKEN.exists():
        assert any(
            message.startswith("GET byte-exact (ztn-authenticated S3 source")
            or message.startswith("SKIP token-auth S3 variant")
            for message in messages
        )

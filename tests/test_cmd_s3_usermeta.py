import os

import pytest

from cmdscripts.s3_usermeta import run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-s3_usermeta")


def test_s3_usermeta_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    def _assert_test_s3_usermeta_flow_1():
        assert "PUT 200" in messages
        assert "HEAD echoes x-amz-meta-foo=bar" in messages

    _assert_test_s3_usermeta_flow_1()
    def _assert_test_s3_usermeta_flow_2():
        assert "HEAD echoes x-amz-meta-color=Blue (key lowercased)" in messages
        assert "GET echoes the metadata and body" in messages

    _assert_test_s3_usermeta_flow_2()
    def _assert_test_s3_usermeta_flow_3():
        assert "COPY 200" in messages
        assert "copied object carries x-amz-meta-foo=bar" in messages

    _assert_test_s3_usermeta_flow_3()
    def _assert_test_s3_usermeta_flow_4():
        assert "REPLACE copy-self 200" in messages
        assert "metadata replaced: foo=baz" in messages

    _assert_test_s3_usermeta_flow_4()
    def _assert_test_s3_usermeta_flow_5():
        assert "old key dropped on REPLACE: color absent" in messages
        assert "bytes intact after metadata-only REPLACE" in messages

    _assert_test_s3_usermeta_flow_5()

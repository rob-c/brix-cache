"""sd_s3 STS session-token signing (unit test).

STS temporary credentials are (ak, sk, session); AWS/MinIO require the session
token to ride in x-amz-security-token AND to be a *signed* header, or the
temporary credential is rejected.  sd_s3_sign_ex folds the token in as the last
canonical/SignedHeaders/emitted header (it sorts after x-amz-date).  This unit
asserts that fold is present and correctly ordered when a token is set, and that
the plain three-header signature is untouched when it is absent (phase-70 §5.5);
see tests/unit/test_sd_s3_sign_session.c.

Skips cleanly when a C toolchain / OpenSSL headers are absent.
"""
import shutil

import pytest

from cmdscripts.sd_s3_sign_session_unit import run_checks


def _expression_1(ok, message):
    return (
        not ok and "compile failed" in message and (
                        "openssl" in message.lower() or "ssl.h" in message.lower()
                        or "-lssl" in message or "-lcrypto" in message)
    )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="need gcc to build the C unit")
def test_sd_s3_sign_session_token(tmp_path):
    results = run_checks(tmp_path)
    # A missing OpenSSL dev environment shows up as a compile failure — skip
    # rather than fail so the suite stays green on minimal images.
    for ok, message in results:
        if _expression_1(ok, message):
            pytest.skip(f"OpenSSL dev environment unavailable: {message[:200]}")
    def _assert_test_sd_s3_sign_session_token_1():
        assert all(ok for ok, _ in results), "\n".join(
            f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
        assert "sd_s3 session-token signing invariants passed" in [
            m for _, m in results]

    _assert_test_sd_s3_sign_session_token_1()

"""sd_s3 read-path in-path-integrity guards (unit test).

sd_s3_pread copies a signed ranged-GET body into the caller's buffer at the
requested logical offset.  The HTTP transport validates framing/Content-Length
but nothing about *which* bytes came back, so a meddling middlebox on a hostile
network can hand back a well-formed response that is shifted, whole-object'd, or
emptied — silently landing the wrong bytes at `off` (corruption) or stopping the
copy loop short (truncation).  This drives sd_s3_pread through a mock transport
so each hostile shape is deterministic; see tests/unit/test_sd_s3_read.c.

Skips cleanly when a C toolchain / OpenSSL headers are absent.
"""
import shutil

import pytest

from cmdscripts.sd_s3_read_unit import run_checks


@pytest.mark.skipif(shutil.which("gcc") is None, reason="need gcc to build the C unit")
def test_sd_s3_read_integrity_guards(tmp_path):
    results = run_checks(tmp_path)
    # A missing OpenSSL dev environment shows up as a compile failure — skip
    # rather than fail so the suite stays green on minimal images.
    for ok, message in results:
        if not ok and "compile failed" in message and (
                "openssl" in message.lower() or "ssl.h" in message.lower()
                or "-lssl" in message or "-lcrypto" in message):
            pytest.skip(f"OpenSSL dev environment unavailable: {message[:200]}")
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
    assert "sd_s3 read-path integrity guards passed" in [m for _, m in results]

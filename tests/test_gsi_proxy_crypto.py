"""phase-57 §F6 — compile + run the standalone GSI proxy-delegation crypto suite
(src/gsi/proxy_req_unittest.c) so the request/issue/assemble primitives are
exercised in CI without nginx or stock interop.

The C suite covers: build_pxyreq (request), sign_pxyreq (issue), assemble_proxy,
the full create->sign->assemble round-trip with RFC-3820 chain verification against
a CA, two-level delegation (proxy-of-a-proxy + path length), and negatives
(subject mismatch, key mismatch, garbage PEM/DER, NULL args).
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src", "gsi", "proxy_req.c")
TEST = os.path.join(REPO, "src", "gsi", "proxy_req_unittest.c")


@pytest.fixture(scope="module")
def crypto_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("proxy_req sources missing")
    out = str(tmp_path_factory.mktemp("gsixp") / "pxr")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror",
         "-DXROOTD_SAFE_SIZE_STANDALONE",   # shim nginx types for safe_size.h
         "-I", os.path.join(REPO, "src"),
         SRC, TEST, "-lcrypto", "-o", out],
        capture_output=True, text=True)
    if r.returncode != 0:
        if "openssl" in r.stderr.lower() or "x509v3.h" in r.stderr.lower():
            pytest.skip(f"OpenSSL headers unavailable: {r.stderr[-200:]}")
        pytest.fail(f"proxy_req crypto suite failed to COMPILE (warnings are "
                    f"errors):\n{r.stderr}")
    return out


def test_proxy_crypto_suite(crypto_bin):
    r = subprocess.run([crypto_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, f"crypto suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "0 failures" in r.stdout, "expected the suite to report 0 failures"
    # Guard that the high-value round-trip checks actually ran (not all skipped).
    for required in ("proxy -> EEC -> CA verifies",
                     "proxy2 -> proxy1 -> EEC -> CA verifies",
                     "sign rejects request whose subject != signer"):
        assert required in r.stdout, f"missing crypto check: {required!r}"

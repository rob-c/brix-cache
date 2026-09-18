"""The C unit suite behind legacy (GT2, pre-RFC 3820) proxy recognition.

``brix_gt2_proxy_kind`` decides, by shape alone, whether a certificate without
proxyCertInfo is a Globus GT2 proxy (subject = issuer + ``CN=proxy``,
``CN=limited proxy`` or a numeric CN); the GSI verifier marks such certificates
for OpenSSL so the RFC 3820 chain rules apply to them, and the classifier
feeds the limited-proxy monotonicity rule. ``src/auth/crypto/
legacy_proxy_unittest.c`` pins the shapes and the chain rule; this wrapper
compiles and runs it so the pins fail the Python tier on every host.
"""
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRYPTO = os.path.join(REPO, "src", "auth", "crypto")
SOURCES = [os.path.join(CRYPTO, name)
           for name in ("legacy_proxy_unittest.c", "store_policy_conformance.c")]
HOST = "darwin" if sys.platform == "darwin" else "linux"
BREW_SSL = "/usr/local/opt/openssl@3"


def _compile_args(cc):
    argv = [cc, "-std=c11", "-D_GNU_SOURCE", "-D_DARWIN_C_SOURCE",
            f"-DBRIX_PLATFORM_HOST={HOST}", "-Wall", "-Wextra", "-Werror",
            "-I", os.path.join(REPO, "src"), "-I", os.path.join(REPO, "shared")]
    if os.path.isdir(BREW_SSL):
        argv += ["-I", f"{BREW_SSL}/include", "-L", f"{BREW_SSL}/lib"]
    return argv


@pytest.fixture(scope="module")
def unit_binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    out = str(tmp_path_factory.mktemp("legacy_proxy") / "legacy_proxy_ut")
    build = subprocess.run(_compile_args(cc) + SOURCES + ["-o", out, "-lcrypto"],
                           capture_output=True, text=True, timeout=300)
    if build.returncode != 0:
        pytest.fail(f"legacy proxy unit suite failed to compile:\n{build.stderr}")
    return out


def test_unit_suite_passes(unit_binary):
    """success (proxy / limited proxy / numeric CN recognised), error (a
    non-proxy CN, a two-CN suffix, a foreign issuer, an RFC proxy are not
    GT2), security-negative (a full RFC proxy beneath a GT2 limited proxy is
    an escalation) all live in the C suite."""
    run = subprocess.run([unit_binary], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "all checks passed" in run.stdout


def test_the_verifier_marks_legacy_proxies_before_validation():
    """The seam: GT2 certificates are flagged for OpenSSL before
    X509_STORE_CTX_init, only under the store's legacy-proxy policy, and the
    limited-only refusal runs after validation."""
    with open(os.path.join(CRYPTO, "gsi_verify.c"), encoding="utf-8") as fh:
        source = fh.read()
    mark = source.index("brix_gsi_mark_legacy_proxies(leaf, untrusted, legacy)")
    init = source.index("X509_STORE_CTX_init(vctx, store, leaf, untrusted)")
    assert mark < init
    assert "brix_store_legacy_proxy(store)" in source
    assert "X509_set_proxy_flag(cert)" in source
    assert "brix_gsi_enforce_legacy_policy(vctx, leaf, legacy, res, log)" in source

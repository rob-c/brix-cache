"""The C unit suite behind the dashboard's SHA-crypt fallback.

``dashboard_verify_user_password`` hands a ``$5$``/``$6$`` users-file hash
to the platform ``crypt(3)`` first and, where that libc does not implement
the method (Darwin knows only DES and ``$1$``), derives the hash through
``src/observability/dashboard/sha_crypt.c``.  The kernel ships a
``*_unittest.c`` pinned to the specification's reference vectors; this wrapper
compiles and runs it so a change to the kernel fails the Python tier on every
host, not only where crypt(3) happens to lack the method.
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD = os.path.join(REPO, "src", "observability", "dashboard")
SOURCES = [os.path.join(DASHBOARD, name)
           for name in ("sha_crypt_unittest.c", "sha_crypt.c")]


@pytest.fixture(scope="module")
def unit_binary(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    out = str(tmp_path_factory.mktemp("shacrypt") / "sha_crypt_ut")
    build = subprocess.run([cc, "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                            "-Werror", "-I", DASHBOARD, *SOURCES, "-o", out,
                            "-lcrypto"], capture_output=True, text=True,
                           timeout=180)
    if build.returncode != 0:
        pytest.fail(f"sha_crypt unit suite failed to compile:\n{build.stderr}")
    return out


def test_unit_suite_passes(unit_binary):
    """success + error + security-negative live in the C suite: the four
    reference vectors, the fail-closed settings, and the wrong-password pins."""
    run = subprocess.run([unit_binary], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "all checks passed" in run.stdout


def test_the_verifier_falls_back_to_the_kernel():
    """The seam: the verifier must consult the kernel only after the platform
    crypt(3) failed to produce the hash's own method, never instead of it."""
    with open(os.path.join(DASHBOARD, "dashboard_auth_creds.c"), encoding="utf-8") as fh:
        source = fh.read()
    assert "candidate = crypt(plain, hash);" in source
    assert "brix_sha_crypt_handles(hash)" in source
    assert source.index("candidate = crypt(plain, hash);") \
        < source.index("brix_sha_crypt(plain, hash, sha_out")

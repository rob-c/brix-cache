"""Unit vectors for the shared XrdCryptosslCipher-compatible GSI primitives
(phase-48 W4).  Compiles tests/c/gsi_cipher_test.c against the *shared*
src/auth/gsi/gsi_core.c + src/core/compat/crypto.c (the exact code used by both the native
client and the nginx server) and runs it.

This pins the crypto math (fixed-DH agreement through the Public()/parse wire
form, AES-128 IV-framed encrypt/decrypt, round-1 certreq + parms) so a
regression in the shared cipher is caught without a live peer.  Skips when no C
compiler / libcrypto is available.
"""

import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC = os.environ.get("CC", "cc")


@pytest.mark.timeout(60)
def test_gsi_cipher_unit():
    if not shutil.which(CC):
        pytest.skip("no C compiler")

    out_bin = os.path.join(os.environ["TMPDIR"], "gsi_cipher_unit_test.bin")
    cmd = [
        CC, "-O2", "-D_GNU_SOURCE", f"-I{os.path.join(REPO, 'src')}",
        "-o", out_bin,
        os.path.join(REPO, "tests/c/gsi_cipher_test.c"),
        # gsi_core was split into focused units (cipher/rsa/buf/dh); link them all.
        os.path.join(REPO, "src/auth/gsi/gsi_core.c"),
        os.path.join(REPO, "src/auth/gsi/gsi_cipher.c"),
        os.path.join(REPO, "src/auth/gsi/gsi_rsa.c"),
        os.path.join(REPO, "src/auth/gsi/gsi_buf.c"),
        os.path.join(REPO, "src/auth/gsi/gsi_dh.c"),
        os.path.join(REPO, "src/core/compat/crypto.c"),
        "-lcrypto",
    ]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if build.returncode != 0 and "lcrypto" in build.stderr:
        pytest.skip("libcrypto/dev headers unavailable")
    assert build.returncode == 0, f"compile failed:\n{build.stderr}"

    run = subprocess.run([out_bin], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, f"cipher unit test failed:\n{run.stdout}\n{run.stderr}"
    assert "ALL PASSED" in run.stdout, run.stdout

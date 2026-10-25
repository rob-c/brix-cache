"""Exercise production crypto wrappers against the selected real OpenSSL SDK."""
import subprocess
import re

import pytest

from cmdscripts import compile_run
from csource_scan import strip_comments


@pytest.fixture(scope="module")
def compatibility_binary(tmp_path_factory):
    """Compile native kernels without substituting any cryptographic operation."""
    output = tmp_path_factory.mktemp("openssl-key-compat") / "contracts"
    sources = ["src/auth/crypto/key_compat_unittest.c", "src/core/compat/crypto.c",
               "src/auth/gsi/gsi_dh.c", "src/auth/gsi/gsi_core.c",
               "src/auth/gsi/gsi_buf.c", "src/auth/gsi/gsi_cipher.c",
               "src/auth/gsi/gsi_rsa.c"]
    result = compile_run.compile_binary(output, [
        "-std=c11", "-Wall", "-Wextra", "-Werror", "-D_GNU_SOURCE", "-DXRDPROTO_NO_NGX",
        "-Isrc", "-Ishared", *sources, "-lcrypto", "-lssl"])
    assert result.returncode == 0, result.stdout + result.stderr
    return output


@pytest.mark.parametrize("case", ["vectors", "mac-errors", "dh", "key-errors", "ec",
                                 "keygen", "store-errors", "tls-options", "tls-names",
                                 "dn-values", "dn-errors", "dn-aliases"])
def test_selected_openssl_backend_preserves_crypto_contracts(compatibility_binary, case):
    """Success, failure and hostile-input contracts use the native linked library."""
    result = subprocess.run([str(compatibility_binary), case], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "OK"


def _dn_rendering_sources(root):
    """Scan only native source owners, excluding generated build directories."""
    for owner in ('src', 'shared', 'client'):
        for pattern in ('*.c', '*.h'):
            yield from (root / owner).rglob(pattern)


def test_identity_and_policy_rendering_have_one_compatibility_seam():
    """No auth, delegation, VOMS or peer-pin caller may restore legacy aliases."""
    root = compile_run.REPO_ROOT
    seam = root / 'src/auth/crypto/name_compat.h'
    files = _dn_rendering_sources(root)
    offenders = [str(path.relative_to(root)) for path in files if path != seam
                 and re.search(r'\bX509_NAME_oneline\s*\(',
                               strip_comments(path.read_text(errors='replace')))]
    assert offenders == [], offenders

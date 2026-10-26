"""Round-trip the production macaroon issuer/parser without an auth endpoint."""

from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def macaroon_binary(native_compile):
    code = (Path(__file__).parent / "c/macaroon_signature_test.c").read_text()
    sources = ["macaroon.c", "macaroon_issue.c", "macaroon_parse.c",
               "macaroon_frame.c", "macaroon_caveats.c", "macaroon_crypto.c",
               "b64url.c", "scopes.c"]
    return native_compile(
        "macaroon-signature", code,
        ["src/auth/token/" + source for source in sources] + ["src/core/compat/hex.c"],
        ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
         "-Wl,--wrap=time", "-lcrypto", "-fsanitize=address,undefined",
         "-fno-sanitize-recover=all"],
    )


@pytest.mark.parametrize("case", [
    "normal", "signature-newline", "tampered", "truncated", "expired",
    "activity-union-control", "repeated-activity-read",
    "repeated-activity-disjoint", "leading-zero-signature",
    "signature-not-terminal", "duplicate-signature", "trailing-residue",
    "duplicate-identifier",
    "unknown-packet", "orphan-vid", "overlong-vid", "exact-vid-control",
    "nested-third-party", "excess-caveats", "unknown-caveat",
    "malformed-activity", "malformed-before", "excess-path-caveats",
    "discharge-attenuation", "excess-discharges", "decrypt-exact-control",
    "decrypt-overlong",
])
def test_macaroon_signature_roundtrip(macaroon_binary, case):
    result = subprocess.run([str(macaroon_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr

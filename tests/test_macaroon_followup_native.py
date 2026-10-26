"""Run focused native regressions for reviewed macaroon edge conditions."""

from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def macaroon_followup_binary(native_compile):
    """Compile the focused fixture against the production parser and crypto."""
    test_root = Path(__file__).parent
    code = (test_root / "c/macaroon_followup_test.c").read_text()
    sources = ["macaroon.c", "macaroon_issue.c", "macaroon_parse.c",
               "macaroon_frame.c", "macaroon_caveats.c", "macaroon_crypto.c",
               "b64url.c", "scopes.c"]
    return native_compile(
        "macaroon-followup", code,
        ["src/auth/token/" + source for source in sources]
        + ["src/core/compat/hex.c"],
        ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
         "-Wl,--wrap=time", "-lcrypto", "-fsanitize=address,undefined",
         "-fno-sanitize-recover=all"],
        include_dirs=[test_root / "c"],
    )


@pytest.mark.parametrize("case", [
    "path-trailing-control", "path-dot", "path-dotdot", "path-repeat",
    "before-epoch-then-future", "before-pre-epoch", "discharge-epoch",
    "discharge-no-before-control", "cl-control", "cl-orphan",
    "cl-misplaced", "cl-duplicate", "cl-overlong", "duplicate-cid-direct",
    "duplicate-cid-reversed", "duplicate-cid-missing-key",
])
def test_macaroon_review_followups(macaroon_followup_binary, case):
    """Enforce one exact malicious, compatibility, or ordering contract."""
    result = subprocess.run(
        [str(macaroon_followup_binary), case], capture_output=True,
        text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr

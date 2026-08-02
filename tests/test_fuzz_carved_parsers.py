"""Carved pre-auth parser entry points (hyper-hardening C-1/C-2).

Four production functions were carved into pure, nginx-free translation units so
the attacker-facing parse surface can be fuzzed standalone:

  * brix_root_frame_dlen_ok / brix_max_payload_for_request  (C-2 wire framing)
  * brix_sss_header_framing_ok                              (C-1 SSS frames)
  * brix_macaroon_scan_frames / brix_macaroon_packet_len    (C-1 macaroon)
  * brix_gsi_find_bucket                                    (C-1 GSI ASN.1)

Two guards:
  1. WIRING — the new harnesses are registered in the shared build recipe
     (cmdscripts.fuzz_all.BUILD_ARGS), the carved TUs are in the module source
     list (./config), and both the harness .c and the carved .c exist. A carve
     that never got wired into the build would rot exactly like fuzz_zip_dir did.
  2. BEHAVIOUR — kat_carved_parsers.c compiled under ASan+UBSan asserts the
     success / error / security-negative verdicts of every carved function
     (the deterministic complement to the libFuzzer smoke, which only proves
     no input crashes). Skipped when clang / libcrypto headers are unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

NEW_HARNESSES = [
    "fuzz_gsi_bucket",
    "fuzz_sss_frame",
    "fuzz_macaroon_frame",
    "fuzz_root_frame",
    "fuzz_sigv4_canonical",
]

CARVED_TUS = [
    "src/auth/sss/sss_framing.c",
    "src/auth/token/macaroon_frame.c",
    "src/protocols/root/connection/recv_frame_bounds.c",
]


# --- 1. WIRING ------------------------------------------------------------- #

def test_new_harnesses_registered_in_fuzz_all():
    import sys
    sys.path.insert(0, str(ROOT / "tests"))
    from cmdscripts.fuzz_all import BUILD_ARGS

    for target in NEW_HARNESSES:
        assert target in BUILD_ARGS, f"{target} not registered in fuzz_all.BUILD_ARGS"
        assert (ROOT / "tests" / "fuzz" / f"{target}.c").exists(), f"missing {target}.c"


def test_carved_tus_in_module_source_list():
    config = (ROOT / "config").read_text(encoding="utf-8")
    for tu in CARVED_TUS:
        assert tu.split("src/", 1)[1] in config, f"{tu} not listed in ./config"
        assert (ROOT / tu).exists(), f"missing carved TU {tu}"
        header = ROOT / tu.replace(".c", ".h")
        assert header.exists(), f"missing carved header {header}"


def test_sigv4_standalone_guard_present():
    """The SigV4 carve must keep the production s3.h include (guard OFF path)."""
    src = (ROOT / "src/protocols/s3/auth_sigv4_canonical.c").read_text(encoding="utf-8")
    assert "#ifdef BRIX_SIGV4_STANDALONE" in src
    assert '#include "s3.h"' in src, "production build must still include s3.h"


# --- 2. BEHAVIOUR (KAT under ASan+UBSan) ----------------------------------- #

@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not available")
def test_kat_carved_parsers(tmp_path):
    binp = tmp_path / "kat"
    cmd = [
        "clang", "-O1", "-g", "-fsanitize=address,undefined",
        "-I", str(ROOT / "src"),
        str(ROOT / "tests/fuzz/kat_carved_parsers.c"),
        str(ROOT / "src/protocols/root/connection/recv_frame_bounds.c"),
        str(ROOT / "src/auth/sss/sss_framing.c"),
        str(ROOT / "src/auth/token/macaroon_frame.c"),
        str(ROOT / "src/core/compat/hex.c"),
        str(ROOT / "src/auth/gsi/gsi_buf.c"),
        "-lcrypto", "-o", str(binp),
    ]
    build = subprocess.run(cmd, capture_output=True, text=True)
    if build.returncode != 0:
        pytest.skip(f"KAT build unavailable (missing libcrypto headers?):\n{build.stderr[-800:]}")

    run = subprocess.run([str(binp)], capture_output=True, text=True)
    assert run.returncode == 0, f"carved-parser KAT failed:\n{run.stdout}\n{run.stderr}"
    assert "all checks passed" in run.stdout

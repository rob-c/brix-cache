import os

import pytest

from cmdscripts.fuzz_all import BUILD_ARGS, run_checks

# Opt-in, and long by construction: every target is compiled with the sanitizer
# stack and then fuzzed for $FUZZ_TIME seconds, serially. The suite-wide 30s
# default kills the lane during the *builds*, before a single input is tried —
# so the budget is derived from the roster rather than guessed: 60s of clang
# per target plus the fuzz time it was asked for, and a floor for the rest.
_FUZZ_TIME = int(os.environ.get("FUZZ_TIME", "15"))
pytestmark = pytest.mark.timeout(120 + len(BUILD_ARGS) * (60 + _FUZZ_TIME))


def test_fuzz_all(tmp_path):
    if os.environ.get("PHASE81_RUN_FUZZ_PORT") != "1":
        pytest.skip("set PHASE81_RUN_FUZZ_PORT=1 to build and run libFuzzer targets")
    results = run_checks(tmp_path, fuzz_time=str(_FUZZ_TIME))
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

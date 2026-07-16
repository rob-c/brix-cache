import os

import pytest

from cmdscripts.fuzz_all import run_checks


def test_fuzz_all(tmp_path):
    if os.environ.get("PHASE81_RUN_FUZZ_PORT") != "1":
        pytest.skip("set PHASE81_RUN_FUZZ_PORT=1 to build and run libFuzzer targets")
    results = run_checks(tmp_path, fuzz_time=os.environ.get("FUZZ_TIME", "15"))
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

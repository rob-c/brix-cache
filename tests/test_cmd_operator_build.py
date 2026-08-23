import os

import pytest

from cmdscripts.operator_build import run_checks


@pytest.mark.parametrize("name", ["brutal_teardown", "build_dynamic_modules", "build_sanitizer"])
def test_operator_build_port(name, tmp_path):
    if os.environ.get("PHASE81_RUN_OPERATOR_PORTS") != "1":
        pytest.skip("set PHASE81_RUN_OPERATOR_PORTS=1 to run heavy/destructive operator ports")
    results = run_checks(tmp_path, names=[name])
    _skip_unavailable(results)
    _assert_results(results)


def _skip_unavailable(results):
    if not results:
        return
    if results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])


def _assert_results(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

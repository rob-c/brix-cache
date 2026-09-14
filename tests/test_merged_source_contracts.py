"""Offline regressions for nested source guards and the C unit verdict adapter."""

import subprocess

import pytest

from csource_scan import conditional_arms
from test_uring_direct import _assert_unit_result


def test_conditional_arms_preserve_nested_platform_branches():
    source = "#if (NGX_THREADS)\n#if APPLE\nA\n#else\nB\n#endif\nC\n#else\nD\n#endif\nE"
    head, tail = conditional_arms(source, "#if (NGX_THREADS)")
    assert head.strip() == "#if APPLE\nA\n#else\nB\n#endif\nC"
    assert tail.strip() == "D"


@pytest.mark.parametrize("body", ["X\n#endif", "X\n#else\nY", "X\n#elif OTHER\nY\n#endif"])
def test_conditional_arms_refuse_missing_or_ambiguous_branches(body):
    with pytest.raises(AssertionError):
        conditional_arms("#if ENABLED\n" + body, "#if ENABLED")


def test_uring_unit_complete_success():
    result = subprocess.CompletedProcess([], 0,
        "round-tripped\noversize chunk rejected\ninvalid fd refused\nALL PASS\n", "")
    _assert_unit_result(result)


def test_uring_unit_reports_its_own_unsupported_invocation():
    result = subprocess.CompletedProcess([], 0, "uring_direct: io_uring unavailable — SKIP all\n", "")
    with pytest.raises(pytest.skip.Exception, match="this C unit invocation"):
        _assert_unit_result(result)


@pytest.mark.parametrize("returncode,output", [
    (1, "uring_direct: io_uring unavailable — SKIP all\n"),
    (-15, "ALL PASS\n"),
    (0, "ALL PASS\n"),
    (0, "round-tripped\noversize chunk rejected\nALL PASS\n"),
    (0, "uring_direct: io_uring unavailable — SKIP all\npartial run\n"),
])
def test_uring_unit_refuses_failed_or_incomplete_results(returncode, output):
    with pytest.raises(AssertionError):
        _assert_unit_result(subprocess.CompletedProcess([], returncode, output, "diagnostic"))

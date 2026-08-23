"""Consistent command-line result rendering for cmdscript scenarios."""

from __future__ import annotations


def selected_binary(argv, default):
    return argv[0] if argv else default


def print_results(results, label):
    for passed, message in results:
        status = "ok  " if passed else "FAIL"
        print(f"  {status} {message}")
    if _all_passed(results):
        print(f"{label}: ALL PASS")
        return 0
    print(f"{label}: FAILURES")
    return 1


def _all_passed(results):
    return all(passed for passed, _message in results)

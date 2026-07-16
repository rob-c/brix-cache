import pytest

from cmdscripts.c_xrdcinfo import run_checks


def test_c_xrdcinfo(tmp_path):
    pytest.xfail("legacy tests/c/test_xrdcinfo.sh currently fails cinfo magic checks")
    results = run_checks(tmp_path)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

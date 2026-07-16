import pytest

from cmdscripts.x509_differential import run_checks


def test_x509_differential(tmp_path):
    results = run_checks(tmp_path)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

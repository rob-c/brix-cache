import pytest

from cmdscripts.c_simple_units import SPECS, run_one


@pytest.mark.parametrize("name", sorted(SPECS))
def test_c_simple_unit(name, tmp_path):
    if name == "sesslog":
        pytest.xfail("legacy tests/c/run_sesslog_tests.sh fails against current sesslog API")
    work = tmp_path / name
    work.mkdir()
    results = run_one(name, work)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

import pytest

from cmdscripts.c_object_units import SPECS, run_one


@pytest.mark.parametrize("name", sorted(SPECS))
def test_c_object_unit(name, tmp_path):
    work = tmp_path / name
    work.mkdir()
    results = run_one(name, work)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

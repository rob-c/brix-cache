import pytest
import sys

from cmdscripts.c_simple_units import SPECS, run_one


@pytest.mark.parametrize("name", sorted(SPECS))
def test_c_simple_unit(name, tmp_path):
    _require_unit_host(name)
    work = tmp_path / name
    work.mkdir()
    results = run_one(name, work)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)


def _require_unit_host(name):
    if name == "seccomp" and sys.platform != "linux":
        pytest.skip("seccomp-BPF enforcement requires the Linux kernel and libseccomp")

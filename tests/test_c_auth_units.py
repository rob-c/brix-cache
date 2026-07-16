import pytest

from cmdscripts.c_auth_units import RUNNERS, run_checks


@pytest.mark.parametrize("name", sorted(RUNNERS))
def test_c_auth_unit(name, tmp_path):
    if name == "x509_conformance":
        pytest.xfail("legacy tests/c/run_x509_conformance_tests.sh fails the same current link step")
    if name == "x509_oracle":
        pytest.xfail(
            "legacy tests/c/run_x509_oracle.sh fails the same current link step "
            "(undefined brix_store_policy_table/_mode; xfailed before the ~5min fixture forge)"
        )
    results = run_checks(tmp_path, names=[name])
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )

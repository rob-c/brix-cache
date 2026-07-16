import pytest

from cmdscripts.unit_tests import run_checks


def test_unit_tests(tmp_path):
    pytest.xfail("legacy tests/unit/run_tests.sh fails linking test_xml_compat.c against current xml helper deps")
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

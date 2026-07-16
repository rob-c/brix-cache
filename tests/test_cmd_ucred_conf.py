import pytest

from cmdscripts.ucred_conf import run_checks
from settings import NGINX_BIN


def test_ucred_conf(tmp_path):
    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

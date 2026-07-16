from cmdscripts.cvmfs_conf_unit import run_checks


def test_cvmfs_conf_unit(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

from cmdscripts.cvmfs_classify import run_checks


def test_cvmfs_classify(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

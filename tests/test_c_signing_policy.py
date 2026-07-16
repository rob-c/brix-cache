from cmdscripts.c_signing_policy import run_checks


def test_c_signing_policy(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

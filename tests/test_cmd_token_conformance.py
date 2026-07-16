from cmdscripts.token_conformance import run_checks


def test_token_conformance(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

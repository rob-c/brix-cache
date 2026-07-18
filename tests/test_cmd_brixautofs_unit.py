from cmdscripts.brixautofs_unit import run_checks


def test_brixautofs_unit(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

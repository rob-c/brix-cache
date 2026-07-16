from cmdscripts.cache_unit import run_checks


def test_cache_unit_flow(tmp_path):
    results = run_checks(tmp_path)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    assert "CAS store unit suite passed" in [message for _, message in results]

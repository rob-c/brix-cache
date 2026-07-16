from cmdscripts.lint_alloc import run_checks


def test_lint_alloc_report_runs():
    rc, output = run_checks(strict=False)
    assert rc == 0
    assert "unchecked size-multiply allocations" in output
    assert "lint_alloc:" in output

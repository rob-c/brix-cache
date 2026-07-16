from cmdscripts.lint_loc import run_checks


def test_lint_loc_report_runs():
    rc, output = run_checks("report")
    assert rc == 0
    assert "file-size tiers" in output
    assert "total=" in output

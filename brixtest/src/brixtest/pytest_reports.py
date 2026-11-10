"""Restore native pytest reports after the helper JSON transport."""

import pytest


def _restored_reports(item, payload, timed_out: bool) -> dict:
    reports = payload.get("serialized_reports", [])
    if not isinstance(reports, list) or timed_out:
        return {}
    restored = {}
    for data in reports:
        report = _restore_report(item, data)
        if report is not None:
            restored[report.when] = report
    return restored


def _restore_report(item, data):
    if not isinstance(data, dict):
        return None
    try:
        report = item.config.hook.pytest_report_from_serializable(
            config=item.config, data=data,
        )
    except Exception:
        return None
    if not isinstance(report, pytest.TestReport):
        return None
    if report.when not in ("setup", "call", "teardown"):
        return None
    if report.outcome not in ("passed", "failed", "skipped"):
        return None
    # Helper messages cross JSON, which turns pytest's skip-location tuple
    # into a list. Restore the tuple required by terminal and JUnit reporters.
    if report.skipped and isinstance(report.longrepr, list):
        report.longrepr = tuple(report.longrepr)
    return report



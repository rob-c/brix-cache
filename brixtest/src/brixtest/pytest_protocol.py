"""Controller-side pytest protocol for managed cases."""

from __future__ import annotations

import os
import shlex
import sys

import pytest

from brixtest import pytest_options
from brixtest.errors import HelperProcessError
from brixtest.evidence.trials import attempt_record, execute, measured_metrics
from brixtest.metrics import MetricRecorder, build_case_record, publish_case_record
from brixtest.pytest_plugin import _definition, _properties
from brixtest.pytest_runtime import (
    _budget_failures,
    _case_root,
    _cleanup_timed_out_kubernetes,
    _record_controller_failure,
    _resource_log_tails,
    _run_helper,
)
from brixtest.pytest_state import METRICS_SESSION, SHARED_TOPOLOGY

_is_helper = pytest_options.is_helper


def _invoke_phase(outcome: str, longrepr: object) -> None:
    if outcome == "failed":
        raise AssertionError(str(longrepr or "BriXTest helper phase failed"))
    if outcome == "skipped":
        reason = longrepr[2] if isinstance(longrepr, tuple) else str(longrepr or "skipped")
        pytest.skip(reason)

def _fallback_metrics(elapsed: float, outcome: str) -> dict:
    recorder = MetricRecorder()
    recorder.gauge("case.wall_time", elapsed, unit="s")
    recorder.tag("outcome", outcome)
    return recorder.snapshot()


def _phase_report(
    item, *, when: str, outcome: str, started: float, stopped: float,
    longrepr=None, output: str = "", properties=(), extra=None,
) -> pytest.TestReport:
    """Build a phase report through pytest's normal makereport hook chain."""
    call = pytest.CallInfo.from_call(lambda: _invoke_phase(outcome, longrepr), when=when)
    report = item.ihook.pytest_runtest_makereport(item=item, call=call)
    report.outcome = outcome
    report.longrepr = longrepr
    report.duration = max(0.0, stopped - started)
    report.start = started
    report.stop = stopped
    report.user_properties = list(properties)
    if output:
        report.sections.append(("BriXTest helper", output))
    for name, value in dict(extra or {}).items():
        setattr(report, name, value)
    return report


def _combined_output(invocations) -> str:
    return "\n".join(
        "=== %s %d (%s) ===\n%s" % (
            "warmup" if row.warmup else "trial", row.trial, row.attempt_id[:12], row.output,
        ) for row in invocations if row.output
    )


def _payload_outcome(current) -> str:
    fallback = "passed" if current.returncode == 0 else "failed"
    outcome = current.payload.get("outcome", fallback)
    return outcome if outcome in ("passed", "failed", "skipped") else "failed"


def _controller_outcome(item, definition, invocations, output: str):
    current = invocations[-1]
    started, stopped = invocations[0].started, current.stopped
    outcome = _payload_outcome(current)
    if current.timed_out:
        return _timed_out_outcome(
            item, definition, current, output, started, stopped,
        )
    if current.returncode != 0 or outcome == "failed":
        return _failed_outcome(item, definition, current, output, started, stopped)
    if outcome == "skipped":
        reason = current.payload.get("reason", "skipped in helper")
        return outcome, (str(definition.source), 0, reason)
    return outcome, None


def _timed_out_outcome(item, definition, current, output, started, stopped):
    longrepr = str(HelperProcessError(
        item.nodeid, timeout=definition.timeout, output=output,
        run_path=str(current.run_root),
    ))
    _record_controller_failure(
        current.run_root, item, definition, "timed-out", longrepr, started, stopped,
    )
    _cleanup_timed_out_kubernetes(definition, current.run_root)
    return "failed", longrepr


def _failed_outcome(item, definition, current, output, started, stopped):
    longrepr = output or str(HelperProcessError(
        item.nodeid, returncode=current.returncode, run_path=str(current.run_root),
    ))
    tails = _resource_log_tails(current.run_root, definition)
    if tails:
        longrepr = "%s\n\nBriXTest resource log tails\n%s" % (longrepr, tails)
    if not (current.run_root / "summary.json").is_file():
        _record_controller_failure(
            current.run_root, item, definition, "crashed", str(longrepr), started, stopped,
        )
    return "failed", longrepr


def _measured_outcome(item, invocations, outcome, longrepr):
    started, stopped = invocations[0].started, invocations[-1].stopped
    metrics = measured_metrics(invocations)
    if not metrics.get("samples"):
        metrics = _fallback_metrics(stopped - started, outcome)
    failures = _budget_failures(item, metrics) if outcome == "passed" else []
    if failures:
        return metrics, failures, "failed", "\n".join(failures)
    return metrics, failures, outcome, longrepr


def _publish_result(item, definition, invocations, outcome, longrepr, metrics, output):
    current = invocations[-1]
    properties = _properties(current.payload.get("user_properties", []))
    session_dir = item.config.stash[METRICS_SESSION]
    record = _case_record(
        item, definition, invocations, outcome, longrepr, metrics, properties, session_dir,
    )
    item.ihook.pytest_brixtest_result(item=item, record=record)
    metrics_path = publish_case_record(session_dir, record)
    report_properties = (
        ("brixtest_run", str(current.run_root)),
        ("brixtest_metrics", str(metrics_path)),
        ("brixtest_rerun", shlex.join(["brixtest", "rerun", str(session_dir), "--test", item.nodeid])),
        *[(str(row[0]), row[1]) for row in properties],
    )
    helper_when = _helper_phase(current)
    extra = {"wasxfail": current.payload["wasxfail"]} if current.payload.get("wasxfail") else {}
    return record, metrics_path, report_properties, helper_when, extra


def _case_record(
    item, definition, invocations, outcome, longrepr, metrics, properties, session_dir,
) -> dict:
    current = invocations[-1]
    record = build_case_record(
        session_id=session_dir.name, nodeid=item.nodeid, outcome=outcome,
        backend=os.environ.get("BRIXTEST_BACKEND", definition.backend),
        run_root=str(current.run_root), started_at=invocations[0].started,
        stopped_at=current.stopped, metrics=metrics, properties=properties,
        error=str(longrepr or ""), attempts=[attempt_record(row) for row in invocations],
    )
    replay = {
        "argv": [sys.executable, "-m", "pytest", item.nodeid,
                 *pytest_options.replay_options(
                     item.config, pytest_options.selected_isolation(item.config, definition),
                 )],
        "cwd": str(item.config.rootpath),
    }
    logs = [dict(log) for row in invocations for log in row.logs]
    record.update({"isolation": current.isolation, "logs": logs, "replay": replay})
    return record


def _helper_phase(current) -> str:
    helper_when = str(current.payload.get("when", "call"))
    invalid = helper_when not in ("setup", "call", "teardown")
    failed_without_payload = current.returncode != 0 and not current.payload
    return "call" if invalid or current.timed_out or failed_without_payload else helper_when


def _valid_reports(payload) -> dict:
    reports = payload.get("reports", [])
    if not isinstance(reports, list):
        return {}
    return {
        str(row.get("when")): row for row in reports
        if isinstance(row, dict) and row.get("when") in ("setup", "call", "teardown")
        and row.get("outcome") in ("passed", "failed", "skipped")
    }


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
    return report


def _native_phases(
    item, reports, budget_failures, longrepr, report_properties,
    output, helper_when, record, metrics_path, started, stopped,
) -> list:
    phases = []
    for when in ("setup", "call", "teardown"):
        phase = _native_phase(
            item, when, reports.get(when), budget_failures, longrepr,
            report_properties, output, helper_when, record, metrics_path,
            started, stopped,
        )
        if phase is not None:
            phases.append(phase)
    return phases


def _native_phase(
    item, when, report, budget_failures, longrepr, report_properties,
    output, helper_when, record, metrics_path, started, stopped,
):
    if report is None:
        return None
    report.nodeid = item.nodeid
    _apply_native_budget(report, when, budget_failures, longrepr)
    _decorate_native_report(
        report, when, helper_when, report_properties, output, record, metrics_path,
    )
    carrier = _phase_report(
        item, when=when, outcome=report.outcome,
        started=float(getattr(report, "start", started)),
        stopped=float(getattr(report, "stop", stopped)),
        longrepr=report.longrepr, properties=report.user_properties,
    )
    extras = {name: value for name, value in vars(carrier).items() if name not in vars(report)}
    vars(carrier).update(vars(report))
    vars(carrier).update(extras)
    return carrier


def _apply_native_budget(report, when, budget_failures, longrepr) -> None:
    if when == "call" and budget_failures:
        report.outcome, report.longrepr = "failed", longrepr


def _decorate_native_report(
    report, when, helper_when, report_properties, output, record, metrics_path,
) -> None:
    if when not in ("call", helper_when):
        return
    report.user_properties = [*list(report.user_properties), *list(report_properties[:3])]
    if output and report.outcome != "passed":
        report.sections.append(("BriXTest helper", output))
    report.brixtest_metrics = record
    report.brixtest_metrics_path = str(metrics_path)


def _reported_phases(
    reports, definition, budget_failures, longrepr, output, helper_when, report_properties,
) -> list:
    phases = []
    for when in ("setup", "call", "teardown"):
        row = reports.get(when)
        if row is None:
            continue
        phases.append(_reported_phase(
            when, row, definition, budget_failures, longrepr, output,
            helper_when, report_properties,
        ))
    return phases


def _reported_phase(
    when, row, definition, budget_failures, longrepr, output, helper_when, report_properties,
) -> tuple:
    phase_outcome, phase_longrepr = _reported_outcome(
        when, row, definition, budget_failures, longrepr, output,
    )
    extra = {"wasxfail": row["wasxfail"]} if row.get("wasxfail") else {}
    selected = when in ("call", helper_when)
    return (
        when, phase_outcome, phase_longrepr, output if selected else "",
        report_properties if selected else (), extra,
    )


def _reported_outcome(when, row, definition, budget_failures, longrepr, output):
    phase_outcome = str(row["outcome"])
    if when == "call" and budget_failures:
        return "failed", longrepr
    if phase_outcome == "failed":
        return phase_outcome, output or str(row.get("longrepr", "helper phase failed"))
    if phase_outcome == "skipped":
        return phase_outcome, (
            str(definition.source), 0, str(row.get("reason", "")) or "skipped in helper",
        )
    return phase_outcome, None


def _fallback_phases(helper_when, outcome, longrepr, output, properties, extra) -> list:
    if helper_when == "setup" and outcome != "passed":
        return [
            ("setup", outcome, longrepr, output, properties, extra),
            ("teardown", "passed", None, "", (), {}),
        ]
    if helper_when == "teardown" and outcome != "passed":
        return [
            ("setup", "passed", None, "", (), {}),
            ("call", "passed", None, output, properties, {}),
            ("teardown", outcome, longrepr, "", (), extra),
        ]
    return [
        ("setup", "passed", None, "", (), {}),
        ("call", outcome, longrepr, output, properties, extra),
        ("teardown", "passed", None, "", (), {}),
    ]


def _emit_phases(item, phases, helper_when, started, stopped, record, metrics_path) -> None:
    instant = started
    for phase in phases:
        if isinstance(phase, pytest.TestReport):
            item.ihook.pytest_runtest_logreport(report=phase)
            continue
        when, outcome, longrepr, output, properties, extra = phase
        report = _phase_report(
            item, when=when, outcome=outcome,
            started=started if when == helper_when else instant,
            stopped=stopped if when == helper_when else instant,
            longrepr=longrepr, output=output, properties=properties, extra=extra,
        )
        if when in (helper_when, "call"):
            report.brixtest_metrics = record
            report.brixtest_metrics_path = str(metrics_path)
        item.ihook.pytest_runtest_logreport(report=report)


def _managed_definition(item):
    definition = _definition(item)
    if definition is None or _is_helper(item.config):
        return None
    return definition


def _phase_sequence(
    item, current, definition, budget_failures, longrepr, report_properties,
    output, helper_when, record, metrics_path, started, stopped, outcome, extra,
):
    native = _restored_reports(item, current.payload, current.timed_out)
    if native:
        return _native_phases(
            item, native, budget_failures, longrepr, report_properties,
            output, helper_when, record, metrics_path, started, stopped,
        )
    reports = _valid_reports(current.payload)
    if reports and not current.timed_out:
        return _reported_phases(
            reports, definition, budget_failures, longrepr, output,
            helper_when, report_properties,
        )
    return _fallback_phases(
        helper_when, outcome, longrepr, output, report_properties, extra,
    )


def _finish_topology(item) -> None:
    topology = item.config.stash.get(SHARED_TOPOLOGY, None)
    if topology is not None:
        topology.finished(item.nodeid)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    definition = _managed_definition(item)
    if definition is None:
        return None
    item.ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    invocations = execute(
        nodeid=item.nodeid, warmups=definition.warmup, trials=definition.trials,
        root_factory=lambda: _case_root(item),
        invoke=lambda root, **values: _run_helper(item, definition, root, **values),
    )
    current = invocations[-1]
    output = _combined_output(invocations)
    outcome, longrepr = _controller_outcome(item, definition, invocations, output)
    metrics, budget_failures, outcome, longrepr = _measured_outcome(
        item, invocations, outcome, longrepr,
    )
    record, metrics_path, report_properties, helper_when, extra = _publish_result(
        item, definition, invocations, outcome, longrepr, metrics, output,
    )
    phases = _phase_sequence(
        item, current, definition, budget_failures, longrepr, report_properties,
        output, helper_when, record, metrics_path, invocations[0].started,
        current.stopped, outcome, extra,
    )
    _emit_phases(
        item, phases, helper_when, invocations[0].started, current.stopped,
        record, metrics_path,
    )
    _finish_topology(item)
    item.ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
    return True

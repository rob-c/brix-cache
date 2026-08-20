"""Pytest integration: every ``@case`` executes in a supervised subprocess."""

from __future__ import annotations

import hashlib
import dataclasses
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Dict, Mapping, Optional, Set

import pytest

from brixtest import pytest_options
from brixtest.archive import (
    archive_case_logs,
    post_search_archive,
    write_sqlite_archive,
)
from brixtest.design import CaseDefinition, get_case, is_case
from brixtest.errors import HelperProcessError, SpecError
from brixtest.evidence.trials import attempt_record, execute, measured_metrics
from brixtest.evidence.export import post_otlp, upload_session_s3, write_parquet
from brixtest.isolation import build_launch
from brixtest.metrics import (
    MetricRecorder,
    build_case_record,
    evaluate_budget,
    publish_case_record,
    write_session_outputs,
)
from brixtest.pytest_metrics import pytest_terminal_summary as _terminal_summary
from brixtest.pytest_design import describe as _describe
from brixtest.pytest_hooks import register_hooks
from brixtest.pytest_state import (
    CASE_MANAGER,
    METRICS_PAYLOAD,
    METRICS_SESSION,
    PARQUET_PATH,
    S3_URI,
    SHARED_TOPOLOGY,
    SQLITE_PATH,
)
from brixtest.runtime.manager import CaseManager
from brixtest.runtime.logcapture import BoundedLogPump
from brixtest.topology import SharedTopology, merge_worker_topologies
from brixtest.test_policy import TestPolicyError, enforce as enforce_test_policy
from brixtest.runtime.testworker import execute as execute_test_worker

# Imported hooks are normal plugin attributes; the assignment also makes that
# intentional export explicit to static checkers.
pytest_terminal_summary = _terminal_summary
pytest_addoption = pytest_options.pytest_addoption
pytest_configure = pytest_options.pytest_configure
_is_helper = pytest_options.is_helper
_HELPER_ENV = pytest_options.HELPER_ENV
_RESULT_ENV = pytest_options.RESULT_ENV


def pytest_addhooks(pluginmanager) -> None:
    """Expose BriXTest planning and result hooks to cooperating pytest plugins."""
    register_hooks(pluginmanager)


def _definition(item) -> Optional[CaseDefinition]:
    target = getattr(item, "obj", None)
    if not is_case(target):
        return None
    definition = get_case(target)
    callspec = getattr(item, "callspec", None)
    parameters = getattr(callspec, "params", {})
    if parameters:
        return dataclasses.replace(definition, parameters=dict(parameters))
    return definition


def pytest_pycollect_makemodule(module_path, parent):
    config = parent.config
    helper_plugins = list(config.getoption("--brixtest-helper-plugin"))
    helper_plugins.extend(config.getini("brixtest_helper_plugins").split())
    safe_imports = list(config.getoption("--brixtest-safe-import"))
    safe_imports.extend(config.getini("brixtest_safe_imports").split())
    safe_imports.extend(name.split(".", 1)[0] for name in helper_plugins)
    try:
        enforce_test_policy(Path(str(module_path)), allowed_imports=safe_imports)
    except TestPolicyError as exc:
        raise pytest.UsageError("brixtest: %s" % exc) from exc
    return None


def pytest_collection_modifyitems(config, items) -> None:
    rows = []
    for item in items:
        definition = _definition(item)
        if definition is not None:
            rows.append((item.nodeid, definition))
            if not _is_helper(config):
                try:
                    pytest_options.selected_isolation(config, definition)
                except SpecError as exc:
                    raise pytest.UsageError("brixtest: %s" % exc) from exc
            item.add_marker("brixtest")
            item.ihook.pytest_brixtest_plan(item=item, definition=definition)
            if _is_helper(config):
                original_runtest = item.runtest

                def threaded_runtest(invoke=original_runtest):
                    return execute_test_worker(invoke)

                item.runtest = threaded_runtest
    if not _is_helper(config):
        try:
            session_dir = config.stash[METRICS_SESSION]
            worker = getattr(config, "workerinput", {}).get("workerid", "")
            topology_dir = session_dir / "workers" / worker if worker else session_dir
            config.stash[SHARED_TOPOLOGY] = SharedTopology.build(
                rows, topology_dir, case_session_dir=session_dir,
            )
        except SpecError as exc:
            raise pytest.UsageError("brixtest: %s" % exc) from exc


def _json_safe(value: object) -> object:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return str(value)
    return value


def _properties(value: object) -> list[list[object]]:
    if not isinstance(value, (list, tuple)):
        return []
    rows = []
    for item in value:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            rows.append([str(item[0]), _json_safe(item[1])])
    return rows


def _update_helper_result(update: Mapping[str, object]) -> None:
    path_value = os.environ.get(_RESULT_ENV)
    if not path_value or not os.environ.get(_HELPER_ENV):
        return
    path = Path(path_value)
    try:
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict):
            payload = {}
    except (OSError, ValueError, TypeError):
        payload = {}
    values = dict(update)
    phase = values.pop("_phase_report", None)
    if isinstance(phase, dict):
        reports = payload.setdefault("reports", [])
        if isinstance(reports, list):
            reports.append(phase)
    serialized = values.pop("_serialized_report", None)
    if isinstance(serialized, dict):
        reports = payload.setdefault("serialized_reports", [])
        if isinstance(reports, list):
            reports.append(serialized)
    payload.update(values)
    try:
        path.write_text(json.dumps(payload, sort_keys=True) + "\n")
    except OSError:
        pass


def pytest_collection_finish(session) -> None:
    if not session.config.getoption("--brixtest-describe") or _is_helper(session.config):
        return
    _describe(session, _definition)


def _safe_name(nodeid: str) -> str:
    digest = hashlib.sha256(nodeid.encode()).hexdigest()[:10]
    stem = "".join(char if char.isalnum() else "-" for char in nodeid)[-60:]
    return "%s-%s-%s" % (time.strftime("%Y%m%dT%H%M%S"), stem.strip("-"), digest)


def _case_root(item) -> Path:
    base = Path(os.environ.get(
        "BRIXTEST_RUNS", str(Path(tempfile.gettempdir()) / "brixtest-runs")
    )).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base / ("%s-%s" % (_safe_name(item.nodeid), uuid.uuid4().hex[:8]))


def _children(root: int) -> Set[int]:
    """Best-effort Linux descendant snapshot taken before the helper is killed."""
    parents: Dict[int, int] = {}
    proc = Path("/proc")
    if not proc.is_dir():
        return set()
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            tail = (entry / "stat").read_text().rpartition(")")[2].split()
            parents[int(entry.name)] = int(tail[1])
        except (OSError, ValueError, IndexError):
            continue
    descendants: Set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid not in descendants and (parent == root or parent in descendants):
                descendants.add(pid)
                changed = True
    return descendants


def _signal_tree(proc: subprocess.Popen, signum: int) -> None:
    descendants = _children(proc.pid)
    for pid in sorted(descendants, reverse=True):
        try:
            os.killpg(pid, signum)
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(pid, signum)
            except (ProcessLookupError, PermissionError):
                pass
    try:
        os.killpg(proc.pid, signum)
    except (ProcessLookupError, PermissionError):
        pass


def _run_helper(
    item, definition: CaseDefinition, run_root: Path, *, attempt_id: str,
    trial: int, warmup: bool,
):
    control = run_root.parent / ".brixtest-control" / uuid.uuid4().hex
    control.mkdir(parents=True, exist_ok=False)
    result_path = control / "result.json"
    result_path.write_text("{}\n")
    helper_log = control / "helper.log"
    env = dict(os.environ)
    env[_HELPER_ENV] = "1"
    env["BRIXTEST_CONTROLLER_PID"] = str(os.getpid())
    env[_RESULT_ENV] = str(result_path)
    env["BRIXTEST_CASE_RUN"] = str(run_root)
    env["BRIXTEST_ATTEMPT_ID"] = attempt_id
    env["BRIXTEST_TRIAL"] = str(trial)
    env["BRIXTEST_WARMUP"] = "1" if warmup else "0"
    topology = item.config.stash.get(SHARED_TOPOLOGY, None)
    if topology is not None:
        env["BRIXTEST_SHARED_SERVERS_JSON"] = json.dumps(topology.for_test(item.nodeid))
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    package_root = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = os.pathsep.join(
        value for value in (package_root, env.get("PYTHONPATH", "")) if value
    )
    argv = [
        sys.executable, "-m", "pytest", item.nodeid,
        "-p", "brixtest.pytest_plugin", "--brixtest-helper",
        "-q", "--tb=long",
    ]
    helper_plugins = list(item.config.getoption("--brixtest-helper-plugin"))
    helper_plugins.extend(item.config.getini("brixtest_helper_plugins").split())
    for selected in item.ihook.pytest_brixtest_helper_plugins(config=item.config, item=item):
        if selected is None:
            continue
        if isinstance(selected, str):
            helper_plugins.append(selected)
        else:
            helper_plugins.extend(selected)
    valid_plugin = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
    for plugin in dict.fromkeys(helper_plugins):
        if valid_plugin.fullmatch(plugin) is None:
            raise SpecError(
                "helper plugin", plugin,
                "must be an importable pytest plugin name",
            )
        argv.extend(("-p", plugin))
    safe_imports = list(item.config.getoption("--brixtest-safe-import"))
    safe_imports.extend(item.config.getini("brixtest_safe_imports").split())
    safe_imports.extend(plugin.split(".", 1)[0] for plugin in helper_plugins)
    for module_root in dict.fromkeys(safe_imports):
        argv.extend(("--brixtest-safe-import", module_root))
    isolation = pytest_options.selected_isolation(item.config, definition)
    env["BRIXTEST_ISOLATION_KIND"] = isolation.kind
    launch = build_launch(
        isolation, argv, env, cwd=Path(item.config.rootpath),
        readonly_roots=(Path(item.config.rootpath), Path(__file__).resolve().parents[1]),
        writable_root=run_root.parent, control_dir=control,
        host_aliases=definition.hosts,
    )
    started = time.time()
    timed_out = False
    process = subprocess.Popen(
        launch.argv, cwd=str(launch.cwd), env=launch.env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdout is not None
    helper_limit = int(item.config.getoption("--brixtest-helper-log-max-bytes"))
    pump = BoundedLogPump(process.stdout, helper_log, helper_limit)
    pump.start()
    try:
        process.wait(timeout=definition.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _signal_tree(process, signal.SIGTERM)
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            _signal_tree(process, signal.SIGKILL)
            process.wait()
    for cleanup in launch.cleanup:
        try:
            subprocess.run(
                cleanup, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not pump.join(timeout=1.0):
        _signal_tree(process, signal.SIGTERM)
        if not pump.join(timeout=0.5):
            _signal_tree(process, signal.SIGKILL)
            pump.join(timeout=0.5)
    try:
        payload_bytes = helper_log.read_bytes()
    except OSError:
        payload_bytes = b""
    display_limit = 1 << 20
    if len(payload_bytes) > display_limit:
        payload_bytes = payload_bytes[-display_limit:]
        output = "[BriXTest helper output truncated to final 1 MiB]\n"
    else:
        output = ""
    output += payload_bytes.decode("utf-8", errors="replace")
    try:
        payload = json.loads(result_path.read_text())
    except (OSError, ValueError, TypeError):
        payload = {}
    try:
        result_path.unlink()
    except OSError:
        pass
    logs = archive_case_logs(
        item.config.stash[METRICS_SESSION], item.nodeid, run_root,
        helper_log=helper_log, attempt_id=attempt_id,
    )
    shutil.rmtree(control, ignore_errors=True)
    return (
        process.returncode, output, payload, timed_out, started, time.time(),
        isolation.kind, logs,
    )


def _record_controller_failure(
    run_root: Path, item, definition: CaseDefinition, outcome: str, error: str,
    started: float, stopped: float,
) -> None:
    path = run_root / "summary.json"
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        payload = {
            "schema": 1, "nodeid": item.nodeid, "source": str(definition.source),
            "backend": os.environ.get("BRIXTEST_BACKEND", definition.backend),
            "run_root": str(run_root), "servers": {}, "artifacts": {},
            "binaries": {},
        }
    payload.update({
        "outcome": outcome, "error": error,
        "wall_seconds": round(stopped - started, 6),
    })
    try:
        run_root.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except OSError:
        pass


def _resource_log_tails(
    run_root: Path, definition: CaseDefinition, *, limit: int = 64 << 10,
) -> str:
    """Return bounded, labelled tails from resource logs for failure diagnostics."""
    roots = (run_root / "runtime" / "logs", run_root / "runtime" / "client-logs")
    sections = []
    used = 0
    policies = {
        run_root / "runtime" / "logs" / (item.name + ".log"): item.logs
        for item in definition.servers
    }
    for item in definition.clients:
        client_root = run_root / "runtime" / "client-logs" / item.name
        for path in client_root.glob("*.log") if client_root.is_dir() else ():
            policies[path] = item.logs
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.log")):
            try:
                lines = getattr(policies.get(path), "tail_lines", 40)
                if lines == 0:
                    continue
                tail = "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
            except OSError:
                continue
            if not tail:
                continue
            section = "--- %s ---\n%s" % (path.relative_to(run_root), tail)
            encoded = section.encode("utf-8", errors="replace")
            if used + len(encoded) > limit:
                sections.append("[additional resource log tails omitted]")
                return "\n".join(sections)
            sections.append(section)
            used += len(encoded)
    return "\n".join(sections)


def _cleanup_timed_out_kubernetes(definition: CaseDefinition, run_root: Path) -> None:
    selected = os.environ.get("BRIXTEST_BACKEND", definition.backend)
    if selected not in ("kubernetes", "minikube"):
        return
    namespace = "brixtest-%s" % run_root.name.lower().replace("_", "-")[-40:]
    kubectl = os.environ.get("BRIXTEST_KUBECTL", "kubectl")
    try:
        argv = [kubectl]
        if selected == "minikube":
            argv.extend((
                "--context", os.environ.get("BRIXTEST_MINIKUBE_PROFILE", "brixtest"),
            ))
        argv.extend(("delete", "namespace", namespace, "--wait=false"))
        subprocess.run(
            argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _budget_failures(item, metrics: Mapping[str, object]) -> list[str]:
    failures = []
    for marker in item.iter_markers("brixtest_budget"):
        try:
            if len(marker.args) != 1 or not isinstance(marker.args[0], str):
                raise SpecError(
                    "brixtest_budget", marker.args,
                    "needs exactly one positional metric name",
                )
            unexpected = set(marker.kwargs) - {"min", "max", "aggregate", "labels"}
            if unexpected:
                raise SpecError(
                    "brixtest_budget options", sorted(unexpected),
                    "known: min, max, aggregate, labels",
                )
            failure = evaluate_budget(
                metrics, marker.args[0], minimum=marker.kwargs.get("min"),
                maximum=marker.kwargs.get("max"),
                aggregate=marker.kwargs.get("aggregate", "last"),
                labels=marker.kwargs.get("labels"),
            )
            if failure:
                failures.append(failure)
        except SpecError as exc:
            failures.append(str(exc))
    return failures


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
    def phase_call() -> None:
        if outcome == "failed":
            raise AssertionError(str(longrepr or "BriXTest helper phase failed"))
        if outcome == "skipped":
            reason = longrepr[2] if isinstance(longrepr, tuple) else str(longrepr or "skipped")
            pytest.skip(reason)

    call = pytest.CallInfo.from_call(phase_call, when=when)
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


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    definition = _definition(item)
    if definition is None or _is_helper(item.config):
        return None
    item.ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    invocations = execute(
        nodeid=item.nodeid, warmups=definition.warmup, trials=definition.trials,
        root_factory=lambda: _case_root(item),
        invoke=lambda root, **values: _run_helper(item, definition, root, **values),
    )
    current = invocations[-1]
    run_root = current.run_root
    returncode, payload, timed_out = current.returncode, current.payload, current.timed_out
    started, stopped, isolation = invocations[0].started, current.stopped, current.isolation
    output = "\n".join(
        "=== %s %d (%s) ===\n%s" % (
            "warmup" if row.warmup else "trial", row.trial, row.attempt_id[:12], row.output
        ) for row in invocations if row.output
    )
    logs = [dict(log) for row in invocations for log in row.logs]
    outcome = payload.get("outcome", "passed" if returncode == 0 else "failed")
    if outcome not in ("passed", "failed", "skipped"):
        outcome = "failed"
    longrepr = None
    if timed_out:
        outcome = "failed"
        timeout_error = str(HelperProcessError(
            item.nodeid, timeout=definition.timeout, output=output,
            run_path=str(run_root),
        ))
        longrepr = timeout_error
        _record_controller_failure(
            run_root, item, definition, "timed-out", timeout_error, started, stopped
        )
        _cleanup_timed_out_kubernetes(definition, run_root)
    elif returncode != 0 or outcome == "failed":
        outcome = "failed"
        longrepr = output or str(HelperProcessError(
            item.nodeid, returncode=returncode, run_path=str(run_root)
        ))
        tails = _resource_log_tails(run_root, definition)
        if tails:
            longrepr = "%s\n\nBriXTest resource log tails\n%s" % (longrepr, tails)
        if not (run_root / "summary.json").is_file():
            _record_controller_failure(
                run_root, item, definition, "crashed", str(longrepr), started, stopped
            )
    elif outcome == "skipped":
        longrepr = (str(definition.source), 0, payload.get("reason", "skipped in helper"))
    metrics = measured_metrics(invocations)
    if not metrics.get("samples"):
        metrics = _fallback_metrics(stopped - started, outcome)
    budget_failures = []
    if outcome == "passed":
        budget_failures = _budget_failures(item, metrics)
        if budget_failures:
            outcome = "failed"
            longrepr = "\n".join(budget_failures)
    properties = _properties(payload.get("user_properties", []))
    session_dir = item.config.stash[METRICS_SESSION]
    selected_backend = os.environ.get("BRIXTEST_BACKEND", definition.backend)
    record = build_case_record(
        session_id=session_dir.name, nodeid=item.nodeid, outcome=outcome,
        backend=selected_backend, run_root=str(run_root), started_at=started,
        stopped_at=stopped, metrics=metrics, properties=properties,
        error=str(longrepr or ""), attempts=[attempt_record(row) for row in invocations],
    )
    replay = {
        "argv": [sys.executable, "-m", "pytest", item.nodeid,
                 *pytest_options.replay_options(
                     item.config, pytest_options.selected_isolation(item.config, definition)
                 )],
        "cwd": str(item.config.rootpath),
    }
    record.update({"isolation": isolation, "logs": logs, "replay": replay})
    item.ihook.pytest_brixtest_result(item=item, record=record)
    metrics_path = publish_case_record(session_dir, record)
    extra = {}
    if payload.get("wasxfail"):
        extra["wasxfail"] = payload["wasxfail"]
    report_properties = tuple([
        ("brixtest_run", str(run_root)),
        ("brixtest_metrics", str(metrics_path)),
        ("brixtest_rerun", shlex.join([
            "brixtest", "rerun", str(session_dir), "--test", item.nodeid,
        ])),
        *[(str(row[0]), row[1]) for row in properties],
    ])
    helper_when = str(payload.get("when", "call"))
    if helper_when not in ("setup", "call", "teardown"):
        helper_when = "call"
    if timed_out or returncode != 0 and not payload:
        helper_when = "call"

    phases = []
    instant = started
    helper_reports = payload.get("reports", [])
    valid_reports = {
        str(row.get("when")): row for row in helper_reports
        if isinstance(row, dict)
        and row.get("when") in ("setup", "call", "teardown")
        and row.get("outcome") in ("passed", "failed", "skipped")
    } if isinstance(helper_reports, list) else {}
    serialized_reports = payload.get("serialized_reports", [])
    native_reports = {}
    if isinstance(serialized_reports, list) and not timed_out:
        for data in serialized_reports:
            if not isinstance(data, dict):
                continue
            try:
                restored = item.config.hook.pytest_report_from_serializable(
                    config=item.config, data=data,
                )
            except Exception:
                restored = None
            if (
                isinstance(restored, pytest.TestReport)
                and restored.when in ("setup", "call", "teardown")
                and restored.outcome in ("passed", "failed", "skipped")
            ):
                native_reports[restored.when] = restored
    if native_reports and not timed_out:
        for when in ("setup", "call", "teardown"):
            report = native_reports.get(when)
            if report is None:
                continue
            report.nodeid = item.nodeid
            if when == "call" and budget_failures:
                report.outcome = "failed"
                report.longrepr = longrepr
            if when in ("call", helper_when):
                report.user_properties = [
                    *list(report.user_properties), *list(report_properties[:3]),
                ]
                if output and report.outcome != "passed":
                    report.sections.append(("BriXTest helper", output))
                report.brixtest_metrics = record
                report.brixtest_metrics_path = str(metrics_path)
            # Re-enter the controller's normal makereport hook chain for
            # cooperating plugins, then overlay the losslessly deserialized
            # helper report (including third-party serialized attributes).
            carrier = _phase_report(
                item, when=when, outcome=report.outcome,
                started=float(getattr(report, "start", started)),
                stopped=float(getattr(report, "stop", stopped)),
                longrepr=report.longrepr, properties=report.user_properties,
            )
            controller_extras = {
                name: value for name, value in vars(carrier).items()
                if name not in vars(report)
            }
            vars(carrier).update(vars(report))
            vars(carrier).update(controller_extras)
            phases.append(carrier)
    elif valid_reports and not timed_out:
        for when in ("setup", "call", "teardown"):
            row = valid_reports.get(when)
            if row is None:
                continue
            phase_outcome = str(row["outcome"])
            reason = str(row.get("reason", ""))
            phase_longrepr = None
            if when == "call" and budget_failures:
                phase_outcome = "failed"
                phase_longrepr = longrepr
            elif phase_outcome == "failed":
                phase_longrepr = output or str(row.get("longrepr", "helper phase failed"))
            elif phase_outcome == "skipped":
                phase_longrepr = (str(definition.source), 0, reason or "skipped in helper")
            phase_extra = {"wasxfail": row["wasxfail"]} if row.get("wasxfail") else {}
            phases.append((
                when, phase_outcome, phase_longrepr,
                output if when in ("call", helper_when) else "",
                report_properties if when in ("call", helper_when) else (), phase_extra,
            ))
    elif helper_when == "setup" and outcome != "passed":
        phases.append(("setup", outcome, longrepr, output, report_properties, extra))
        phases.append(("teardown", "passed", None, "", (), {}))
    elif helper_when == "teardown" and outcome != "passed":
        phases.append(("setup", "passed", None, "", (), {}))
        phases.append(("call", "passed", None, output, report_properties, {}))
        phases.append(("teardown", outcome, longrepr, "", (), extra))
    else:
        phases.append(("setup", "passed", None, "", (), {}))
        phases.append(("call", outcome, longrepr, output, report_properties, extra))
        phases.append(("teardown", "passed", None, "", (), {}))

    for phase in phases:
        if isinstance(phase, pytest.TestReport):
            item.ihook.pytest_runtest_logreport(report=phase)
            continue
        when, phase_outcome, phase_longrepr, phase_output, phase_properties, phase_extra = phase
        phase_started = started if when == helper_when else instant
        phase_stopped = stopped if when == helper_when else instant
        report = _phase_report(
            item, when=when, outcome=phase_outcome,
            started=phase_started, stopped=phase_stopped,
            longrepr=phase_longrepr, output=phase_output,
            properties=phase_properties, extra=phase_extra,
        )
        if when == helper_when or when == "call":
            report.brixtest_metrics = record
            report.brixtest_metrics_path = str(metrics_path)
        item.ihook.pytest_runtest_logreport(report=report)
    topology = item.config.stash.get(SHARED_TOPOLOGY, None)
    if topology is not None:
        topology.finished(item.nodeid)
    item.ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
    return True


@pytest.fixture
def run(request):
    definition = _definition(request.node)
    if definition is None:
        raise SpecError(
            "run fixture", request.node.nodeid,
            "is reserved for functions decorated with @brixtest.case",
        )
    if not _is_helper(request.config):
        raise SpecError(
            "run fixture", request.node.nodeid,
            "managed cases may execute only in a BriXTest helper",
        )
    manager = CaseManager(definition, request.node.nodeid)
    manager._set_pytest_hook(request.node.ihook)
    request.node.stash[CASE_MANAGER] = manager
    value = manager.start()
    for server_value in value.servers.values():
        request.node.ihook.pytest_brixtest_server_ready(
            run=value, server=server_value,
        )
    for artifact_value in value.artifacts.values():
        request.node.ihook.pytest_brixtest_artifact_materialized(
            run=value, artifact=artifact_value,
        )
    try:
        yield value
    finally:
        servers = tuple(value.servers.values())
        failure = None
        try:
            manager.close()
        except BaseException as exc:
            failure = exc
        for server_value in servers:
            request.node.ihook.pytest_brixtest_server_stopped(
                run=value, server=server_value, error=str(failure or ""),
            )
        if failure is not None:
            raise failure


@pytest.fixture
def brixtest_metrics(run):
    """Explicit pytest fixture alias for the managed case's metrics recorder."""
    return run.metrics


@pytest.fixture
def metrics(brixtest_metrics):
    """Concise fixture alias; equivalent to ``run.metrics``."""
    return brixtest_metrics


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    manager = item.stash.get(CASE_MANAGER, None)
    if manager is not None:
        manager.metrics.observe(
            "pytest.phase_time", report.duration, unit="s", labels={"phase": report.when}
        )
        if report.when == "call":
            manager.set_outcome(report.outcome)
        _update_helper_result({
            "metrics": manager.metrics.snapshot(),
            "evidence": manager.evidence.snapshot(),
            "user_properties": _properties(report.user_properties),
        })
    if _is_helper(item.config):
        serialized = item.config.hook.pytest_report_to_serializable(
            config=item.config, report=report,
        )
        if isinstance(serialized, dict):
            _update_helper_result({"_serialized_report": serialized})


def pytest_runtest_logreport(report) -> None:
    if not os.environ.get(_HELPER_ENV):
        return
    reason = ""
    if report.outcome == "skipped" and isinstance(report.longrepr, tuple):
        reason = str(report.longrepr[2])
    update = {"_phase_report": {
        "nodeid": report.nodeid, "outcome": report.outcome,
        "when": report.when, "reason": reason,
        "wasxfail": getattr(report, "wasxfail", ""),
        "longrepr": str(report.longrepr) if report.longrepr else "",
        "user_properties": _properties(report.user_properties),
    }}
    if _is_relevant_report(report):
        update.update({
            "nodeid": report.nodeid, "outcome": report.outcome,
            "when": report.when, "reason": reason,
            "wasxfail": getattr(report, "wasxfail", ""),
            "user_properties": _properties(report.user_properties),
        })
    _update_helper_result(update)


def _is_relevant_report(report) -> bool:
    if report.when == "call":
        return True
    return report.when in ("setup", "teardown") and report.outcome in ("failed", "skipped")


def _is_controller(config) -> bool:
    return not _is_helper(config) and not hasattr(config, "workerinput")


def pytest_sessionfinish(session, exitstatus) -> None:
    config = session.config
    if _is_helper(config):
        return
    session_dir = config.stash[METRICS_SESSION]
    topology = config.stash.get(SHARED_TOPOLOGY, None)
    if topology is not None:
        pools = topology.close()
        failed_pools = [
            row for row in pools
            if row.get("services") and row.get("result", {}).get("outcome") != "passed"
        ]
        if failed_pools:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
            exitstatus = int(pytest.ExitCode.TESTS_FAILED)
            terminal = config.pluginmanager.get_plugin("terminalreporter")
            if terminal is not None:
                terminal.write_line(
                    "BriXTest: %d shared server pool(s) failed monitoring/teardown" %
                    len(failed_pools), red=True,
                )
    if hasattr(config, "workerinput"):
        return
    pools = merge_worker_topologies(session_dir)
    failed_pools = [
        row for row in pools
        if row.get("services") and row.get("result", {}).get("outcome") != "passed"
    ]
    if failed_pools:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        exitstatus = int(pytest.ExitCode.TESTS_FAILED)
    explicit_json = config.getoption("--brixtest-metrics-json")
    explicit_html = config.getoption("--brixtest-metrics-html")
    if not (session_dir / "cases").is_dir() and not explicit_json and not explicit_html:
        return
    config.stash[METRICS_PAYLOAD] = write_session_outputs(
        session_dir, exitstatus=int(exitstatus),
        json_path=Path(explicit_json).resolve() if explicit_json else None,
        html_path=Path(explicit_html).resolve() if explicit_html else None,
    )
    payload = config.stash[METRICS_PAYLOAD]
    sqlite_option = config.getoption("--brixtest-sqlite")
    sqlite_path = Path(sqlite_option).resolve() if sqlite_option else session_dir / "archive.sqlite3"
    config.stash[SQLITE_PATH] = write_sqlite_archive(payload, session_dir, sqlite_path)
    search_url = config.getoption("--brixtest-search-url")
    if search_url:
        post_search_archive(
            payload, session_dir, search_url,
            index=config.getoption("--brixtest-search-index"),
            manage_schema=config.getoption("--brixtest-search-manage-schema"),
        )
    parquet = config.getoption("--brixtest-parquet")
    if parquet:
        config.stash[PARQUET_PATH] = write_parquet(payload, Path(parquet).resolve())
    otlp = config.getoption("--brixtest-otlp-endpoint")
    if otlp:
        post_otlp(payload, otlp)
    s3 = config.getoption("--brixtest-s3")
    if s3:
        config.stash[S3_URI] = upload_session_s3(session_dir, s3)

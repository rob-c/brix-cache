"""Pytest integration: every ``@case`` executes in a supervised subprocess."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
from pathlib import Path
from typing import Mapping, Optional

import pytest

from brixtest import pytest_options
from brixtest.archive import (
    post_search_archive,
    write_sqlite_archive,
)
from brixtest.design import CaseDefinition, get_case, is_case
from brixtest.errors import SpecError
from brixtest.evidence.export import post_otlp, upload_session_s3, write_parquet
from brixtest.helper_control import start_helper_heartbeat, stop_helper_heartbeat
from brixtest.helper_transport import publish as publish_helper_message
from brixtest.metrics import (
    write_session_outputs,
)
from brixtest.pytest_design import describe as _describe
from brixtest.pytest_hooks import register_hooks
from brixtest.pytest_metrics import pytest_terminal_summary as _terminal_summary
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
from brixtest.runtime.testworker import execute as execute_test_worker
from brixtest.test_policy import TestPolicyError
from brixtest.test_policy import enforce as enforce_test_policy
from brixtest.topology import SharedTopology, merge_worker_topologies

# Imported hooks are normal plugin attributes; the assignment also makes that
# intentional export explicit to static checkers.
pytest_terminal_summary = _terminal_summary
pytest_addoption = pytest_options.pytest_addoption
_is_helper = pytest_options.is_helper
_HELPER_ENV = pytest_options.HELPER_ENV
_RESULT_ENV = pytest_options.RESULT_ENV


def pytest_configure(config) -> None:
    pytest_options.pytest_configure(config)
    if _is_helper(config):
        start_helper_heartbeat()


def pytest_unconfigure(config) -> None:
    if _is_helper(config):
        stop_helper_heartbeat()


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node) -> None:
    """Give each xdist worker access to one controller-owned topology broker."""
    from brixtest.topology.broker import TopologyBroker

    config = node.config
    broker = config.stash.get(SHARED_TOPOLOGY, None)
    if broker is None:
        broker = TopologyBroker(config.stash[METRICS_SESSION])
        config.stash[SHARED_TOPOLOGY] = broker
    worker = str(node.workerinput.get("workerid", node.gateway.id))
    expected = int(node.workerinput.get("workercount", 1))
    node.workerinput["brixtest_topology"] = dict(
        broker.worker_settings(worker, expected),
    )


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


def pytest_collection_modifyitems(config, items) -> None:
    rows = []
    for item in items:
        row = _prepare_managed_item(config, item)
        if row is not None:
            rows.append(row)
    if not _is_helper(config):
        _build_shared_topology(config, rows)


def _threaded_runtest(invoke):
    return execute_test_worker(invoke)


def _prepare_managed_item(config, item):
    definition = _definition(item)
    if definition is None:
        return None
    if not _is_helper(config):
        try:
            pytest_options.selected_isolation(config, definition)
        except SpecError as exc:
            raise pytest.UsageError("brixtest: %s" % exc) from exc
    item.add_marker("brixtest")
    item.ihook.pytest_brixtest_plan(item=item, definition=definition)
    if _is_helper(config):
        original = item.runtest
        item.runtest = lambda: _threaded_runtest(original)
    return item.nodeid, definition


def _build_shared_topology(config, rows) -> None:
    try:
        session_dir = config.stash[METRICS_SESSION]
        settings = getattr(config, "workerinput", {}).get("brixtest_topology")
        if settings:
            _register_remote_topology(config, rows, settings)
        else:
            config.stash[SHARED_TOPOLOGY] = SharedTopology.build(
                rows, session_dir, case_session_dir=session_dir,
            )
    except SpecError as exc:
        raise pytest.UsageError("brixtest: %s" % exc) from exc


def _register_remote_topology(config, rows, settings) -> None:
    from brixtest.topology.broker import RemoteTopology

    topology = RemoteTopology(
        str(settings["address"]), str(settings["token"]), str(settings["worker"]),
    )
    topology.register(rows, int(settings["expected"]))
    config.stash[SHARED_TOPOLOGY] = topology


def _json_safe(value: object) -> object:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return str(value)
    return value


def _properties(value: object) -> list[list[object]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [
        [str(item[0]), _json_safe(item[1])]
        for item in value
        if isinstance(item, (list, tuple)) and len(item) >= 2
    ]


def _update_helper_result(update: Mapping[str, object]) -> None:
    path_value = os.environ.get(_RESULT_ENV)
    if not path_value or not os.environ.get(_HELPER_ENV):
        return
    path = Path(path_value)
    payload = _helper_result_payload(path)
    values = dict(update)
    _append_helper_report(payload, values, "_phase_report", "reports")
    _append_helper_report(
        payload, values, "_serialized_report", "serialized_reports",
    )
    payload.update(values)
    with contextlib.suppress(OSError):
        path.write_text(json.dumps(payload, sort_keys=True) + "\n")
    publish_helper_message("result", payload)


def _helper_result_payload(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _append_helper_report(
    payload: dict, values: dict, source: str, destination: str,
) -> None:
    report = values.pop(source, None)
    if not isinstance(report, dict):
        return
    reports = payload.setdefault(destination, [])
    if isinstance(reports, list):
        reports.append(report)


def pytest_collection_finish(session) -> None:
    if not session.config.getoption("--brixtest-describe") or _is_helper(session.config):
        return
    _describe(session, _definition)



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
    _notify_started_resources(request.node, value)
    try:
        yield value
    finally:
        _finish_managed_run(request.node, manager, value)


def _notify_started_resources(node, value) -> None:
    for server_value in value.servers.values():
        node.ihook.pytest_brixtest_server_ready(
            run=value, server=server_value,
        )
    for artifact_value in value.artifacts.values():
        node.ihook.pytest_brixtest_artifact_materialized(
            run=value, artifact=artifact_value,
        )


def _finish_managed_run(node, manager, value) -> None:
    servers = tuple(value.servers.values())
    failure = None
    try:
        manager.close()
    except BaseException as exc:
        failure = exc
    for server_value in servers:
        node.ihook.pytest_brixtest_server_stopped(
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


def _failed_pools(pools) -> list:
    return [
        row for row in pools
        if row.get("services") and row.get("result", {}).get("outcome") != "passed"
    ]


def _close_session_topology(session, exitstatus: int) -> int:
    config = session.config
    if hasattr(config, "workerinput"):
        return exitstatus
    topology = config.stash.get(SHARED_TOPOLOGY, None)
    failed = _failed_pools(topology.close()) if topology is not None else []
    if not failed:
        return exitstatus
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    terminal = config.pluginmanager.get_plugin("terminalreporter")
    if terminal is not None:
        terminal.write_line(
            "BriXTest: %d shared server pool(s) failed monitoring/teardown" % len(failed),
            red=True,
        )
    return int(pytest.ExitCode.TESTS_FAILED)


def _publish_session_archives(config, session_dir, payload) -> None:
    sqlite_option = config.getoption("--brixtest-sqlite")
    sqlite_path = Path(sqlite_option).resolve() if sqlite_option \
        else session_dir / "archive.sqlite3"
    config.stash[SQLITE_PATH] = write_sqlite_archive(payload, session_dir, sqlite_path)
    _publish_search_archive(config, session_dir, payload)
    _publish_parquet(config, payload)
    _publish_otlp(config, payload)
    _publish_s3(config, session_dir)


def _publish_search_archive(config, session_dir, payload) -> None:
    search_url = config.getoption("--brixtest-search-url")
    if search_url:
        post_search_archive(
            payload, session_dir, search_url,
            index=config.getoption("--brixtest-search-index"),
            manage_schema=config.getoption("--brixtest-search-manage-schema"),
        )


def _publish_parquet(config, payload) -> None:
    parquet = config.getoption("--brixtest-parquet")
    if parquet:
        config.stash[PARQUET_PATH] = write_parquet(payload, Path(parquet).resolve())


def _publish_otlp(config, payload) -> None:
    otlp = config.getoption("--brixtest-otlp-endpoint")
    if otlp:
        post_otlp(payload, otlp)


def _publish_s3(config, session_dir) -> None:
    s3 = config.getoption("--brixtest-s3")
    if s3:
        config.stash[S3_URI] = upload_session_s3(session_dir, s3)


def pytest_sessionfinish(session, exitstatus) -> None:
    config = session.config
    if _is_helper(config):
        stop_helper_heartbeat()
        return
    session_dir = config.stash[METRICS_SESSION]
    exitstatus = _close_session_topology(session, int(exitstatus))
    if hasattr(config, "workerinput"):
        return
    exitstatus = _merged_topology_exitstatus(session, session_dir, exitstatus)
    explicit_json = config.getoption("--brixtest-metrics-json")
    explicit_html = config.getoption("--brixtest-metrics-html")
    if not _needs_session_outputs(session_dir, explicit_json, explicit_html):
        return
    config.stash[METRICS_PAYLOAD] = write_session_outputs(
        session_dir, exitstatus=int(exitstatus),
        json_path=Path(explicit_json).resolve() if explicit_json else None,
        html_path=Path(explicit_html).resolve() if explicit_html else None,
    )
    payload = config.stash[METRICS_PAYLOAD]
    _publish_session_archives(config, session_dir, payload)


def _merged_topology_exitstatus(session, session_dir: Path, exitstatus: int) -> int:
    failed_pools = _failed_pools(merge_worker_topologies(session_dir))
    if not failed_pools:
        return int(exitstatus)
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    return int(pytest.ExitCode.TESTS_FAILED)


def _needs_session_outputs(
    session_dir: Path, explicit_json: object, explicit_html: object,
) -> bool:
    return (session_dir / "cases").is_dir() or bool(explicit_json) or bool(explicit_html)


from brixtest.pytest_protocol import (  # noqa: E402 - imports plugin helpers
    pytest_runtest_protocol as pytest_runtest_protocol,
)

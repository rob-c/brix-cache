"""Black-box guarantees that BriXTest remains a pytest enhancement."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run(tmp_path: Path, source: str, *, plugins=(), extra=()):
    test_file = tmp_path / "test_managed.py"
    test_file.write_text(source)
    package = Path(__file__).resolve().parents[1] / "src"
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("BRIXTEST_")
    }
    env.update({
        "PYTHONPATH": os.pathsep.join((str(tmp_path), str(package))),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPYCACHEPREFIX": str(tmp_path / "pycache"),
        "BRIXTEST_RUNS": str(tmp_path / "runs"),
        "PHASES": str(tmp_path / "phases.jsonl"),
    })
    argv = [
        sys.executable, "-m", "pytest", str(test_file),
        "-p", "brixtest.pytest_plugin", "-q", *extra,
    ]
    for plugin in plugins:
        argv.extend(("-p", plugin))
    return subprocess.run(
        argv, cwd=tmp_path, env=env, capture_output=True, text=True,
        timeout=60, check=False,
    )


def test_standard_fixtures_parametrize_yield_and_worker_thread_are_preserved(tmp_path):
    result = _run(tmp_path, """
import logging
import sys
import threading
import pytest
from brixtest import case, client

READER = client(
    "reader", command=[sys.executable, "-c", "import os;print(os.environ['VALUE'])"],
    env={"VALUE": "{param_value}"},
)

@pytest.fixture
def prepared(tmp_path, monkeypatch, request):
    monkeypatch.setenv("FIXTURE_VALUE", request.node.callspec.params["value"])
    marker = tmp_path / "yielded"
    yield marker
    marker.write_text("closed")

@pytest.mark.parametrize("value", ["one", "two"])
@case(clients=[READER], observe=[], keep="never")
def test_managed(run, value, prepared, caplog, request):
    import os
    assert os.environ["FIXTURE_VALUE"] == value
    assert request.node.callspec.params["value"] == value
    assert threading.current_thread().name == "brixtest-test-worker"
    with caplog.at_level(logging.INFO):
        logging.getLogger("managed").info("value=%s", value)
    assert "value=" + value in caplog.text
    assert prepared.parent.is_dir()
    assert run.client(READER).run().stdout.strip() == value
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 passed" in result.stdout


def test_trusted_helper_plugin_participates_in_normal_pytest_call_chain(tmp_path):
    (tmp_path / "helper_adapter.py").write_text("""
import os
import pytest

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    os.environ["HELPER_ADAPTER_ACTIVE"] = "yes"
    yield
""")
    result = _run(tmp_path, """
from brixtest import case

@case(observe=[], keep="never")
def test_adapter(run):
    import os
    assert os.environ["HELPER_ADAPTER_ACTIVE"] == "yes"
""", extra=("--brixtest-helper-plugin", "helper_adapter"))
    assert result.returncode == 0, result.stdout + result.stderr


def test_controller_makereport_hooks_receive_setup_call_and_teardown(tmp_path):
    (tmp_path / "phase_observer.py").write_text("""
import json
import os
from pathlib import Path
import pytest

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if not os.environ.get("BRIXTEST_HELPER"):
        path = Path(os.environ["PHASES"])
        with path.open("a") as handle:
            handle.write(json.dumps({"when": report.when, "outcome": report.outcome}) + "\\n")
""")
    result = _run(tmp_path, """
from brixtest import case

@case(observe=[], keep="never")
def test_phases(run):
    assert True
""", plugins=("phase_observer",))
    assert result.returncode == 0, result.stdout + result.stderr
    phases = [json.loads(line) for line in (tmp_path / "phases.jsonl").read_text().splitlines()]
    assert phases == [
        {"when": "setup", "outcome": "passed"},
        {"when": "call", "outcome": "passed"},
        {"when": "teardown", "outcome": "passed"},
    ]


def test_pytest_report_serialization_hooks_preserve_plugin_fields(tmp_path):
    (tmp_path / "report_adapter.py").write_text("""
import json
import os
from pathlib import Path
import pytest

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if os.environ.get("BRIXTEST_HELPER"):
        report.adapter_value = "helper-" + report.when

@pytest.hookimpl(hookwrapper=True)
def pytest_report_to_serializable(config, report):
    outcome = yield
    data = outcome.get_result()
    if isinstance(data, dict) and hasattr(report, "adapter_value"):
        data["adapter_value"] = report.adapter_value

@pytest.hookimpl(hookwrapper=True)
def pytest_report_from_serializable(config, data):
    outcome = yield
    report = outcome.get_result()
    if report is not None and "adapter_value" in data:
        report.adapter_value = data["adapter_value"]

def pytest_runtest_logreport(report):
    if os.environ.get("BRIXTEST_HELPER"):
        return
    path = Path(os.environ["PHASES"])
    with path.open("a") as handle:
        handle.write(json.dumps({"when": report.when, "adapter": getattr(report, "adapter_value", "")}) + "\\n")
""")
    result = _run(tmp_path, """
from brixtest import case

@case(observe=[], keep="never")
def test_report_transport(run):
    assert True
""", plugins=("report_adapter",), extra=("--brixtest-helper-plugin", "report_adapter"))
    assert result.returncode == 0, result.stdout + result.stderr
    phases = [json.loads(line) for line in (tmp_path / "phases.jsonl").read_text().splitlines()]
    assert phases == [
        {"when": "setup", "adapter": "helper-setup"},
        {"when": "call", "adapter": "helper-call"},
        {"when": "teardown", "adapter": "helper-teardown"},
    ]


def test_resource_lifecycle_hooks_run_inside_the_supervised_helper(tmp_path):
    (tmp_path / "lifecycle_adapter.py").write_text("""
import json
import os
from pathlib import Path

def record(event, name):
    with Path(os.environ["PHASES"]).open("a") as handle:
        handle.write(json.dumps({"event": event, "name": name}) + "\\n")

def pytest_brixtest_server_ready(run, server):
    record("server-ready", server.name)

def pytest_brixtest_server_stopped(run, server, error):
    assert not error
    record("server-stopped", server.name)

def pytest_brixtest_tool_result(run, tool, result):
    assert result.returncode == 0
    record("tool-result", tool.name)

def pytest_brixtest_artifact_materialized(run, artifact):
    assert artifact.verify()
    record("artifact", artifact.name)
""")
    result = _run(tmp_path, """
import sys
from brixtest import case, server, text_artifact, tool

SERVER_CODE = (
    "import http.server,sys;"
    "http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),"
    "http.server.SimpleHTTPRequestHandler).serve_forever()"
)
ORIGIN = server(
    "origin", command=[sys.executable, "-u", "-c", SERVER_CODE, "{port}"],
)
INPUT = text_artifact("input", "payload")
CHECK = tool("check", command=[sys.executable, "-c", "print('ok')"])

@case(ORIGIN, INPUT, CHECK, observe=[], keep="never")
def test_lifecycle(run):
    assert run.tool(CHECK).run().stdout.strip() == "ok"
""", plugins=("lifecycle_adapter",), extra=(
        "--brixtest-helper-plugin", "lifecycle_adapter",
    ))
    assert result.returncode == 0, result.stdout + result.stderr
    events = [json.loads(line) for line in (tmp_path / "phases.jsonl").read_text().splitlines()]
    assert events == [
        {"event": "server-ready", "name": "origin"},
        {"event": "artifact", "name": "input"},
        {"event": "tool-result", "name": "check"},
        {"event": "server-stopped", "name": "origin"},
    ]


def test_skip_xfail_and_fixture_setup_errors_keep_pytest_outcomes(tmp_path):
    result = _run(tmp_path, """
import pytest
from brixtest import case

@pytest.fixture
def broken():
    raise RuntimeError("fixture setup trace")

@case(observe=[], keep="never")
def test_skip(run):
    pytest.skip("managed skip")

@pytest.mark.xfail(reason="managed xfail")
@case(observe=[], keep="never")
def test_xfail(run):
    assert False

@case(observe=[], keep="never")
def test_setup_error(run, broken):
    pass
""")
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "fixture setup trace" in combined
    assert ("1 failed" in combined or "1 error" in combined)
    assert "1 skipped" in combined and "1 xfailed" in combined

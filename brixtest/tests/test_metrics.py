"""Executable examples for BriXTest's first-class pytest metrics surface."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from brixtest import MetricRecorder, case
from brixtest.errors import SpecError


@pytest.mark.brixtest_budget("transfer.throughput", min=100, max=200)
@case(timeout=20, keep="never")
def test_pythonic_metrics_are_part_of_the_run(run, metrics, record_property):
    assert metrics is run.metrics
    with metrics.timer("transfer.prepare") as measured:
        payload = b"brixtest" * 128
    metrics.gauge("transfer.throughput", 128.5, unit="MiB/s")
    metrics.count("transfer.bytes", len(payload), unit="bytes")
    metrics.tag("transport", "xrootd")
    record_property("brixtest_example", "metrics")
    assert measured.elapsed >= 0


def _run_pytest(tmp_path: Path, source_text: str):
    case_file = tmp_path / "test_sample.py"
    case_file.write_text(source_text)
    source = Path(__file__).resolve().parents[1] / "src"
    env = dict(os.environ)
    for name in (
        "BRIXTEST_HELPER", "BRIXTEST_HELPER_RESULT", "BRIXTEST_METRICS_SESSION",
        "BRIXTEST_CASE_RUN", "BRIXTEST_CONTROLLER_PID",
    ):
        env.pop(name, None)
    env.update({
        "PYTHONPATH": str(source), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPYCACHEPREFIX": str(tmp_path / "pycache"),
        "BRIXTEST_RUNS": str(tmp_path / "runs"),
    })
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "-q"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20,
        check=False,
    )


def test_success_metrics_are_stored_rendered_and_visible_from_cli(tmp_path):
    result = _run_pytest(
        tmp_path,
        "import pytest\n"
        "from brixtest import case\n"
        "@pytest.mark.brixtest_budget('request.latency', max=1.0)\n"
        "@case(keep='never')\n"
        "def test_sample(run, metrics, record_property):\n"
        "    with metrics.timer('request.latency'):\n"
        "        metrics.count('request.bytes', 4096, unit='bytes')\n"
        "    metrics.gauge('request.rate', 42.5, unit='req/s', labels={'route': 'read'})\n"
        "    record_property('build', 'debug')\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert "BriXTest metrics" in output
    assert "request.rate{route=read}" in output

    sessions = list((tmp_path / "runs" / "metrics").glob("*/session.json"))
    assert len(sessions) == 1
    payload = json.loads(sessions[0].read_text())
    assert payload["counts"] == {"passed": 1}
    assert payload["tests"][0]["properties"] == [["build", "debug"]]
    assert any(row["name"] == "request.rate" for row in payload["aggregates"])
    report = sessions[0].with_name("report.html")
    assert "request.rate{route=read}" in report.read_text()

    source = Path(__file__).resolve().parents[1] / "src"
    cli = subprocess.run(
        [sys.executable, "-m", "brixtest", "metrics", "show", "latest",
         "--runs", str(tmp_path / "runs")],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(source)},
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert cli.returncode == 0, cli.stdout + cli.stderr
    assert "request.rate{route=read}" in cli.stdout


def test_error_metric_budget_turns_a_passing_body_into_a_pytest_failure(tmp_path):
    result = _run_pytest(
        tmp_path,
        "import pytest\n"
        "from brixtest import case\n"
        "@pytest.mark.brixtest_budget('response.seconds', max=0.01)\n"
        "@case(keep='never')\n"
        "def test_sample(run):\n"
        "    run.metrics.gauge('response.seconds', 2.5, unit='s')\n",
    )
    assert result.returncode != 0
    assert "metric budget 'response.seconds' failed" in result.stdout + result.stderr
    session = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    assert json.loads(session.read_text())["counts"] == {"failed": 1}


def test_security_negative_metrics_refuse_unbounded_or_non_finite_data():
    metrics = MetricRecorder()
    with pytest.raises(SpecError, match="metric name"):
        metrics.gauge("../../escape", 1)
    with pytest.raises(SpecError, match="NaN and infinity"):
        metrics.observe("latency", float("nan"))
    with pytest.raises(SpecError, match="at most 8"):
        metrics.count("requests", labels={"label%d" % index: index for index in range(9)})
    with pytest.raises(SpecError, match="printable"):
        metrics.tag("revision", "unsafe\nvalue")

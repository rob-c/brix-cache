"""The controller must remain responsive when a managed case wedges forever."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def test_timeout_terminates_helper_without_hanging_controller(tmp_path):
    case_file = tmp_path / "test_hang.py"
    case_file.write_text(
        "import os,subprocess,sys,time\n"
        "from pathlib import Path\n"
        "from brixtest import case\n"
        "@case(timeout=3.0, keep='always')\n"
        "def test_hang(run):\n"
        "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n"
        "    Path(os.environ['BRIXTEST_CHILD_PID']).write_text(str(child.pid))\n"
        "    time.sleep(60)\n"
    )
    source = Path(__file__).resolve().parents[1] / "src"
    env = dict(os.environ)
    env.update({
        "PYTHONPATH": str(source), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "BRIXTEST_RUNS": str(tmp_path / "runs"),
        "BRIXTEST_CHILD_PID": str(tmp_path / "child.pid"),
    })
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "-q"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15,
        check=False,
    )
    elapsed = time.monotonic() - started
    assert result.returncode != 0
    assert elapsed < 10.0
    assert "helper exceeded 3.0s and was terminated" in result.stdout + result.stderr
    summaries = list((tmp_path / "runs").glob("*/summary.json"))
    assert len(summaries) == 1
    assert json.loads(summaries[0].read_text())["outcome"] == "timed-out"
    child_pid = int((tmp_path / "child.pid").read_text())
    deadline = time.monotonic() + 2.0
    child_proc = Path(f"/proc/{child_pid}")
    while child_proc.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not child_proc.exists()


def test_first_failure_stops_suite_with_full_trace_and_replay_record(tmp_path):
    case_file = tmp_path / "test_failfast.py"
    case_file.write_text(
        "from pathlib import Path\n"
        "from brixtest import case\n"
        "@case(keep='never')\n"
        "def test_01_first(run):\n"
        "    marker = 'full-trace-marker'\n"
        "    raise RuntimeError(marker)\n"
        "@case(keep='never')\n"
        "def test_02_must_not_run(run):\n"
        "    Path('second-ran').write_text('bad')\n"
    )
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
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "-q"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "RuntimeError: full-trace-marker" in output
    assert "marker = 'full-trace-marker'" in output
    assert not (tmp_path / "second-ran").exists()
    session = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    payload = json.loads(session.read_text())
    assert len(payload["tests"]) == 1
    assert payload["tests"][0]["replay"]["argv"]
    assert session.with_name("archive.sqlite3").is_file()
    assert "brixtest rerun" in output

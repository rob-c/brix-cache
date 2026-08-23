"""The controller must remain responsive when a managed case wedges forever."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path


_HANG_CASE = (
    "import os,subprocess,sys,time\n"
    "from pathlib import Path\n"
    "from brixtest import case\n"
    "@case(timeout=3.0, keep='always')\n"
    "def test_hang(run):\n"
    "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n"
    "    Path(os.environ['BRIXTEST_CHILD_PID']).write_text(str(child.pid))\n"
    "    time.sleep(60)\n"
)

_FAILFAST_CASE = (
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


def _case_environment(tmp_path, extra=None):
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
        **(extra or {}),
    })
    return env


def _run_case(tmp_path, filename, source_text, timeout, extra_env=None):
    case_file = tmp_path / filename
    case_file.write_text(source_text)
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "-q"],
        cwd=tmp_path, env=_case_environment(tmp_path, extra_env),
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    return result, time.monotonic() - started


def _wait_for_exit(pid):
    child_proc = Path("/proc/%d" % pid)
    deadline = time.monotonic() + 2.0
    while child_proc.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    return not child_proc.exists()


def test_timeout_terminates_helper_without_hanging_controller(tmp_path):
    result, elapsed = _run_case(
        tmp_path, "test_hang.py", _HANG_CASE, 15,
        {"BRIXTEST_CHILD_PID": str(tmp_path / "child.pid")},
    )
    summaries = list((tmp_path / "runs").glob("*/summary.json"))
    child_pid = int((tmp_path / "child.pid").read_text())
    assert (
        result.returncode != 0, elapsed < 10.0,
        "helper exceeded 3.0s and was terminated" in result.stdout + result.stderr,
        len(summaries), json.loads(summaries[0].read_text())["outcome"],
        _wait_for_exit(child_pid),
    ) == (True, True, True, 1, "timed-out", True)


def test_first_failure_stops_suite_with_full_trace_and_replay_record(tmp_path):
    result, _ = _run_case(tmp_path, "test_failfast.py", _FAILFAST_CASE, 20)
    output = result.stdout + result.stderr
    session = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    payload = json.loads(session.read_text())
    assert (
        result.returncode != 0, "RuntimeError: full-trace-marker" in output,
        "marker = 'full-trace-marker'" in output,
        (tmp_path / "second-ran").exists(), len(payload["tests"]),
        bool(payload["tests"][0]["replay"]["argv"]),
        session.with_name("archive.sqlite3").is_file(), "brixtest rerun" in output,
    ) == (True, True, True, False, 1, True, True, True)

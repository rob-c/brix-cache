"""End-to-end contracts for attempts, attachments, and fatal evidence."""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def _run_pytest(tmp_path: Path, source_text: str):
    case_file = tmp_path / "test_sample.py"
    case_file.write_text(source_text)
    source = Path(__file__).resolve().parents[1] / "src"
    env = dict(os.environ)
    for name in (
        "BRIXTEST_HELPER", "BRIXTEST_HELPER_RESULT", "BRIXTEST_METRICS_SESSION",
        "BRIXTEST_CASE_RUN", "BRIXTEST_CONTROLLER_PID", "BRIXTEST_ATTEMPT_ID",
        "BRIXTEST_TRIAL", "BRIXTEST_WARMUP",
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
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=40,
        check=False,
    )


def _session(tmp_path: Path) -> tuple[Path, dict]:
    path = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    return path.parent, json.loads(path.read_text())


def test_warmups_trials_spans_attachments_and_resources_share_one_record(tmp_path):
    result = _run_pytest(
        tmp_path,
        "import os\n"
        "from brixtest import case, process_tree\n"
        "@case(warmup=1, trials=3, observe=[process_tree(interval=.01)], keep='never')\n"
        "def test_sample(run):\n"
        "    with run.step('operation', trial=os.environ['BRIXTEST_TRIAL']):\n"
        "        run.metrics.observe('operation.seconds', .01, unit='s')\n"
        "    run.attach_json('result.json', {'trial': os.environ['BRIXTEST_TRIAL']})\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    session_dir, payload = _session(tmp_path)
    record = payload["tests"][0]
    assert len(record["attempts"]) == 4
    assert [row["warmup"] for row in record["attempts"]] == [True, False, False, False]
    assert [row["index"] for row in record["attempts"]] == [0, 1, 2, 3]
    assert len([sample for sample in record["metrics"]["samples"]
                if sample["name"] == "operation.seconds"]) == 3
    assert all(row["spans"][0]["name"] == "operation" for row in record["attempts"])
    assert all(row["artifacts"][0]["name"] == "result.json" for row in record["attempts"])
    assert list((session_dir / "objects" / "sha256").glob("*/*"))
    database = sqlite3.connect(str(session_dir / "archive.sqlite3"))
    try:
        assert database.execute("select count(*) from evidence_attempts").fetchone()[0] == 4
        assert database.execute("select count(*) from evidence_metrics where name='operation.seconds'").fetchone()[0] == 4
    finally:
        database.close()


def test_trial_sequence_stops_after_first_failure_and_is_directly_rerunnable(tmp_path):
    result = _run_pytest(
        tmp_path,
        "from brixtest import case\n"
        "@case(trials=5, keep='never')\n"
        "def test_sample(run):\n"
        "    raise AssertionError('first-trial-failure')\n",
    )
    assert result.returncode != 0
    session_dir, payload = _session(tmp_path)
    record = payload["tests"][0]
    assert len(record["attempts"]) == 1
    assert record["outcome"] == "failed"
    assert "first-trial-failure" in record["error"]
    assert record["replay"]["argv"][-1] != ""
    assert "brixtest rerun" in result.stdout + result.stderr
    assert (session_dir / "logs").is_dir()


def test_sanitizer_signature_is_a_fatal_evidence_finding(tmp_path):
    result = _run_pytest(
        tmp_path,
        "from brixtest import case\n"
        "@case(keep='always')\n"
        "def test_sample(run):\n"
        "    (run.workspace / 'asan.log').write_text('ERROR: AddressSanitizer: heap-use-after-free\\n')\n",
    )
    assert result.returncode != 0
    _, payload = _session(tmp_path)
    attempt = payload["tests"][0]["attempts"][0]
    assert any(row["kind"] == "asan-error" and row["severity"] == "error"
               for row in attempt["findings"])

"""Shared-server loss is a normal correlated test failure, never an internal error."""

import json
import os
import subprocess
import sys
from pathlib import Path


def _write_crashing_suite(root: Path) -> None:
    (root / "origin.json.in").write_text('{"host":"{host}","port":{port}}\n')
    (root / "server.py").write_text(
        "import json,os,sys,threading\n"
        "from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer\n"
        "config=json.load(open(sys.argv[1]))\n"
        "class H(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  body=b'complete';self.send_response(200)\n"
        "  self.send_header('Content-Length',str(len(body)));self.end_headers()\n"
        "  self.wfile.write(body);self.wfile.flush()\n"
        "  threading.Timer(.05,lambda:os._exit(23)).start()\n"
        " def log_message(self,fmt,*args): print(fmt%args,flush=True)\n"
        "ThreadingHTTPServer((config['host'],config['port']),H).serve_forever()\n"
    )
    (root / "test_crash.py").write_text(
        "import sys,time,urllib.request\n"
        "from pathlib import Path\n"
        "from brixtest import case,file_artifact,server,tcp,template_config\n"
        "HERE=Path(__file__).parent\n"
        "CODE=file_artifact('server_code',HERE/'server.py')\n"
        "ORIGIN=server('origin',command=(sys.executable,'{artifact_server_code}',"
        "'{config}'),config=template_config('origin.json.in'),ports=('http',),"
        "readiness=tcp('http'),scope='session')\n"
        "@case(ORIGIN,CODE,keep='never')\n"
        "def test_first(run):\n"
        " assert urllib.request.urlopen(run.server(ORIGIN).url()).read()==b'complete'\n"
        " time.sleep(.35)\n"
        "@case(ORIGIN,CODE,keep='never')\n"
        "def test_consumer_after_crash(run):\n"
        " raise AssertionError('a helper must not be launched')\n"
    )


def _run_suite(root: Path) -> subprocess.CompletedProcess:
    source = Path(__file__).resolve().parents[1] / "src"
    environment = {
        name: value for name, value in os.environ.items()
        if not name.startswith("BRIXTEST_")
    }
    environment.update({
        "PYTHONPATH": str(source), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPYCACHEPREFIX": str(root / "pycache"),
        "BRIXTEST_RUNS": str(root / "runs"),
    })
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(root / "test_crash.py"),
         "-p", "brixtest.pytest_plugin", "-q"],
        cwd=root, env=environment, capture_output=True, text=True,
        timeout=45, check=False,
    )


def _session_attempts(session):
    return [row["attempts"][0] for row in session["tests"]]


def _failed_attempt(attempts):
    return next(row for row in attempts if row["outcome"] == "failed")


def _instance_ids(attempts):
    return {row["servers"][0]["instance_id"] for row in attempts}


def test_shared_crash_fails_next_consumer_with_one_correlated_trace(tmp_path):
    _write_crashing_suite(tmp_path)
    result = _run_suite(tmp_path)
    output = result.stdout + result.stderr
    assert result.returncode == 1, output
    assert "INTERNALERROR" not in output, output
    session_path = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    session = json.loads(session_path.read_text())
    assert session["counts"] == {"failed": 1, "passed": 1}
    assert len(session["topology"]["pools"]) == 1
    pool = session["topology"]["pools"][0]
    assert pool["result"]["outcome"] == "failed"
    assert "exited unexpectedly with status 23" in pool["result"]["traceback"]
    attempts = _session_attempts(session)
    assert len(_instance_ids(attempts)) == 1
    failed = _failed_attempt(attempts)
    assert "BriXTest controller invocation failed" in failed["error"]
    assert "@shared/" in failed["error"]
    assert pool["services"]["origin"]["log_artifact"]["sha256"]

"""Suite environment values are applied before collection and scoped by role."""

import json
import os
import subprocess
import sys
from pathlib import Path


def _environment(tmp_path):
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
    return env


def test_global_server_and_client_environments_are_scoped(tmp_path):
    (tmp_path / "empty.conf").write_text("static config\n")
    case_file = tmp_path / "test_environment.py"
    case_file.write_text(
        "import os,sys,time\n"
        "from pathlib import Path\n"
        "assert os.environ['GLOBAL_VALUE'] == 'global'\n"
        "from brixtest import case,client,immediate,server,static_config\n"
        "service=server('service', command=[sys.executable,'-c',"
        "'import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(os.environ[\"GLOBAL_VALUE\"]+\"|\"+os.environ[\"SERVER_VALUE\"]); time.sleep(60)',"
        "'{workspace}/server.env'], config=static_config('empty.conf'),"
        "ports=['unused'], readiness=immediate())\n"
        "reader=client('reader', command=[sys.executable,'-c',"
        "'import os; print(os.environ[\"GLOBAL_VALUE\"]+\"|\"+os.environ[\"CLIENT_VALUE\"])'])\n"
        "@case(servers=[service],clients=[reader],keep='never')\n"
        "def test_values(run):\n"
        "    path=run.workspace/'server.env'\n"
        "    deadline=time.monotonic()+5\n"
        "    value=''\n"
        "    while value != 'global|server' and time.monotonic()<deadline:\n"
        "        if path.exists(): value=path.read_text()\n"
        "        if value != 'global|server': time.sleep(.01)\n"
        "    assert value == 'global|server'\n"
        "    assert run.client(reader).run().stdout.strip() == 'global|client'\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "-q",
         "--brixtest-env", "GLOBAL_VALUE=global",
         "--brixtest-server-env", "SERVER_VALUE=server",
         "--brixtest-client-env", "CLIENT_VALUE=client"],
        cwd=tmp_path, env=_environment(tmp_path), capture_output=True, text=True,
        timeout=20, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_invalid_environment_fails_before_test_collection(tmp_path):
    sentinel = tmp_path / "imported"
    case_file = tmp_path / "test_import.py"
    case_file.write_text("from pathlib import Path\nPath('imported').write_text('bad')\n")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "--brixtest-env", "9BAD=value"],
        cwd=tmp_path, env=_environment(tmp_path), capture_output=True, text=True,
        timeout=10, check=False,
    )
    assert result.returncode != 0
    assert "invalid name" in result.stdout + result.stderr
    assert not sentinel.exists()


def test_json_suite_profile_applies_binary_sanitizer_and_environment_overrides(tmp_path):
    profile = tmp_path / "asan-profile.json"
    profile.write_text(json.dumps({
        "backend": "local",
        "binaries": {"python": sys.executable},
        "sanitizer": "asan",
        "test_env": {"PROFILE_VALUE": "profile"},
        "client_env": {"CLIENT_PROFILE": "yes"},
    }))
    case_file = tmp_path / "test_profile.py"
    case_file.write_text(
        "import os,sys\n"
        "assert os.environ['PROFILE_VALUE']=='command-line'\n"
        "assert 'halt_on_error=1' in os.environ['ASAN_OPTIONS']\n"
        "from brixtest import binary,case,client\n"
        "PY=binary('python','/does/not/exist')\n"
        "CHECK=client('check',command=[PY,'-c','import os;print(os.environ[\"CLIENT_PROFILE\"])'])\n"
        "@case(CHECK,observe=[],keep='never')\n"
        "def test_profile(run):\n"
        " assert run.binary(PY).overridden\n"
        " assert run.client(CHECK).run().stdout.strip()=='yes'\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "-q",
         "--brixtest-profile", str(profile),
         "--brixtest-env", "PROFILE_VALUE=command-line"],
        cwd=tmp_path, env=_environment(tmp_path), capture_output=True, text=True,
        timeout=20, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_suite_profile_rejects_unknown_fields_before_collection(tmp_path):
    sentinel = tmp_path / "imported"
    profile = tmp_path / "unsafe.json"
    profile.write_text('{"shell": "rm -rf anything"}\n')
    case_file = tmp_path / "test_import.py"
    case_file.write_text("from pathlib import Path\nPath('imported').write_text('bad')\n")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "--brixtest-profile", str(profile)],
        cwd=tmp_path, env=_environment(tmp_path), capture_output=True, text=True,
        timeout=10, check=False,
    )
    assert result.returncode != 0
    assert "unknown fields" in result.stdout + result.stderr
    assert not sentinel.exists()

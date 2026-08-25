"""Complete-suite candidate binary and sanitizer substitution contracts."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _environment():
    values = dict(os.environ)
    values["PYTHONPATH"] = str(ROOT / "src")
    return values


def _candidate_suite(tmp_path):
    source = tmp_path / "test_candidate_suite.py"
    source.write_text(
        "from brixtest import binary,case,tool\n"
        "NGINX=binary('nginx','/bin/false')\n"
        "CHECK=tool('candidate',command=(NGINX,'-c',"
        "'import os;assert \\\"abort_on_error=1\\\" in os.environ[\\\"ASAN_OPTIONS\\\"]'))\n"
        "@case(NGINX,CHECK,keep='never')\n"
        "def test_candidate_executes(run): assert run.tool(CHECK).run().ok\n"
        "@case(NGINX,keep='never')\n"
        "def test_candidate_is_immutable(run): assert run.binary(NGINX).verify()\n"
    )
    return source


def _run_suite(source: Path, session: Path, candidate: Path):
    return subprocess.run(
        [
            sys.executable, "-m", "pytest", "-p", "brixtest.pytest_plugin",
            str(source), "-q",
            "--brixtest-binary", "nginx=%s" % candidate,
            "--brixtest-sanitizer", "asan",
            "--brixtest-metrics-dir", str(session),
        ],
        cwd=str(ROOT), env=_environment(), capture_output=True, text=True,
        timeout=90, check=False,
    )


def _session_payload(root: Path) -> str:
    paths = tuple(root.rglob("session.json"))
    assert len(paths) == 1
    return json.dumps(json.loads(paths[0].read_text()), sort_keys=True)


def test_dynamic_candidate_runs_the_entire_selected_suite_twice(tmp_path):
    suite = _candidate_suite(tmp_path)
    candidate = Path(sys.executable).resolve()
    first = _run_suite(suite, tmp_path / "first", candidate)
    second = _run_suite(suite, tmp_path / "second", candidate)
    assert first.returncode == second.returncode == 0, first.stdout + first.stderr
    assert "2 passed" in first.stdout and "2 passed" in second.stdout
    for session in (tmp_path / "first", tmp_path / "second"):
        payload = _session_payload(session)
        assert "replay-binary:nginx" in payload
        assert "replay-library:nginx" in payload


def _real_candidate(name: str):
    value = os.environ.get(name)
    return Path(value).resolve() if value else None


def _required_real_candidate(name: str) -> Path:
    candidate = _real_candidate(name)
    if candidate is None:
        pytest.skip("set %s to an executable nginx candidate" % name)
    assert candidate.is_file()
    assert os.access(str(candidate), os.X_OK)
    return candidate


def _top_level_examples() -> list[str]:
    return [str(path) for path in sorted((ROOT / "examples").glob("test_*.py"))]


@pytest.mark.parametrize(
    "environment_name", ("BRIXTEST_DYNAMIC_NGINX", "BRIXTEST_ASAN_NGINX"),
)
def test_real_nginx_candidate_runs_the_complete_example_suite(tmp_path, environment_name):
    candidate = _required_real_candidate(environment_name)
    executable = tmp_path / "bin" / "nginx"
    executable.parent.mkdir()
    executable.symlink_to(candidate)
    environment = _environment()
    environment["PATH"] = "%s%s%s" % (
        executable.parent, os.pathsep, environment.get("PATH", ""),
    )
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", *_top_level_examples(), "-q",
            "--brixtest-binary", "nginx=%s" % candidate,
            "--brixtest-sanitizer", "asan",
            "--brixtest-metrics-dir", str(tmp_path / environment_name.lower()),
        ],
        cwd=str(ROOT), env=environment, capture_output=True, text=True,
        timeout=300, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "20 passed" in result.stdout

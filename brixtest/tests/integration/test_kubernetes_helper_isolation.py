"""Opt-in remote pytest-helper validation against Docker-backed Minikube."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

if os.environ.get("BRIXTEST_MINIKUBE") != "1" and not os.environ.get("BRIXTEST_HELPER"):
    pytest.skip(
        "set BRIXTEST_MINIKUBE=1 or use tools/minikube_cluster.py test",
        allow_module_level=True,
    )

from brixtest import case, kubernetes  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads((ROOT / "k8s" / "minikube" / "cluster.json").read_text())
REMOTE = kubernetes(CONFIG["helper_image"], context=CONFIG["profile"])


@case(isolation=REMOTE, backend="local", observe=[], timeout=120, keep="never")
def test_remote_helper_uses_its_pod_service_account(run):
    from pathlib import Path

    token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    namespace = token.with_name("namespace")
    assert token.is_file() and token.stat().st_size > 0
    assert namespace.read_text().strip() == "default"
    denied = run.command(
        "/opt/brixtest/bin/kubectl", "auth", "can-i", "get", "pods",
        expected_exit_codes=(1,),
    )
    assert denied.stdout.strip() == "no"


def test_hung_remote_helper_is_bounded_and_force_cleaned(tmp_path):
    source = tmp_path / "test_remote_hang.py"
    source.write_text(_hung_case(CONFIG["helper_image"], CONFIG["profile"]))
    started = time.monotonic()
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", str(source),
            "-p", "brixtest.pytest_plugin", "-q", "--tb=long",
            "--brixtest-runs", str(tmp_path / "runs"),
        ],
        cwd=tmp_path, env=_nested_environment(),
        capture_output=True, text=True, timeout=45.0, check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert time.monotonic() - started < 30
    assert "helper exceeded 15.0s and was terminated" in output


def _nested_environment():
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return environment


def _hung_case(image, context):
    return """\
from brixtest import case, kubernetes

@case(
    isolation=kubernetes(%r, context=%r), backend='local', observe=[],
    timeout=15, keep='never',
)
def test_hung_remote_helper(run):
    import time
    print('remote-partial-output', flush=True)
    time.sleep(60)
""" % (image, context)

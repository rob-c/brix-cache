#!/usr/bin/env python3
"""Start, inspect, and test BriXTest's reproducible local Kubernetes profile."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "k8s" / "minikube" / "cluster.json"


def _config():
    return json.loads(CONFIG.read_text())


def _run(argv, *, env=None) -> int:
    return subprocess.run(argv, cwd=str(ROOT), env=env, check=False).returncode


def start(config) -> int:
    return _run([
        "minikube", "start", "-p", config["profile"],
        "--driver=" + config["driver"],
        "--container-runtime=" + config["container_runtime"],
        "--cpus=" + str(config["cpus"]),
        "--memory=" + str(config["memory_mb"]),
    ])


def status(config) -> int:
    return _run(["minikube", "status", "-p", config["profile"]])


def test(config) -> int:
    loaded = _run([
        "minikube", "image", "load", "-p", config["profile"],
        config["server_image_load"],
    ])
    if loaded:
        return loaded
    env = dict(os.environ)
    env.update({
        "BRIXTEST_MINIKUBE": "1", "PYTHONPATH": "src",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    })
    return _run([
        sys.executable, "-m", "pytest",
        "tests/integration/test_minikube_auth.py", "-v",
        "-p", "brixtest.pytest_plugin",
    ], env=env)


def main(argv=None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    command = values[0] if values else "status"
    config = _config()
    if command == "start":
        return start(config)
    if command == "status":
        return status(config)
    if command == "test":
        return test(config)
    print("usage: minikube_cluster.py start|status|test", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

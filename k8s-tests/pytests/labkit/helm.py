"""helm — thin wrappers over the helm CLI for the e2e deploy fixtures.

Subprocess-backed by design; only used under ``-m e2e``.
"""
from __future__ import annotations

import json

from .shell import run


def install(release, chart, namespace, sets=None, wait=True, timeout="3m"):
    cmd = ["helm", "upgrade", "--install", release, str(chart), "-n", namespace,
           "--create-namespace"]
    for k, v in (sets or {}).items():
        cmd += ["--set", f"{k}={v}"]
    if wait:
        cmd += ["--wait", "--timeout", timeout]
    return run(cmd, timeout=600)


def uninstall(release, namespace):
    return run(["helm", "uninstall", release, "-n", namespace])


def lint(chart):
    return run(["helm", "lint", str(chart)])


def status(release, namespace):
    r = run(["helm", "status", release, "-n", namespace, "-o", "json"])
    return json.loads(r.stdout) if r.returncode == 0 else {}

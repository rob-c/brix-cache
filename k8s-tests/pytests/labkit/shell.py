"""shell — the single subprocess seam for helm/docker/minikube/xrd-lab.

Everything that runs an external CLI goes through ``run``; tests never call
``subprocess`` directly, so a reviewer sees one obvious idiom everywhere.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from subprocess import CompletedProcess  # re-exported

LAB_DIR = Path(__file__).resolve().parents[2]  # k8s-tests/
XRD_LAB = LAB_DIR / "xrd-lab"


def run(argv, *, check=False, env=None, timeout=None, text=True, input=None):
    """Run ``argv`` and return the CompletedProcess (stdout/stderr captured).

    A thin, predictable wrapper: no shell, always captured, optional ``check``.
    """
    full_env = None
    if env is not None:
        full_env = {**os.environ, **env}
    return subprocess.run(
        list(argv), check=check, env=full_env, timeout=timeout,
        capture_output=True, text=text, input=input,
    )


def lab(*args, dry=False, env=None, timeout=None):
    """Run ``k8s-tests/xrd-lab`` with ``args``; ``dry=True`` sets XRD_LAB_DRY_RUN=1."""
    e = dict(env or {})
    if dry:
        e["XRD_LAB_DRY_RUN"] = "1"
    return run([str(XRD_LAB), *args], env=e, timeout=timeout)

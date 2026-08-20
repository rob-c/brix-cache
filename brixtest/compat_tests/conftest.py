"""One-line project activation for every test under this directory."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from brixtest.project import activate_project  # noqa: E402


def pytest_configure(config):
    config._brixtest_project = activate_project(config, PROJECT_ROOT)


def pytest_sessionfinish(session, exitstatus):
    if hasattr(session.config, "workerinput"):
        return  # xdist worker: the controller owns the fleet
    activation = getattr(session.config, "_brixtest_project", None)
    if activation is not None:
        activation.stop()

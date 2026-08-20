"""Self-tests for the public case API, isolated from the legacy harness tests."""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

pytest_plugins = ["brixtest.pytest_plugin"]

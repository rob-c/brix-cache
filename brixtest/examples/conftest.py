"""Keep the executable examples self-contained inside the BriXTest project."""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

pytest_plugins = ["brixtest.pytest_plugin"]

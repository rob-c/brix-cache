"""labtools — the k8s test-lab's tool LOGIC as importable Python.

Each module is a pure function set (tested directly by pytests/) plus a thin
``main(argv)`` CLI. The tools/*.sh scripts are one-line wrappers over these, so
xrd-lab and CI keep working with a single source of truth in Python.
"""
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]          # k8s-tests/
REPO = LAB.parent
CONFIG_DIR = LAB / "charts" / "topology-role" / "configs"
SUITE = LAB / "remote-suite" / "tests"

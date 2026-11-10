"""Shared subprocess and compiler helpers for native-test contracts."""

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path


def _nested_pytest(tmp_path: Path, source: str, *extra: str):
    test_file = tmp_path / "test_native_generated.py"
    test_file.write_text(source)
    package = Path(__file__).resolve().parents[1] / "src"
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("BRIXTEST_")
    }
    environment.update({
        "PYTHONPATH": str(package),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPYCACHEPREFIX": str(tmp_path / "pycache"),
        "BRIXTEST_RUNS": str(tmp_path / "runs"),
    })
    return subprocess.run(
        [
            sys.executable, "-m", "pytest", str(test_file),
            "-p", "brixtest.pytest_plugin", "-q", *extra,
        ],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
        timeout=90, check=False,
    )


def _write(tmp_path: Path, name: str, source: str) -> Path:
    path = tmp_path / "c" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(source)
    return path


def _compiler(language: str = "c") -> str | None:
    names = ("c++", "g++", "clang++") if language == "c++" else ("cc", "gcc", "clang")
    return next((value for name in names if (value := shutil.which(name))), None)


def _loopback_available() -> bool:
    try:
        handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return False
    handle.close()
    return True


def _tree_text(root: Path, pattern: str) -> str:
    return "\n".join(path.read_text() for path in root.rglob(pattern))



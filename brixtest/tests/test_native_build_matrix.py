"""Parametrized native builds remain ordinary, independently reported pytest cases."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def _nested_pytest(tmp_path: Path, source: str):
    test_file = tmp_path / "test_build_matrix.py"
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
        [sys.executable, "-m", "pytest", str(test_file),
         "-p", "brixtest.pytest_plugin", "-q"],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
        timeout=90, check=False,
    )


@pytest.mark.skipif(
    not any(shutil.which(name) for name in ("cc", "gcc", "clang")),
    reason="C compiler unavailable",
)
def test_defines_and_compile_flags_accept_pytest_parameters(tmp_path):
    source_dir = tmp_path / "c"
    source_dir.mkdir()
    (source_dir / "matrix.c").write_text(r'''
#include <stdio.h>
#ifndef MATRIX_VALUE
#error MATRIX_VALUE is required
#endif
int main(void) {
    if (MATRIX_VALUE != 3 && MATRIX_VALUE != 7) return 2;
    puts("MATRIX PASS");
    return 0;
}
''')
    result = _nested_pytest(tmp_path, '''
import pytest
from brixtest import native_test, param

test_matrix = native_test(
    "matrix", sources=("c/matrix.c",),
    defines={"MATRIX_VALUE": param("value")},
    compile_args=("-Wall", "-Wextra", "-Werror", param("optimization")),
    stdout="MATRIX PASS", observe=(), keep="never",
)
test_matrix = pytest.mark.parametrize(
    "value,optimization", ((3, "-O0"), (7, "-O2")),
)(test_matrix)
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 passed" in result.stdout

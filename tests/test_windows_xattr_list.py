"""Exercise the Windows xattr-list test oracle without native Windows APIs."""

import os
from pathlib import Path
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def xattr_list_binary(tmp_path_factory):
    output = tmp_path_factory.mktemp("windows-xattr-list") / "list-check"
    result = subprocess.run(
        [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-I", str(REPO / "src"), str(REPO / "tests/c/windows_xattr_list_test.c"),
         "-o", str(output)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return output


@pytest.mark.parametrize("scenario", ["success", "error", "malformed"])
def test_windows_xattr_list(xattr_list_binary, scenario):
    result = subprocess.run(
        [str(xattr_list_binary), scenario], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr

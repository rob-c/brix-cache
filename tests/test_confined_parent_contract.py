"""Compile confinement helper contracts against the configured nginx SDK."""

from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def confined_parent_binary(native_compile):
    code = (Path(__file__).parent / "c/confined_parent_contract_test.c").read_text()
    return native_compile(
        "confined-parent-contract", code,
        ["src/fs/path/resolve_confined_helpers.c"],
        ["-std=gnu11", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"],
    )


@pytest.mark.parametrize("case", ["success", "invalid", "bounds"])
def test_confined_parent_contract(confined_parent_binary, case):
    result = subprocess.run(
        [str(confined_parent_binary), case], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr

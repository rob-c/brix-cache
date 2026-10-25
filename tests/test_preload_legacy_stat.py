"""Legacy glibc metadata callers reach the existing preload mapping bodies."""

import subprocess
import sys

import pytest

from cmdscripts.compile_run import compile_binary

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="glibc ELF ABI is Linux-only")


@pytest.fixture(scope="module")
def driver(tmp_path_factory):
    binary = tmp_path_factory.mktemp("legacy-stat") / "probe"
    result = compile_binary(binary, [
        "-O1", "-Wall", "-Wextra", "-Werror", "-D_GNU_SOURCE", "-DXRDPROTO_NO_NGX",
        "-Iclient/lib", "-Iclient/preload", "-Isrc", "-Ishared",
        "tests/c/preload_legacy_stat_test.c", "client/lib/platform/linux/preload_lfs.c",
        "-ldl",
    ])
    assert result.returncode == 0, result.stderr
    return binary


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_native_legacy_stat_contract(driver, case):
    """Shared dispatch, typed errors, local passthrough and ABI rejection."""
    result = subprocess.run([str(driver), case], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr

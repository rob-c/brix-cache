"""Capacity refusal must precede allocation on every POSIX host."""
import shutil
import subprocess
from pathlib import Path

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def reserve_probe(tmp_path_factory):
    """Compile the real driver with deterministic metadata and allocator seams."""
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler required for POSIX reserve contract")
    executable = tmp_path_factory.mktemp("reserve-preflight") / "probe"
    command = [compiler, "-std=gnu11", "-D_GNU_SOURCE", "-DXRDPROTO_NO_NGX",
               *PLATFORM_HOST_FLAGS, "-Wall", "-Wextra", "-Werror",
               "-I", str(ROOT / "src"), "-I", str(ROOT / "shared"),
               str(ROOT / "tests/c/test_sd_posix_reserve.c"),
               "-o", str(executable)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return executable


@pytest.mark.parametrize("case", ["fresh-fit", "already-reserved", "fragment-fallback"])
def test_feasible_reservation_reaches_allocator(reserve_probe, case):
    """Success: fresh and already allocated capacity both remain usable."""
    result = subprocess.run([str(reserve_probe), case], capture_output=True,
                            text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", ["metadata-error", "allocator-quota", "zero-unit"])
def test_metadata_and_allocator_errors_remain_authoritative(reserve_probe, case):
    """Error: failed metadata and real quota refusals retain their errno."""
    result = subprocess.run([str(reserve_probe), case], capture_output=True,
                            text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", ["oversized", "round-up", "huge-capacity", "huge-allocation"])
def test_hostile_sizes_cannot_trigger_overflow_or_impossible_allocation(reserve_probe, case):
    """Security-negative: reject impossible allocation before the allocator runs."""
    result = subprocess.run([str(reserve_probe), case], capture_output=True,
                            text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr

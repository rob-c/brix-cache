"""Compile real pgwrite completion code and test accounting, errors and integrity.

Set TEST_NGINX_SRC to a configured nginx source tree and TEST_NGINX_BUILD_DIR
to its generated header directory when that directory differs from objs/.
No running nginx instance or writable export is needed.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS

REPO = Path(__file__).resolve().parents[1]


def _nginx_include_flags():
    """Locate configured nginx headers and their source include directories."""
    source = Path(os.environ.get("TEST_NGINX_SRC", "/tmp/nginx-1.28.3"))
    build = Path(os.environ.get("TEST_NGINX_BUILD_DIR", str(source / "objs")))
    if not (build / "ngx_auto_config.h").is_file():
        pytest.skip("configured nginx headers unavailable")
    includes = [source / part for part in (
        "src/core", "src/event", "src/event/modules", "src/os/unix",
        "src/http", "src/http/modules", "src/stream",
    )]
    includes.extend((build, REPO / "src", REPO / "shared"))
    return [f"-I{path}" for path in includes]


def _completion_sources():
    """Link the separate production helpers with the private orchestrator harness."""
    write = REPO / "src/protocols/root/write"
    sources = [REPO / "tests/c/pgwrite_completion_test.c"]
    sources.extend(write / name for name in (
        "pgwrite_helpers.c", "pgw_fob.c", "wrts_journal.c",
    ))
    return list(map(str, sources))


@pytest.fixture(scope="module")
def completion_binary(tmp_path_factory):
    """Compile the production orchestrator and separate helper translation unit."""
    compiler = shutil.which(os.environ.get("CC", "cc"))
    if compiler is None:
        pytest.skip("C compiler unavailable")
    linker_gc = "-Wl,-dead_strip" if sys.platform == "darwin" else "-Wl,--gc-sections"
    output = tmp_path_factory.mktemp("pgwrite-completion") / "regression"
    result = subprocess.run(
        [compiler, "-O2", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-parameter", "-ffunction-sections", "-fdata-sections",
         # INVARIANT 14: these TUs reach platform/platform.h, which selects its
         # <host>/host.h from this token alone and #errors without it.
         *PLATFORM_HOST_FLAGS,
         *_nginx_include_flags(), *_completion_sources(), linker_gc, "-o", str(output)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"pgwrite compilation failed:\n{result.stderr}"
    return output


@pytest.mark.parametrize("scenario", ["success", "error", "uncorrected-retry"])
def test_pgwrite_completion(completion_binary, scenario):
    """Run success, storage error, or checksum integrity refusal assertions."""
    result = subprocess.run(
        [str(completion_binary), scenario], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"{scenario} failed:\n{result.stdout}\n{result.stderr}"

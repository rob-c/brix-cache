"""Compile production cache registries and test state ownership without a fleet.

TEST_NGINX_SRC selects nginx sources; TEST_NGINX_BUILD_DIR selects generated
headers when they are outside the source tree's objs/ directory.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS

REPO = Path(__file__).resolve().parents[1]
NGINX_SOURCE = Path(os.environ.get("TEST_NGINX_SRC", "/tmp/nginx-1.28.3"))


def _include_flags():
    """Resolve the actual configured nginx header closure."""
    build = Path(os.environ.get("TEST_NGINX_BUILD_DIR", str(NGINX_SOURCE / "objs")))
    if not (build / "ngx_auto_config.h").is_file():
        pytest.skip("configured nginx headers unavailable")
    includes = [NGINX_SOURCE / part for part in (
        "src/core", "src/event", "src/event/modules", "src/os/unix",
        "src/http", "src/http/modules", "src/stream",
    )]
    includes.extend((build, REPO / "src", REPO / "shared"))
    return [f"-I{path}" for path in includes]


def _sources():
    """Link the real registration, coalescing and credential-comparison code."""
    paths = [REPO / part for part in (
        "tests/c/test_cache_registry_state.c",
        "src/protocols/cvmfs/swarm.c",
        "src/protocols/shared/http_cache_fill.c",
        "src/protocols/shared/http_cache_fill_registry.c",
    )]
    paths.append(NGINX_SOURCE / "src/core/ngx_string.c")
    return list(map(str, paths))


@pytest.fixture(scope="module")
def registry_binary(tmp_path_factory):
    """Compile separate production TUs; discard unused network/worker entry points."""
    compiler = shutil.which(os.environ.get("CC", "cc"))
    if compiler is None:
        pytest.skip("C compiler unavailable")
    linker_gc = "-Wl,-dead_strip" if sys.platform == "darwin" else "-Wl,--gc-sections"
    output = tmp_path_factory.mktemp("cache-registry") / "regression"
    result = subprocess.run(
        [compiler, "-O2", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-parameter", "-ffunction-sections", "-fdata-sections",
         # INVARIANT 14: these TUs reach platform/platform.h, which selects its
         # <host>/host.h from this token alone and #errors without it.
         *PLATFORM_HOST_FLAGS,
         *_include_flags(), *_sources(), linker_gc, "-lcrypto", "-o", str(output)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"cache registry compilation failed:\n{result.stderr}"
    return output


@pytest.mark.parametrize("scenario", ["success", "error", "isolation"])
def test_cache_registry_state(registry_binary, scenario):
    """Assert success, refusal and caller-isolation behavior in the production code."""
    result = subprocess.run(
        [str(registry_binary), scenario], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"{scenario} failed:\n{result.stdout}\n{result.stderr}"

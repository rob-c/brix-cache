"""Deep and hostile trees must not consume a native call stack per directory."""

from pathlib import Path
import shlex
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def walk_driver(native_compile):
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/protocols/webdav/propfind_walk.c").read_text()
    traversal = source.split("/*\n * Core PROPFIND logic", 1)[0]
    assert "propfind_walk(" in traversal
    driver = (root / "tests/c/propfind_walk_stack_test.c").read_text()
    flags = subprocess.run(["pkg-config", "--cflags", "libxml-2.0"],
                           capture_output=True, text=True, check=True).stdout
    return native_compile("propfind-stack", traversal + driver,
                          ["src/core/compat/fs_walk.c"],
                          ["-I", str(root / "src/protocols/webdav"),
                           *shlex.split(flags), "-ffunction-sections",
                           "-fdata-sections", "-Wl,--gc-sections", "-pthread"])


@pytest.mark.parametrize("case", ["deep", "cap", "emit-error", "oom",
                                  "denied", "symlink"])
def test_real_propfind_walk_on_a_small_thread_stack(walk_driver, case):
    subprocess.run([str(walk_driver), case], check=True, timeout=10)

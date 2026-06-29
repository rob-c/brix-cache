"""Compile + run the standalone crash-safe reparented command runner suite
(src/fs/xfer/xfer_spawn_unittest.c).

The runner (xrootd_xfer_run_reparented) is the synchronous, double-forked,
reparented-to-init external-command launcher that write-through (and later TPC)
use instead of posix_spawn, so nginx never reaps the child — avoiding the
SHM/SIGCHLD master-crash hazard. The C suite checks exit-code propagation, exec
failure (127), kill-by-signal (128), env + PATH handling, and the reparent
invariant (no child is left for the parent to reap).
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src", "fs", "xfer", "xfer_spawn.c")
TEST = os.path.join(REPO, "src", "fs", "xfer", "xfer_spawn_unittest.c")


@pytest.fixture(scope="module")
def spawn_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("xfer_spawn sources missing")
    out = str(tmp_path_factory.mktemp("xferspawn") / "ut")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", os.path.join(REPO, "src"),
         SRC, TEST, "-o", out],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail(f"xfer_spawn suite failed to COMPILE (warnings are errors):"
                    f"\n{r.stderr}")
    return out


def test_reparented_runner_suite(spawn_bin):
    r = subprocess.run([spawn_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, f"runner suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "0 failures" in r.stdout
    # The reparent invariant is the security-critical one — confirm it ran.
    assert "reparent invariant (no reapable child)" in r.stdout

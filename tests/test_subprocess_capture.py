"""Compile + run the standalone stdout-capture helper suite
(src/core/compat/subprocess_unittest.c).

The helper (brix_subprocess_capture) is what the TPC token exchange, the WebDAV
credential exchange and the native client's oidc-token refresh use to run
`curl`/`oidc-token` and read its output + exit code. It runs the command under a
double-forked, reparented agent so that nginx's SIGCHLD handler — which fires on
the worker's MAIN thread, whatever mask the thread-pool caller set — can never
reap the command first and leave the helper reading a stolen status as "exit 0"
(the rhB42 fast-tier halt, history-testing-and-incidents §24.15).

The C suite checks capture + exit-code propagation, exec failure (127),
kill-by-signal (-1), truncation without a hang, the argument guards, and — the
race pin — 300 runs under a hostile reaper thread that must all report the
real exit code, followed by the reparent invariant (no child left to reap).
"""
import os
import shutil
import subprocess

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS, pal_host_sources


def _guard_capture_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")


def _guard_capture_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("subprocess sources missing")


def _guard_capture_bin_3(r):
    if r.returncode != 0:
        pytest.fail(f"subprocess suite failed to COMPILE (warnings are errors):"
                    f"\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src", "core", "compat", "subprocess.c")
TEST = os.path.join(REPO, "src", "core", "compat", "subprocess_unittest.c")


@pytest.fixture(scope="module")
def capture_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_capture_bin_1(cc)
    _guard_capture_bin_2()
    out = str(tmp_path_factory.mktemp("subprocess") / "ut")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-pthread",
         # INVARIANT 14: the TU reaches platform/platform.h, which selects its
         # <host>/host.h from this token alone and #errors without it.
         *PLATFORM_HOST_FLAGS,
         "-I", os.path.join(REPO, "src"), SRC, TEST,
         # The capture kernel opens its pipe and reaps with a deadline through
         # the PAL (brix_plat_pipe2 / brix_plat_wait_pid_timeout); the module
         # build compiles the whole host directory, this line names the two
         # bodies it reaches.
         *[os.path.join(REPO, rel)
           for rel in pal_host_sources("storage_wrapper", "process_wrapper")],
         "-o", out],
        capture_output=True, text=True)
    _guard_capture_bin_3(r)
    return out


@pytest.fixture(scope="module")
def suite_output(capture_bin):
    r = subprocess.run([capture_bin], capture_output=True, text=True, timeout=120)
    print(r.stdout)
    return r


def test_capture_suite_passes(suite_output):
    assert suite_output.returncode == 0, (
        f"capture suite reported failures:\n{suite_output.stdout}\n{suite_output.stderr}")
    assert "0 failures" in suite_output.stdout


def test_error_contracts_ran(suite_output):
    # The two shapes callers map to distinct errors: a signalled child is rc -1
    # (kXR_ServerError), a missing command is exit 127 (kXR_AuthFailed).
    assert "ok killed -> rc -1" in suite_output.stdout
    assert "ok exec failure: ec 127" in suite_output.stdout
    assert "ok truncation: ec after overflow" in suite_output.stdout


def test_hostile_reaper_pin_ran(suite_output):
    # The security-critical checks: a reaper on another thread never turns a
    # failing command into "exit 0", and nothing is left for us to reap.
    assert "ok hostile reaper (300/300 exit 7" in suite_output.stdout
    assert "ok reparent invariant (no reapable child)" in suite_output.stdout

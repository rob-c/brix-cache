"""test_creds_guard.py — unit test of the reserved-id guard predicate.

Compiles c/creds_guard_test.c against src/impersonate/idmap.c and runs it.  This
exercises xrootd_imp_creds_privileged() — the single authoritative test that the
broker calls (at floor = XROOTD_IMP_HARD_MIN_ID = 1000) before ANY setfsuid, and
that the mapping layer calls to deny reserved principals.  It is the core proof
that dropping to uid/gid < 1000 is detected and refused in every case.

Pure logic: needs no user namespace, no root, no server.  Skips only if a C
compiler or the nginx source tree is unavailable.
"""

import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
NGINX_SRC = os.environ.get("TEST_NGINX_SRC", "/tmp/nginx-1.28.3")
CC = os.environ.get("CC", "cc")
IMP = os.path.join(REPO, "src", "impersonate")


def _inc_flags():
    subs = ["src/core", "src/event", "src/event/modules", "src/os/unix",
            "objs", "src/stream"]
    return [f"-I{os.path.join(NGINX_SRC, s)}" for s in subs] + [f"-I{IMP}"]


@pytest.mark.timeout(60)
def test_reserved_id_guard_predicate():
    if not shutil.which(CC):
        pytest.skip("no C compiler")
    if not os.path.isfile(os.path.join(NGINX_SRC, "src/core/ngx_config.h")):
        pytest.skip(f"nginx source tree not at {NGINX_SRC} (set TEST_NGINX_SRC)")

    out_bin = "/tmp/creds_guard_test.bin"
    cmd = [CC, "-O2", "-D_GNU_SOURCE", "-Wall", *_inc_flags(), "-o", out_bin,
           os.path.join(HERE, "c", "creds_guard_test.c"),
           os.path.join(IMP, "idmap.c")]
    build = subprocess.run(cmd, capture_output=True, text=True)
    assert build.returncode == 0, f"compile failed:\n{build.stderr}"

    run = subprocess.run([out_bin], capture_output=True, text=True, timeout=30)
    out = run.stdout + "\n" + run.stderr
    assert run.returncode == 0, out
    assert "ALL PASSED" in run.stdout, out

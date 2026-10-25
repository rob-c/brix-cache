"""test_impersonate_idmap.py — unit tests for the phase-40 idmap layer.

Compiles tests/c/idmap_test.c against the split idmap implementation and its
policy state (using the nginx source tree for headers) and runs it. The C test
exercises grid-mapfile + getpwnam + the squash/deny/min_uid/reserved-uid policy +
the TTL cache against the host's real NSS (its own user). Pure logic — needs no
nginx server, no root.

Skips cleanly when a C compiler or the nginx source tree is unavailable.
"""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from cmdscripts.compile_run import pal_host_sources
from test_platform_linux_native import native_compile

def _guard_test_idmap_unit_1():
    if not shutil.which(CC):
        pytest.skip("no C compiler")

def _guard_test_idmap_unit_2():
    if not os.path.isfile(os.path.join(NGINX_SRC, "src/core/ngx_config.h")):
        pytest.skip(f"nginx source tree not at {NGINX_SRC} (set TEST_NGINX_SRC)")

def _check_test_idmap_unit_1(build):
    assert build.returncode == 0, f"compile failed:\n{build.stderr}"

def _guard_test_idmap_unit_3(run):
    if "SKIP:" in run.stdout:
        pytest.skip(run.stdout.strip())


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The nginx source tree (for ngx_config.h / ngx_core.h). Mirrors TEST_NGINX_BIN.
NGINX_SRC = os.environ.get("TEST_NGINX_SRC", "/tmp/nginx-1.28.3")
CC = os.environ.get("CC", "cc")


def _inc_flags():
    base = NGINX_SRC
    subs = [
        "src/core", "src/event", "src/event/modules", "src/event/quic", "src/os/unix",
        "objs", "src/stream",
    ]
    return [f"-I{os.path.join(base, s)}" for s in subs] + [f"-I{os.path.join(REPO, 'src')}"]


def _require_clean_identity():
    # The C test's happy-path checks resolve the CURRENT user through the idmap,
    # which (correctly, for security) REFUSES any user that is a member of a
    # reserved/low-gid or privileged group (wheel/sudo/adm/...) — those targets
    # could escalate via supplementary groups.  A developer/CI account is usually
    # in exactly such groups, so the happy-path assertions cannot hold for it.
    # Skip cleanly in that case (the policy itself is exercised by the DENY checks
    # and by tests/test_impersonate_*; this unit test needs a "clean" target user).
    import grp
    _self_gids = set(os.getgroups()) | {os.getgid()}
    _privileged_names = {"wheel", "sudo", "admin", "root", "adm", "docker"}
    _priv_gids = set()
    for _name in _privileged_names:
        try:
            _priv_gids.add(grp.getgrnam(_name).gr_gid)
        except KeyError:
            pass
    if any(g < 1000 for g in _self_gids) or (_self_gids & _priv_gids):
        pytest.skip(
            "current user is in a reserved/low-gid or privileged group "
            f"(gids={sorted(_self_gids)}); the idmap correctly refuses to "
            "impersonate it, so the happy-path checks are not applicable — "
            "run as a clean user (uid>=1000, no privileged groups) to exercise them")


@pytest.mark.timeout(60)
def test_idmap_unit(tmp_path, native_compile):
    _guard_test_idmap_unit_1()
    _guard_test_idmap_unit_2()
    _require_clean_identity()
    test_c = os.path.join(REPO, "tests/c/idmap_test.c")
    sources = ["src/auth/impersonate/" + name + ".c" for name in (
        "impersonate_state", "idmap", "idmap_denylist", "idmap_gridmap")]
    out_bin = native_compile("idmap-unit", Path(test_c).read_text(),
                             [*sources, *pal_host_sources("process_wrapper")],
                             ["-ffunction-sections", "-fdata-sections",
                              "-Wl,--gc-sections"])

    run = subprocess.run([out_bin], capture_output=True, text=True, timeout=30)
    # The harness self-skips (rc 0, "SKIP:") when run as a sub-1000 uid.
    _guard_test_idmap_unit_3(run)
    def _assert_test_idmap_unit_1():
        assert run.returncode == 0, f"idmap test failed:\n{run.stdout}\n{run.stderr}"
        assert "ALL PASSED" in run.stdout, run.stdout

    _assert_test_idmap_unit_1()

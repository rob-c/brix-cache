"""test_userns_impersonate.py — end-to-end test of the phase-40 impersonation
broker inside an unprivileged user namespace.

This test is intentionally OUTSIDE the main test suite (its own `tests/userns/`
sub-folder) because it requires capabilities the rest of the suite does not:

  * unprivileged user namespaces (CLONE_NEWUSER),
  * the setuid-root `newuidmap`/`newgidmap` helpers, and
  * a `/etc/subuid` + `/etc/subgid` range for the invoking user.

It compiles `c/userns_broker_test.c` against the real broker/client/idmap sources
and runs it.  That driver creates a user namespace with a subuid RANGE map, becomes
in-ns root over a private range of uids, bind-mounts a fake `/etc/passwd`, forks the
actual privileged broker, and drives the worker client through the wire protocol —
asserting ownership-by-mapped-user, kernel DAC enforcement, confinement, deny
policy, squash, and no cross-request credential leak.

When userns / newuidmap / subuid are unavailable, the driver prints `SKIP: ...`
and exits 0; this test then skips (never fails) so it is CI-safe everywhere.
"""

import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
NGINX_SRC = os.environ.get("TEST_NGINX_SRC", "/tmp/nginx-1.28.3")
CC = os.environ.get("CC", "cc")

IMP = os.path.join(REPO, "src", "auth", "impersonate")
# broker.c was split into broker.c (dispatch) + broker_creds.c (become/restore/
# drop_caps + the svc-user uid/gid globals) + broker_ops.c (imp_do_op); the
# standalone driver must link all three or the privilege-switch symbols are
# undefined.
SRCS = [
    os.path.join(HERE, "c", "userns_broker_test.c"),
    os.path.join(IMP, "broker.c"),
    os.path.join(IMP, "broker_creds.c"),
    os.path.join(IMP, "broker_ops.c"),
    os.path.join(IMP, "client.c"),
    os.path.join(IMP, "idmap.c"),
]


def _inc_flags():
    subs = [
        "src/core", "src/event", "src/event/modules", "src/os/unix",
        "objs", "src/stream",
    ]
    return [f"-I{os.path.join(NGINX_SRC, s)}" for s in subs] + [f"-I{IMP}", f"-I{os.path.join(REPO, 'src')}"]


def _userns_supported():
    """Cheap pre-flight: can this host create an unprivileged user namespace?"""
    try:
        r = subprocess.run(
            ["unshare", "-Ur", "true"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.timeout(120)
def test_userns_impersonation_end_to_end():
    if not shutil.which(CC):
        pytest.skip("no C compiler")
    if not os.path.isfile(os.path.join(NGINX_SRC, "src/core/ngx_config.h")):
        pytest.skip(f"nginx source tree not at {NGINX_SRC} (set TEST_NGINX_SRC)")
    if not (shutil.which("newuidmap") and shutil.which("newgidmap")):
        pytest.skip("newuidmap/newgidmap not installed (uidmap package)")
    if not _userns_supported():
        pytest.skip("unprivileged user namespaces unavailable on this host")

    out_bin = "/tmp/userns_broker_test.bin"
    cmd = [CC, "-O2", "-D_GNU_SOURCE", "-Wall", *_inc_flags(),
           "-o", out_bin, *SRCS]
    build = subprocess.run(cmd, capture_output=True, text=True)
    assert build.returncode == 0, f"compile failed:\n{build.stderr}"

    run = subprocess.run([out_bin], capture_output=True, text=True, timeout=90)
    combined = run.stdout + "\n" + run.stderr

    # The driver self-skips (exit 0 + "SKIP:") when in-ns prerequisites are unmet.
    if "SKIP:" in run.stdout and "ALL PASSED" not in run.stdout:
        pytest.skip(f"userns prerequisites unmet:\n{combined}")

    assert run.returncode == 0, f"userns broker test failed:\n{combined}"
    assert "ALL PASSED" in run.stdout, combined
    # Sanity: the security-critical assertions actually executed.
    assert "DAC enforced" in combined
    assert "no setfsuid credential leak" in combined

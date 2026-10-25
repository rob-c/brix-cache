"""Proof: a tape/nearline (frm://) backend serves under STRICT `brix_seccomp
enforce` + `brix_seccomp_allow_exec off` — execve/execveat KILLED — because the
default FRM MSS adapter is the built-in POSIX "stub" (src/fs/backend/frm/
sd_frm_stub.c): recall/migrate/purge are plain file copies (open/read/write/
rename/unlink), all allowlisted, no fork+exec.  Only the external-HSM "exec"
adapter (tape://exec + $BRIX_FRM_STAGECMD) fork+execs and needs allow_exec.

This refutes the earlier (wrong) claim that a tape:// backend requires allow_exec.

Run:  PYTHONPATH=tests pytest tests/test_seccomp_tape_stub.py -v
"""
from __future__ import annotations

import os
import shutil

import pytest

import settings
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST
from lib_py.seccomp_probe import worker_seccomp as _worker_seccomp
from lib_py.process_host import procfs_available

# The whole premise is a worker running under a seccomp filter, which is a
# Linux kernel feature, and the proof reads the worker's Seccomp: line out of
# /proc. A host with no procfs can neither run the filter nor establish that it
# is running, so the assertion below would fail for a reason that has nothing
# to do with the tape path it is testing.
pytestmark = [pytest.mark.skipif(
                  not procfs_available(),
                  reason="seccomp enforcement and its /proc proof are Linux-only"),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-frmsec")]

BIND = BIND_HOST
BASE = os.path.join(settings.TEST_ROOT, "frmsec")
TAPE_BYTES = b"TAPE-STUB-NO-EXEC-" + b"t" * 200 + b"\n"


def _traversable(path: str) -> None:
    from pathlib import Path
    for anc in [Path(path).resolve(), *Path(path).resolve().parents]:
        if str(anc) == "/":
            break
        try:
            anc.chmod((anc.stat().st_mode & 0o777) | 0o001)
        except (PermissionError, FileNotFoundError):
            pass


@pytest.fixture(scope="module")
def harness():
    os.makedirs(BASE, exist_ok=True)
    os.chmod(BASE, 0o755)
    _traversable(BASE)
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()
        shutil.rmtree(BASE, ignore_errors=True)


def test_tape_stub_recall_under_seccomp_enforce(harness):
    """A read of a nearline object recalls it through the POSIX stub adapter and
    serves the tape bytes, while the worker runs `brix_seccomp enforce` (execve
    killed) — proving the tape data path uses no exec."""
    client = pytest.importorskip("XRootD.client",
                                 reason="pyxrootd client not installed")
    from XRootD.client.flags import OpenFlags

    root = os.path.join(BASE, "stub")
    tape = os.path.join(root, "tape")      # the base dir IS the offline "tape"
    cache = os.path.join(root, "cache")    # recall target (brix_cache_store)
    os.makedirs(tape, exist_ok=True)
    os.makedirs(cache, exist_ok=True)
    for d in (root, tape, cache):
        os.chmod(d, 0o777)                 # worker (nobody) creates .online + cache
    with open(os.path.join(tape, "near.dat"), "wb") as fh:
        fh.write(TAPE_BYTES)
    _traversable(tape)

    ep = harness.start(NginxInstanceSpec(
        name="frmsec-stub",
        template="nginx_lc_frm_stub_seccomp.conf",
        protocol="root",
        readiness="tcp",
        template_values={"STORAGE_BACKEND": f"frm://stub{tape}",
                         "CACHE_DIR": cache}))

    # The worker really is under an enforce filter (execve/execveat are killed) —
    # so if the stub recall tried to exec, it would die with SIGSYS.
    assert _worker_seccomp(ep.prefix) == "2", \
        "worker is not under a seccomp enforce filter"

    # Read the nearline object → triggers the stub POSIX recall → serves the bytes.
    f = client.File()
    st, _ = f.open(f"root://{BIND}:{ep.port}//near.dat", OpenFlags.READ)
    assert st.ok, f"nearline open failed under enforce: {st.message}"
    rst, data = f.read()
    f.close()
    assert rst.ok, f"nearline read failed under enforce: {rst.message}"
    assert data == TAPE_BYTES, \
        "stub recall under strict enforce must serve the tape bytes (no exec needed)"

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

pytestmark = pytest.mark.uses_lifecycle_harness

BIND = "127.0.0.1"
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


def _worker_seccomp(prefix: str) -> "str | None":
    """Seccomp: value from the (single) nginx worker under `prefix`'s master."""
    with open(os.path.join(prefix, "logs", "nginx.pid"), encoding="utf-8") as fh:
        master = int(fh.read().strip())
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf-8") as fh:
                ppid = int(fh.read().rpartition(")")[2].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        if ppid != master:
            continue
        try:
            with open(f"/proc/{entry}/status", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("Seccomp:"):
                        return line.split()[1]
        except OSError:
            continue
    return None


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

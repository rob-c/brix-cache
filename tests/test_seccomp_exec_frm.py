"""E2E proof of `brix_seccomp_allow_exec` on the FRM "exec" MSS adapter.

The exec adapter (`tape://exec` / `frm://exec` + $BRIX_FRM_STAGECMD) drives a real
HSM by fork+execing the operator stage command for exists/recall/migrate/purge.
`brix_seccomp_allow_exec` DEFAULTS ON, so under `brix_seccomp enforce` the stage
command runs out of the box; `brix_seccomp_allow_exec off` opts back into the strict
anti-shell posture, which KILLs execve.

This drives the REAL exec adapter with a mock stage command written in POSIX shell
(`test -f` / `mkdir` / `cp`), and proves end-to-end:

  * enforce, default allow_exec  -> the stage command runs, the nearline object is
    recalled and served;
  * enforce + allow_exec off     -> the stage command's execve is SIGSYS-killed, the
    recall fails, and the object is NOT served.

Run:  PYTHONPATH=tests pytest tests/test_seccomp_exec_frm.py -v
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

import settings
from cmdscripts import frm_stagecmd
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

BIND = "127.0.0.1"
BASE = os.path.join(settings.TEST_ROOT, "frmexec")
TAPE_BYTES = b"EXEC-ADAPTER-RECALL-" + b"e" * 200 + b"\n"


def _traversable(path: str) -> None:
    for anc in [Path(path).resolve(), *Path(path).resolve().parents]:
        if str(anc) == "/":
            break
        try:
            anc.chmod((anc.stat().st_mode & 0o777) | 0o001)
        except (PermissionError, FileNotFoundError):
            pass


def _worker_seccomp(prefix: str) -> "str | None":
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


def _start(harness, name: str, allow_exec: bool):
    root = os.path.join(BASE, name)
    base = os.path.join(root, "base")     # frm://exec<base> — online buffer root
    tape = os.path.join(root, "tape")     # the mock's offline "tape"
    cache = os.path.join(root, "cache")   # brix_cache_store recall target
    for d in (root, base, tape, cache):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o777)                # worker (nobody) writes .online + cache
    with open(os.path.join(tape, "near.dat"), "wb") as fh:
        fh.write(TAPE_BYTES)
    audit = os.path.join(root, "audit.log")
    open(audit, "w").close()
    os.chmod(audit, 0o666)
    # Exec MSS adapter — logs "verb key" best-effort (unprivileged worker may
    # lack write perms). Tape dir + audit path ride in a JSON sidecar (nginx
    # rewrites its worker environ; only argv + BRIX_FRM_STAGECMD survive).
    stagecmd = frm_stagecmd.install(
        root, tape=tape, audit=audit, audit_format="verb_key",
        audit_best_effort=True)
    _traversable(stagecmd)
    _traversable(tape)
    _traversable(cache)

    return harness.start(NginxInstanceSpec(
        name=f"frmexec-{name}",
        template="nginx_lc_frm_exec_seccomp.conf",
        protocol="root",
        readiness="tcp",
        template_values={
            "STORAGE_BACKEND": f"frm://exec{base}",
            "CACHE_DIR": cache,
            # allow_exec is ON BY DEFAULT: the works-case supplies NO directive
            # (proving the default), the killed-case must explicitly opt out.
            "ALLOW_EXEC_LINE": ("" if allow_exec
                                else "        brix_seccomp_allow_exec off;"),
        },
        env={"BRIX_FRM_STAGECMD": stagecmd}))


def _read_nearline(port: int):
    from XRootD import client
    from XRootD.client.flags import OpenFlags
    fh = client.File()
    st, _ = fh.open(f"root://{BIND}:{port}//near.dat", OpenFlags.READ)
    if not st.ok:
        return None
    rst, data = fh.read()
    fh.close()
    return data if rst.ok else None


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


def test_exec_recall_works_under_enforce_by_default(harness):
    """enforce with NO allow_exec directive: because allow_exec DEFAULTS ON, the FRM
    exec adapter fork+execs the mock stage command, recalls the nearline object, and
    serves its bytes — the exec path works end-to-end under a live seccomp filter
    without any opt-in."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    ep = _start(harness, "allow", allow_exec=True)
    assert _worker_seccomp(ep.prefix) == "2", "worker is not under seccomp enforce"
    data = _read_nearline(ep.port)
    assert data == TAPE_BYTES, \
        "under enforce the (default-on) stage command must run and serve the recall"


def test_exec_recall_killed_under_enforce_with_allow_exec_off(harness):
    """enforce + `brix_seccomp_allow_exec off`: the strict anti-shell posture KILLs
    the stage command's execve, so residency/recall cannot run and the object is NOT
    served — proving `off` still hardens (and that the worker really is filtered)."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    ep = _start(harness, "deny", allow_exec=False)
    assert _worker_seccomp(ep.prefix) == "2", "worker is not under seccomp enforce"
    data = _read_nearline(ep.port)
    assert data != TAPE_BYTES, \
        "with allow_exec off the stage command execve must be killed — no recall/serve"

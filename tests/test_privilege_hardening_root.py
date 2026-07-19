"""Host-root privilege-hardening e2e — verifies the "launched as root" defenses.

Confirms three source hardenings that only matter, and can only be observed, when
the nginx master runs as real root:

  * item 1 — a worker (even in the DEFAULT posture: impersonation off, seccomp off)
    that runs as root sheds EVERY capability and sets NO_NEW_PRIVS at worker init;
  * item 3 — the root-equivalent impersonation broker installs a seccomp filter
    (SECCOMP_MODE_FILTER) and holds only CAP_SETUID+CAP_SETGID;
  * item 1 in map mode — the (nobody) worker is likewise cap-shed + NNP.

Everything is read from /proc/<pid>/status, so no request needs to be driven. Off
a root host every test skips cleanly.

Run:  sudo -E env PYTHONPATH=tests pytest tests/test_privilege_hardening_root.py -v
"""
from __future__ import annotations

import os
import shutil
import time

import pytest

import settings
from server_launcher import LifecycleHarness, launch_fleet_nginx
from server_registry import NginxInstanceSpec, endpoint_for

import impersonation_gridmap_helpers as H

pytestmark = [
    pytest.mark.privileged,
    pytest.mark.skipif(os.geteuid() != 0,
                       reason="privilege-drop hardening needs a real root master"),
]

BIND = "127.0.0.1"
BASE = os.path.join(settings.TEST_ROOT, "hardening")
CAP_SETUID_SETGID = "00000000000000c0"   # (1<<CAP_SETUID)|(1<<CAP_SETGID)
NO_CAPS = "0000000000000000"
_SOCKS: "list[str]" = []


def _status(pid: int) -> "dict[str, str]":
    out: "dict[str, str]" = {}
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            key, _, val = line.partition(":")
            if key in ("CapEff", "CapBnd", "CapPrm", "NoNewPrivs", "Seccomp", "Uid"):
                out[key] = val.strip()
    return out


def _ppid(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            # ppid is the field after the (comm) parenthesised name.
            return int(fh.read().rpartition(")")[2].split()[1])
    except (OSError, IndexError, ValueError):
        return -1


def _worker_pids(master: int) -> "list[int]":
    """nginx worker pids = direct children of the master (the broker is double-
    forked and reparented to init, so it is excluded)."""
    pids = []
    for entry in os.listdir("/proc"):
        if entry.isdigit() and _ppid(int(entry)) == master:
            pids.append(int(entry))
    return pids


@pytest.fixture(scope="module")
def harness():
    os.makedirs(BASE, exist_ok=True)
    os.chmod(BASE, 0o755)
    H.make_world_traversable(BASE)
    _SOCKS.clear()
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()
        for sock in _SOCKS:
            H.reap_broker(sock)
        shutil.rmtree(BASE, ignore_errors=True)


def _launch(harness, spec) -> object:
    unique = harness.register(spec)
    ep = endpoint_for(unique)
    harness.launcher.render_nginx(unique)
    harness.nginx_test(unique.name)
    launch_fleet_nginx(ep.config, prefix=ep.prefix)
    sock = spec.template_values.get("SOCK")
    if sock:
        _SOCKS.append(sock)
    for _ in range(120):
        if os.path.exists(ep.pidfile):
            break
        time.sleep(0.1)
    time.sleep(0.8)   # let the worker(s)/broker finish init
    return ep


def _master(ep) -> int:
    with open(ep.pidfile, encoding="utf-8") as fh:
        return int(fh.read().strip())


def test_root_worker_sheds_dangerous_caps_and_sets_nnp(harness):
    """item 1 — DEFAULT posture (impersonation off, HTTP-only): a `user root;`
    worker is uid 0 yet its capability set is reduced to ONLY CAP_SETUID+CAP_SETGID
    (CapEff==00..c0) — every dangerous cap (DAC_OVERRIDE, MKNOD, SYS_ADMIN, PTRACE,
    CHOWN, FOWNER, ...) is shed and NO_NEW_PRIVS is set, so a worker-code exploit
    can no longer bypass on-disk DAC, create device nodes, or ptrace. SETUID/SETGID
    are retained only so a legitimate identity drop (pblock/single) still works and
    add no escalation to an already-uid-0 process. Old code left this worker fully
    privileged (the cap-drop ran only in `map` mode / stream workers)."""
    export, _run, _auth = H.prepare_export(BASE, "caps-off")
    ep = _launch(harness, NginxInstanceSpec(
        name="hard-caps-off",
        template="nginx_hardening_root_webdav.conf",
        protocol="http", data_root=export, readiness="tcp",
        template_values={"EXPORT": export}))
    workers = _worker_pids(_master(ep))
    assert workers, "no worker process found"
    st = _status(workers[0])
    assert st.get("Uid", "").split()[:1] == ["0"], f"worker is not root: {st}"
    # CapEff == setuid|setgid proves every dangerous cap (DAC_OVERRIDE, MKNOD,
    # SYS_ADMIN, PTRACE, CHOWN, ...) is dropped.
    assert st.get("CapEff") == CAP_SETUID_SETGID, \
        f"root worker retains dangerous capabilities: {st}"
    assert st.get("CapPrm") == CAP_SETUID_SETGID, \
        f"root worker retains dangerous permitted caps: {st}"
    assert st.get("NoNewPrivs") == "1", f"NO_NEW_PRIVS not set on worker: {st}"


def test_broker_seccomp_confined_and_map_worker_hardened(harness):
    """item 3 — the root-equivalent impersonation broker runs under a seccomp
    filter and holds only CAP_SETUID+CAP_SETGID; item 1 — the map-mode (nobody)
    worker is cap-shed + NNP."""
    export, run_dir, auth_dir = H.prepare_export(BASE, "map")
    gridmap = os.path.join(auth_dir, "gridmap")
    H.write_gridmap(gridmap, [("gm-probe", "nobody")])  # content irrelevant; no request driven
    ti = H.token_authority(auth_dir)
    sock = os.path.join(run_dir, "impersonate.sock")
    ep = _launch(harness, NginxInstanceSpec(
        name="hard-map",
        template="nginx_impersonate_gridmap_webdav.conf",
        protocol="http", data_root=export, readiness="tcp",
        template_values={
            "EXPORT": export, "SOCK": sock, "GRIDMAP": gridmap,
            "JWKS": ti.jwks_path, "ISSUER": H.ISSUER, "AUDIENCE": H.AUDIENCE,
            "DEFAULT_USER_LINE": "",
        }))

    with open(sock + ".pid", encoding="utf-8") as fh:
        broker = int(fh.read().strip())
    bst = _status(broker)
    assert bst.get("Seccomp") == "2", f"broker not under a seccomp filter: {bst}"
    assert bst.get("NoNewPrivs") == "1", f"broker NO_NEW_PRIVS not set: {bst}"
    assert bst.get("CapEff") == CAP_SETUID_SETGID, \
        f"broker CapEff is not exactly CAP_SETUID+CAP_SETGID: {bst}"

    workers = _worker_pids(_master(ep))
    assert workers, "no worker process found"
    wst = _status(workers[0])
    assert wst.get("CapEff") == NO_CAPS, f"map worker still holds capabilities: {wst}"
    assert wst.get("NoNewPrivs") == "1", f"map worker NO_NEW_PRIVS not set: {wst}"

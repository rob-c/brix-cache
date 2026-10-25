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
import pwd
import shutil
import subprocess
import time

import pytest
import requests

import settings
from cmdscripts.live_common import inject_nginx_load_modules
from server_launcher import LifecycleHarness, launch_fleet_nginx
from server_registry import NginxInstanceSpec, endpoint_for

import impersonation_gridmap_helpers as H
from settings import BIND_HOST

pytestmark = [
    pytest.mark.privileged,
    pytest.mark.skipif(os.geteuid() != 0,
                       reason="privilege-drop hardening needs a real root master"),
]

BIND = BIND_HOST
BASE = os.path.join(settings.TEST_ROOT, "hardening")
CAP_SETUID_SETGID = "00000000000000c0"   # (1<<CAP_SETUID)|(1<<CAP_SETGID)
NO_CAPS = "0000000000000000"
_SOCKS: "list[str]" = []


def _status(pid: int) -> "dict[str, str]":
    out: "dict[str, str]" = {}
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            key, _, val = line.partition(":")
            if key in ("CapEff", "CapBnd", "CapPrm", "CapInh", "CapAmb",
                       "NoNewPrivs", "Seccomp", "Uid"):
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


def _required_tool(name: str, reason: str) -> str:
    tool = shutil.which(name)
    if tool is None:
        pytest.skip(reason)
    return tool


def _probe_paths(name: str, binary_name: str):
    probe = os.path.join(BASE, name)
    return (
        probe,
        os.path.join(probe, "prefix"),
        os.path.join(probe, binary_name),
        os.path.join(probe, "nginx.conf"),
        os.path.join(probe, "nginx.log"),
    )


def _prepare_probe(prefix: str, binary: str, config: str, account) -> None:
    logs = os.path.join(prefix, "logs")
    os.makedirs(logs, exist_ok=True)
    os.chown(prefix, account.pw_uid, account.pw_gid)
    os.chown(logs, account.pw_uid, account.pw_gid)
    shutil.copy2(settings.NGINX_BIN, binary)
    source = os.path.join(os.path.dirname(__file__), "configs",
                          "nginx_module_load_smoke.conf")
    shutil.copy2(source, config)
    inject_nginx_load_modules(config, settings.NGINX_BIN)


def _start_probe(command, log_path: str):
    with open(log_path, "wb") as log:
        return subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT)


def _wait_for_workers(proc) -> list[int]:
    for _ in range(50):
        workers = _worker_pids(proc.pid)
        if workers or proc.poll() is not None:
            return workers
        time.sleep(0.1)
    return []


def _stop_probe(proc) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _assert_unprivileged_status(status, uid: int) -> None:
    assert status.get("Uid", "").split()[:1] == [str(uid)], status
    assert status.get("CapEff") == NO_CAPS, status
    assert status.get("CapPrm") == NO_CAPS, status
    assert status.get("CapInh") == NO_CAPS, status
    assert status.get("CapAmb") == NO_CAPS, status
    assert status.get("NoNewPrivs") == "1", status


def _fail_without_workers(workers, log_path: str) -> None:
    if workers:
        return
    with open(log_path, encoding="utf-8") as log:
        pytest.fail(log.read())


def test_root_configured_worker_deescalates_to_nobody(harness):
    """item 1 — DEFAULT posture (impersonation off, HTTP-only) with `user root;` and
    no brix_worker_user: brix FORCE-DROPS the root-capable worker down to `nobody` at
    init (brix_imp_worker_deescalate), so pre-auth credential parsing never runs as a
    root-capable identity. Observable steady state: the worker is uid 65534, holds NO
    capabilities at all (not even the transient SETUID/SETGID retained across the
    drop), and NO_NEW_PRIVS is set. (Before the de-escalation this worker stayed uid 0
    with CapEff==CAP_SETUID+CAP_SETGID; that root state is now only momentary.)"""
    export, _run, _auth = H.prepare_export(BASE, "caps-off")
    ep = _launch(harness, NginxInstanceSpec(
        name="hard-caps-off",
        template="nginx_hardening_root_webdav.conf",
        protocol="http", data_root=export, readiness="tcp",
        template_values={"EXPORT": export}))
    workers = _worker_pids(_master(ep))
    assert workers, "no worker process found"
    st = _status(workers[0])
    # The root-configured worker de-escalated to nobody (65534) — not uid 0.
    assert st.get("Uid", "").split()[:1] == ["65534"], \
        f"root-configured worker was not dropped to nobody: {st}"
    assert st.get("CapEff") == NO_CAPS, \
        f"de-escalated worker still holds capabilities: {st}"
    assert st.get("CapPrm") == NO_CAPS, \
        f"de-escalated worker still holds permitted caps: {st}"
    assert st.get("NoNewPrivs") == "1", f"NO_NEW_PRIVS not set on worker: {st}"


def test_already_target_worker_terminally_drops_file_capabilities():
    """A worker executed as the target uid with file SETUID/SETGID capabilities
    must not take the already-target shortcut while retaining those capabilities."""
    setcap = _required_tool(
        "setcap", "setcap and setpriv are required for the file-capability probe")
    setpriv = _required_tool(
        "setpriv", "setcap and setpriv are required for the file-capability probe")
    nobody = pwd.getpwnam("nobody")
    _probe, prefix, binary, config, log_path = _probe_paths(
        "already-target-cap", "nginx-cap-probe")
    proc = None
    _prepare_probe(prefix, binary, config, nobody)
    subprocess.run([setcap, "cap_setuid,cap_setgid+ep", binary], check=True)
    try:
        proc = _start_probe([
            setpriv, f"--reuid={nobody.pw_uid}",
            f"--regid={nobody.pw_gid}", "--init-groups", binary,
            "-e", "stderr", "-p", prefix + "/", "-c", config,
            "-g", "daemon off;",
        ], log_path)
        workers = _wait_for_workers(proc)
        _fail_without_workers(workers, log_path)
        _assert_unprivileged_status(_status(workers[0]), nobody.pw_uid)
    finally:
        _stop_probe(proc)
        subprocess.run([setcap, "-r", binary], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_default_safe_nginx_identity_with_primary_group_starts():
    """An ordinary capability-free service account remains usable by default."""
    setpriv = _required_tool(
        "setpriv", "setpriv is required for the supplementary-group probe")
    account = pwd.getpwnam("daemon")
    _probe, prefix, binary, config, log_path = _probe_paths(
        "safe-service-groups", "nginx-group-probe")
    proc = None
    _prepare_probe(prefix, binary, config, account)
    try:
        proc = _start_probe([
            setpriv, f"--reuid={account.pw_uid}",
            f"--regid={account.pw_gid}", "--clear-groups", binary,
            "-e", "stderr", "-p", prefix + "/", "-c", config,
            "-g", "daemon off;",
        ], log_path)
        workers = _wait_for_workers(proc)
        _fail_without_workers(workers, log_path)
        _assert_unprivileged_status(_status(workers[0]), account.pw_uid)
    finally:
        _stop_probe(proc)


def test_default_service_identity_rejects_unregistered_supplementary_group():
    """An arbitrary non-root group is not assumed harmless (disk/docker/lxd)."""
    setpriv = _required_tool(
        "setpriv", "setpriv is required for the supplementary-group probe")
    account = pwd.getpwnam("daemon")
    extra = pwd.getpwnam("nobody").pw_gid
    _probe, prefix, binary, config, log_path = _probe_paths(
        "unsafe-service-groups", "nginx-group-probe")
    _prepare_probe(prefix, binary, config, account)
    proc = None
    try:
        proc = _start_probe([
            setpriv, f"--reuid={account.pw_uid}",
            f"--regid={account.pw_gid}", f"--groups={extra}", binary,
            "-e", "stderr", "-p", prefix + "/", "-c", config,
            "-g", "daemon off;",
        ], log_path)
        time.sleep(1)
    finally:
        _stop_probe(proc)
    with open(log_path, encoding="utf-8") as log:
        assert "cannot transition" in log.read()


def test_single_process_mode_refuses_privileged_serving():
    """`master_process off` must exit instead of serving in the root process."""
    probe = os.path.join(BASE, "single-process-refusal")
    prefix = os.path.join(probe, "prefix")
    config = os.path.join(probe, "nginx.conf")

    os.makedirs(os.path.join(prefix, "logs"), exist_ok=True)
    source = os.path.join(os.path.dirname(__file__), "configs",
                          "nginx_module_load_smoke.conf")
    shutil.copy2(source, config)
    inject_nginx_load_modules(config, settings.NGINX_BIN)
    result = subprocess.run([
        settings.NGINX_BIN, "-e", "stderr", "-p", prefix + "/",
        "-c", config, "-g", "master_process off; daemon off;",
    ], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
       text=True, timeout=10)
    assert result.returncode != 0, \
        "root single-process mode unexpectedly remained available"
    assert "master_process off is unsupported" in result.stdout, result.stdout


def test_http_only_worker_is_seccomp_filtered(harness):
    """An HTTP-only (WebDAV/S3-style) config with `brix_seccomp enforce` — no
    stream{} block at all — produces a worker under a seccomp filter (Seccomp:2)
    that STILL serves.  Before the fix these workers were never filtered (the
    install sat after the stream-config early-return and the directive was
    stream-only)."""
    export, _run, _auth = H.prepare_export(BASE, "http-seccomp")
    ep = _launch(harness, NginxInstanceSpec(
        name="hard-http-seccomp",
        template="nginx_hardening_http_seccomp.conf",
        protocol="http", data_root=export, readiness="tcp",
        template_values={"EXPORT": export}))
    workers = _worker_pids(_master(ep))
    assert workers, "no worker process found"
    st = _status(workers[0])
    assert st.get("Seccomp") == "2", \
        f"http-only worker is not seccomp-filtered (Seccomp!=2): {st}"
    assert st.get("NoNewPrivs") == "1", f"NO_NEW_PRIVS not set: {st}"
    # And the data plane still works under enforce (xattr + serving syscalls are
    # allowlisted) — a PUT must succeed, not get EPERM'd/killed.
    r = requests.put(f"http://{BIND}:{ep.port}/o.dat", data=b"seccomp-ok", timeout=15)
    assert r.status_code in (200, 201, 204), f"PUT under enforce failed: {r.status_code}"


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

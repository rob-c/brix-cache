"""Host-root worker privilege de-escalation e2e (brix_imp_worker_deescalate).

A `user root;` worker — or any worker holding CAP_SETUID — is root-capable, so the
pre-authentication credential parsers (JWT/macaroon/X.509/VOMS/krb5) would run on
attacker-controlled bytes as a root-capable identity.  brix force-drops such a worker
at init to a confined account:

  * default (no brix_worker_user)  -> dropped to "nobody" (uid 65534) + a warning;
  * brix_worker_user <acct>        -> dropped to that account;
  * account missing / uid|gid 0    -> the worker REFUSES to serve (fail-closed).

Linux checks procfs capability sets; FreeBSD checks native saved credentials and
procctl no-new-privileges. All actual nginx workers are inspected. Off a root
host every test skips cleanly.

Run:  sudo -E env PYTHONPATH=tests pytest tests/test_worker_deescalation_root.py -v
"""
from __future__ import annotations

import os
import pwd
import grp
import shutil
import sys
import time

import pytest
import psutil

import settings
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST
from lib_py.process_host import (native_no_new_privileges, native_process_record,
                                nginx_worker_title)
from lib_py.util import process_cmdline

pytestmark = [
    pytest.mark.privileged,
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.skipif(os.geteuid() != 0,
                       reason="worker de-escalation needs a real root master"),
]

BIND = BIND_HOST
BASE = os.path.join(settings.TEST_ROOT, "wdeesc")
NO_CAPS = "0000000000000000"


def _status(pid: int) -> dict:
    if sys.platform.startswith('freebsd'):
        return dict(credentials=native_process_record(pid, 'credentials', '-s'),
                    no_new_privileges=native_no_new_privileges(pid))
    out: "dict[str, str]" = {}
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            key, _, val = line.partition(":")
            if key in ("CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb",
                       "NoNewPrivs", "Uid", "Gid", "Groups"):
                out[key] = val.strip()
    return out


def _worker_statuses(prefix: str) -> list[dict]:
    """Inspect every actual worker; cache managers/helpers cannot satisfy this."""
    with open(os.path.join(prefix, "logs", "nginx.pid"), encoding="utf-8") as fh:
        master = int(fh.read().strip())
    children = psutil.Process(master).children()
    return [_status(child.pid) for child in children
            if nginx_worker_title(process_cmdline(child.pid))]


def _assert_confined(status, account):
    """Require complete irreversible identity loss and native NNP readback."""
    assert account.pw_uid > 0 and account.pw_gid > 0
    if 'credentials' in status:
        _assert_native_confined(status, account)
        return
    assert status['Uid'].split() == [str(account.pw_uid)] * 4, status
    assert status['Gid'].split() == [str(account.pw_gid)] * 4, status
    assert set(status['Groups'].split()) == {str(account.pw_gid)}, status
    for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'):
        assert status[name] == NO_CAPS, status
    assert status['NoNewPrivs'] == '1', status


def _assert_native_confined(status, account):
    credentials = status['credentials']
    assert [credentials[key] for key in ('ruid', 'uid', 'svuid')] == [account.pw_uid] * 3
    assert [credentials[key] for key in ('rgid', 'group', 'svgid')] == [account.pw_gid] * 3
    assert set(credentials['groups']) == {account.pw_gid}, credentials
    assert status['no_new_privileges'] is True, status


def _assert_workers_confined(prefix, account):
    workers = _worker_statuses(prefix)
    assert workers, 'no actual worker process found'
    for status in workers:
        _assert_confined(status, account)


def _distinct_confined_account() -> "pwd.struct_passwd | None":
    """An existing account with uid>0 AND gid>0 that is NOT nobody — so a drop to it
    is distinguishable from the default-nobody drop."""
    for name in ("daemon", "bin", "games", "ftp", "mail", "adm", "sync"):
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            continue
        if pw.pw_uid > 0 and pw.pw_gid > 0:
            return pw
    return None


def _make_traversable(path: str) -> None:
    from pathlib import Path
    for anc in [Path(path).resolve(), *Path(path).resolve().parents]:
        if str(anc) == "/":
            break
        try:
            anc.chmod((anc.stat().st_mode & 0o777) | 0o001)
        except (PermissionError, FileNotFoundError):
            pass


def _spec(name: str, worker_user_line: str):
    root = os.path.join(BASE, name)
    backend = os.path.join(root, "backend")
    cache = os.path.join(root, "cache")
    for d in (root, backend, cache):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o777)
    _make_traversable(backend)
    return NginxInstanceSpec(
        name=f"wdeesc-{name}",
        template="nginx_worker_deescalate_root.conf",
        protocol="root",
        readiness="tcp",
        template_values={
            "BIND_HOST": BIND_HOST,
            "ROOT_GROUP": grp.getgrgid(pwd.getpwnam('root').pw_gid).gr_name,
            "BACKEND_DIR": backend,
            "CACHE_DIR": cache,
            "WORKER_USER_LINE": worker_user_line,
        })


@pytest.fixture(scope="module")
def harness():
    os.makedirs(BASE, exist_ok=True)
    os.chmod(BASE, 0o755)
    _make_traversable(BASE)
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()
        shutil.rmtree(BASE, ignore_errors=True)


def test_root_worker_drops_to_nobody_by_default(harness):
    """`user root;`, no brix_worker_user: the root-capable worker is force-dropped to
    nobody (uid 65534) with NO capabilities and NO_NEW_PRIVS — pre-auth parsing runs
    unprivileged without any opt-in."""
    ep = harness.start(_spec("default", ""))
    _assert_workers_confined(ep.prefix, pwd.getpwnam('nobody'))


def test_root_worker_drops_to_configured_account(harness):
    """`user root;` + `brix_worker_user <acct>`: the worker is dropped to exactly the
    configured confined account (not nobody), proving the directive is honored."""
    pw = _distinct_confined_account()
    if pw is None:
        pytest.skip("no distinct uid>0/gid>0 account available to prove the directive")
    ep = harness.start(_spec("configured",
                             f"        brix_worker_user {pw.pw_name};"))
    _assert_workers_confined(ep.prefix, pw)


def test_root_worker_refuses_on_missing_account(harness):
    """security-neg — `brix_worker_user <nonexistent>`: brix cannot reach a confined
    account, so the worker REFUSES to serve (fail-closed) rather than parse as root.
    The refusal is logged; no serving worker settles at uid 0."""
    # The master binds the listen socket, so tcp-readiness passes even though the
    # worker init returns NGX_ERROR and the worker exits (fatal code 2 -> nginx does
    # not respawn it). Give it a moment, then assert the fail-closed refusal was
    # logged and that no worker is sitting at uid 0 serving.
    ep = harness.start(_spec(
        "missing", "        brix_worker_user brix_no_such_account_xyz;"))
    time.sleep(1.5)
    log_path = os.path.join(ep.prefix, "logs", "error.log")
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        log = fh.read()
    assert "refusing to serve" in log and "brix_no_such_account_xyz" in log, \
        "worker did not fail closed on a missing brix_worker_user account"
    assert _worker_statuses(ep.prefix) == [], 'a worker survived an unreachable confined account'

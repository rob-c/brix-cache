"""Self-test for account provisioning. The unprivileged guard runs anywhere; the real
roundtrip is skipped unless run as root."""
import os
import pwd
from types import SimpleNamespace

import pytest

from mu_authz_lib import accounts, principals
from lib_py import account_host

privileged = pytest.mark.skipif(os.geteuid() != 0, reason="needs root")


def test_require_privileged_raises_when_unprivileged(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError):
        accounts.require_privileged()


def test_create_group_reuses_matching_identity(monkeypatch):
    monkeypatch.setattr(
        accounts.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=65534))
    calls = []
    monkeypatch.setattr(
        accounts.subprocess, "run", lambda *args, **kwargs: calls.append(args))

    accounts._create_group("brixtest_squashed", 65534)

    assert calls == []


def test_create_group_creates_absent_identity(monkeypatch):
    def missing(_name):
        raise KeyError

    calls = []

    def succeed(argv, **_kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(accounts.grp, "getgrnam", missing)
    monkeypatch.setattr(accounts.subprocess, "run", succeed)

    accounts._create_group("brixtest_alice", 20001)

    assert calls == [account_host.group_add('brixtest_alice', 20001)]


@pytest.mark.parametrize('host,group,user', [
    ('linux', ['groupadd', '-g', '1701', 'brixtest_alice'],
     ['useradd', '-M', '-u', '1701', '-g', '1701', '-s', '/sbin/nologin', 'brixtest_alice']),
    ('freebsd15', ['/usr/sbin/pw', 'groupadd', 'brixtest_alice', '-g', '1701'],
     ['/usr/sbin/pw', 'useradd', 'brixtest_alice', '-u', '1701', '-g', '1701',
      '-s', '/sbin/nologin', '-d', '/nonexistent', '-h', '-']),
])
def test_account_commands_select_real_host_tools(monkeypatch, host, group, user):
    """BSD uses pw, while the Linux shadow-utils identity contract is retained."""
    monkeypatch.setattr(account_host.sys, 'platform', host)
    assert account_host.group_add('brixtest_alice', 1701) == group
    assert account_host.user_add('brixtest_alice', 1701, 1701, '/sbin/nologin') == user
    assert '-o' not in user and '-o' not in group
    assert '-r' not in account_host.user_delete('brixtest_alice')
    assert account_host.group_delete('brixtest_alice')[-1] == 'brixtest_alice'


def test_inactive_negative_principal_never_aliases_the_system_nobody_account(monkeypatch):
    """No credentials/gridmap exist for squashed; creating nobody aliases is unsafe."""
    monkeypatch.setattr(accounts, 'require_privileged', lambda: None)
    monkeypatch.setattr(accounts.subprocess, 'run', lambda *args, **kwargs:
                        pytest.fail('inactive identity must not modify accounts'))
    monkeypatch.setattr(accounts, '_remove_mismatched_user', lambda *args: True)
    principal = SimpleNamespace(name='squashed', uid=65534)
    accounts.provision({'squashed': principal})


def test_shared_uid_has_one_real_account_and_no_inactive_alias():
    """The gridmap and provisioner agree on the first identity for a shared uid."""
    cast = {name: SimpleNamespace(name=name, uid=uid) for name, uid in (
        ('alice', 1701), ('collide', 1701), ('bob', 1702), ('squashed', 65534))}
    assert accounts.canonical_account_names(cast) == {
        'alice': 'brixtest_alice', 'collide': 'brixtest_alice', 'bob': 'brixtest_bob'}


def test_create_group_rejects_unremovable_mismatched_identity(monkeypatch):
    monkeypatch.setattr(
        accounts.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=1234))
    monkeypatch.setattr(
        accounts.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=8, stderr=b"group is still in use"))

    with pytest.raises(RuntimeError, match="cannot replace group.*1234.*20001"):
        accounts._create_group("brixtest_alice", 20001)


def _unused_fixture_ids():
    """Select fresh ids rather than aliasing live fixture or system accounts."""
    used = {entry.pw_uid for entry in pwd.getpwall()}
    used.update(entry.gr_gid for entry in accounts.grp.getgrall())
    return sorted(set(range(62000, 65000)) - used)[:2]


@privileged
@pytest.mark.privileged
def test_provision_and_reap_roundtrip(monkeypatch):
    """Own a distinct namespace/ids, never reap the live MU fleet's accounts."""
    user_uid, broker_uid = _unused_fixture_ids()
    monkeypatch.setattr(accounts, 'PREFIX', 'brixtest_unit_')
    monkeypatch.setattr(accounts, 'BROKER_UID', broker_uid)
    accounts.sweep_leftover()
    cast = {'alice': SimpleNamespace(name='alice', uid=user_uid),
            'collide': SimpleNamespace(name='collide', uid=user_uid)}
    accounts.provision(cast)
    try:
        assert pwd.getpwnam("brixtest_unit_alice").pw_uid == cast["alice"].uid
        # collide shares alice's uid; only one account is created for that uid.
        assert cast["collide"].uid == cast["alice"].uid
    finally:
        accounts.reap()
    with pytest.raises(KeyError):
        pwd.getpwnam("brixtest_unit_alice")

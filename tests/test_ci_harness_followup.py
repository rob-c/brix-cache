"""Slow logging and incomplete process metadata cannot weaken fixture ownership."""

import os
from types import SimpleNamespace

import pytest

from tests import test_audit16c_query_token as audit
from tests import test_xrootdfs_daemonized as daemon
from brix_suite.launcher import start_operations
from brix_suite import settings
from cmdscripts import fwd_matrix_cell_a as forwarding


def _process(uid, command, executable):
    identities = None if uid is None else SimpleNamespace(real=uid)
    return SimpleNamespace(info={'uids': identities, 'cmdline': command},
                           exe=lambda: executable)


def _finder(monkeypatch, processes):
    monkeypatch.setattr(daemon.psutil, 'process_iter', lambda _fields: iter(processes))
    return daemon._owned_daemon('/private/mount')


def test_daemon_discovery_ignores_missing_metadata_and_keeps_exact_owner(monkeypatch):
    owner = _process(os.geteuid(), ['xrootdfs', '/private/mount'], daemon.XROOTDFS)
    zombie = _process(os.geteuid(), None, daemon.XROOTDFS)
    opaque = _process(None, [], daemon.XROOTDFS)
    assert _finder(monkeypatch, [zombie, opaque, owner]) is owner


@pytest.mark.parametrize('kind', ['gone', 'denied'])
def test_disappearing_or_inaccessible_process_is_never_owned(monkeypatch, kind):
    invalid = _process(os.geteuid(), ['/private/mount'], daemon.XROOTDFS)

    def unreadable():
        error = daemon.psutil.NoSuchProcess if kind == 'gone' else daemon.psutil.AccessDenied
        raise error(42)

    invalid.exe = unreadable
    with pytest.raises(AssertionError, match='expected one owned daemon'):
        _finder(monkeypatch, [invalid])


@pytest.mark.parametrize('uid,command,executable', [
    (-1, ['/private/mount'], None),
    (None, ['/private/mount'], '/unrelated/program'),
    (None, ['/private/mount-suffix'], None),
])
def test_foreign_uid_binary_or_partial_mount_argument_cannot_be_owned(
        monkeypatch, uid, command, executable):
    candidate = _process(os.geteuid() if uid is None else uid, command,
                         daemon.XROOTDFS if executable is None else executable)
    with pytest.raises(AssertionError, match='expected one owned daemon'):
        _finder(monkeypatch, [candidate])


def test_ambiguous_daemon_identity_fails_closed(monkeypatch):
    owner = _process(os.geteuid(), ['/private/mount'], daemon.XROOTDFS)
    with pytest.raises(AssertionError, match='expected one owned daemon'):
        _finder(monkeypatch, [owner, owner])


def test_access_log_waits_for_the_requested_arm(monkeypatch):
    snapshots = iter(['200 GET /on/seed.txt?authz=xxxx',
                      '200 GET /on/seed.txt?authz=xxxx\n401 GET /off/seed.txt?authz=xxxx'])
    monkeypatch.setattr(audit, '_access_log', lambda _endpoint: next(snapshots))
    monkeypatch.setattr(audit.time, 'sleep', lambda _seconds: None)
    assert audit._log_lines_for(None, '/off/seed.txt') == ['401 GET /off/seed.txt?authz=xxxx']


def test_missing_log_evidence_is_not_a_success(monkeypatch):
    monkeypatch.setattr(audit, '_access_log', lambda _endpoint: '')
    monkeypatch.setattr(audit.time, 'sleep', lambda _seconds: None)
    assert audit._log_lines_for(None, '/off/seed.txt') == []


def test_delayed_logging_does_not_allow_an_unredacted_credential():
    with pytest.raises(AssertionError, match='query token reached a log'):
        audit._assert_token_redacted('private-token', ['401 GET /off/?authz=private-token'])


def test_root_reference_config_grants_traversal_and_preserves_private_mode(tmp_path, monkeypatch):
    root = tmp_path / 'owned'
    config = root / 'registry/server/conf/xrootd.cfg'
    config.parent.mkdir(parents=True, mode=0o700)
    config.write_text('xrd.port 12345\n')
    config.chmod(0o600)
    changed = []
    monkeypatch.setattr(settings, 'TEST_ROOT', str(root))
    monkeypatch.setattr(start_operations.shutil, 'chown', lambda path, **kw: changed.append((path, kw)))
    start_operations._prepare_xrootd_config_identity(config, 'reference-user')
    assert config.parent.stat().st_mode & 0o555 == 0o555
    assert config.stat().st_mode & 0o777 == 0o600
    assert changed == [(config, {'user': 'reference-user'})]


def test_reference_config_cannot_open_or_chown_foreign_paths(tmp_path, monkeypatch):
    root = tmp_path / 'owned'
    root.mkdir()
    foreign = tmp_path / 'private-config'
    foreign.write_text('private')
    foreign.chmod(0o600)
    link = root / 'config'
    link.symlink_to(foreign)
    monkeypatch.setattr(settings, 'TEST_ROOT', str(root))
    with pytest.raises(ValueError, match='inside TEST_ROOT'):
        start_operations._prepare_xrootd_config_identity(link, 'nobody')
    assert foreign.stat().st_mode & 0o777 == 0o600


def test_reference_identity_failure_aborts_startup(tmp_path, monkeypatch):
    config = tmp_path / 'xrootd.cfg'
    config.write_text('xrd.port 12345\n')
    monkeypatch.setattr(settings, 'TEST_ROOT', str(tmp_path))

    def refused(*_args, **_kwargs):
        raise PermissionError('cannot delegate reference config')

    monkeypatch.setattr(start_operations.shutil, 'chown', refused)
    with pytest.raises(PermissionError, match='cannot delegate'):
        start_operations._prepare_xrootd_config_identity(config, 'nobody')


@pytest.mark.parametrize('credential,expected', [('token', 'fwd/object.bin'), ('gsi', 'object.bin')])
def test_forwarding_token_objects_use_the_configured_namespace(credential, expected):
    assert forwarding._object_name(credential, 'object.bin') == expected
    assert forwarding.stock_token_path() == 'fwd'


def _negative_forwarding_harness(root, denied):
    observations = []

    def transfer(_protocol, _credential, _port, object_name, who):
        observations.append((object_name, who))
        return SimpleNamespace(deny_obs='denied')

    harness = SimpleNamespace(prefix=root, front_put_get=transfer,
        assert_denied=lambda *_args: denied,
        record=lambda *args: observations.append(args))
    return harness, observations


@pytest.mark.parametrize('denied,leaked,verdict', [
    (True, False, 'PASS'), (False, False, 'FAIL'), (True, True, 'FAIL'),
])
def test_forwarding_denial_checks_bytes_in_the_actual_token_namespace(
        tmp_path, denied, leaked, verdict):
    target = tmp_path / 'obk_RR_token/data/fwd/negB_RR.bin'
    if leaked:
        target.parent.mkdir(parents=True)
        target.write_bytes(b'forbidden bytes')
    harness, observations = _negative_forwarding_harness(tmp_path, denied)
    forwarding._negative(harness, 'A RR token', 'RR', 'token', 'root', 12345)
    assert observations[0] == ('fwd/negB_RR.bin', 'B')
    assert observations[-1][1] == verdict

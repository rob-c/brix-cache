"""Slow logging and incomplete process metadata cannot weaken fixture ownership."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

from tests import test_audit16c_query_token as audit
from tests import test_xrootdfs_daemonized as daemon
from brix_suite.launcher import internal_operations, start_operations
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


@pytest.mark.parametrize('mask', [0, 0o022, 0o077])
def test_reference_logs_have_deterministic_private_access(tmp_path, mask):
    """A permissive caller cannot leave the reference's log exposed or unwritable."""
    log = tmp_path / 'logs/reference.log'
    script = ('import os, pwd, sys\n'
              'from brix_suite.launcher.internal_operations import _prepare_log\n'
              '_prepare_log(sys.argv[1], pwd.getpwuid(os.geteuid()).pw_name)\n')
    result = subprocess.run([sys.executable, '-c', script, str(log)],
                            cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, umask=mask, timeout=15)
    assert result.returncode == 0, result.stderr
    assert log.stat().st_mode & 0o777 == 0o600
    assert log.parent.stat().st_mode & 0o777 == 0o700
    assert log.stat().st_uid == log.parent.stat().st_uid == os.geteuid()
    with log.open('a') as stream:
        stream.write('runtime append\n')
    assert log.read_text() == 'runtime append\n'


def test_reference_log_path_error_cannot_truncate_a_foreign_file(tmp_path):
    occupied = tmp_path / 'occupied'
    occupied.write_text('preserved')
    with pytest.raises(FileExistsError):
        internal_operations._prepare_log(occupied / 'reference.log', 'nobody')
    assert occupied.read_text() == 'preserved'


@pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                    reason='real alternate-UID log access requires Linux root')
def test_reference_log_identity_is_owned_and_private():
    """The selected reference UID can write; an unrelated UID cannot read it."""
    import pwd
    reference, unrelated = pwd.getpwnam('nobody'), pwd.getpwnam('daemon')
    with tempfile.TemporaryDirectory(prefix='brix-reference-log-', dir='/tmp') as name:
        root = Path(name)
        root.chmod(0o755)
        log = root / 'logs/reference.log'
        internal_operations._prepare_log(log, reference.pw_name)
        writer = subprocess.run(['/usr/bin/python3', '-c',
                                 'import sys; open(sys.argv[1], "a").write("owned\\n")', str(log)],
                                user=reference.pw_uid, group=reference.pw_gid, extra_groups=(),
                                capture_output=True, text=True, timeout=10)
        assert writer.returncode == 0, writer.stderr
        reader = subprocess.run(['/usr/bin/python3', '-c',
                                 'import sys; open(sys.argv[1]).read()', str(log)],
                                user=unrelated.pw_uid, group=unrelated.pw_gid, extra_groups=(),
                                capture_output=True, text=True, timeout=10)
        assert reader.returncode != 0 and 'PermissionError' in reader.stderr
        assert str(log) in reader.stderr
        assert log.read_text() == 'owned\n'


@pytest.fixture
def shared_fixture_anchor():
    """Use /tmp's root-owned sticky contract for this disposable shared anchor."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        pytest.skip('real shared-anchor access requires Linux root')
    with tempfile.TemporaryDirectory(prefix='brix-shared-anchor-', dir='/tmp') as name:
        anchor = Path(name)
        anchor.chmod(0o1777)
        yield anchor


def _anchor_actor(username, code, path):
    import pwd
    identity = pwd.getpwnam(username)
    return subprocess.run(['/usr/bin/python3', '-c', code, str(path)],
                          user=identity.pw_uid, group=identity.pw_gid, extra_groups=(),
                          capture_output=True, text=True, timeout=10)


def test_shared_fixture_anchor_permits_private_owned_leaves(shared_fixture_anchor):
    leaf = shared_fixture_anchor / 'owned'
    result = _anchor_actor('nobody',
        'import os,sys; os.mkdir(sys.argv[1],0o700); open(sys.argv[1]+"/data","w").write("fixture")', leaf)
    assert result.returncode == 0, result.stderr
    assert (leaf / 'data').read_text() == 'fixture'
    assert leaf.stat().st_uid != shared_fixture_anchor.stat().st_uid == 0
    assert leaf.stat().st_mode & 0o777 == 0o700


def test_shared_fixture_anchor_cannot_be_narrowed_by_fixture_user(shared_fixture_anchor):
    result = _anchor_actor('nobody', 'import os,sys; os.chmod(sys.argv[1],0o700)',
                           shared_fixture_anchor)
    assert result.returncode != 0 and 'PermissionError' in result.stderr
    assert shared_fixture_anchor.stat().st_mode & 0o7777 == 0o1777


def test_shared_fixture_anchor_rejects_foreign_leaf_removal(shared_fixture_anchor):
    leaf = shared_fixture_anchor / 'owned'
    created = _anchor_actor('nobody', 'import os,sys; os.mkdir(sys.argv[1],0o700)', leaf)
    assert created.returncode == 0, created.stderr
    removed = _anchor_actor('daemon', 'import os,sys; os.rmdir(sys.argv[1])', leaf)
    assert removed.returncode != 0 and 'PermissionError' in removed.stderr
    assert leaf.is_dir()


def test_reference_loader_error_is_retained_with_its_real_exit_status(tmp_path):
    log = tmp_path / 'xrootd.log'
    command = [sys.executable, '-c',
               'import sys; sys.stderr.write("loader diagnostic\\n"); sys.exit(7)']
    process = start_operations._spawn_xrootd(command, dict(os.environ), log)
    assert process.wait(timeout=5) == 7
    assert log.with_suffix('.bootstrap.log').read_text() == 'loader diagnostic\n'


def test_reference_diagnostic_tail_is_bounded_and_handles_absence(tmp_path):
    log = tmp_path / 'xrootd.log'
    assert 'xrootd.log:' in start_operations._reference_log_tail(log)
    log.write_bytes(b'x' * 8192 + b'last diagnostic')
    tail = start_operations._reference_log_tail(log)
    assert len(tail) == 4096 and tail.endswith('last diagnostic')


@pytest.mark.parametrize('diagnostic', ['startup failed', 'READY'])
def test_reference_start_failure_cannot_be_hidden_by_log_text(tmp_path, diagnostic):
    logs = tmp_path / 'logs'
    logs.mkdir()
    (logs / 'xrootd.bootstrap.log').write_text(diagnostic)
    killed = []

    def never_ready(*_args):
        raise RuntimeError('listener was not ready')

    launcher = SimpleNamespace(_xrootd_procs={}, _owned=[], _wait_ready=never_ready,
                               _kill_xrootd=lambda name: killed.append(name))
    spec = SimpleNamespace(name='owned-reference', readiness='tcp')
    endpoint = SimpleNamespace(host='127.0.0.1', port=12345, prefix=tmp_path)
    with pytest.raises(RuntimeError, match='listener was not ready') as failure:
        start_operations._track_xrootd(launcher, spec, endpoint, object())
    assert diagnostic in str(failure.value)
    assert killed == ['owned-reference'] and launcher._owned == []


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

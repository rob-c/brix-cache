"""Real harmless processes prove helper detection cannot reap a suite runner."""

from contextlib import contextmanager
import os
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from brix_suite import orphans


@contextmanager
def _process(arguments, root, **environment):
    """Keep each child in its own test root and always reap our exact Popen."""
    process = subprocess.Popen(
        [sys.executable, *arguments],
        env=dict(os.environ, TEST_ROOT=str(root), **environment),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def test_python_script_helper_is_reaped(tmp_path):
    """A real repository helper still follows TEST_ROOT ownership."""
    with _process(['-u', str(Path(__file__).resolve()), '--idle'], tmp_path) as child:
        assert child.pid in dict(orphans.find_orphans(tmp_path))
        assert orphans.kill_orphans(tmp_path) == []
        assert child.wait(timeout=5) < 0


def test_test_path_argument_is_not_a_helper(tmp_path):
    """A data argument naming this tree never turns Python -c into a daemon."""
    args = ['-c', 'import time; time.sleep(120)', str(Path(__file__).resolve())]
    with _process(args, tmp_path) as child:
        assert child.pid not in dict(orphans.find_orphans(tmp_path))
        assert orphans.kill_orphans(tmp_path) == []
        assert child.poll() is None


def test_operator_module_with_ignore_option_is_protected(tmp_path):
    """The suite module's --ignore path cannot cause it to be killed as a helper."""
    package = tmp_path / 'cmdscripts'
    package.mkdir()
    (package / '__init__.py').write_text('')
    (package / 'operator_runtime.py').write_text('import time; time.sleep(120)\n')
    args = ['-m', 'cmdscripts.operator_runtime',
            '--ignore=' + str(Path(__file__).resolve())]
    with _process(args, tmp_path, PYTHONPATH=str(tmp_path)) as child:
        assert child.pid not in dict(orphans.find_orphans(tmp_path))
        with pytest.raises(orphans.ForeignLaneError):
            orphans.kill_orphans(tmp_path)
        assert child.poll() is None


@pytest.mark.parametrize('entry', ['script', 'module'])
def test_operator_entrypoint_is_never_a_helper(monkeypatch, entry):
    """Both supported spellings remain harnesses even inside the tests tree."""
    script = Path(__file__).parent / 'cmdscripts' / 'operator_runtime.py'
    arguments = [sys.executable, str(script)] if entry == 'script' else [
        sys.executable, '-m', 'cmdscripts.operator_runtime']
    monkeypatch.setattr(orphans, '_process_argv', lambda pid: arguments)
    monkeypatch.setattr(orphans, '_environ', lambda pid: b'TEST_ROOT=/tmp/owned\0')
    command = ' '.join(arguments)
    assert orphans._is_harness_cmd(command)
    assert not orphans._helper_matches(900001, 'python', command)


def test_ownership_accepts_raw_and_resolved_root_spellings(monkeypatch):
    """Darwin spells /tmp paths as /private/tmp after realpath; either spelling
    still names the same lane, without weakening whole-path boundaries."""
    monkeypatch.setattr(orphans.os.path, 'realpath',
                        lambda path: '/private/tmp/lane')
    assert orphans.owns('/tmp/lane', 'nginx -p /tmp/lane/registry/main')
    assert orphans.owns('/tmp/lane', 'nginx -p /private/tmp/lane/registry/main')
    assert not orphans.owns('/tmp/lane', 'nginx -p /tmp/lane-sibling/main')


@pytest.mark.parametrize('host,flag', [('freebsd15', '-e'), ('darwin', '-E')])
def test_native_snapshot_selects_real_environment_and_columns(monkeypatch, host, flag):
    calls = []
    monkeypatch.setattr(orphans.sys, 'platform', host)
    monkeypatch.setattr(orphans.subprocess, 'run', lambda args, **kwargs:
        (calls.append((args, kwargs)) or SimpleNamespace(stdout='42 1 python /bin/python\n')))
    assert orphans._ps_snapshot() == ['42 1 python /bin/python']
    args, options = calls[0]
    assert args == ['ps', '-ax', flag, '-ww', '-o', 'pid=', '-o', 'ppid=',
                    '-o', 'ucomm=', '-o', 'command=']
    assert options['check'] is True and options['timeout'] == 10


@pytest.mark.parametrize('text', [
    'TEST_ROOT=/tmp/lane PATH=/bin python -m cmdscripts.operator_runtime',
    'python -m cmdscripts.operator_runtime TEST_ROOT=/tmp/lane PATH=/bin',
])
def test_native_environment_position_does_not_hide_the_harness(text):
    arguments, environment = orphans._ps_split_command(text)
    assert arguments == ['python', '-m', 'cmdscripts.operator_runtime']
    assert environment == ['TEST_ROOT=/tmp/lane', 'PATH=/bin']


def test_native_process_snapshot_failure_cannot_authorize_cleanup(monkeypatch, tmp_path):
    monkeypatch.setattr(orphans, '_HAVE_PROCFS', False)
    monkeypatch.setattr(orphans, '_PS_CACHE', {'at': 0.0, 'table': {}})

    def unavailable(*args, **kwargs):
        raise RuntimeError('cannot inspect native process ownership')

    monkeypatch.setattr(orphans, '_ps_snapshot', unavailable)
    monkeypatch.setattr(orphans, 'native_process_table', unavailable)
    with pytest.raises(RuntimeError, match='cannot inspect native process ownership'):
        orphans.kill_orphans(tmp_path)


def test_empty_native_snapshot_cannot_claim_the_host_is_unowned(monkeypatch):
    monkeypatch.setattr(orphans.subprocess, 'run', lambda *args, **kwargs:
        SimpleNamespace(stdout=''))
    with pytest.raises(RuntimeError, match='snapshot is empty'):
        orphans._ps_snapshot()


def test_native_command_option_cannot_become_an_environment_assignment():
    arguments, environment = orphans._ps_split_command(
        'PATH=/bin python -m cmdscripts.operator_runtime --ignore=/tests/test_case.py')
    assert arguments[-1] == '--ignore=/tests/test_case.py'
    assert environment == ['PATH=/bin']


def test_operator_stop_cannot_inherit_a_foreign_registry(monkeypatch, tmp_path):
    from cmdscripts import operator_build

    calls = []
    monkeypatch.setenv('TEST_REGISTRY_ROOT', '/other/lane/registry')
    monkeypatch.setenv('TEST_REGISTRY_MANIFEST', '/other/lane/registry/manifest.json')
    monkeypatch.setattr(operator_build, 'run', lambda args, **kwargs:
                        calls.append((args, kwargs)))
    operator_build._stop_registered_servers(tmp_path)
    assert calls[0][1]['env'] == {
        'TEST_ROOT': str(tmp_path), 'TEST_REGISTRY_ROOT': str(tmp_path / 'registry'),
        'TEST_REGISTRY_MANIFEST': str(tmp_path / 'registry/manifest.json')}


def test_empty_proc_directory_is_not_a_process_interface(tmp_path):
    from lib_py.process_host import procfs_available

    (tmp_path / 'self').mkdir()
    assert not procfs_available(tmp_path)


def test_complete_readable_proc_interface_is_detected(tmp_path):
    from lib_py.process_host import procfs_available

    (tmp_path / 'self').mkdir()
    for name in ('stat', 'cmdline', 'comm'):
        (tmp_path / 'self' / name).write_text('fixture')
    assert procfs_available(tmp_path)


def test_directory_masquerading_as_a_proc_file_is_refused(tmp_path):
    from lib_py.process_host import procfs_available

    (tmp_path / 'self').mkdir()
    for name in ('stat', 'cmdline'):
        (tmp_path / 'self' / name).write_text('fixture')
    (tmp_path / 'self' / 'comm').mkdir()
    assert not procfs_available(tmp_path)


def test_native_process_row_preserves_spaces_and_assignment_arguments():
    from lib_py.process_host import _native_process_row

    arguments = ['/bin/python', '/tmp/a b/test.py', '--ignore=/tests/test_case.py']
    info = dict(ppid=1, name='python', cmdline=arguments, status='sleeping',
                environ={'TEST_ROOT': '/tmp/lane with spaces'}, uids=None)
    assert _native_process_row(info) == (1, 'python', arguments,
                                         ['TEST_ROOT=/tmp/lane with spaces'])


def test_unreadable_owned_process_environment_refuses_cleanup(monkeypatch):
    from lib_py.process_host import _native_process_row

    info = dict(ppid=1, name='python', cmdline=['python', '-m', 'pytest'],
                status='sleeping', environ=None, uids=SimpleNamespace(real=os.geteuid()))
    row = _native_process_row(info)
    assert row[3] is None
    monkeypatch.setattr(orphans, '_HAVE_PROCFS', False)
    monkeypatch.setattr(orphans, '_ps_table', lambda: {704: row})
    with pytest.raises(RuntimeError, match='owned process environment'):
        orphans._declared_root(704)


@pytest.fixture
def unknown_native_claimant(monkeypatch):
    """Keep an unreadable environment and real command classification distinct."""
    def select(command):
        row = (1, 'opaque-helper', command.split(), None)
        monkeypatch.setattr(orphans, '_HAVE_PROCFS', False)
        monkeypatch.setattr(orphans, '_ps_table', lambda: {704: row})
        monkeypatch.setattr(orphans, '_all_pids', lambda: [704])
        monkeypatch.setattr(orphans, '_is_fleet_process', lambda *args: False)
    return select


def test_known_nonharness_private_environment_cannot_veto_another_lane(unknown_native_claimant):
    """A protected helper is irrelevant to harness ownership, not readable/empty."""
    unknown_native_claimant('/tmp/opaque-helper')
    assert orphans.lane_harnesses('/tmp/owned', exclude_self=False) == []
    with pytest.raises(RuntimeError, match='owned process environment'):
        orphans.lane_claimants('/tmp/owned', exclude_self=False)


@pytest.mark.parametrize('command', ['python -m pytest', ''])
def test_opaque_harness_or_unknown_argv_still_refuses_cleanup(unknown_native_claimant, command):
    """A possible live harness must never become absent ownership evidence."""
    unknown_native_claimant(command)
    with pytest.raises(RuntimeError, match='owned process environment'):
        orphans.lane_harnesses('/tmp/owned', exclude_self=False)


@pytest.mark.parametrize('fresh', ['exited', 'readable', 'still-unknown'])
def test_unknown_native_owner_requires_a_fresh_proof_not_an_empty_environment(monkeypatch, fresh):
    unknown = (1, 'python', ['python', '-m', 'pytest'], None)
    updated = {'exited': {}, 'readable': {704: (*unknown[:3], ['TEST_ROOT=/tmp/owned'])},
               'still-unknown': {704: unknown}}
    snapshots = iter([{704: unknown}, updated[fresh]])
    refreshes = []
    monkeypatch.setattr(orphans, '_HAVE_PROCFS', False)
    monkeypatch.setattr(orphans, '_ps_table', lambda: next(snapshots))
    monkeypatch.setattr(orphans, '_refresh_ps_cache', lambda: refreshes.append('fresh'))
    environments = {'exited': b'', 'readable': b'TEST_ROOT=/tmp/owned\0', 'still-unknown': b''}
    monkeypatch.setattr(orphans, '_environ', lambda pid: environments[fresh])
    if fresh == 'still-unknown':
        with pytest.raises(RuntimeError, match='owned process environment.*704'):
            orphans._declared_root(704)
    else:
        expected = {'exited': None, 'readable': os.path.realpath('/tmp/owned')}
        assert orphans._declared_root(704) == expected[fresh]
    assert refreshes == ['fresh']


def test_exited_zombie_cannot_keep_claiming_a_lane():
    from lib_py.process_host import _native_process_row

    assert _native_process_row({'status': 'zombie'}) is None


@pytest.mark.parametrize('live,readable', [(True, True), (True, False), (False, False)])
def test_native_snapshot_rechecks_exit_without_hiding_live_owner(live, readable):
    from lib_py.process_host import _live_native_process_row

    info = dict(ppid=1, name='python', cmdline=['python', '-m', 'pytest'],
                status='sleeping', environ={'TEST_ROOT': '/tmp/owned'} if readable else None,
                uids=SimpleNamespace(real=os.geteuid()))
    process = SimpleNamespace(info=info, is_running=lambda: live)
    row = _live_native_process_row(process)
    if not live:
        assert row is None
    else:
        expected = ['TEST_ROOT=/tmp/owned'] if readable else None
        assert row == (1, 'python', info['cmdline'], expected)


def test_host_lane_view_refreshes_its_snapshot(monkeypatch):
    refreshed = []
    monkeypatch.setattr(orphans, '_refresh_ps_cache', lambda: refreshed.append(True))
    monkeypatch.setattr(orphans, '_all_pids', lambda: [])
    assert orphans.live_lanes() == {}
    assert refreshed == [True]


def test_lsof_port_and_state_selections_are_conjoined(monkeypatch):
    from lib_py import util

    calls = []
    monkeypatch.setattr(util, 'run', lambda command, **options:
                        (calls.append(command) or SimpleNamespace(stdout='704\n')))
    assert util._lsof_listener_pids(12345) == [704]
    assert calls == [['lsof', '-a', '-t', '-nP', '-iTCP:12345', '-sTCP:LISTEN']]


def test_native_listener_peer_suffix_cannot_hide_ownership(monkeypatch):
    from lib_py import util

    fields = 'p704\ncnginx\nn*:12345->*:*\np705\ncother\nn*:12346\n'
    monkeypatch.setattr(util, 'run', lambda *args, **kwargs:
                        SimpleNamespace(stdout=fields))
    lines = util._lsof_listener_lines()
    assert [util._listener_port(line) for line in lines] == [12345, 12346]
    assert [util._pids_in_text(line) for line in lines] == [{704}, {705}]


def _assert_native_listener_state(listener, empty):
    """Native snapshots must distinguish LISTEN from both CLOSED socket forms."""
    if not sys.platform.startswith('freebsd'):
        return
    from lib_py import util

    native = util.native_listener_pids()
    assert native is not None and 0 not in native
    assert os.getpid() in native[listener.getsockname()[1]]
    assert empty.getsockname()[1] not in native


def test_empty_port_cannot_select_an_unrelated_real_listener():
    from lib_py import util

    if not shutil.which('lsof'):
        pytest.skip('native listener inspection needs lsof')
    with socket.socket() as listener, socket.socket() as empty, socket.socket() as unbound:
        from ephemeral_port import free_port
        listener.bind(('', free_port('')))
        listener.listen()
        empty.bind(('', free_port('')))
        assert os.getpid() in util._lsof_listener_pids(listener.getsockname()[1])
        assert util._lsof_listener_pids(empty.getsockname()[1]) == []
        assert os.getpid() in orphans._listener_pids_lsof(listener.getsockname()[1])
        assert orphans._listener_pids_lsof(empty.getsockname()[1]) == set()
        assert unbound.getsockname()[1] == 0
        _assert_native_listener_state(listener, empty)


def test_native_socket_table_preserves_all_holders_and_unknown_occupancy():
    from lib_py.process_host import _sockstat_listener_pids

    rows = [{'pid': pid, 'local': {'port': port}, 'conn-state': 'LISTEN'} for pid, port in (
        (704, 12345), (705, 12345), (704, 12345), (None, 12346), (0, 12347))]
    assert _sockstat_listener_pids(json.dumps({'sockstat': {'socket': rows}})) == {
        12345: {704, 705}, 12346: set(), 12347: set()}
    assert _sockstat_listener_pids('{"sockstat": {}}') == {}


def test_closed_unbound_and_bound_sockets_cannot_authorize_cleanup():
    from lib_py.process_host import _sockstat_listener_pids

    rows = [{'pid': 704, 'local': {'port': port}, 'conn-state': 'CLOSED'}
            for port in (0, 12345)]
    rows.append({'pid': 705, 'local': {'port': 12346}, 'conn-state': 'LISTEN'})
    assert _sockstat_listener_pids(json.dumps({'sockstat': {'socket': rows}})) == {
        12346: {705}}


@pytest.mark.parametrize('row', [
    {'pid': 704, 'local': {'port': 12345}},
    {'pid': 704, 'local': {'port': 0}, 'conn-state': 'LISTEN'},
    {'pid': 704, 'local': {'port': 12345}, 'conn-state': 'unknown'},
    {'pid': True, 'local': {'port': 0}, 'conn-state': 'CLOSED'},
    {'pid': 704, 'local': {'port': False}, 'conn-state': 'CLOSED'},
    {'pid': 704, 'local': {'port': -1}, 'conn-state': 'CLOSED'},
])
def test_malformed_socket_state_cannot_be_hidden_as_closed(row):
    from lib_py.process_host import _sockstat_listener_pids

    with pytest.raises(RuntimeError, match='parse native listener ownership'):
        _sockstat_listener_pids(json.dumps({'sockstat': {'socket': [row]}}))


def test_native_socket_query_requires_connection_state(monkeypatch):
    from lib_py import process_host

    calls = []
    monkeypatch.setattr(process_host, 'sys', SimpleNamespace(platform='freebsd15'))
    monkeypatch.setattr(process_host.subprocess, 'run', lambda command, **options:
                        (calls.append(command) or SimpleNamespace(stdout='{"sockstat": {}}')))
    assert process_host.native_listener_pids() == {}
    assert calls == [['sockstat', '--libxo=json', '-l', '-s', '-P', 'tcp']]


@pytest.mark.parametrize('contents', [
    'not-json', '{}', '{"sockstat": null}', '{"sockstat": {"socket": {}}}',
    '{"sockstat": {"socket": [{"local": {"port": "12345"}}]}}',
    '{"sockstat": {"socket": [{"pid": true, "local": {"port": 12345}}]}}',
    '{"sockstat": {"socket": [{"local": {"port": 0}}]}}',
])
def test_malformed_native_socket_table_is_not_false_quiescence(contents):
    from lib_py.process_host import _sockstat_listener_pids

    with pytest.raises(RuntimeError, match='parse native listener ownership'):
        _sockstat_listener_pids(contents)


def test_failed_native_socket_inspection_cannot_authorize_cleanup(monkeypatch):
    from lib_py import process_host

    monkeypatch.setattr(process_host, 'sys', SimpleNamespace(platform='freebsd15'))

    def fail(*args, **options):
        raise subprocess.TimeoutExpired('sockstat', 5)

    monkeypatch.setattr(process_host.subprocess, 'run', fail)
    with pytest.raises(RuntimeError, match='inspect native listener ownership'):
        process_host.native_listener_pids()


def test_native_listener_routes_keep_unknown_owner_without_fake_pid(monkeypatch):
    from lib_py import util

    monkeypatch.setattr(util, 'native_listener_pids', lambda: {12345: {704, 705}, 12346: set()})
    monkeypatch.setattr(util, 'have_cmd', lambda name: False)
    assert util.pids_on_port(12345) == [704, 705]
    assert util.pids_on_port(12346) == []
    assert util.listening_port_pids() == {12345: {704, 705}, 12346: set()}
    lines = util.listener_table_lines()
    assert {pid for line in lines for pid in util._pids_in_text(line)} == {704, 705}
    assert {util._listener_port(line) for line in lines} == {12345, 12346}


if __name__ == '__main__':
    time.sleep(120)
@pytest.mark.parametrize('busy,alive,own', [
    (False, True, True), (True, True, True), (True, True, False), (True, False, True),
])
def test_native_busy_environment_keeps_ownership_unknown_not_foreign(busy, alive, own):
    """An EBUSY snapshot must not authorize cleanup or hide a live owned process."""
    import errno
    import os
    from types import SimpleNamespace
    from lib_py.process_host import _native_process_info, _live_native_process_row

    info = dict(ppid=1, name='fixture', cmdline=['fixture'], status='running',
                uids=SimpleNamespace(real=os.geteuid() + int(not own)),
                environ={'TEST_ROOT': '/private-owned-test'})
    calls = []

    def snapshot(attrs, ad_value):
        calls.append(tuple(attrs))
        if busy and 'environ' in attrs:
            raise OSError(errno.EBUSY, 'injected native environment race')
        return {name: info[name] for name in attrs}

    def environment():
        if busy:
            raise OSError(errno.EBUSY, 'injected native environment race')
        return info['environ']

    process = SimpleNamespace(as_dict=snapshot, is_running=lambda: alive,
                              environ=environment)
    process.info = _native_process_info(process, list(info))
    row = _live_native_process_row(process)
    assert len(calls) == 1 + busy
    environment = _expected_busy_environment(busy, own)
    expected = (1, 'fixture', ['fixture'], environment) if alive else None
    assert row == expected


def _native_retry_environment(calls, settled):
    """Model an exec transition without touching any real process state."""
    import errno
    import psutil

    calls.append('environment')
    if len(calls) == 1 or settled == 'still-busy':
        raise OSError(errno.EBUSY, 'native exec in progress')
    if settled == 'exited':
        raise psutil.NoSuchProcess(123)
    if settled == 'unrelated-error':
        raise OSError(errno.EIO, 'native inspection failed')
    return {'TEST_ROOT': '/private-owned-test'}


def _assert_native_retry_outcome(process, settled):
    """Keep result/error contracts separate from retry-budget accounting."""
    import errno
    import psutil
    from lib_py import process_host

    if settled == 'exited':
        with pytest.raises(psutil.NoSuchProcess):
            process_host._retry_busy_native_environment(process)
    elif settled == 'unrelated-error':
        with pytest.raises(OSError) as error:
            process_host._retry_busy_native_environment(process)
        assert error.value.errno == errno.EIO
    else:
        expected = None if settled == 'still-busy' else {'TEST_ROOT': '/private-owned-test'}
        assert process_host._retry_busy_native_environment(process) == expected


@pytest.mark.parametrize('settled', ['readable', 'exited', 'unrelated-error', 'still-busy'])
def test_native_environment_retry_is_bounded_and_preserves_uncertainty(monkeypatch, settled):
    """Exec may finish; a persistent unknown or unrelated error never becomes empty."""
    from types import SimpleNamespace
    from lib_py import process_host

    calls, waits = [], []
    monkeypatch.setattr(process_host.time, 'sleep', waits.append)
    process = SimpleNamespace(environ=lambda: _native_retry_environment(calls, settled))
    _assert_native_retry_outcome(process, settled)
    expected_attempts = 3 if settled == 'still-busy' else 2
    assert calls == ['environment'] * expected_attempts
    assert waits == [0.02] * expected_attempts


def _expected_busy_environment(busy, own):
    if not busy:
        return ['TEST_ROOT=/private-owned-test']
    return None if own else []


def test_native_snapshot_does_not_hide_unrelated_system_errors():
    import errno
    from types import SimpleNamespace
    from lib_py.process_host import _native_process_info

    def fail(**kwargs):
        raise OSError(errno.EIO, 'injected native inspection failure')

    with pytest.raises(OSError) as error:
        _native_process_info(SimpleNamespace(as_dict=fail), ['environ'])
    assert error.value.errno == errno.EIO


def test_native_process_table_retains_live_siblings_when_one_pid_disappears(monkeypatch):
    from types import SimpleNamespace
    import psutil
    from lib_py.process_host import native_process_table

    def disappeared(**kwargs):
        raise psutil.NoSuchProcess(123)

    gone = SimpleNamespace(pid=123, as_dict=disappeared)
    data = dict(ppid=1, name='live', cmdline=['live'], status='running',
                environ={}, uids=None)
    live = SimpleNamespace(pid=124, as_dict=lambda **kwargs: data,
                           is_running=lambda: True)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([gone, live]))
    assert native_process_table() == {124: (1, 'live', ['live'], [])}


@pytest.mark.parametrize('own,alive', [(True, True), (False, True), (True, False)])
def test_native_busy_then_denied_environment_preserves_ownership(monkeypatch, own, alive):
    """A sysctl exec race must not drop a live owner or veto unrelated records."""
    import errno
    import psutil
    from lib_py import process_host

    info = dict(ppid=1, name='python', cmdline=['python', '-m', 'pytest'],
                status='running', uids=SimpleNamespace(real=os.geteuid() + int(not own)))

    def snapshot(attrs, **kwargs):
        if 'environ' in attrs:
            raise OSError(errno.EBUSY, 'injected exec transition')
        return info

    def denied():
        raise psutil.AccessDenied(123)

    process = SimpleNamespace(pid=123, as_dict=snapshot, environ=denied,
                              is_running=lambda: alive)
    monkeypatch.setattr(process_host.time, 'sleep', lambda _seconds: None)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([process]))
    expected = {123: (1, 'python', info['cmdline'], None if own else [])} if alive else {}
    assert process_host.native_process_table() == expected

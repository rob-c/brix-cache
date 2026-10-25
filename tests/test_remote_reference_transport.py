"""A failed or misrouted remote oracle must never become native-green."""
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools.ci import remote_reference_policy as policy
from tools.ci import remote_reference_transport as transport
from tools.ci import remote_reference_daemon as daemon
from brix_suite.clients.xrdcl import worker_link


@pytest.mark.parametrize('value', ['', '{}', '[]', '["relative"]', '["/bin/python", null]',
                                 '["/bin/python", "bad\\u0000argument"]'])
def test_explicit_remote_worker_configuration_is_validated_without_native_fallback(monkeypatch, value):
    monkeypatch.setenv('TEST_XRDCL_REMOTE_COMMAND', value)
    with pytest.raises(ValueError):
        worker_link._worker_command(sys.executable)


def test_remote_worker_command_is_an_argv_not_a_shell_string(monkeypatch):
    command = [sys.executable, '-m', 'tools.ci.remote_reference_transport', 'client',
               '--socket', '/private/lab/socket;not-a-shell']
    monkeypatch.setenv('TEST_XRDCL_REMOTE_COMMAND', json.dumps(command))
    assert worker_link._worker_command('/other/python') == command


def test_broken_explicit_remote_probe_never_tries_any_native_interpreter(monkeypatch):
    calls = []
    monkeypatch.setenv('TEST_XRDCL_REMOTE_COMMAND', json.dumps(['/selected/python', 'remote']))
    monkeypatch.setattr(worker_link, '_probe_bindings', lambda value: calls.append(value) or False)
    worker_link._worker_python.cache_clear()
    try:
        with pytest.raises(worker_link.XrdClWorkerError, match='native fallback is forbidden'):
            worker_link._worker_python()
        assert calls == ['/selected/python']
    finally:
        worker_link._worker_python.cache_clear()


def test_ordinary_native_worker_argv_is_unchanged(monkeypatch):
    monkeypatch.delenv('TEST_XRDCL_REMOTE_COMMAND', raising=False)
    assert worker_link._worker_command('/selected/python') == ['/selected/python', '-u', worker_link._WORKER]


@pytest.mark.parametrize('payload', [b'\x00\xff\n' * 100, bytes(range(256)) * 8192])
def test_transport_frames_preserve_binary_bytes_and_full_large_writes(payload):
    import threading

    stream = io.BytesIO()
    transport.send(stream, dict(data=base64.b64encode(payload).decode()), threading.Lock())
    stream.seek(0)
    assert base64.b64decode(transport.receive(stream)['data']) == payload


@pytest.mark.parametrize('content', [b'', b'{"ok":true}', b'{}' + b' ' * (8 * 1024 * 1024)])
def test_closed_truncated_and_oversized_frames_are_errors_not_passes(content):
    with pytest.raises((EOFError, ValueError)):
        transport.receive(io.BytesIO(content))


def test_credentials_are_explicit_byte_exact_and_owner_private(tmp_path):
    source = tmp_path / 'native'
    source.mkdir()
    (source / 'proxy').write_bytes(b'ephemeral proxy\x00bytes')
    ca = source / 'ca'
    ca.mkdir()
    (ca / 'hash.0').write_bytes(b'public CA')
    values = dict(X509_USER_PROXY=str(source / 'proxy'), X509_CERT_DIR=str(ca),
                  XrdSecPROTOCOL='gsi', XRD_REQUESTTIMEOUT='7', PATH='/native/bin')
    bundle = policy.client_environment(values, source)
    destination = tmp_path / 'oracle'
    baseline = dict(HOME='/operator', PATH='/pinned/bin', BEARER_TOKEN='operator-secret',
                    X509_USER_CERT='/operator/key', XRD_NOTLSOK='1')
    env = policy.oracle_environment(bundle, source, destination, baseline)
    assert Path(env['X509_USER_PROXY']).read_bytes() == b'ephemeral proxy\x00bytes'
    assert Path(env['X509_USER_PROXY']).stat().st_mode & 0o077 == 0
    assert (Path(env['X509_CERT_DIR']) / 'hash.0').read_bytes() == b'public CA'
    assert env['PATH'] == '/pinned/bin'
    assert not {'BEARER_TOKEN', 'XRD_NOTLSOK'} & env.keys()
    assert env['HOME'] == env['TMPDIR'] == str(destination)
    assert not Path(env['X509_USER_CERT']).exists()


def test_credential_symlink_cannot_read_an_operator_file(tmp_path):
    source = tmp_path / 'native'
    source.mkdir()
    outside = tmp_path / 'operator-secret'
    outside.write_bytes(b'never transmit')
    (source / 'proxy').symlink_to(outside)
    with pytest.raises(ValueError):
        policy.client_environment(dict(X509_USER_PROXY=str(source / 'proxy')), source)
    assert outside.read_bytes() == b'never transmit'


def test_kerberos_file_cache_and_client_keytab_are_copied_not_borrowed(tmp_path):
    root = tmp_path / 'native'
    root.mkdir()
    ticket = root / 'ticket'
    ticket.write_bytes(b'fixture ticket')
    bundle = policy.client_environment(dict(KRB5CCNAME='FILE:' + str(ticket),
        KRB5_CLIENT_KTNAME='FILE:' + str(root / 'missing')), root)
    env = policy.oracle_environment(bundle, root, tmp_path / 'private',
                                    dict(KRB5CCNAME='FILE:/operator/ticket'))
    assert Path(env['KRB5CCNAME'].removeprefix('FILE:')).read_bytes() == b'fixture ticket'
    assert not Path(env['KRB5_CLIENT_KTNAME'].removeprefix('FILE:')).exists()


def test_absent_native_kerberos_cache_cannot_use_operator_or_default_uid_cache(tmp_path):
    bundle = policy.client_environment({}, tmp_path)
    env = policy.oracle_environment(bundle, tmp_path, tmp_path / 'private',
                                    dict(KRB5CCNAME='FILE:/operator/ticket'))
    assert env['KRB5CCNAME'].startswith('FILE:' + str(tmp_path / 'private'))
    assert not Path(env['KRB5CCNAME'].removeprefix('FILE:')).exists()


@pytest.mark.parametrize('value', ['DIR:/operator/tickets', 'KEYRING:persistent:501', 'KCM:'])
def test_host_kerberos_cache_services_are_not_available_to_the_remote_oracle(tmp_path, value):
    with pytest.raises(ValueError, match='file-backed Kerberos'):
        policy.client_environment(dict(KRB5CCNAME=value), tmp_path)


@pytest.mark.parametrize('value', ['/outside/proxy', '/native/../outside/proxy', 'relative'])
def test_receiver_independently_refuses_credential_namespace_escape(tmp_path, value):
    bundle = dict(values={'X509_USER_PROXY': value}, directories=[],
                  files={value: base64.b64encode(b'no').decode()})
    with pytest.raises(ValueError):
        policy.oracle_environment(bundle, Path('/native'), tmp_path, {})
    assert list(tmp_path.iterdir()) == []


def test_removed_credential_cannot_reuse_the_previous_generation(tmp_path):
    args = SimpleNamespace(fixture_root=Path('/native'))
    bundle = dict(values={'X509_USER_PROXY': '/native/proxy'}, directories=[],
                  files={'/native/proxy': base64.b64encode(b'first').decode()})
    first = transport._request_environment(bundle, args, tmp_path)
    bundle['files'] = {}
    second = transport._request_environment(bundle, args, tmp_path)
    assert Path(first['X509_USER_PROXY']).read_bytes() == b'first'
    assert not Path(second['X509_USER_PROXY']).exists()


def test_shared_credential_manifest_never_reads_native_operator_paths(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail('manifest must not inspect native paths')

    monkeypatch.setattr(Path, 'stat', forbidden)
    bundle = policy.client_environment(dict(X509_USER_PROXY='/operator/proxy', PATH='/operator/bin'),
                                       tmp_path, shared=True)
    assert bundle == dict(values={'X509_USER_PROXY': '/operator/proxy'}, files={}, directories=[], shared=True)


def test_shared_credentials_without_independent_namespace_proof_are_refused(tmp_path):
    args = SimpleNamespace(fixture_root=tmp_path, shared_fixture_proof=None)
    bundle = policy.client_environment({}, tmp_path, shared=True)
    with pytest.raises(ValueError, match='verified shared fixtures'):
        transport._request_environment(bundle, args, tmp_path)


def _shared_credentials_lab(tmp_path):
    root = tmp_path / 'shared'
    root.mkdir()
    proof = root / 'proof'
    proof.write_text('native nonce')
    args = SimpleNamespace(fixture_root=root, shared_fixture_proof=proof,
                           shared_fixture_token='native nonce')
    return root, args


def test_shared_credential_reader_uses_fresh_bytes_and_missing_stays_missing(tmp_path):
    root, args = _shared_credentials_lab(tmp_path)
    proxy = root / 'proxy'
    proxy.write_bytes(b'first')
    bundle = policy.client_environment(dict(X509_USER_PROXY=str(proxy)), root, shared=True)
    first = transport._request_environment(bundle, args, tmp_path)
    proxy.unlink()
    second = transport._request_environment(bundle, args, tmp_path)
    assert Path(first['X509_USER_PROXY']).read_bytes() == b'first'
    assert not Path(second['X509_USER_PROXY']).exists()


def test_shared_credential_reader_cannot_follow_a_link_outside_the_lab(tmp_path):
    root, args = _shared_credentials_lab(tmp_path)
    outside = tmp_path / 'operator-secret'
    outside.write_bytes(b'never read')
    (root / 'proxy').symlink_to(outside)
    bundle = policy.client_environment(dict(X509_USER_PROXY=str(root / 'proxy')), root, shared=True)
    with pytest.raises(ValueError):
        transport._request_environment(bundle, args, tmp_path)


@pytest.mark.parametrize('url', ['root://localhost:6001//data', 'roots://127.0.0.1:6002//data'])  # net-literal-allow: offline endpoint corpus
def test_only_the_selected_loopback_endpoint_is_forwarded(url):
    calls = []
    assert policy.forwarded_url(url, lambda *args: calls.append(args)) == url
    assert len(calls) == 1 and calls[0][0] == '127.0.0.1'  # net-literal-allow: exact private forward assertion


@pytest.mark.parametrize('url', ['root://192.0.2.10:6001//data', 'root://example.org:6001//data',  # net-literal-allow: rejected endpoint corpus
                               'root://localhost//data'])  # net-literal-allow: missing port corpus
def test_remote_oracle_cannot_be_used_as_an_external_network_proxy(url):
    calls = []
    with pytest.raises(ValueError):
        policy.forwarded_url(url, lambda *args: calls.append(args))
    assert calls == []


def test_worker_transport_does_not_modify_offsets_payloads_or_url_parser_inputs():
    calls = []
    forward = lambda *args: calls.append(args)
    requests = [dict(op='file_call', method='write', args=[b'\x00\xff'.hex(), 1 << 40]),
                dict(op='file_call', method='read', args=[1000, 250]),
                dict(op='url_parse', url='root://example.org:1094//opaque')]  # net-literal-allow: parser-only input, no dial
    for request in requests:
        snapshot = json.dumps(request)
        assert json.dumps(policy.worker_request(request, forward)) == snapshot
    assert calls == []


def test_port_band_and_budget_are_checked_before_ssh(monkeypatch):
    calls = []
    args = SimpleNamespace(port_start=6000, port_stop=9580)
    forward = transport.Forwards(args)
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match='port band'):
        forward('127.0.0.1', 22)  # net-literal-allow: rejected SSH destination
    assert calls == []


def test_cli_without_verified_shared_fixtures_is_not_silently_enabled():
    hello = dict(kind='cli', tool='xrdcp', argv=['/native/local', '-'])
    with pytest.raises(ValueError, match='shared fixtures'):
        transport._command(hello, SimpleNamespace(shared_fixture_proof=None), lambda *args: None)


@pytest.mark.parametrize('tool', ['sh', '/bin/sh', 'xrootd'])
def test_bridge_is_not_a_general_shell_or_an_unvalidated_daemon_launcher(tool):
    with pytest.raises(ValueError, match='unsupported'):
        transport._command(dict(kind='cli', tool=tool), SimpleNamespace(), None)


@pytest.mark.parametrize('contents', ['native nonce', 'wrong nonce'])
def test_cli_requires_the_actual_native_shared_namespace_proof(tmp_path, contents):
    proof = tmp_path / 'proof'
    proof.write_text(contents)
    args = SimpleNamespace(fixture_root=tmp_path, shared_fixture_proof=proof,
        shared_fixture_token='native nonce', xrdcp=Path('/pinned/xrdcp'))
    hello = dict(kind='cli', tool='xrdcp', argv=[str(tmp_path / 'input'), '-'])
    if contents == 'native nonce':
        assert transport._command(hello, args, None) == ['/pinned/xrdcp', *hello['argv']]
    else:
        with pytest.raises(ValueError, match='does not match'):
            transport._command(hello, args, None)


@pytest.mark.parametrize('value', ['/etc/passwd', 'file:///etc/passwd', '../outside',
                                 'file:///native/%2e%2e/etc/passwd',
                                 'file://example.org/data', 'https://example.org/data'])  # net-literal-allow: rejected local-file/network escape corpus
def test_shared_cli_cannot_read_files_or_urls_outside_its_fixture_root(tmp_path, value):
    with pytest.raises(ValueError):
        transport._local_file_argument(value, tmp_path)


def test_worker_local_copy_never_bypasses_the_shared_fixture_proof():
    request = dict(op='cp_call', method='add_job', kwargs={'source': '/local/input', 'target': '-'})
    with pytest.raises(ValueError, match='shared fixtures'):
        transport._worker_files(request, SimpleNamespace(shared_fixture_proof=None))


def test_full_scheduler_marks_remote_client_reports_as_non_native(monkeypatch):
    from tools.ci import native_suite

    monkeypatch.delenv('TEST_XRDCL_REMOTE_COMMAND', raising=False)
    assert native_suite._reference_lane_identity() == {}
    monkeypatch.setenv('TEST_XRDCL_REMOTE_COMMAND', '["/selected/bridge"]')
    record = native_suite._reference_lane_identity()
    assert record['native_full_suite'] is False
    assert record['native_dependency_results_replaced'] is False
    assert record['reference_python_mode'] == 'remote'
    assert record['reference_cli_mode'] == 'native'
    assert record['reference_daemon_mode'] == 'native'


def test_reference_config_changes_only_private_control_locations(tmp_path):
    args = SimpleNamespace(fixture_root=tmp_path)
    source = ('xrd.port 6123\nall.adminpath /native/private\nall.pidpath /native/private\n'
              f'oss.localroot {tmp_path}/data\nall.export /\nxrootd.async off nosf\n')
    adapted = daemon._configuration(source, args, tmp_path / 'owned')
    assert f'oss.localroot {tmp_path}/data\n' in adapted
    assert 'all.export /\nxrootd.async off nosf\n' in adapted
    assert adapted.count(str(tmp_path / 'owned/control')) == 2
    assert '/native/private' not in adapted


@pytest.mark.parametrize('line', ['include /operator/private.cfg', 'oss.localroot /operator/data'])
def test_remote_config_cannot_borrow_operator_includes_or_export_data(tmp_path, line):
    with pytest.raises(ValueError):
        daemon._configuration(line, SimpleNamespace(fixture_root=tmp_path), tmp_path / 'owned')


@pytest.mark.parametrize('arguments', [['-b', '-c', 'cfg'], ['-R', 'root', '-c', 'cfg'], []])
def test_remote_daemon_cannot_detach_or_request_privilege(tmp_path, arguments):
    args = SimpleNamespace(fixture_root=tmp_path, xrootd=Path('/pinned/xrootd'))
    with pytest.raises(ValueError):
        daemon._config_argument(arguments, args)


def test_reverse_readiness_is_published_only_after_the_real_daemon_accepts(monkeypatch):
    calls = []
    monkeypatch.setattr(daemon, '_accepting', lambda port: calls.append(('real', port)) or True)
    monkeypatch.setattr(daemon, '_attest_listeners', lambda pid, port: calls.append(('attest', pid, port)))
    hello = dict(daemon_port=6123)
    forward = SimpleNamespace(reverse=lambda *args: calls.append(('reverse', *args)))
    daemon.ready(hello, SimpleNamespace(pid=123, poll=lambda: None), forward, 'owned')
    assert calls == [('real', 6123), ('attest', 123, 6123), ('reverse', 6123, 'owned')]
    assert hello['daemon_lease'] == 'owned'


def test_failed_reference_daemon_never_publishes_an_ssh_readiness_listener():
    calls = []
    forward = SimpleNamespace(reverse=lambda *args: calls.append(args))
    with pytest.raises(RuntimeError, match='did not become ready'):
        daemon.ready(dict(daemon_port=6123), SimpleNamespace(poll=lambda: 1), forward, 'owned')
    assert calls == []


@pytest.mark.parametrize('addresses', [[], [('0.0.0.0', 6123)], [('::', 6123)],  # net-literal-allow: reject wildcard reference listeners
                                     [('127.0.0.1', 6124)], [('192.0.2.1', 6123)]])  # net-literal-allow: rejected listener corpus
def test_reference_daemon_refuses_wildcard_foreign_and_missing_listeners(monkeypatch, addresses):
    import psutil

    records = [SimpleNamespace(laddr=SimpleNamespace(ip=host, port=port), status=psutil.CONN_LISTEN)
               for host, port in addresses]
    monkeypatch.setattr(psutil, 'Process', lambda pid: SimpleNamespace(net_connections=lambda **kw: records))
    with pytest.raises(RuntimeError):
        daemon._attest_listeners(123, 6123)


def test_reference_daemon_attests_both_loopback_families(monkeypatch):
    import psutil

    records = [SimpleNamespace(laddr=SimpleNamespace(ip=host, port=6123), status=psutil.CONN_LISTEN)
               for host in ('127.0.0.1', '::1')]  # net-literal-allow: private listener proof
    monkeypatch.setattr(psutil, 'Process', lambda pid: SimpleNamespace(net_connections=lambda **kw: records))
    daemon._attest_listeners(123, 6123)


@pytest.mark.parametrize('api', ['net_connections', 'connections'])
def test_reference_listener_attestation_accepts_both_public_psutil_apis(monkeypatch, api):
    import psutil

    address = SimpleNamespace(ip='127.0.0.1', port=6123)  # net-literal-allow: private listener proof
    records = [SimpleNamespace(laddr=address, status=psutil.CONN_LISTEN),
               SimpleNamespace(laddr=address, status=psutil.CONN_ESTABLISHED)]
    process = SimpleNamespace(**{api: lambda **kw: records})
    monkeypatch.setattr(psutil, 'Process', lambda pid: process)
    assert daemon._process_listeners(123) == [address]


def test_legacy_psutil_listener_inspection_failure_is_not_readiness(monkeypatch):
    import psutil

    def denied(**kwargs):
        raise psutil.AccessDenied(123)

    monkeypatch.setattr(psutil, 'Process', lambda pid: SimpleNamespace(connections=denied))
    with pytest.raises(psutil.AccessDenied):
        daemon._attest_listeners(123, 6123)


def test_legacy_psutil_still_refuses_a_wildcard_listener(monkeypatch):
    import psutil

    records = [SimpleNamespace(laddr=SimpleNamespace(ip='0.0.0.0', port=6123),  # net-literal-allow: rejected listener proof
                               status=psutil.CONN_LISTEN)]
    monkeypatch.setattr(psutil, 'Process', lambda pid: SimpleNamespace(connections=lambda **kw: records))
    with pytest.raises(RuntimeError, match='non-loopback'):
        daemon._attest_listeners(123, 6123)


def test_daemon_without_explicit_bind_guard_cannot_start():
    with pytest.raises(ValueError, match='explicit loopback bind adapter'):
        daemon.environment(SimpleNamespace(), {})


def test_bind_guard_selection_refuses_a_symlink(tmp_path):
    plain = tmp_path / 'plain'
    plain.write_bytes(b'library')
    link = tmp_path / 'link'
    link.symlink_to(plain)
    with pytest.raises(ValueError, match='owner-controlled plain library'):
        daemon.environment(SimpleNamespace(daemon_bind_guard=link), {})


@pytest.mark.parametrize('mode', [0o720, 0o702])
def test_bind_guard_selection_refuses_group_or_other_writable_libraries(tmp_path, mode):
    guard = tmp_path / 'guard'
    guard.write_bytes(b'not executed')
    guard.chmod(mode)
    with pytest.raises(ValueError, match='owner-controlled plain library'):
        daemon.environment(SimpleNamespace(daemon_bind_guard=guard), {})


def test_stale_daemon_cannot_cancel_another_connections_reverse_lease(monkeypatch):
    forward = transport.Forwards(SimpleNamespace(port_start=6000, port_stop=9580))
    calls = []
    monkeypatch.setattr(forward, '_control', lambda *args: calls.append(args))
    forward.reverse(6123, 'first')
    with pytest.raises(ValueError, match='owner mismatch'):
        forward.retire(6123, 'different')
    forward('127.0.0.1', 6123)  # net-literal-allow: reuse the healthy reference directly on its own host
    assert len(calls) == 1
    forward.retire(6123, 'first')
    assert calls[1][0:2] == ('cancel', '-R')
    assert forward.reverse_ports == {}


@pytest.mark.parametrize('arguments,expected', [(['--', '--version'], ['--version']),
    (['--', '--', '-literal-file'], ['--', '-literal-file']), ([], [])])
def test_relay_delimiter_does_not_change_the_official_tools_argv(arguments, expected):
    assert transport._client_argv(arguments) == expected


def _native_export_lab(tmp_path):
    shared, native = tmp_path / 'shared', tmp_path / 'native'
    shared.mkdir()
    native.mkdir(mode=0o700)
    marker = native / '.brix-reference-native-export.json'
    marker.write_text(json.dumps(dict(schema_version=1, shared_root=str(shared.resolve()))))
    return shared, native, marker


def test_reference_storage_mapping_retains_the_complete_fixture_namespace(tmp_path, monkeypatch):
    from lib_py.reference_host import reference_brix_data_root

    shared, native, _ = _native_export_lab(tmp_path)
    path = str(shared / 'worker/module/our-data')
    monkeypatch.delenv('TEST_REFERENCE_BRIX_DATA_ROOT', raising=False)
    assert reference_brix_data_root(path, shared) == path
    monkeypatch.setenv('TEST_REFERENCE_BRIX_DATA_ROOT', str(native))
    assert reference_brix_data_root(path, shared) == str(native / 'worker/module/our-data')


def test_reference_storage_mapping_rejects_a_different_lanes_marker(tmp_path, monkeypatch):
    from lib_py.reference_host import reference_brix_data_root

    shared, native, marker = _native_export_lab(tmp_path)
    marker.write_text(json.dumps(dict(schema_version=1, shared_root='/different/lab')))
    monkeypatch.setenv('TEST_REFERENCE_BRIX_DATA_ROOT', str(native))
    with pytest.raises(ValueError, match='another fixture lane'):
        reference_brix_data_root(shared / 'our-data', shared)


def test_reference_storage_mapping_cannot_escape_either_storage_root(tmp_path, monkeypatch):
    from lib_py.reference_host import reference_brix_data_root

    shared, native, _ = _native_export_lab(tmp_path)
    monkeypatch.setenv('TEST_REFERENCE_BRIX_DATA_ROOT', str(native))
    with pytest.raises(ValueError):
        reference_brix_data_root(shared / '../outside', shared)
    (native / 'module').symlink_to(tmp_path)
    with pytest.raises(ValueError):
        reference_brix_data_root(shared / 'module/escaped', shared)


def test_native_reference_platform_is_unchanged_without_an_external_oracle(monkeypatch):
    from lib_py.reference_host import reference_platform

    monkeypatch.delenv('TEST_REFERENCE_PROVENANCE', raising=False)
    assert reference_platform() == sys.platform


@pytest.mark.parametrize('corrupt', [False, True])
def test_remote_reference_platform_comes_from_digest_pinned_actual_evidence(tmp_path, monkeypatch, corrupt):
    import hashlib
    from lib_py.reference_host import reference_platform

    path = tmp_path / 'reference.json'
    path.write_text(json.dumps({'system': 'Darwin'}))
    monkeypatch.setenv('TEST_REFERENCE_PROVENANCE', str(path))
    monkeypatch.setenv('TEST_REFERENCE_PROVENANCE_SHA256', hashlib.sha256(path.read_bytes()).hexdigest())
    if corrupt:
        path.write_text(json.dumps({'system': 'Linux'}))
        with pytest.raises(ValueError, match='digest mismatch'):
            reference_platform()
    else:
        assert reference_platform() == 'darwin'


@pytest.mark.parametrize('closed', [False, True])
def test_bridge_shutdown_closes_only_owned_connections_and_handles_a_closed_peer(closed):
    import socket

    lease = transport.PeerLease(None, None)
    own, remote = socket.socketpair()
    foreign, foreign_remote = socket.socketpair()
    try:
        lease.register(own)
        if closed:
            own.close()
        lease.stop()
        assert lease.stopped.is_set()
        assert remote.recv(1) == b''
        foreign.sendall(b'untouched')
        assert foreign_remote.recv(9) == b'untouched'
    finally:
        for peer in (own, remote, foreign, foreign_remote):
            peer.close()


def test_signal_stop_request_never_reenters_the_registration_lock():
    lease = transport.PeerLease(None, None)
    with lease.lock:
        lease.request_stop()
    assert lease.stop_requested
    assert not lease.stopped.is_set()


def test_daemon_stdin_eof_keeps_monitoring_the_control_connection():
    import threading

    stream = io.BytesIO()
    transport.send(stream, dict(kind='eof'), threading.Lock())
    stream.seek(0)
    calls, errors = [], []
    process = SimpleNamespace(stdin=io.BytesIO(), terminate=lambda: calls.append('terminate'))
    transport._input(stream, process, None, None, None, 'daemon', errors)
    assert calls == ['terminate']
    assert errors == ['EOFError']
    assert process.stdin.closed


def test_cancelled_lease_interrupts_a_silent_child_without_waiting_for_its_deadline():
    import threading
    import time

    cancelled = threading.Event()
    cancelled.set()
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        with pytest.raises(ConnectionAbortedError, match='lease stopped'):
            transport._relay_output(process, io.BytesIO(), threading.Lock(), time.monotonic() + 60, cancelled)
    finally:
        transport._stop_child(process)
    assert process.poll() is not None


@pytest.mark.parametrize('failure', [None, 'child', 'reverse'])
def test_private_credentials_are_removed_even_when_owned_retirement_fails(tmp_path, monkeypatch, failure):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    (directory / 'key').write_bytes(b'fixture credential')
    outside = tmp_path / 'outside'
    outside.write_bytes(b'unchanged')
    calls = []

    def retire(stage):
        calls.append(stage)
        if stage == failure:
            raise RuntimeError('injected ' + stage + ' retirement failure')

    monkeypatch.setattr(transport, '_stop_child', lambda child: retire('child'))
    monkeypatch.setattr(daemon, 'retire', lambda *args: retire('reverse'))
    _check_private_retirement(failure, lambda: transport._retire_connection(object(), {}, None, directory))
    assert calls == ['child', 'reverse']
    assert not directory.exists()
    assert outside.read_bytes() == b'unchanged'


def _check_private_retirement(failure, operation):
    if failure is None:
        operation()
    else:
        with pytest.raises(RuntimeError, match='retirement failure'):
            operation()


@pytest.fixture
def private_reference_socket():
    """Use a short owned Unix path, independent of the long pytest root."""
    import socket
    import tempfile

    with tempfile.TemporaryDirectory(prefix='rr-input-', dir='/tmp') as directory:
        with socket.socket(socket.AF_UNIX) as listener:
            path = Path(directory) / 'socket'
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(5)
            yield listener, path


def _client_with_open_input(listener, path, root, kind, code):
    """The remote child exits while the native stdin pipe stays deliberately open."""
    import threading

    command = [sys.executable, '-m', 'tools.ci.remote_reference_transport', 'client',
        '--socket', str(path), '--fixture-root', str(root), '--kind', kind,
        '--tool', 'xrdfs', '--', '--version']
    environment = dict(PATH=os.environ['PATH'], PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    with subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            process.stdin.write(b'{"op":"ping"}\n')
            process.stdin.flush()
            with listener.accept()[0] as peer, peer.makefile('rwb') as stream:
                assert transport.receive(stream)['kind'] == kind
                assert transport.receive(stream)['kind'] == 'input'
                for output in ('stdout', 'stderr'):
                    transport.send(stream, dict(kind=output, data='AP8K'), threading.Lock())
                transport.send(stream, dict(kind='exit', code=code), threading.Lock())
                process.wait(timeout=5)
            return subprocess.CompletedProcess(command, process.returncode,
                process.stdout.read(), process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize('kind', ['cli', 'worker'])
@pytest.mark.parametrize('code', [0, 7])
def test_open_input_cannot_abort_or_mask_the_remote_child_exit(
        private_reference_socket, tmp_path, kind, code):
    listener, path = private_reference_socket
    result = _client_with_open_input(listener, path, tmp_path, kind, code)
    assert result.returncode == code, result.stderr
    assert result.stdout == result.stderr == b'\x00\xff\n'


def test_worker_input_reassembles_fragmented_and_unterminated_records():
    chunks = [b'{"op":', b'"ping"}\n{"op":"n', b'ext"}\n{"final":true}']
    assert list(transport._worker_input_records(chunks)) == [
        b'{"op":"ping"}\n', b'{"op":"next"}\n', b'{"final":true}']


@pytest.mark.parametrize('newline', [b'', b'\n'])
def test_worker_input_refuses_oversized_records_before_relay(newline):
    chunks = [b'x' * (64 * 1024 * 1024), b'x' + newline]
    with pytest.raises(ValueError, match='input exceeds'):
        list(transport._worker_input_records(chunks))


def test_remote_eof_without_an_exit_record_cannot_be_success():
    with pytest.raises(EOFError, match='before completion'):
        transport._client_output(io.BytesIO())

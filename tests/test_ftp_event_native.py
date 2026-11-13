"""GridFTP data events retain peer admission, bounded retries and socket ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def event_binary(server_native_compile):
    names = ('ngx_get_connection', 'ngx_close_connection', 'ngx_handle_read_event',
        'ngx_handle_write_event', 'ngx_nonblocking', 'socket', 'connect', 'bind',
        'getsockopt', 'getpeername', 'accept', 'brix_ftp_ev_data_ready',
        'brix_ftp_ev_dc_start_tls', 'brix_ftp_ev_metric_xfer', 'brix_ftp_ev_cns_note_stored',
        'brix_ftp_ev_reply', 'brix_ftp_ev_resume', 'brix_vfs_close', 'brix_vfs_closedir',
        'brix_vfs_writer_abort', 'ngx_ssl_shutdown', 'brix_ftp_ev_vfs_ctx',
        'brix_vfs_writer_open', 'brix_vfs_writer_write', 'brix_vfs_writer_commit',
        'brix_vfs_unlink', 'brix_ftp_ev_tls_begin', 'brix_ftp_ev_tls_verify', 'brix_ftp_ev_flush')
    return server_native_compile('ftp-event', 'tests/c/ftp_event_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, mode='normal', protection='C'):
    result = subprocess.run([str(binary), operation, mode, protection],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return tuple(map(int, result.stdout.split()))


@pytest.mark.parametrize('operation', ['active', 'passive'])
@pytest.mark.parametrize('protection,ready,tls', [('C', 1, 0), ('P', 0, 1)])
def test_admitted_data_channel_selects_required_security_before_pump(event_binary, operation, protection, ready, tls):
    assert invoke(event_binary, operation, protection=protection)[:5] == (0, ready, tls, 0, 0)


@pytest.mark.parametrize('mode', ['socket', 'nonblocking', 'connection', 'connect', 'write-arm'])
def test_active_setup_failure_releases_socket_and_consumes_port_arm(event_binary, mode):
    assert invoke(event_binary, 'active', mode)[:5] == (-1, 0, 0, 0, 0)


@pytest.mark.parametrize('mode', ['timeout', 'getsockopt', 'socket-error'])
@pytest.mark.parametrize('protection', ['C', 'P'])
def test_active_completion_failure_never_starts_pump_or_tls(event_binary, mode, protection):
    result = invoke(event_binary, 'active', mode, protection)
    assert result[:5] == (0, 0, 0, 1, 1) and result[6] == 550


@pytest.mark.parametrize('mode', ['immediate', 'bind'])
def test_immediate_connect_and_failed_optional_source_bind_complete_asynchronously(event_binary, mode):
    assert invoke(event_binary, 'active', mode)[:5] == (0, 1, 0, 0, 0)


@pytest.mark.parametrize('mode', ['no-listener', 'connection', 'read-arm'])
def test_passive_setup_refusal_cannot_leave_listener_owned(event_binary, mode):
    assert invoke(event_binary, 'passive', mode)[:5] == (-1, 0, 0, 0, 0)


@pytest.mark.parametrize('mode', ['timeout', 'accept-error', 'nonblocking', 'data-connection',
                                 'again-arm', 'flood-arm'])
def test_passive_failure_sends_one_terminal_result(event_binary, mode):
    result = invoke(event_binary, 'passive', mode)
    assert result[:5] == (0, 0, 0, 1, 1) and result[6] == 550


@pytest.mark.parametrize('mode,protection,accepted,posted', [
    ('again', 'C', 0, 0), ('offpeer', 'C', 1, 0), ('peer-error', 'C', 1, 0),
    ('normal', 'X', 1, 0), ('flood', 'C', 64, 1)])
def test_untrusted_passive_peers_never_consume_transfer_authority(event_binary, mode, protection, accepted, posted):
    result = invoke(event_binary, 'passive', mode, protection)
    assert result[:5] == (0, 0, 0, 0, 0) and result[7:9] == (accepted, posted)


@pytest.mark.parametrize('mode', ['normal', 'short', 'again', 'empty'])
def test_send_pump_preserves_exact_payload_across_short_writes(event_binary, mode):
    result = invoke(event_binary, 'drain', mode)
    assert result[:5] == (0, 0, 0, 0, 0)
    assert result[9] == (0 if mode == 'empty' else len('byte-exact-data'))


@pytest.mark.parametrize('mode', ['timeout', 'write-arm', 'send-error', 'send-zero'])
def test_send_failure_finishes_once_without_claiming_bytes(event_binary, mode):
    result = invoke(event_binary, 'drain', mode)
    assert result[:5] == (-1, 0, 0, 1, 1) and result[6] == 550 and result[9] == 0


@pytest.mark.parametrize('mode,notes,code', [('normal', 1, 226), ('writer', 0, 226),
                                         ('failure', 0, 550), ('specific', 0, 450)])
def test_completion_closes_handles_and_only_committed_writes_notify_namespace(event_binary, mode, notes, code):
    result = invoke(event_binary, 'finish', mode)
    assert result[3:7] == (1, 1, notes, code)


@pytest.mark.parametrize('protection', ['C', 'P'])
@pytest.mark.parametrize('mode', ['normal', 'block-again', 'block-fragments'])
def test_extended_blocks_commit_exact_contiguous_payload_once(event_binary, protection, mode):
    result = invoke(event_binary, 'blocks', mode, protection)
    assert result[3:7] == (1, 1, 1, 226)
    assert result[9:] == (7, 1, 1, 0, 0)


@pytest.mark.parametrize('protection', ['C', 'P'])
@pytest.mark.parametrize('mode', ['block-error', 'block-overflow', 'overlap',
    'short-header', 'short-payload', 'child-timeout', 'writer-write'])
def test_invalid_or_incomplete_blocks_abort_without_publication(event_binary, protection, mode):
    result = invoke(event_binary, 'blocks', mode, protection)
    assert result[3:7] == (1, 1, 0, 550)
    assert result[10:] == (1, 0, 1, 0)


@pytest.mark.parametrize('mode,opens,commits,aborted,code', [
    ('tls-start', 0, 0, 0, 550), ('tls-identity', 0, 0, 0, 550),
    ('writer-error', 1, 0, 0, 550), ('writer-busy', 1, 0, 0, 450),
    ('writer-commit', 1, 1, 0, 550)])
def test_protected_blocks_require_identity_before_open_and_success_before_notice(event_binary, mode, opens, commits, aborted, code):
    result = invoke(event_binary, 'blocks', mode, 'P')
    assert result[3:7] == (1, 1, 0, code)
    assert result[10:] == (opens, commits, aborted, 0)


@pytest.mark.parametrize('protection', ['C', 'P'])
def test_completed_transfer_with_a_hole_aborts_and_removes_partial_object(event_binary, protection):
    result = invoke(event_binary, 'blocks', 'hole', protection)
    assert result[3:7] == (1, 1, 0, 550)
    assert result[9:] == (7, 1, 0, 1, 1)


@pytest.mark.parametrize('mode', ['timeout', 'nonblocking', 'connection', 'writer-error',
                                 'writer-busy', 'block-listener-arm'])
def test_mode_e_admission_failures_release_every_accepted_socket(event_binary, mode):
    result = invoke(event_binary, 'blocks', mode)
    assert result[3:6] == (1, 1, 0)
    assert result[6] == (450 if mode == 'writer-busy' else 550)


@pytest.mark.parametrize('mode', ['offpeer', 'flood'])
def test_mode_e_offpeer_flood_cannot_open_destination(event_binary, mode):
    result = invoke(event_binary, 'blocks', mode)
    assert result[3:6] == (0, 0, 0) and result[10:] == (0, 0, 0, 0)
    assert result[8] == int(mode == 'flood')

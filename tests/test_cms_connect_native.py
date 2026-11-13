"""CMS connection ownership, bounded retries and draining-worker behavior."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def cms_connect(server_native_compile):
    return server_native_compile('cms-connect', 'tests/c/cms_connect_native_test.c',
        ['-Wl,--wrap=' + name for name in ('ngx_event_connect_peer',
        'ngx_close_connection', 'brix_dns_target_note_failure',
        'brix_cms_state_relay_drop_ctx', 'brix_sess_end', 'ngx_brix_cms_send_login',
        'ngx_brix_cms_send_status', 'ngx_brix_cms_send_load', 'ngx_handle_read_event')])


def invoke(binary, operation, mode):
    result = subprocess.run([str(binary), operation, mode], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['immediate', 'delayed', 'custom-timeout'])
def test_registered_link_sends_one_login_and_keeps_read_deadline(cms_connect, mode):
    invoke(cms_connect, 'dial', mode)


@pytest.mark.parametrize('mode', ['unresolved', 'dial-error', 'dial-declined',
    'dial-empty', 'login', 'status', 'load', 'read-event', 'delete-event', 'timeout'])
def test_failed_initialization_closes_once_and_schedules_bounded_retry(cms_connect, mode):
    invoke(cms_connect, 'dial', mode)


@pytest.mark.parametrize('mode', ['read-timeout', 'write-timeout', 'connection-error',
    'hint', 'exiting', 'terminate', 'load'])
def test_disconnect_reason_and_timer_ownership_survive_every_exit(cms_connect, mode):
    invoke(cms_connect, 'disconnect', mode)


def test_repeated_retarget_failure_restores_configured_manager(cms_connect):
    invoke(cms_connect, 'retry', 'retarget')

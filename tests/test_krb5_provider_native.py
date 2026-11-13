"""Kerberos provider failures release resources and cannot authenticate a peer."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def provider(server_native_compile):
    names = ('malloc', 'ngx_create_pool', 'ngx_pnalloc', 'brix_krb5_forward_available',
        'gss_import_name', 'gss_release_name', 'gss_release_buffer', 'gss_display_status',
        'gss_init_sec_context', 'gss_delete_sec_context', 'brix_cache_io_send', 'brix_cache_io_recv_exact',
        'krb5_init_context', 'krb5_free_context', 'krb5_cc_resolve', 'krb5_cc_close',
        'gss_krb5_import_cred', 'gss_release_cred', 'gss_store_cred_into', 'krb5_cc_get_principal',
        'krb5_parse_name', 'krb5_get_credentials', 'krb5_mk_req_extended')
    return server_native_compile('krb5-provider', 'tests/c/krb5_provider_native_test.c',
                                 ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, mode='normal'):
    result = subprocess.run([str(binary), operation, mode], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return dict((key, int(value)) for key, value in
                (line.split('=', 1) for line in result.stdout.splitlines()))


@pytest.mark.parametrize('operation,steps,wires', [('single', 1, 0), ('negotiate', 2, 1),
    ('origin', 2, 1), ('raw', 0, 1), ('apreq', 0, 0)])
def test_success_preserves_tokens_identity_and_exact_exchange_count(provider, operation, steps, wires):
    body = invoke(provider, operation)
    assert (body['rc'], body['steps'], body['wires']) == (0, steps, wires)


@pytest.mark.parametrize('operation', ['single', 'negotiate', 'origin'])
@pytest.mark.parametrize('mode', ['null-spn', 'empty-spn', 'import-error', 'context-error',
                                 'display-error', 'token-oom', 'empty-token'])
def test_gss_failure_cannot_publish_success_and_releases_all_provider_state(provider, operation, mode):
    assert invoke(provider, operation, mode)['rc'] == -1


@pytest.mark.parametrize('operation', ['negotiate', 'origin'])
@pytest.mark.parametrize('mode', ['no-mutual', 'closed-early', 'empty-reply', 'runaway'])
def test_unverified_or_unfinished_exchange_is_refused(provider, operation, mode):
    body = invoke(provider, operation, mode)
    assert body['rc'] == -1 and body['steps'] <= 8


@pytest.mark.parametrize('operation', ['negotiate', 'origin'])
def test_final_output_token_is_sent_before_success(provider, operation):
    body = invoke(provider, operation, 'final-token')
    assert (body['rc'], body['steps'], body['wires']) == (0, 2, 2)


@pytest.mark.parametrize('operation', ['origin', 'raw'])
@pytest.mark.parametrize('mode', ['pool-oom', 'send-header', 'send-body', 'recv-header',
                                 'recv-body', 'oversized', 'reply-oom', 'rejected'])
def test_origin_transport_failures_preserve_authentication_error(provider, operation, mode):
    body = invoke(provider, operation, mode)
    assert body['rc'] == -1 and body['error'] == (3008 if mode == 'pool-oom' else 3030)


@pytest.mark.parametrize('mode', ['continued', 'null-spn', 'empty-spn'])
def test_raw_origin_cannot_delegate_again_or_accept_missing_service_identity(provider, mode):
    body = invoke(provider, 'raw', mode)
    assert (body['rc'], body['error']) == (-1, 3030)


def test_source_backend_without_request_connection_uses_worker_log(provider):
    assert invoke(provider, 'raw', 'no-connection')['rc'] == 0


@pytest.mark.parametrize('operation,mode', [('single', 'null-pool'), ('single', 'null-output'),
    ('negotiate', 'null-pool'), ('negotiate', 'null-wire'), ('negotiate', 'wire-error'),
    ('origin', 'unavailable')])
def test_invalid_or_unavailable_forwarding_refuses_before_peer_authentication(provider, operation, mode):
    assert invoke(provider, operation, mode)['rc'] == -1


@pytest.mark.parametrize('operation', ['import', 'export'])
def test_credential_carry_uses_explicit_cache_and_never_sets_process_default(provider, operation):
    body = invoke(provider, operation)
    assert body['rc'] == 0 and body['stored'] == int(operation == 'export')


@pytest.mark.parametrize('operation', ['import', 'export'])
@pytest.mark.parametrize('mode', ['null-path', 'null-cred', 'long-path'])
def test_invalid_carry_arguments_never_reach_store(provider, operation, mode):
    body = invoke(provider, operation, mode)
    assert body['rc'] == -1 and body['stored'] == 0


@pytest.mark.parametrize('mode', ['null-hold', 'hold-oom', 'krb-context', 'resolve-error', 'cred-error'])
def test_import_failure_leaves_no_credential_or_backing_handles(provider, mode):
    assert invoke(provider, 'import', mode)['rc'] == -1


def test_store_failure_propagates_without_falling_back_to_default_cache(provider):
    body = invoke(provider, 'export', 'store-error')
    assert body['rc'] == -1 and body['stored'] == 1


@pytest.mark.parametrize('operation', ['apreq', 'raw'])
@pytest.mark.parametrize('mode', ['krb-context', 'resolve-error', 'principal-error', 'parse-error',
                                 'ticket-error', 'request-error', 'token-oom'])
def test_ticket_provider_failure_releases_each_completed_step(provider, operation, mode):
    body = invoke(provider, operation, mode)
    assert body['rc'] == -1 and body['wires'] == 0

"""Admin control responses enforce input policy before touching shared state."""

import json
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def dashboard_control(server_native_compile):
    seams = ('json_object', 'json_array', 'admin_audit', 'dashboard_json_send',
             'brix_proxy_pool_add', 'brix_proxy_pool_drain', 'brix_proxy_pool_undrain',
             'brix_proxy_pool_remove', 'brix_proxy_pool_in_flight', 'brix_proxy_pool_snapshot',
             'brix_uring_killswitch_set', 'brix_uring_killswitch_get')
    return server_native_compile('dashboard-control', 'tests/c/dashboard_control_native_test.c',
                                 [f'-Wl,--wrap={name}' for name in seams])


def invoke(binary, operation='add', mode='normal', method='POST', body=None, argument='', fail_json=0):
    payload = {} if body is None else body
    result = subprocess.run([str(binary), operation, mode, method, json.dumps(payload),
                             argument, str(fail_json)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    fields = {}
    for line in result.stdout.splitlines():
        key, value = line.split('=', 1)
        fields[key] = value if key in ('json', 'action') else int(value)
    response = json.loads(fields.pop('json', '{}'))
    return fields, response


@pytest.mark.parametrize('url', ['http://backend.invalid', 'https://BACKEND.invalid:8443/path'])
@pytest.mark.parametrize('weight,expected', [(-1, 1), (0, 1), (17, 17), (1001, 1000)])
def test_valid_backend_add_clamps_weight_and_reports_assigned_id(dashboard_control, url, weight, expected):
    result, body = invoke(dashboard_control, body={'url': url, 'weight': weight})
    assert result['rc'] == 201 and result['calls'] == result['audits'] == 1
    assert result['weight'] == expected and body['id'] == 42 and body['result'] == 'added'


@pytest.mark.parametrize('payload,status,error', [
    ({}, 400, 'missing_field'), ({'url': 17}, 400, 'missing_field'),
    ({'url': 'ftp://backend.invalid'}, 400, 'invalid_field'),
    ({'url': 'http://backend.invalid\r\nInjected: bad'}, 400, 'invalid_field'),
    ({'url': 'https://backend.invalid.attacker.test'}, 403, 'host_not_allowed'),
    ({'url': 'https://attacker.test/backend.invalid'}, 403, 'host_not_allowed'),
    ({'url': 'http://127.0.0.1'}, 403, 'host_not_allowed'),  # net-literal-allow: unlisted loopback input must be rejected before dispatch
])
def test_invalid_or_unlisted_backend_never_reaches_shared_pool(dashboard_control, payload, status, error):
    result, body = invoke(dashboard_control, body=payload)
    assert result['rc'] == status and body['error'] == error
    assert result['calls'] == 0 and result['audits'] == 1


@pytest.mark.parametrize('mode,status,error', [('disabled', 404, 'proxy_pool_disabled'),
                                             ('failed', 400, 'add_failed')])
def test_backend_mutation_failure_is_not_reported_as_added(dashboard_control, mode, status, error):
    result, body = invoke(dashboard_control, mode=mode, body={'url': 'https://backend.invalid'})
    assert result['rc'] == status and body['error'] == error and result['calls'] == 1


@pytest.mark.parametrize('action', ['drain', 'undrain'])
@pytest.mark.parametrize('method,status,calls', [('POST', 200, 1), ('GET', 405, 0),
                                              ('DELETE', 405, 0), ('PUT', 405, 0)])
def test_drain_mutation_requires_post(dashboard_control, action, method, status, calls):
    result, body = invoke(dashboard_control, 'one', method=method, argument=action)
    assert result['rc'] == status and result['calls'] == calls
    assert body.get('result', body.get('error')) == (action + 'ed' if calls else 'method_not_allowed')


@pytest.mark.parametrize('action', ['drain', 'undrain'])
def test_missing_drain_target_is_not_success(dashboard_control, action):
    result, body = invoke(dashboard_control, 'one', 'missing', argument=action)
    assert result['rc'] == 404 and result['calls'] == 1 and body['error'] == 'not_found'


@pytest.mark.parametrize('method,mode,status,code,calls', [
    ('DELETE', 'normal', 200, 'removed', 1), ('DELETE', 'busy', 409, 'in_flight', 1),
    ('DELETE', 'missing', 404, 'not_found', 1), ('GET', 'missing', 404, 'not_found', 1),
    ('POST', 'normal', 405, 'method_not_allowed', 0), ('PUT', 'normal', 405, 'method_not_allowed', 0),
])
def test_single_backend_controls_preserve_pool_outcome(dashboard_control, method, mode, status, code, calls):
    result, body = invoke(dashboard_control, 'one', mode, method)
    assert result['rc'] == status and result['calls'] == calls
    assert body.get('result', body.get('error')) == code


def test_inflight_read_returns_the_requested_backend(dashboard_control):
    result, body = invoke(dashboard_control, 'one', method='GET')
    assert result['rc'] == 200 and body['id'] == 42 and body['in_flight'] == 7


def test_unknown_action_does_not_mutate_pool(dashboard_control):
    result, body = invoke(dashboard_control, 'one', argument='restart')
    assert result['rc'] == 404 and result['calls'] == 0 and body['error'] == 'not_found'


def test_snapshot_preserves_every_backend_field_and_state(dashboard_control):
    result, body = invoke(dashboard_control, 'list')
    assert result['rc'] == 200 and result['calls'] == 1
    assert body['backends'] == [dict(id=i + 1, host='backend.invalid', port=443,
        ssl=bool(i % 2), weight=i + 10, state=state, in_flight=i)
        for i, state in enumerate(['active', 'draining', 'dead', 'resolving'])]


def test_empty_snapshot_is_an_empty_list(dashboard_control):
    result, body = invoke(dashboard_control, 'list', 'empty')
    assert result['rc'] == 200 and body['backends'] == []


@pytest.mark.parametrize('operation,method,argument', [('add', 'POST', ''),
    ('one', 'POST', 'drain'), ('one', 'GET', ''), ('list', 'GET', ''),
    ('uring-set', 'POST', ''), ('uring-get', 'GET', '')])
def test_response_allocation_failure_never_claims_success(dashboard_control, operation, method, argument):
    result, body = invoke(dashboard_control, operation, method=method, argument=argument,
                          body={'url': 'https://backend.invalid', 'enabled': True}, fail_json=1)
    assert result['rc'] == 500 and body == {}


def test_list_array_allocation_failure_is_internal_error(dashboard_control):
    result, body = invoke(dashboard_control, 'list', 'array-oom')
    assert result['rc'] == 500 and body == {}


@pytest.mark.parametrize('enabled,disabled,word', [(True, 0, 'enabled'), (False, 1, 'disabled')])
def test_uring_switch_inverts_enabled_exactly_once(dashboard_control, enabled, disabled, word):
    result, body = invoke(dashboard_control, 'uring-set', body={'enabled': enabled})
    assert result['rc'] == 200 and result['calls'] == 1 and result['disabled'] == disabled
    assert body['result'] == word


@pytest.mark.parametrize('payload', [{}, {'enabled': 0}, {'enabled': 1}, {'enabled': 'false'}, {'enabled': None}])
def test_uring_requires_a_json_boolean_before_mutating(dashboard_control, payload):
    result, body = invoke(dashboard_control, 'uring-set', body=payload)
    assert result['rc'] == 400 and result['calls'] == 0 and body['error'] == 'missing_field'


def test_unconfigured_uring_cannot_be_enabled_by_admin(dashboard_control):
    result, body = invoke(dashboard_control, 'uring-set', 'disabled', body={'enabled': True})
    assert result['rc'] == 404 and body['error'] == 'io_uring_not_enabled'


@pytest.mark.parametrize('mode,disabled', [('normal', False), ('disabled', True)])
def test_uring_read_reports_current_switch(dashboard_control, mode, disabled):
    result, body = invoke(dashboard_control, 'uring-get', mode)
    assert result['rc'] == 200 and body['disabled'] is disabled


@pytest.mark.parametrize('tail,id,action', [('42', 42, ''), ('42/drain', 42, 'drain'),
                                         ('42/undrain/', 42, 'undrain')])
def test_backend_uri_parser_extracts_id_and_action(dashboard_control, tail, id, action):
    result, _body = invoke(dashboard_control, 'parse', argument='/brix/api/v1/admin/proxy/backends/' + tail)
    assert result['rc'] == 0 and result['id'] == id and result['action'] == action


@pytest.mark.parametrize('tail', ['', '0', '-1', 'abc', '42x', '9' * 64])
def test_invalid_backend_identifier_is_refused(dashboard_control, tail):
    result, _body = invoke(dashboard_control, 'parse', argument='/brix/api/v1/admin/proxy/backends/' + tail)
    assert result['rc'] == -1 and result['id'] == 0

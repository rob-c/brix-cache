"""Tape bulk operations must authorize the complete batch before side effects."""

import json
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def tape(server_native_compile):
    wrappers = ['tape_queue', 'tape_send_object', 'tape_error', 'tape_authz_path',
        'tape_residency', 'brix_http_set_header', 'ngx_http_send_header',
        'brix_stage_request_add', 'brix_stage_request_get', 'brix_stage_request_list_active',
        'brix_stage_request_owner_check', 'brix_stage_request_cancel', 'brix_stage_request_delete',
        'brix_stage_request_pin_release', 'ngx_pcalloc', 'ngx_pnalloc']
    binary = server_native_compile('tape-ops', 'tests/c/tape_ops_native_test.c',
                                   ['-Wl,--wrap=' + name for name in wrappers])
    def invoke(operation, body=None, mode='', state=0, residency=0, nearline=0):
        result = subprocess.run([str(binary), operation, mode, json.dumps(body or {}),
            str(state), str(residency), str(nearline)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        lines = result.stdout.splitlines()
        observed = {key: int(value) for key, value in (part.split('=') for part in lines[0].split())}
        return observed, json.loads(lines[1]), lines[2]
    return invoke


def stage_body(checksum=None, algorithm=None):
    files = [{'path': '/a'}, {'path': '/b'}]
    if checksum is not None:
        files[-1]['checksum'] = checksum
    if algorithm is not None:
        files[-1]['checksumType'] = algorithm
    return {'files': files}


@pytest.mark.parametrize('mode,expected', [('', 'SUBMITTED'), ('active', 'STARTED')])
@pytest.mark.parametrize('algorithm,code', [(None, 4), ('md5', 5), ('CRC32', 6),
    ('sha1', 1), ('sha256', 2), ('sha2', 2), ('unknown', 0)])
def test_stage_checksums_and_durable_request_id(tape, mode, expected, algorithm, code):
    observed, body, location = tape('stage', stage_body('abcd', algorithm), mode)
    assert observed['status'] == 201 and observed['auth'] == observed['adds'] == 2
    assert observed['checksum'] == code
    assert body['id'] == body['requestId'] == '1.44@fixture'
    assert location == '/api/v1/stage/' + body['id']
    assert body['files'] == [{'path': path, 'state': expected} for path in ('/a', '/b')]


def test_stage_enqueue_errors_are_per_file_and_not_submitted(tape):
    observed, body, _location = tape('stage', stage_body(), 'enqueue-error')
    assert observed['adds'] == 2 and observed['status'] == 201
    assert body['files'] == [{'path': path, 'error': 'could not enqueue'} for path in ('/a', '/b')]


@pytest.mark.parametrize('operation,key,values', [('stage', 'files', [{'path': '/a'}, {'path': '/denied'}]),
    ('release', 'paths', ['/a', '/denied']), ('archive', 'paths', ['/a', '/denied'])])
def test_later_denial_prevents_all_mutation_and_disclosure(tape, operation, key, values):
    observed, body, _location = tape(operation, {key: values})
    assert observed['status'] == 403 and observed['auth'] == 2
    assert observed['adds'] == observed['releases'] == observed['residency'] == 0
    assert body == {'detail': 'path not permitted'}


@pytest.mark.parametrize('operation,body', [('stage', {}), ('stage', {'files': []}),
    ('stage', {'files': [1]}), ('stage', {'files': [{'path': 7}]}),
    ('stage', {'files': [{}] * 4097}), ('release', {}), ('release', {'paths': [1]}),
    ('archive', {}), ('archive', {'paths': []}), ('archive', {'paths': [False]})])
def test_malformed_batches_never_reach_registry(tape, operation, body):
    observed, reply, _location = tape(operation, body)
    assert observed['status'] == 400 and 'detail' in reply
    assert observed['adds'] == observed['releases'] == observed['residency'] == 0


@pytest.mark.parametrize('operation', ['stage', 'get', 'list', 'cancel', 'delete'])
def test_unconfigured_registry_has_explicit_unavailable_status(tape, operation):
    observed, reply, _location = tape(operation, stage_body(), 'no-queue')
    assert observed['status'] == 503 and 'detail' in reply
    assert observed['mutations'] == observed['adds'] == 0


@pytest.mark.parametrize('operation', ['stage', 'release', 'archive'])
def test_path_allocation_failure_never_mutates(tape, operation):
    body = stage_body() if operation == 'stage' else {'paths': ['/a', '/b']}
    observed, reply, _location = tape(operation, body, 'path-allocation')
    assert observed['status'] == 500 and reply is None
    assert observed['adds'] == observed['releases'] == 0


def test_stage_array_allocation_failure_never_resolves(tape):
    observed, reply, _location = tape('stage', stage_body(), 'array-allocation')
    assert observed['status'] == 500 and reply is None
    assert observed['auth'] == observed['adds'] == 0


@pytest.mark.parametrize('state,label', [(0, 'SUBMITTED'), (1, 'STARTED'), (2, 'COMPLETED'),
                                       (3, 'FAILED'), (4, 'CANCELLED'), (99, 'UNKNOWN')])
def test_poll_reports_lifecycle_and_failure_without_requeue(tape, state, label):
    observed, body, _location = tape('get', state=state)
    assert observed['status'] == 200 and observed['adds'] == 0
    assert body['createdAt'] == 1234 and body['files'][0]['state'] == label
    assert ('error' in body['files'][0]) == (state == 3)


@pytest.mark.parametrize('mode', ['', 'empty'])
def test_list_exposes_only_returned_active_records(tape, mode):
    observed, body, _location = tape('list', mode=mode)
    assert observed['status'] == 200
    assert [item['state'] for item in body['requests']] == ([] if mode else ['SUBMITTED', 'STARTED'])


@pytest.mark.parametrize('operation', ['cancel', 'delete'])
@pytest.mark.parametrize('mode,status,mutations', [('', 204, 1), ('missing', 204, 1),
                                               ('foreign-owner', 403, 0)])
def test_termination_checks_owner_before_idempotent_mutation(tape, operation, mode, status, mutations):
    observed, _body, _location = tape(operation, mode=mode)
    assert observed['status'] == status and observed['owners'] == 1
    assert observed['mutations'] == mutations


@pytest.mark.parametrize('mode,unpinned', [('', ['/a', '/b']), ('release-error', []), ('late-deny', [])])
def test_release_reports_per_file_results_after_complete_authorization(tape, mode, unpinned):
    observed, body, _location = tape('release', {'paths': ['/a', '/b']}, mode)
    assert observed['status'] == 200 and observed['auth'] == 4
    assert body['unpinnedFiles'] == unpinned
    assert body['nonUnpinnedFiles'] == ([] if unpinned else ['/a', '/b'])


@pytest.mark.parametrize('mode', ['late-deny', 'residency-error', 'residency-missing'])
def test_archiveinfo_handles_revoked_access_and_missing_storage(tape, mode):
    observed, body, _location = tape('archive', {'paths': ['/a', '/b']}, mode)
    assert observed['status'] == 200
    expected = {'error': 'denied'} if mode == 'late-deny' else {'exists': False, 'locality': 'NONE'}
    assert body['files'] == [{'path': path, **expected} for path in ('/a', '/b')]

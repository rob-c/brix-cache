"""Tape REST calls preserve caller identity, JSON paths, and no-failover semantics."""

import errno
import json
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def nearline(server_native_compile):
    return server_native_compile('http-nearline', 'tests/c/http_nearline_native_test.c')


def invoke(binary, action='residency', mode='normal', body='[{"locality":"TAPE"}]',
           status=200, stage_status=201, key='/file', base='/api/v1/'):
    result = subprocess.run([str(binary), action, mode, body, str(status), str(stage_status), key, base],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    fields, requests = {}, []
    for line in result.stdout.splitlines():
        name, value = line.split('=', 1)
        if name == 'path':
            requests.append({'path': value})
        elif name == 'body':
            requests[-1]['body'] = json.loads(value)
        else:
            fields[name] = value if name == 'request_id' else int(value)
    return fields, requests


@pytest.mark.parametrize('locality,rc,requests', [('DISK', 0, 1), ('DISK_AND_TAPE', 0, 1),
    ('TAPE', -2, 2), ('UNAVAILABLE', -2, 1), ('LOST', -1, 1), ('NONE', -1, 1)])
def test_recall_only_stages_objects_known_to_be_on_tape(nearline, locality, rc, requests):
    result, wire = invoke(nearline, 'recall', body=json.dumps([{'locality': locality}]))
    assert result['rc'] == rc and result['requests'] == result['releases'] == requests
    assert result['request_id'] == ('fixture-id' if locality == 'TAPE' else '')
    assert wire[0] == {'path': '/api/v1/archiveinfo', 'body': {'paths': ['/file']}}


@pytest.mark.parametrize('key', ['/quote"and\\slash', '/line\nbreak', '/control\x01tab\t', '/unicode/λ'])
def test_json_encoding_keeps_one_exact_path(nearline, key):
    result, wire = invoke(nearline, 'recall', key=key)
    assert result['rc'] == -2
    assert wire == [{'path': '/api/v1/archiveinfo', 'body': {'paths': [key]}},
                    {'path': '/api/v1/stage', 'body': {'files': [{'path': key}]}}]


@pytest.mark.parametrize('mode', ['bearer', 'proxy'])
def test_prestage_carries_caller_identity_on_both_requests(nearline, mode):
    result, _wire = invoke(nearline, 'credential', mode)
    assert result['rc'] == -2 and result['requests'] == 2
    assert result['certificates'] == (2 if mode == 'proxy' else 0)


def test_unpresentable_caller_certificate_cannot_fall_back_to_service(nearline):
    result, wire = invoke(nearline, 'credential', 'unsupported-cert')
    assert result['rc'] == -1 and result['errno'] == errno.EACCES and wire == []


def test_credential_without_user_material_retains_the_instance_identity(nearline):
    result, wire = invoke(nearline, 'credential', 'empty')
    assert result['rc'] == -2 and len(wire) == 2 and result['certificates'] == 0


@pytest.mark.parametrize('status,error', [(-1, errno.EIO), (401, errno.EACCES),
    (403, errno.EACCES), (404, errno.ENOENT), (500, errno.EIO)])
def test_probe_error_does_not_retry_against_another_origin(nearline, status, error):
    result, wire = invoke(nearline, 'recall', status=status)
    assert result['rc'] == -1 and result['errno'] == error and len(wire) == 1
    assert result['releases'] == int(status >= 0)


@pytest.mark.parametrize('body,error', [('', errno.EIO), ('[]', errno.ENOENT), ('{}', errno.ENOENT),
    ('[{}]', errno.EIO), ('[{"locality":"UNKNOWN"}]', errno.EIO),
    ('[{"locality":123}]', errno.EIO), ('[{"locality":"' + 'a' * 40 + '"}]', errno.EIO)])
def test_unreadable_locality_never_reports_online(nearline, body, error):
    result, _wire = invoke(nearline, body=body)
    assert result['rc'] == -1 and result['errno'] == error and result['releases'] == 1


@pytest.mark.parametrize('mode', ['null-instance', 'null-state', 'null-key', 'null-out'])
def test_invalid_probe_arguments_do_not_issue_http(nearline, mode):
    result, wire = invoke(nearline, mode=mode)
    assert result['rc'] == -1 and result['errno'] == errno.EINVAL and wire == []


@pytest.mark.parametrize('base', ['', '/', 'relative', '/api?query', '/api#fragment', '/api\r\nBad', '/api with space'])
def test_invalid_tape_api_base_keeps_nearline_disabled(nearline, base):
    result, wire = invoke(nearline, base=base)
    assert result['rc'] == -1 and result['errno'] == errno.ENOTSUP and wire == []


@pytest.mark.parametrize('key', ['/' + 'x' * 5000, '/' + '\x01' * 1000, '/' + '"' * 3000])
def test_oversized_json_path_is_refused_without_truncation(nearline, key):
    result, wire = invoke(nearline, key=key)
    assert result['rc'] == -1 and result['errno'] == errno.ENAMETOOLONG and wire == []


@pytest.mark.parametrize('status', [-1, 200, 201, 202, 403, 500])
def test_stage_submission_remains_asynchronous_for_all_responses(nearline, status):
    result, wire = invoke(nearline, 'recall', stage_status=status)
    assert result['rc'] == -2 and len(wire) == 2
    assert result['request_id'] == ('fixture-id' if status in (200, 201, 202) else '')


def test_null_request_id_queries_residency_without_submitting(nearline):
    result, wire = invoke(nearline, 'recall', 'null-id')
    assert result['rc'] == -2 and len(wire) == 1


def test_missing_response_buffer_is_a_probe_error(nearline):
    result, _wire = invoke(nearline, mode='null-body')
    assert result['rc'] == -1 and result['errno'] == errno.EIO and result['releases'] == 1

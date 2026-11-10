"""Validate native storage-report summaries and tape stage/poll requests."""

import json
import subprocess

import pytest

from test_doctor_http_contract import doctor, doctor_environment, doctor_peer


def run_storage_diag(doctor, mode, url, *options):
    return subprocess.run([str(doctor), mode, url, '--probe-timeout', '1000', *options],
                          env=doctor_environment(None), capture_output=True,
                          text=True, timeout=10)


@pytest.mark.parametrize('path', ['/', '/custom/report'])
@pytest.mark.parametrize('as_json', [False, True])
def test_srr_summary_and_verbatim_json(doctor, path, as_json):
    report = {'implementation': 'fixture', 'implementationversion': '2.3',
              'shares': [{'totalsize': 100, 'usedsize': 25},
                         {'totalsize': 300, 'usedsize': 75}]}
    body = json.dumps(report).encode()
    with doctor_peer({'GET': (200, {}, body)}) as (peer, authority):
        base = authority.split('/')[0]
        options = ['--json'] if as_json else []
        result = run_storage_diag(doctor, 'srr', 'http://' + base + path, *options)
    assert result.returncode == 0, result.stderr
    verify_srr_output(result.stdout, body.decode(), as_json)
    request, = peer.requests
    expected = '/.well-known/wlcg-storage-resource-reporting' if path == '/' else path
    assert request[0:2] == ('GET', expected)


def verify_srr_output(output, body, as_json):
    if as_json:
        assert output == body
    else:
        assert 'SRR: implementation=fixture 2.3' in output
        assert 'shares:   2' in output
        assert '400 bytes total, 100 used (25.0% full)' in output


@pytest.mark.parametrize('report,expected', [
    ({}, '0 bytes total, 0 used (0.0% full)'),
    ({'implementation': 'bare'}, 'SRR: implementation=bare\n'),
    ({'totalsize': 0, 'usedsize': 5}, '0 bytes total, 5 used (0.0% full)'),
])
def test_srr_missing_optional_fields_and_zero_capacity(doctor, report, expected):
    with doctor_peer({'GET': (200, {}, json.dumps(report).encode())}) as (_peer, authority):
        result = run_storage_diag(doctor, 'srr', 'http://' + authority)
    assert result.returncode == 0 and expected in result.stdout


@pytest.mark.parametrize('mode,method', [('srr', 'GET'), ('tape', 'POST')])
@pytest.mark.parametrize('response', [(403, {}, b'private-denial'),
                                     (404, {}, b'private-missing'),
                                     (500, {}, b'private-fault'), 'reset'])
def test_storage_request_errors_do_not_poll(doctor, mode, method, response):
    with doctor_peer({method: response}) as (peer, authority):
        result = run_storage_diag(doctor, mode, 'http://' + authority)
    assert result.returncode == 51
    request, = peer.requests
    assert request[0] == method
    for private_body in ('private-denial', 'private-missing', 'private-fault'):
        assert private_body not in result.stdout + result.stderr


@pytest.mark.parametrize('mode,url', [
    ('srr', 'root://invalid.example/path'), ('srr', 'invalid://example/path'),
    ('tape', 'root://invalid.example/path'), ('tape', 'invalid://example/path'),
    ('tape', 'http://invalid.example/'),
    ('tape', 'http://invalid.example/' + 'x' * 901),
])
def test_invalid_storage_target_is_refused_before_network(doctor, mode, url):
    result = run_storage_diag(doctor, mode, url)
    assert result.returncode == 50
    assert 'stage accepted' not in result.stdout


@pytest.mark.parametrize('status,id_key', [(200, 'id'), (201, 'requestId')])
@pytest.mark.parametrize('states', [({}, {}, '?', '?', '?'),
                                  ({'state': 'QUEUED'},
                                   {'state': 'COMPLETED', 'onDisk': 'true'},
                                   'QUEUED', 'COMPLETED', 'true')])
def test_tape_stage_then_poll_exact_request_id(doctor, status, id_key, states):
    stage, poll, queued, completed, ondisk = states
    stage_body = json.dumps({id_key: 'request-123', **stage}).encode()
    responses = {'POST': (status, {}, stage_body),
                 'GET': (200, {}, json.dumps(poll).encode())}
    with doctor_peer(responses) as (peer, authority):
        result = run_storage_diag(doctor, 'tape', 'http://' + authority)
    assert result.returncode == 0, result.stderr
    assert f'stage accepted: request-id=request-123 state={queued}' in result.stdout
    assert f'poll: state={completed} onDisk={ondisk}' in result.stdout
    post, get = peer.requests
    assert post[0:2] == ('POST', '/api/v1/stage')
    assert post[2]['Content-Type'] == 'application/json'
    assert json.loads(peer.bodies[0]) == {'files': [{'path': '/bucket/private-object'}]}
    assert get[0:2] == ('GET', '/api/v1/stage/request-123')
    assert peer.bodies[1] == b''


@pytest.mark.parametrize('body', [b'{}', b'{"state":"QUEUED"}', b'not-json'])
def test_missing_stage_identifier_is_not_reported_accepted(doctor, body):
    with doctor_peer({'POST': (201, {}, body)}) as (peer, authority):
        result = run_storage_diag(doctor, 'tape', 'http://' + authority)
    assert result.returncode == 51 and len(peer.requests) == 1
    assert 'stage accepted' not in result.stdout


@pytest.mark.parametrize('response', [(403, {}, b'denied'), (500, {}, b'error'), 'reset'])
def test_poll_failure_preserves_successful_stage_result(doctor, response):
    responses = {'POST': (201, {}, b'{"id":"pending"}'), 'GET': response}
    with doctor_peer(responses) as (peer, authority):
        result = run_storage_diag(doctor, 'tape', 'http://' + authority)
    assert result.returncode == 0 and len(peer.requests) == 2
    assert 'stage accepted: request-id=pending' in result.stdout
    assert 'poll:' not in result.stdout

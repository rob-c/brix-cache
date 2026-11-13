"""Registry integrity, platform selection, pagination and upload boundaries."""

import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')
REF = 'registry.test:5000/lab/app:v1'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
INDEX = 'application/vnd.oci.image.index.v1+json'
DIGEST = 'sha256:' + hashlib.sha256(b'payload').hexdigest()


@pytest.fixture(scope='module')
def registry_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('oci-registry-native')
    return compile_client_contract(root, output, 'tests/c/oci_registry_native_test.c',
                                   ('regc_call', 'brix_http_upload', 'calloc', 'realloc'))


def response(status=200, body='payload', headers='', **extra):
    return dict(status=str(status), body=body, headers=headers, **extra)


def write_script(directory, prefix, values):
    for key, value in values.items():
        if value is not None:
            (directory / f'{prefix}.{key}').write_text(str(value))


@pytest.fixture
def registry_run(registry_binary, tmp_path):
    """Bind response files and captured output to one disposable directory."""
    def run(verb, replies, expected=0, parameter='', reference=REF, upload=None):
        for index, reply in enumerate(replies):
            write_script(tmp_path, index, reply)
        write_script(tmp_path, 'upload', upload or {})
        result = subprocess.run([str(registry_binary), verb, reference, parameter,
                                 str(expected), str(len(replies)), str(tmp_path)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('status,expected', [(401, -2), (403, -2), (404, -3), (500, -5)])
@pytest.mark.parametrize('verb', ['manifest', 'tags', 'put', 'delete'])
def test_registry_status_mapping(registry_run, status, expected, verb):
    body = json.dumps({'errors': [{'message': 'fixture refusal'}]})
    output = registry_run(verb, [response(status, body)], expected,
                          parameter=MANIFEST, reference=REF + '@' + DIGEST)
    assert 'fixture refusal' in output


@pytest.mark.parametrize('verb', ['manifest', 'tags', 'put', 'delete', 'resolve'])
def test_transport_error_preserves_empty_output(registry_run, verb):
    output = registry_run(verb, [{'result': '-1'}], -1, parameter=MANIFEST,
                          reference=REF + '@' + DIGEST)
    assert 'scripted transport refusal' in output


@pytest.mark.parametrize('body', [None, ''])
def test_empty_manifest_is_refused(registry_run, body):
    assert 'empty body' in registry_run('manifest', [response(body=body)], -5)


@pytest.mark.parametrize('pin', [True, False])
def test_manifest_hash_and_fallback_media_type(registry_run, pin):
    body = json.dumps({'mediaType': MANIFEST})
    digest = 'sha256:' + hashlib.sha256(body.encode()).hexdigest()
    reference = REF + '@' + digest if pin else REF
    output = registry_run('manifest', [response(body=body)], reference=reference)
    assert f'media={MANIFEST}' in output and f'digest={digest}' in output


def test_pinned_manifest_mismatch_releases_body(registry_run):
    output = registry_run('manifest', [response(body='changed')], -4,
                          reference=REF + '@' + DIGEST)
    assert 'digest mismatch' in output and 'body=' not in output


@pytest.mark.parametrize('selected', ['', 'linux', '/arm64', 'linux/', 'linux/arm64/',
    'o' * 64 + '/arm64', 'linux/' + 'a' * 64, 'linux/arm64/' + 'v' * 64])
def test_invalid_platform_has_no_followup_request(registry_run, selected):
    reply = response(body='{"manifests":[]}', headers=f'Content-Type: {INDEX}\r\n')
    assert 'bad platform' in registry_run('resolve', [reply], -5, parameter=selected)


@pytest.mark.parametrize('body', ['{}', '{"manifests":[]}',
    '{"manifests":[{"digest":"x","platform":{"os":"unknown"}}]}',
    '{"manifests":[{"digest":"x","platform":{"os":"linux","architecture":"amd64"}}]}'])
def test_missing_platform_is_reported_without_refetch(registry_run, body):
    output = registry_run('resolve', [response(body=body, headers=f'Content-Type: {INDEX}\r\n')],
                          -3, parameter='linux/arm64/v8')
    assert 'no manifest for platform linux/arm64/v8' in output


def index_reply(digest, architecture='arm64', variant='v8'):
    entry = dict(digest=digest, platform=dict(os='linux', architecture=architecture, variant=variant))
    return response(body=json.dumps({'manifests': [entry]}), headers=f'Content-Type: {INDEX}\r\n')


def test_index_digest_is_validated_before_refetch(registry_run):
    assert 'invalid digest' in registry_run('resolve', [index_reply('not-a-digest')],
                                           -5, parameter='linux/arm64/v8')


@pytest.mark.parametrize('selected', ['linux/arm64', 'linux/arm64/v8', 'default'])
def test_selected_manifest_is_verified(registry_run, selected):
    architecture = 'arm64'
    if selected == 'default':
        architecture = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(platform.machine(), platform.machine())
    output = registry_run('resolve', [index_reply(DIGEST, architecture), response(headers=f'Content-Type: {MANIFEST}\r\n')],
                          parameter=selected)
    assert 'body=payload' in output and f'manifests/{DIGEST}' in output


def test_nested_index_is_refused(registry_run):
    output = registry_run('resolve', [index_reply(DIGEST), response(headers=f'Content-Type: {INDEX}; charset=utf-8\r\n')],
                          -5, parameter='linux/arm64')
    assert 'another index' in output


@pytest.mark.parametrize('body', [None, '{}', '{"tags":[]}', '{"tags":null}'])
def test_empty_tags_are_owned_empty_strings(registry_run, body):
    assert 'tags=\n' in registry_run('tags', [response(body=body)])


def test_tags_skip_non_strings_and_grow_buffer(registry_run):
    tag = 'a' * 700
    body = json.dumps({'tags': [None, 123, {}, 'first', tag]})
    assert f'tags=first\n{tag}\n' in registry_run('tags', [response(body=body)])


@pytest.mark.parametrize('target', ['http://other.test:5000/v2/lab/app/tags/list',
    'http://registry.test:5001/v2/lab/app/tags/list', 'ftp://registry.test/next'])
def test_cross_origin_pagination_is_refused(registry_run, target):
    reply = response(body='{"tags":["one"]}', headers=f'Link: <{target}>; rel="next"\r\n')
    assert 'refusing cross-host' in registry_run('tags', [reply], -5)


@pytest.mark.parametrize('fault,body', [('calloc', '{"tags":[]}'), ('realloc', '{"tags":["one"]}')])
def test_tag_allocation_failure_publishes_no_partial_result(registry_run, fault, body):
    assert 'out of memory' in registry_run('tags', [response(body=body, fault=fault)], -1)


@pytest.mark.parametrize('verb,status', [('put', 201), ('put', 204), ('delete', 200), ('delete', 202), ('delete', 204)])
def test_manifest_mutation_success(registry_run, verb, status):
    registry_run(verb, [response(status)], parameter=MANIFEST, reference=REF + '@' + DIGEST)


def test_delete_resolves_a_tag_before_mutating(registry_run):
    output = registry_run('delete', [response(), response(202)])
    assert f'request=DELETE /v2/lab/app/manifests/{DIGEST}' in output


def test_oversized_media_type_never_sends(registry_run):
    assert 'media type too long' in registry_run('put', [], -5, parameter='a' * 300)


@pytest.mark.parametrize('location', [None, 'ftp://bad/path', 'http://other.test:5000/upload',
                                    'http://registry.test:5001/upload'])
def test_upload_target_validation_precedes_source_read(registry_run, location):
    headers = '' if location is None else f'Location: {location}\r\n'
    output = registry_run('push', [response(404), response(202, headers=headers)],
                          -5, parameter=DIGEST)
    assert 'upload=' not in output


@pytest.mark.parametrize('status,expected', [(401, -2), (404, -3), (500, -5)])
def test_upload_session_status_refusal(registry_run, status, expected):
    registry_run('push', [response(404), response(status)], expected, parameter=DIGEST)


def test_existing_blob_skips_upload(registry_run):
    assert 'upload=' not in registry_run('push', [response()], parameter=DIGEST)


@pytest.mark.parametrize('location', ['/upload', '/upload?state=opaque'])
@pytest.mark.parametrize('status,expected', [(201, 0), (204, 0), (403, -2), (500, -5)])
def test_upload_streams_real_source_and_maps_final_status(registry_run, tmp_path,
                                                        location, status, expected):
    (tmp_path / 'source').write_bytes(b'payload')
    output = registry_run('push', [response(404), response(202, headers=f'Location: {location}\r\n')],
                          expected, parameter=DIGEST, upload={'status': status})
    separator = '&' if '?' in location else '?'
    assert f'upload={location}{separator}digest=sha256%3A' in output


def test_unreadable_upload_source_surfaces_transport_error(registry_run):
    output = registry_run('push', [response(404), response(202, headers='Location: /upload\r\n')],
                          -1, parameter=DIGEST)
    assert 'blob source read failed' in output


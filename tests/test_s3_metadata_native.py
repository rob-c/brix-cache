"""S3 metadata and XML contracts with real signing and an injected HTTP transport."""

import errno
from pathlib import Path
import subprocess
from urllib.parse import quote

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def metadata(server_native_compile):
    boundaries = ['sd_s3_sign', 'sd_s3_sign_ext', 'malloc', 'calloc', 'realloc',
                  'strdup', 'strndup', 'ngx_calloc']
    includes = ['-I' + str(Path(__file__).resolve().parents[1] / 'tests/c')]
    return server_native_compile('s3-metadata', 'tests/c/s3_metadata_native_test.c',
        includes + [f'-Wl,--wrap={name}' for name in boundaries])


def invoke(binary, action, mode='normal', value='', status=200, capacity=8192, argument=1):
    result = subprocess.run([str(binary), action, mode, value, str(status), str(capacity), str(argument)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines())
    return {key: bytes.fromhex(value) if key == 'hex' else int(value) for key, value in fields.items()}


@pytest.mark.parametrize('text,decoded', [('plain', 'plain'), ('&amp;&lt;&gt;&quot;&apos;', '&<>"\''),
    ('&#65;&#x7f;', 'A\x7f'), ('&#x80;&#x7ff;', '\x80\u07ff'),
    ('&#x800;&#xFFFF;', '\u0800\uffff'), ('&#x10000;&#x10ffff;', '\U00010000\U0010ffff'),
    ('&unknown;', '&unknown;'), ('unterminated&', 'unterminated&')])
def test_xml_decoding_matches_independent_unicode_values(metadata, text, decoded):
    result = invoke(metadata, 'xml', value=text)
    assert result['rc'] == len(decoded.encode()) and result['hex'] == decoded.encode()


@pytest.mark.parametrize('text', ['&#-1;', '&#x110000;', '&#99999999999999999999999;', '&#xg;', '&#12oops;'])
def test_malformed_numeric_entities_are_rejected(metadata, text):
    assert invoke(metadata, 'xml', value=text)['rc'] == -1


@pytest.mark.parametrize('text', ['a', '&amp;', '&#x80;', '&#x800;', '&#x10000;'])
@pytest.mark.parametrize('capacity', [0, 1])
def test_xml_capacity_refusal_keeps_room_for_the_terminator(metadata, text, capacity):
    assert invoke(metadata, 'xml', value=text, capacity=capacity)['rc'] == -1


@pytest.mark.parametrize('prefix', ['dir/space and+plus', 'unicode/λ', ''])
@pytest.mark.parametrize('token', ['', 'a+/='])
@pytest.mark.parametrize('limit', [1, 1000])
def test_canonical_queries_encode_and_sort_parameters(metadata, prefix, token, limit):
    result = invoke(metadata, 'query', token, prefix, argument=limit)
    expected = (f'continuation-token={quote(token, safe="")}&' if token else '')
    expected += f'delimiter=%2F&list-type=2&max-keys={limit}&prefix={quote(prefix, safe="")}'
    assert result['hex'] == expected.encode()


@pytest.mark.parametrize('mode,prefix,limit,capacity,error', [
    ('', '', 0, 8192, errno.EINVAL), ('', '', 1001, 8192, errno.EINVAL),
    ('', 'x' * 3072, 1, 8192, errno.ENAMETOOLONG),
    ('x' * 3072, '', 1, 8192, errno.ENAMETOOLONG), ('', 'abc', 1, 5, errno.ENAMETOOLONG)])
def test_query_bounds_fail_before_any_request(metadata, mode, prefix, limit, capacity, error):
    result = invoke(metadata, 'query', mode, prefix, argument=limit, capacity=capacity)
    assert result['rc'] == -1 and result['errno'] == error and result['requests'] == 0


@pytest.mark.parametrize('body,truncated,token', [('', 0, b''), ('<IsTruncated>false</IsTruncated>', 0, b''),
    ('<IsTruncated>true</IsTruncated><NextContinuationToken>abcdef</NextContinuationToken>', 1, b'abc'),
    ('<IsTruncated>true</IsTruncated><NextContinuationToken>unfinished', 1, b'')])
def test_page_metadata_respects_complete_tags_and_capacity(metadata, body, truncated, token):
    result = invoke(metadata, 'page', value=body, capacity=4)
    assert result['truncated'] == truncated and result.get('hex', b'') == token


@pytest.mark.parametrize('action', ['get', 'checksum', 'list', 'set', 'copy', 'restore'])
@pytest.mark.parametrize('mode', ['transport', 'sign'])
def test_transport_and_signing_failures_do_not_claim_success(metadata, action, mode):
    result = invoke(metadata, action, mode, '/bucket/source')
    assert result['rc'] == -1 and result['freed'] == 0
    assert result['requests'] == int(mode == 'transport')


@pytest.mark.parametrize('action', ['get', 'checksum', 'list', 'set', 'copy'])
@pytest.mark.parametrize('status,error', [(403, errno.EACCES), (404, errno.ENOENT), (412, errno.ECANCELED), (503, errno.EIO)])
def test_http_error_status_releases_the_response(metadata, action, status, error):
    result = invoke(metadata, action, value='/bucket/source', status=status)
    assert result['rc'] == -1 and result['errno'] == error
    assert result['requests'] == result['freed'] == 1


@pytest.mark.parametrize('action', ['get', 'checksum'])
@pytest.mark.parametrize('mode', ['null-file', 'null-name', 'null-out', 'null-buffer'])
def test_invalid_read_arguments_never_issue_http(metadata, action, mode):
    result = invoke(metadata, action, mode)
    assert result['rc'] == -1 and result['requests'] == 0


@pytest.mark.parametrize('mode', ['normal', 'absent'])
def test_metadata_value_and_absence_are_distinct(metadata, mode):
    result = invoke(metadata, 'get', mode)
    assert result['rc'] == (0 if mode == 'absent' else 4)
    assert result.get('hex', b'') == (b'' if mode == 'absent' else b'blue')


@pytest.mark.parametrize('mode', ['no-enumerator', 'no-raw'])
def test_metadata_enumeration_never_invents_headers(metadata, mode):
    result = invoke(metadata, 'list', mode)
    assert result['rc'] == -1 and result['errno'] == errno.ENOTSUP


def test_metadata_enumeration_filters_reserved_and_malformed_names(metadata):
    raw = 'x-amz-meta-a: one\r\nX-Amz-Meta-B: two\nx-amz-meta-xrd-unixattr: hidden\nignore: value\nx-amz-meta-: bad\n'
    result = invoke(metadata, 'list', value=raw)
    assert result['hex'] == b'user.a\0user.B\0'
    assert invoke(metadata, 'list', 'probe', raw)['rc'] == len(result['hex'])
    assert invoke(metadata, 'list', value=raw, capacity=1)['errno'] == errno.ERANGE


@pytest.mark.parametrize('mode,value', [('null-name', ''), ('null-value', ''), ('too-many', ''),
    ('long-name', 'x' * 160), ('long-name', 'x' * 150)])
def test_invalid_metadata_updates_do_not_issue_put(metadata, mode, value):
    result = invoke(metadata, 'set', mode, value)
    assert result['rc'] == -1 and result['requests'] == 0


def test_metadata_update_uses_signed_copy_replace(metadata):
    result = invoke(metadata, 'set')
    assert result['rc'] == 0 and result['requests'] == result['freed'] == 1


@pytest.mark.parametrize('action', ['set', 'copy', 'restore', 'set-unix'])
def test_handle_allocation_failure_never_contacts_origin(metadata, action):
    result = invoke(metadata, action, 'allocation', '/bucket/source')
    assert result['rc'] == -1 and result['requests'] == 0


@pytest.mark.parametrize('action,mode', [('copy', 'null-source'), ('copy', 'null-params'),
    ('restore', 'null-params'), ('set-unix', 'null-out'), ('get-unix', 'null-out')])
def test_missing_copy_restore_and_advisory_arguments_are_refused(metadata, action, mode):
    result = invoke(metadata, action, mode)
    assert result['rc'] == -1 and result['requests'] == 0


def test_unknown_advisory_fields_do_not_invent_posix_metadata(metadata):
    assert invoke(metadata, 'get-unix', 'unknown-fields', 'v9 future=value')['rc'] == 1

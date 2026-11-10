"""Batch delete signs one sealed XML request and attributes every origin error."""

import base64
import errno
import hashlib
import re
import subprocess
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def batch(server_native_compile):
    binary = server_native_compile('s3-batch', 'tests/c/s3_batch_native_test.c',
        ['-Wl,--wrap=' + name for name in
         ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc')])
    def run(keys=('first', 'second'), body='<DeleteResult/>', status=200,
            mode='normal', token='none'):
        process = subprocess.run([str(binary), mode, str(status), body, token, *keys],
                                  capture_output=True, text=True, timeout=10)
        assert process.returncode == 0, process.stdout + process.stderr
        result = re.search(r'RESULT rc=(-?\d+) errno=(\d+) done=(\d+) calls=(\d+) freed=(\d+) errors=(.*)',
                           process.stdout)
        assert result, process.stdout
        fields = dict(zip(('rc', 'errno', 'done', 'calls', 'freed'), map(int, result.groups()[:5])))
        fields['errors'] = [int(value) for value in result[6].split(',') if value]
        return fields, process.stdout
    return run


@pytest.mark.parametrize('token', ['none', 'session-credential'])
@pytest.mark.parametrize('keys', [('first', 'second'), ('a&b', '<xml>', 'quote"', "apostrophe'"),
                                tuple(f'key-{i}' for i in range(1000))])
def test_xml_escaping_digest_and_session_token_are_signed(batch, token, keys):
    result, output = batch(keys=keys, token=token)
    assert result['rc'] == 0 and result['done'] == len(keys)
    assert result['calls'] == result['freed'] == 1 and result['errors'] == [0] * len(keys)
    body = output.split('BODY ', 1)[1].split('\nRESULT', 1)[0].encode()
    xml = ET.fromstring(body)
    assert [node.text for node in xml.findall('.//{*}Key')] == list(keys)
    digest = base64.b64encode(hashlib.md5(body).digest()).decode()
    assert re.search(r'^content-md5: (.+)$', output, re.I | re.M)[1].strip() == digest
    signed = re.search(r'SignedHeaders=([^,\s]+)', output)[1].split(';')
    assert 'content-md5' in signed
    assert ('x-amz-security-token' in signed) == (token != 'none')


@pytest.mark.parametrize('key', ['second', 'a&<>"\'b', 'a&unknown;b'])
@pytest.mark.parametrize('code,expected', [('AccessDenied', errno.EACCES), ('NoSuchKey', errno.ENOENT),
    ('NoSuchBucket', errno.ENOENT), ('InternalError', errno.EIO), ('accessdenied', errno.EIO)])
def test_per_key_errors_remain_associated_with_exact_key(batch, key, code, expected):
    body = f'<DeleteResult><Error><Key>{escape(key)}</Key><Code>{code}</Code></Error></DeleteResult>'
    result, _ = batch(keys=('first', key), body=body)
    assert result['rc'] == 0 and result['done'] == 2 and result['errors'] == [0, expected]


@pytest.mark.parametrize('body', ['<Error>', '<Error><Key>first</Key></Error>',
    '<Error><Code>AccessDenied</Code></Error>', '<Error><Key>first<Code>X</Code></Error>',
    '<Error><Key>first</Key><Code>X</Error>',
    '<Error><Key>foreign</Key><Code>AccessDenied</Code></Error>',
    '<Error><Key>first</Key><Code>X</Code></Error><Error>'])
def test_malformed_or_unattributable_verdict_is_batch_failure(batch, body):
    result, _ = batch(body=body)
    assert result['rc'] == -1 and result['errno'] == errno.EIO and result['done'] == 0
    assert result['calls'] == result['freed'] == 1


@pytest.mark.parametrize('status,expected', [(-1, errno.EIO), (-2, errno.EACCES),
    (403, errno.EACCES), (404, errno.ENOENT), (500, errno.EIO)])
def test_transport_and_http_failures_do_not_claim_attempted_keys(batch, status, expected):
    result, _ = batch(status=status)
    assert result['rc'] == -1 and result['errno'] == expected and result['done'] == 0
    assert result['errors'] == [777, 777] and result['freed'] == int(status >= 0)


@pytest.mark.parametrize('mode', ['malloc', 'calloc'])
def test_allocation_failure_never_contacts_origin(batch, mode):
    result, _ = batch(mode=mode)
    assert result['rc'] == -1 and result['errno'] == errno.ENOMEM and result['calls'] == 0
    assert result['errors'] == [777, 777] and result['done'] == 0


@pytest.mark.parametrize('mode,body', [('normal', ''), ('null-body', 'ignored')])
def test_quiet_response_without_errors_is_success(batch, mode, body):
    result, _ = batch(mode=mode, body=body)
    assert result['rc'] == 0 and result['done'] == 2 and result['errors'] == [0, 0]


def test_empty_batch_does_not_contact_origin(batch):
    result, _ = batch(mode='zero')
    assert result['rc'] == result['calls'] == result['freed'] == result['done'] == 0

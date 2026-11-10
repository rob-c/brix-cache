"""S3 client adapters preserve identities, error classes and driver ownership."""

import errno
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU driver-call wrapping')


@pytest.fixture(scope='module')
def adapter(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    seams = ['calloc', 'brix_cred_acquire'] + ['sd_s3_' + name for name in
        ('open_read', 'open_write', 'size', 'pread', 'pwrite', 'write_size', 'commit', 'abort', 'close')]
    return compile_client_contract(root, tmp_path_factory.mktemp('client-s3-adapter'),
                                   'tests/c/client_s3_adapter_native_test.c', seams)


def invoke(binary, action='read', fault='normal', error=0, url='s3s://origin.invalid:9443/bucket/object'):
    result = subprocess.run([str(binary), action, fault, str(error), url],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return decode_result(result.stdout)


def decode_result(output):
    """Keep ordered driver events separate from numeric outcome fields."""
    fields, events = {}, []
    for line in output.splitlines():
        key, value = line.split('=', 1)
        if key == 'event':
            events.append(value)
        else:
            fields[key] = int(value)
    return fields, events


@pytest.mark.parametrize('action', ['read', 'write', 'read-stat', 'write-stat', 'stat', 'commit', 'abort', 'sync'])
def test_driver_ownership_closes_exactly_once_after_success(adapter, action):
    fields, events = invoke(adapter, action)
    assert fields == {'rc': 0, 'error': 0}
    assert events.count('close') == 1 and events[-1] == 'close'
    if action == 'read-stat':
        assert events.count('size') == 1


@pytest.mark.parametrize('fault', ['store', 'partial', 'credential-error'])
@pytest.mark.parametrize('action', ['read', 'write'])
def test_credential_pair_is_selected_atomically(adapter, action, fault):
    fields, events = invoke(adapter, action, fault)
    assert fields['rc'] == 0 and events[0] == 'credentials' and events[-1] == 'close'


@pytest.mark.parametrize('action,fault', [('read', 'open-read'), ('stat', 'open-read'),
    ('write', 'open-write'), ('read', 'read'), ('write', 'write'), ('commit', 'commit'),
    ('read-stat', 'size'), ('stat', 'size')])
@pytest.mark.parametrize('error', [errno.EACCES, errno.EINVAL, errno.ENOENT, errno.ENOSPC])
def test_driver_failure_preserves_error_and_releases_only_acquired_handle(adapter, action, fault, error):
    fields, events = invoke(adapter, action, fault, error)
    assert fields['rc'] == -1 and fields['error'] != 0
    assert events.count('close') == (0 if fault.startswith('open-') else 1)


@pytest.mark.parametrize('action', ['read', 'write', 'stat'])
@pytest.mark.parametrize('url', ['https://origin.invalid/object', 'relative/path', 's3://'])
def test_non_s3_or_invalid_endpoint_never_reaches_driver(adapter, action, url):
    fields, events = invoke(adapter, action, url=url)
    assert fields['rc'] == -1 and events == []


@pytest.mark.parametrize('action', ['read', 'write', 'stat'])
def test_handle_allocation_failure_cannot_issue_an_origin_request(adapter, action):
    fields, events = invoke(adapter, action, 'oom')
    assert fields['rc'] == -1 and events == []


def test_unsupported_truncate_never_mutates_object(adapter):
    fields, events = invoke(adapter, 'truncate')
    assert fields['rc'] == -1 and events == ['open-read', 'close']

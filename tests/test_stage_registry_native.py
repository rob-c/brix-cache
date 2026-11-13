"""Durable stage requests preserve identities, expiry bounds and locks through I/O refusal."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def registry_binary(server_native_compile):
    wrappers = ('srq_lock', 'srq_unlock', 'srq_hdr_read', 'srq_hdr_write',
                'srq_rec_read', 'srq_rec_write', 'srq_alloc_slot')
    return server_native_compile('stage-registry', 'tests/c/stage_registry_native_test.c',
                                tuple('-Wl,--wrap=' + name for name in wrappers))


@pytest.mark.parametrize('operation,boundary,expected', [
    ('lifecycle', 'none', 0), ('invalid', 'none', 0),
    *[(operation, 'lock', -1) for operation in ('mint', 'get', 'find', 'list', 'status', 'delete', 'add')],
    ('reap', 'lock', 0),
    *[(operation, boundary, -1) for operation in ('mint', 'add')
      for boundary in ('header-read', 'header-write')],
    ('add', 'slot', -1), ('add', 'record-write', -1),
    ('get', 'record-read', -5), ('status', 'record-read', -5),
    ('delete', 'record-read', 0), ('reap', 'record-read', 0),
    ('find', 'record-read', -1), ('list', 'record-read', -1),
    ('status', 'record-write', -1), ('delete', 'record-write', -1),
    ('reap', 'record-write', 0),
])
def test_stage_request_journal_ownership(registry_binary, tmp_path, operation, boundary, expected):
    result = subprocess.run([str(registry_binary), str(tmp_path), operation, boundary, str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'stage registry ownership verified'

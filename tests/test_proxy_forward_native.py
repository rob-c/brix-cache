"""Complete proxy dispatch preserves wire handles, rewrite/audit paths and ownership."""

from pathlib import Path
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def forward_binary(server_native_compile):
    wrappers = ['brix_send_error', 'brix_proxy_abort', 'brix_proxy_cleanup',
                'ngx_handle_read_event', 'ngx_alloc']
    flags = ['-Wl,--wrap=' + name for name in wrappers]
    flags += ['-I' + str(Path(__file__).resolve().parent / 'c')]
    return server_native_compile('proxy-forward', 'tests/c/proxy_forward_native_test.c', flags)


def run_forward(binary, mode, operation):
    result = subprocess.run([str(binary), mode, operation], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['audit', 'strip', 'no-audit', 'no-conf'])
@pytest.mark.parametrize('operation', ['open', 'rm', 'rmdir', 'mkdir', 'chmod',
                                      'mv', 'truncate', 'prepare'])
def test_forwarded_paths_and_audit_fields(forward_binary, mode, operation):
    run_forward(forward_binary, mode, operation)


@pytest.mark.parametrize('mode', ['handle', 'invalid-handle'])
@pytest.mark.parametrize('operation', ['read', 'write', 'close', 'sync', 'stat',
                                      'truncate', 'fattr', 'clone'])
def test_opaque_handle_translation_and_refusal(forward_binary, mode, operation):
    run_forward(forward_binary, mode, operation)


@pytest.mark.parametrize('mode', ['allocation', 'retry-allocation', 'send-error',
                                 'arm-error', 'park'])
def test_forwarding_failures_release_or_retain_the_right_owner(forward_binary, mode):
    run_forward(forward_binary, mode, 'fault')


@pytest.mark.parametrize('case', ['length', 'negative', 'separator', 'source',
                                 'destination', 'no-space', 'allocation-2',
                                 'allocation-3', 'allocation-4'])
def test_rename_refuses_invalid_or_incomplete_rewrites(forward_binary, case):
    run_forward(forward_binary, 'rename-refusal', case)


@pytest.mark.parametrize('case', ['long', 'spaces', 'autosplit'])
def test_rename_wire_length_is_independent_of_audit_truncation(forward_binary, case):
    run_forward(forward_binary, 'rename-boundary', case)

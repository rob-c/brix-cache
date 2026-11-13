"""Forwarding rewrites opaque handles and queues each unopened vector slot once."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def proxy_handles(server_native_compile):
    return server_native_compile('proxy-handles', 'tests/c/proxy_handle_translate_native_test.c',
                                 ['-Wl,--wrap=brix_proxy_lazy_open', '-Wl,--wrap=brix_send_error'])


def invoke(binary, operation, mode, opcode):
    result = subprocess.run([str(binary), operation, mode, str(opcode)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['bound', 'free', 'invalid', 'lazy-error'])
@pytest.mark.parametrize('opcode', [3013, 3030, 3019])
def test_scalar_translation_defers_only_unopened_reads(proxy_handles, mode, opcode):
    invoke(proxy_handles, 'scalar', mode, opcode)


@pytest.mark.parametrize('mode', ['bound', 'free', 'invalid', 'lazy-error'])
@pytest.mark.parametrize('opcode', [3025, 3031])
def test_vector_translation_deduplicates_lazy_handles(proxy_handles, mode, opcode):
    invoke(proxy_handles, 'vector', mode, opcode)


@pytest.mark.parametrize('mode', ['bound', 'invalid-sub', 'invalid-vector', 'clamp'])
def test_checkpoint_nested_writev_validates_every_handle(proxy_handles, mode):
    invoke(proxy_handles, 'checkpoint', mode, 3031)


def test_checkpoint_scalar_subrequest_preserves_payload(proxy_handles):
    invoke(proxy_handles, 'checkpoint', 'bound', 3019)

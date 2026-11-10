"""The io_uring emergency switch shares state and preserves it across reload."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def uring_admin_binary(server_native_compile):
    return server_native_compile('uring-admin', 'tests/c/uring_admin_native_test.c',
        ['-Wl,--wrap=ngx_shared_memory_add', '-Wl,--wrap=ngx_slab_alloc'])


@pytest.mark.parametrize('mode', ['maint', 'panic', 'reload', 'cross-worker', 'zone', 'slab'])
def test_runtime_killswitch_contract(uring_admin_binary, tmp_path, mode):
    result = subprocess.run([str(uring_admin_binary), mode, str(tmp_path / 'panic')],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr

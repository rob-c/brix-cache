"""Default spool setup preserves ownership refusals and PrivateTmp diagnostics."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def stage_config(server_native_compile):
    return server_native_compile('default-stage', 'tests/c/default_stage_native_test.c',
        ['-Wl,--wrap=' + name for name in ('geteuid', 'brix_imp_worker_runtime_ids',
        'chown', 'brix_mkdir_recursive', 'mkdir', 'stat64', 'access', 'ngx_pnalloc',
        'fopen64', 'ngx_conf_log_error')])


def invoke(binary, tmp_path, operation, mode, first, second):
    result = subprocess.run([str(binary), operation, mode, str(tmp_path), first,
        str(second)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('mode,uid', [('normal', 1000), ('exists', 1000),
    ('root-new', 5000), ('root-owned', 5000)])
@pytest.mark.parametrize('backend', ['https://host.example/path?q=1', 's3://bucket/' + 'a' * 200])
def test_default_store_has_sanitized_bounded_identity_scoped_name(stage_config, tmp_path, mode, uid, backend):
    output = invoke(stage_config, tmp_path, 'default', mode, backend, 1)
    safe = ''.join(c if c.isalnum() or c in '._-' else '_' for c in backend[:160])
    assert f'store=posix:/tmp/staging/{safe}.{uid}\n' in output
    assert (tmp_path / 'leaf').stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize('mode', ['base', 'mkdir', 'stat', 'not-directory',
    'root-chown', 'foreign', 'access', 'allocation'])
def test_provisioning_or_ownership_failure_leaves_staging_off(stage_config, tmp_path, mode):
    output = invoke(stage_config, tmp_path, 'default', mode, 'https://host/path', 0)
    assert 'store=' not in output


@pytest.mark.parametrize('stage,cache,count', [('', '', 0), ('posix:/var/stage', 'posix:/var/cache', 0),
    ('posix:/tmp/stage', '', 4), ('', 'posix:/tmp/cache', 4),
    ('posix:/tmp/stage', 'posix:/tmp/cache', 5)])
def test_private_tmp_warning_identifies_each_affected_store(stage_config, tmp_path, stage, cache, count):
    output = invoke(stage_config, tmp_path, 'warn', 'private', stage, cache)
    assert f'warnings={count}\n' in output
    if count:
        assert 'PrivateTmp DETECTED' in output


@pytest.mark.parametrize('mode', ['ordinary', 'mount-open'])
def test_no_private_mount_does_not_emit_false_warning(stage_config, tmp_path, mode):
    assert invoke(stage_config, tmp_path, 'warn', mode, 'posix:/tmp/stage', '') == 'warnings=0\n'

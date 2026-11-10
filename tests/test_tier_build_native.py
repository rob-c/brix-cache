"""Remote tiers retain authentication and transport policy through real factories."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def tier_build_binary(server_native_compile):
    wrappers = ('brix_sd_xroot_create_origin', 'brix_sd_http_create',
                'brix_sd_remote_create', 'brix_sd_gsiftp_create',
                'malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc')
    return server_native_compile('tier-build', 'tests/c/tier_build_native_test.c',
                                  ['-Wl,--wrap=' + name for name in wrappers])


@pytest.fixture
def tier_run(tier_build_binary, tmp_path):
    def run(driver, credentials='proxy', path='/bucket', fault='', skip=0, expected=True):
        result = subprocess.run([str(tier_build_binary), driver, credentials, str(tmp_path),
            path, fault, str(skip), str(int(expected))], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('driver', ['xroot', 'http', 's3', 'gsiftp'])
@pytest.mark.parametrize('credentials', ['proxy', 'cert', 'empty', 'anonymous'])
def test_real_tier_factory_builds_with_explicit_credentials(tier_run, tmp_path, driver, credentials):
    output = tier_run(driver, credentials)
    assert '127.0.0.1:443' in output  # net-literal-allow: canonical fixture's resolved endpoint value
    if credentials in ('proxy', 'cert'):
        assert_auth_fields(output, driver, credentials, tmp_path)
    else:
        assert 'fixture-token' not in output and 'fixture-secret' not in output


def assert_auth_fields(output, driver, credentials, ca):
    if driver == 's3':
        assert 'ACCESS fixture-access\nSECRET fixture-secret\nREGION fixture-region\n' in output
        return
    assert 'CA ' + str(ca) in output
    if driver == 'http':
        assert 'TOKEN fixture-token' in output
        return
    expected = 'fixture-proxy.pem' if credentials == 'proxy' else 'fixture-cert.pem'
    assert 'PROXY ' + expected in output
    if driver == 'xroot':
        assert_root_key(output, credentials)


def assert_root_key(output, credentials):
    key = '<none>' if credentials == 'proxy' else 'fixture-key.pem'
    assert 'KEY ' + key in output


@pytest.mark.parametrize('driver,fault,skip', [
    ('xroot', 'calloc', 0), ('xroot', 'calloc', 1), ('xroot', 'calloc', 2),
    ('http', 'calloc', 0), ('http', 'calloc', 1),
    ('s3', 'calloc', 0), ('s3', 'malloc', 0),
    ('gsiftp', 'calloc', 0), ('gsiftp', 'calloc', 1),
])
def test_factory_allocation_failure_cannot_publish_partial_tier(tier_run, driver, fault, skip):
    tier_run(driver, fault=fault, skip=skip, expected=False)


@pytest.mark.parametrize('driver', ['xroot', 'http', 'gsiftp'])
@pytest.mark.parametrize('fault', ['host', 'port'])
def test_invalid_remote_endpoint_cannot_activate(tier_run, driver, fault):
    tier_run(driver, fault=fault, expected=False)


@pytest.mark.parametrize('driver', ['xroot', 'http', 's3', 'gsiftp'])
@pytest.mark.parametrize('fault', ['null', 'unconfigured'])
def test_absent_tier_never_calls_a_factory(tier_run, driver, fault):
    assert tier_run(driver, fault=fault, expected=False) == ''


@pytest.mark.parametrize('path', ['bucket', '/bucket'])
def test_s3_bucket_and_nearline_policy_survive_composition(tier_run, path):
    output = tier_run('s3', path=path)
    assert 'bucket=bucket nearline=1' in output


def test_root_page_verification_is_required(tier_run):
    assert 'nearline=1 verify=2' in tier_run('xroot')


def test_ftp_empty_base_is_root_and_stream_count_is_preserved(tier_run):
    output = tier_run('gsiftp', path='')
    assert 'gsi=1 path=/ streams=3' in output


@pytest.mark.parametrize('path', ['/safe/../escape', '/safe/./escape'])
def test_ftp_unsafe_base_cannot_activate(tier_run, path):
    tier_run('gsiftp', path=path, expected=False)

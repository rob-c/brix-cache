"""Conformance authority, resource ceilings and fixture selectors fail closed."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping and object instrumentation')


@pytest.fixture(scope='module')
def conform_options(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('conform-options'); binary = output / 'xrd'
    plan = client_make(root / 'client', '-n', 'xrd', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    entry = output / 'xrd-entry.o'
    renamed = client_run(root / 'client', ['objcopy', '--redefine-sym',
        'main=brix_test_xrd_main', 'apps/diag/xrd.o', str(entry)],
        cwd=root / 'client', capture_output=True, text=True, timeout=30)
    assert renamed.returncode == 0, renamed.stdout + renamed.stderr
    index = command.index('apps/diag/xrd.o')
    command[index:index + 1] = [str(entry), str(root / 'tests/c/conform_options_native_test.c')]
    command += ['-I.', '-Wl,--wrap=RAND_bytes']
    linked = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert linked.returncode == 0, linked.stdout + linked.stderr
    return binary


def invoke(binary, *options, shape='accept', random_failure=False):
    env = dict(os.environ)
    env.pop('BRIX_CONFORM_RNG_FAIL', None)
    if random_failure:
        env['BRIX_CONFORM_RNG_FAIL'] = '1'
    result = subprocess.run([str(binary), 'conform', shape, 'root://fixture.invalid/data', *options],
                            capture_output=True, text=True, env=env, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return dict(line.split('=', 1) for line in result.stdout.splitlines())


@pytest.mark.parametrize('shape,wall,requests,interval', [('accept', 120, 2000, 0),
    ('full', 3600, 50000, 0), ('watch', 120, 1000, 300)])
def test_default_run_has_finite_resource_limits_and_no_mutation_authority(conform_options, shape, wall, requests, interval):
    state = invoke(conform_options, shape=shape)
    assert state['rc'] == '0' and state['wall'] == str(wall) and state['requests'] == str(requests)
    assert state['interval'] == str(interval) and state['bytes'] == '268435456'
    assert state['mutate'] == state['disrupt'] == '0' and state['key'] == 'a5' * 16


@pytest.mark.parametrize('flag,field', [('--wall-seconds', 'wall'), ('--request-limit', 'requests'),
    ('--byte-limit', 'bytes'), ('--http-request-line-limit', 'line-limit')])
@pytest.mark.parametrize('value', ['16', '1000', '4294967295'])
def test_explicit_ceilings_keep_exact_unsigned_value(conform_options, flag, field, value):
    state = invoke(conform_options, flag, value)
    assert state['rc'] == '0' and state[field] == value


@pytest.mark.parametrize('flag', ['--wall-seconds', '--request-limit', '--byte-limit',
    '--http-request-line-limit', '--watch-interval-seconds', '--watch-cycles'])
@pytest.mark.parametrize('value', ['', '0', '-1', '4294967296', '17junk', '9' * 40])
def test_bad_ceiling_never_becomes_an_unlimited_run(conform_options, flag, value):
    assert invoke(conform_options, flag, value, shape='watch')['rc'] == '4'


@pytest.mark.parametrize('options', [('--allow-mutate',), ('--allow-disrupt',),
    ('--allow-disrupt', '--confirm-target', 'root://different.invalid/data'),
    ('--quota-target', 'root://quota.invalid'), ('--capacity-target', 'root://capacity.invalid'),
    ('--webdav-outside-fixture', 'http://outside.invalid'), ('--move-fixture', 'root://outside.invalid'),
    ('--capture', '/tmp/not-created-by-parser'), ('--watch-cycles', '2'),
    ('--watch-interval-seconds', '2'), ('--adv-fixture', 'authority-bypass')])
def test_incomplete_or_conflicting_authority_is_refused(conform_options, options):
    assert invoke(conform_options, *options)['rc'] == '4'


def test_explicit_mutation_and_disruption_authority_is_bound_to_target(conform_options):
    state = invoke(conform_options, '--allow-mutate', '--scratch', '/fixture', '--allow-disrupt',
                   '--confirm-target', 'root://fixture.invalid/data')
    assert state['rc'] == '0' and state['mutate'] == state['disrupt'] == '1'


@pytest.mark.parametrize('key', ['', '00' * 15, '00' * 17, 'z' * 32])
def test_bad_reproducibility_key_is_not_replaced_by_random_key(conform_options, key):
    assert invoke(conform_options, '--run-key', key)['rc'] == '4'


def test_rng_failure_prevents_run_without_a_supplied_key(conform_options):
    assert invoke(conform_options, random_failure=True)['rc'] == '3'
    state = invoke(conform_options, '--run-key', 'AB' * 16, random_failure=True)
    assert state['rc'] == '0' and state['key'] == 'ab' * 16


@pytest.mark.parametrize('flag,values', [
    ('--readonly-fixture', ['webdav', 's3', 'oci', 'gridftp']),
    ('--auth-fixture', ['gsi', 'ztn', 'krb5', 'sss', 'unix', 'host', 'pwd']),
    ('--tls-cleartext-fixture', ['login', 'data', 'gpf', 'session', 'tpc']),
    ('--denied-fixture', ['root', 'http', 's3']), ('--mutation-fixture', ['root', 'http', 's3']),
    ('--open-fixture', ['readonly', 'staged-nowait', 'idle']), ('--locate-fixture', ['refresh', 'slow']),
    ('--token-fixture', ['audience', 'expired', 'not-yet-valid', 'issuer'])])
def test_distinct_fixture_names_remain_bounded_and_duplicates_are_refused(conform_options, flag, values):
    options = [item for value in values for item in (flag, value + '=root://fixture.invalid')]
    state = invoke(conform_options, *options)
    field = flag.removeprefix('--').split('-')[0]
    assert state['rc'] == '0' and state[field] == str(len(values))
    assert invoke(conform_options, *options, flag, values[0] + '=root://other.invalid')['rc'] == '4'


@pytest.mark.parametrize('flag', ['--readonly-fixture', '--auth-fixture', '--tls-cleartext-fixture',
    '--denied-fixture', '--mutation-fixture', '--open-fixture', '--locate-fixture', '--token-fixture'])
@pytest.mark.parametrize('value', ['missing-equals', '=url', 'root=', 'unknown=url', 'x' * 100 + '=url'])
def test_malformed_named_fixture_cannot_select_another_policy(conform_options, flag, value):
    assert invoke(conform_options, flag, value)['rc'] == '4'


@pytest.mark.parametrize('flag', ['--profile', '--reference', '--budget', '--fail-on', '--scratch',
    '--families', '--exclude', '--only', '--verify-negative', '--out', '--baseline', '--run-key',
    '--confirm-target', '--adv-observer', '--adv-fixture', '--error-fixture', '--also',
    '--quota-target', '--capacity-target', '--webdav-outside-fixture', '--move-fixture',
    '--cache-fixture', '--tpc-fixture', '--readonly-fixture', '--auth-fixture',
    '--tls-cleartext-fixture', '--denied-fixture', '--mutation-fixture', '--open-fixture',
    '--locate-fixture', '--token-fixture'])
def test_missing_option_value_is_refused(conform_options, flag):
    assert invoke(conform_options, flag)['rc'] == '4'


@pytest.mark.parametrize('flag', ['--profile', '--reference', '--budget', '--fail-on',
                                 '--cache-fixture', '--tpc-fixture', '--adv-fixture'])
def test_unknown_policy_name_cannot_silently_select_a_default(conform_options, flag):
    assert invoke(conform_options, flag, 'unknown')['rc'] == '4'


def test_profile_repetition_is_idempotent(conform_options):
    state = invoke(conform_options, '--profile', 'data', '--profile', 'cache', '--profile', 'data')
    assert state['rc'] == '0' and state['profile'] == 'data,cache'


def test_extra_endpoint_limit_refuses_ninth_target(conform_options):
    options = ['--also', 'root://fixture.invalid'] * 8
    assert invoke(conform_options, *options)['also'] == '8'
    assert invoke(conform_options, *options, '--also', 'root://other.invalid')['rc'] == '4'

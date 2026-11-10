"""Umbrella CLI diagnostics preserve identity intent and endpoint ownership."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping and object instrumentation')


@pytest.fixture(scope='module')
def cli_posture(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('cli-posture'); binary = output / 'xrd'
    plan = client_make(root / 'client', '-n', 'xrd', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    seams = ('brix_cred_autorefresh', 'brix_cred_diagnose', 'brix_connect', 'brix_close',
        'brix_stat', 'brix_query', 'brix_tls_info', 'brix_token_discover',
        'brix_token_explain', 'brix_proxy_default_path', 'brix_gsi_cert_explain')
    command += [str(root / 'tests/c/cli_posture_native_test.c'), '-I.',
                *['-Wl,--wrap=' + name for name in seams]]
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    (output / 'xrdrc').write_text('')
    (output / 'proxy').write_text('fixture provider owns interpretation')
    return binary


def invoke(binary, *arguments, mode='normal', flags=0):
    environment = dict(os.environ, BRIX_POSTURE_MODE=mode, BRIX_POSTURE_FLAGS=str(flags),
        BRIX_POSTURE_PROXY=str(binary.parent / ('proxy' if mode == 'authenticated' else 'no-proxy')),
        XRDRC=str(binary.parent / 'xrdrc'), OIDC_ACCOUNT='environment-account')
    result = subprocess.run([str(binary), *arguments], env=environment,
                            capture_output=True, text=True, timeout=10)
    events = [line.removeprefix('event=') for line in result.stderr.splitlines() if line.startswith('event=')]
    return result, events


@pytest.mark.parametrize('options,expected', [([], '1,environment-account,0'),
    (['--read'], '0,environment-account,0'), (['--verbose'], '1,environment-account,1'),
    (['--oidc-account', 'selected', '--read', '-v'], '0,selected,1')])
def test_login_carries_explicit_read_write_intent_to_provider(cli_posture, options, expected):
    result, events = invoke(cli_posture, 'login', *options)
    assert result.returncode == 0 and events == ['refresh', 'diagnose']
    assert f'provider={expected}' in result.stdout and '2 credential(s)' in result.stdout


@pytest.mark.parametrize('options', [['--oidc-account'], ['--unknown'], ['unexpected']])
def test_bad_login_option_never_acquires_credentials(cli_posture, options):
    result, events = invoke(cli_posture, 'login', *options)
    assert result.returncode == 50 and events == []


@pytest.mark.parametrize('mode,success,rc', [('normal', 4, 0), ('partial', 2, 0), ('stat-error', 0, 1)])
def test_ping_counts_actual_successful_probes_and_closes_once(cli_posture, mode, success, rc):
    result, events = invoke(cli_posture, 'ping', '-c', '4', 'root://origin.invalid', mode=mode)
    assert result.returncode == rc and events == ['connect', *['stat'] * 4, 'close']
    expected = f'{success}/4 ok' if success else '4 probes, 0 successful'
    assert expected in result.stdout


@pytest.mark.parametrize('arguments', [['ping'], ['ping', '-c', '0', 'root://origin.invalid'],
    ['ping', '-c', '-1', 'root://origin.invalid'], ['whoami'], ['caps'],
    ['whoami', '--bad'], ['caps', '--bad']])
def test_missing_endpoint_or_invalid_probe_count_performs_no_io(cli_posture, arguments):
    result, events = invoke(cli_posture, *arguments)
    assert result.returncode == 50 and events == []


@pytest.mark.parametrize('verb', ['ping', 'whoami', 'caps'])
def test_connection_denial_is_returned_without_closing_unowned_session(cli_posture, verb):
    result, events = invoke(cli_posture, verb, 'root://origin.invalid', mode='connect-error')
    assert result.returncode != 0 and events == ['connect'] and 'fixture denied' in result.stderr


def test_whoami_absence_is_explicit_and_never_reads_real_credentials(cli_posture):
    result, events = invoke(cli_posture, 'whoami', 'root://origin.invalid')
    assert result.returncode == 0 and events == ['connect', 'token-discover', 'close']
    assert 'anonymous (no credential)' in result.stdout and 'bearer token: none discovered' in result.stdout


def test_whoami_describes_both_selected_credential_types(cli_posture):
    result, events = invoke(cli_posture, 'whoami', 'root://origin.invalid', mode='authenticated')
    assert result.returncode == 0
    assert events == ['connect', 'token-discover', 'token-explain', 'proxy-explain', 'close']
    assert 'auth used:  ztn' in result.stdout and 'offered:    &P=ztn' in result.stdout


@pytest.mark.parametrize('flags,role', [(0, 'unknown'), (1, 'server'), (2, 'manager'), (3, 'supervisor')])
@pytest.mark.parametrize('mode,tls', [('normal', 'cleartext'), ('tls', 'TLSv1.3'), ('tls-unnamed', 'yes')])
def test_caps_preserves_server_role_and_negotiated_tls(cli_posture, flags, role, mode, tls):
    result, events = invoke(cli_posture, 'caps', 'root://origin.invalid', mode=mode, flags=flags)
    assert result.returncode == 0 and f'role={role}  tls={tls}' in result.stdout
    assert events[0] == 'connect' and events[-1] == 'close' and events.count('query') > 5
    assert 'fixture-value' in result.stdout and 'ignored-tail' not in result.stdout


@pytest.mark.parametrize('mode,present', [('bare', True), ('query-error', False)])
def test_caps_refuses_failed_values_and_accepts_bare_legacy_replies(cli_posture, mode, present):
    result, events = invoke(cli_posture, 'caps', 'root://origin.invalid', mode=mode)
    assert result.returncode == 0 and events[-1] == 'close'
    assert ('fixture-value' in result.stdout) is present

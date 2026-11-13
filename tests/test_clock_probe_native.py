"""Clock diagnostics retain exact skew boundaries and clean up remote probes."""

from email.utils import formatdate
import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping and object instrumentation')


@pytest.fixture(scope='module')
def clock_probe(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('clock-probe')
    binary = output / 'xrdcksum'
    plan = client_make(root / 'client', '-n', 'xrdcksum', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    driver = str(root / 'tests/c/clock_probe_native_test.c')
    command[command.index('apps/cksum/xrdcksum.o')] = driver
    command = [item for item in command if not item.startswith('apps/cksum/')]
    command.insert(command.index(driver) + 1, 'apps/diag/xrd_clockskew.o')
    command.append('-I.')
    command += ['-Wl,--wrap=' + name for name in ('clock_gettime', 'time',
        'brix_http_req', 'brix_connect', 'brix_close', 'brix_file_open_write',
        'brix_file_close', 'brix_stat', 'brix_rm')]
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def invoke(binary, operation, value, mode='normal', offset=0):
    environment = dict(os.environ, BRIX_CLOCK_MODE=mode, BRIX_CLOCK_OFFSET=str(offset),
                       BRIX_CLOCK_DATE=formatdate(1700000000 + offset, usegmt=True))
    return subprocess.run([str(binary), operation, value], env=environment,
                          capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize('scheme', ['http', 'https', 'root', 'roots'])
@pytest.mark.parametrize('offset', [-301, -300, -61, -60, 0, 60, 61, 300, 301])
def test_clock_probe_preserves_sign_warning_and_failure_boundaries(clock_probe, scheme, offset):
    result = invoke(clock_probe, 'cli', scheme + '://origin.invalid/data', offset=offset)
    assert result.returncode == int(abs(offset) > 300), result.stdout + result.stderr
    assert f'clock offset: {offset:+.1f} s' in result.stdout
    assert ('WARNING:' in result.stdout) == (abs(offset) > 60)
    assert 'round-trip:   0.0 ms' in result.stdout


@pytest.mark.parametrize('scheme,mode,diagnostic', [
    ('http', 'http-error', 'fixture-http-error'),
    ('http', 'missing-date', 'no parseable Date header'),
    ('https', 'bad-date', 'no parseable Date header'),
    ('root', 'connect-error', 'connect: fixture-connect-error'),
    ('root', 'open-error', 'need an HTTP endpoint or write access'),
    ('roots', 'stat-error', 'stat: fixture-stat-error')])
def test_failed_probe_is_reported_and_owned_resources_are_closed(clock_probe, scheme, mode, diagnostic):
    result = invoke(clock_probe, 'cli', scheme + '://origin.invalid', mode)
    assert result.returncode == 1 and diagnostic in result.stderr
    assert 'clock offset:' not in result.stdout


@pytest.mark.parametrize('value,mode,expected', [('', 'normal', 1),
    ('http://', 'normal', 1), ('-', 'normal', 50), ('ignored', 'missing-endpoint', 50)])
def test_invalid_endpoint_never_reports_a_measurement(clock_probe, value, mode, expected):
    result = invoke(clock_probe, 'cli', value, mode)
    assert result.returncode == expected and result.stdout == ''


@pytest.mark.parametrize('value', ['', 'invalid', 'Sun, 06 Xxx 1994 08:49:37 GMT',
                                  'Sun, 06 anF 1994 08:49:37 GMT'])
def test_malformed_http_date_is_rejected(clock_probe, value):
    result = invoke(clock_probe, 'date', value)
    assert result.returncode == 0 and result.stdout == '-1 0\n'


@pytest.mark.parametrize('epoch,expected', [(0, '?'), (1700000000, '2023-11-14 22:13:20Z')])
def test_epoch_display_is_utc_and_zero_is_unknown(clock_probe, epoch, expected):
    result = invoke(clock_probe, 'epoch', str(epoch))
    assert result.returncode == 0 and result.stdout.strip() == expected

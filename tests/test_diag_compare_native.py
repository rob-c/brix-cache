"""Comparison diagnostics retain real digest and set comparison across finite transports."""

from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_eos_discovery_native import private_diag_entry
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def compare_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('diag-compare'); binary = output / 'xrddiag'
    plan = client_make(root / 'client', '-n', 'xrddiag', f'BINDIR={output}', capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    index = command.index('apps/diag/xrddiag.o')
    command[index:index + 1] = [str(private_diag_entry(root, output)), str(root / 'tests/c/diag_compare_native_test.c')]
    names = ['brix_connect', 'brix_close', 'brix_stat', 'brix_dirlist', 'download_to_fd',
             'brix_http_get', 'brix_http_download', 'mkstemp', 'malloc']
    command += ['-I.', *['-Wl,--wrap=' + name for name in names]]
    result = client_run(root / 'client', command, cwd=root / 'client', capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def invoke(binary, mode='normal', plane='root', url='root://fixture.invalid/file', reference='root://fixture2.invalid/file'):
    result = subprocess.run([str(binary), mode, plane, url, reference], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = [row for row in result.stderr.splitlines() if row.startswith('RESULT ')]
    assert len(rows) == 1, result.stderr
    return tuple(map(int, rows[0].split()[1:])), result.stdout


@pytest.mark.parametrize('plane,mode,connections', [('root', 'normal', 2), ('root', 'dir', 2), ('http', 'normal', 1)])
def test_matching_bytes_and_unordered_name_sets_compare_equal(compare_binary, plane, mode, connections):
    counts, output = invoke(compare_binary, mode, plane)
    assert counts == (0, 0, connections, connections) and '[FAIL]' not in output


@pytest.mark.parametrize('mode', ['size', 'mismatch', 'dir-count', 'dir-name', 'dir-error', 'read', 'stat', 'temp-root'])
def test_reference_difference_or_read_failure_cannot_report_success(compare_binary, mode):
    counts, output = invoke(compare_binary, mode)
    assert counts == (1, 1, 2, 2) and '[FAIL]' in output


@pytest.mark.parametrize('mode', ['mismatch', 'read', 'http', 'http-status', 'tls', 'tls-status', 'temp-root', 'temp-dav', 'temp-tls', 'allocation'])
def test_cross_plane_failure_cleans_up_connection_and_temporary_files(compare_binary, mode):
    counts, _ = invoke(compare_binary, mode, 'http')
    assert counts[0] != 0 and counts[2:] == (1, 1)


@pytest.mark.parametrize('plane,mode,connections,closed', [('root', 'connect-a', 1, 0),
    ('root', 'connect-b', 2, 1), ('http', 'connect-a', 1, 0)])
def test_connect_refusal_closes_only_already_established_sessions(compare_binary, plane, mode, connections, closed):
    counts, _ = invoke(compare_binary, mode, plane)
    assert counts[0] != 0 and counts[2:] == (connections, closed)


@pytest.mark.parametrize('plane,url,reference', [('root', 'root://fixture.invalid/file', '-'),
    ('root', 'root://fixture.invalid', 'root://fixture2.invalid/file'),
    ('root', 'bad://fixture.invalid/file', 'root://fixture2.invalid/file'),
    ('root', 'root://fixture.invalid/file', 'bad://fixture2.invalid/file'),
    ('http', 'bad://fixture.invalid/file', '-'), ('http', 'root://fixture.invalid', '-')])
def test_invalid_or_incomplete_compare_request_does_not_connect(compare_binary, plane, url, reference):
    counts, _ = invoke(compare_binary, plane=plane, url=url, reference=reference)
    assert counts == (50, 0, 0, 0)

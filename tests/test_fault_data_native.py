"""Fault forwarding and HTTP mutation preserve byte counts and bounded output."""

from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def data_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('fault-data')
    binary = output / 'brix-fault-proxy'
    plan = client_make(root / 'client', '-n', 'brix-fault-proxy', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout.replace('\\\n', ' '), binary)
    command += ['-Dmain=brix_fault_unused_main', str(root / 'tests/c/fault_data_native_test.c')]
    command += ['-Wl,--wrap=' + name for name in ('write', 'usleep', 'rand_r')]
    if '--coverage' in command:
        command.append('-O0')
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def invoke(binary, *arguments):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    return tuple(map(int, lines[0].split())), bytes.fromhex(lines[1]) if len(lines) > 1 else b''


@pytest.mark.parametrize('mode,counts,payload', [
    ('normal', (0, 7, 7, 0, 0, 0, 3, 0, 7), b'abcdefg'),
    ('short', (0, 7, 7, 0, 0, 0, 5, 0, 7), b'abcdefg'),
    ('interrupted', (0, 7, 7, 0, 0, 0, 4, 0, 7), b'abcdefg'),
    ('drip', (0, 7, 7, 0, 0, 0, 4, 14000, 7), b'abcdefg'),
    ('duplicate', (0, 7, 7, 0, 0, 3, 6, 0, 14), b'abcabcdefdefgg'),
    ('corrupt', (0, 7, 7, 0, 7, 0, 3, 0, 7), bytes(value ^ 1 for value in b'abcdefg')),
    ('truncate', (-1, 4, 4, 1, 0, 0, 2, 0, 4), b'abcd'),
    ('already-cut', (-1, 4, 0, 1, 0, 0, 0, 0, 0), b''),
    ('lossy', (-1, 0, 0, 1, 0, 0, 0, 0, 0), b''),
    ('one-shot', (-1, 0, 0, 1, 0, 0, 0, 0, 0), b''),
    ('blocked', (-1, 0, 0, 0, 0, 0, 0, 0, 0), b''),
    ('epoch', (-1, 0, 0, 0, 0, 0, 0, 0, 0), b''),
    ('write-error', (-1, 0, 0, 0, 0, 0, 1, 0, 0), b''),
])
def test_forwarding_counts_only_delivered_logical_bytes(data_binary, mode, counts, payload):
    assert invoke(data_binary, 'forward', mode) == (counts, payload)


@pytest.mark.parametrize('mode,expected', [('uniform', (1, 0, 1)),
    ('normal-jitter', (1, 7000, 12)), ('negative-jitter', (1, 0, 12)),
    ('reorder', (1, 3000, 1)), ('rate', (1, 1000000, 0)),
    ('burst', (0, 0, 0)), ('spent-burst', (1, 1000000, 0))])
def test_pacing_clamps_negative_delay_and_spends_burst_first(data_binary, mode, expected):
    assert invoke(data_binary, 'pace', mode)[0] == expected


@pytest.mark.parametrize('mode,counts,payload', [
    ('normal', (4, 3, 5000, 4), b'ABCD'), ('up', (1, 1, 0, 1), b'A'),
    ('blocked', (0, 0, 0, 0), b''), ('epoch', (0, 0, 0, 0), b''),
    ('write-error', (0, 1, 0, 0), b''), ('interrupted', (4, 4, 5000, 4), b'ABCD')])
def test_replay_honors_direction_timing_and_cancellation(data_binary, mode, counts, payload):
    assert invoke(data_binary, 'replay', mode) == (counts, payload)


REQUEST = 'GET / HTTP/1.1\r\nX-Remove : gone\r\nX-Remove-Extra: kept\r\nTransfer-Encoding: chunked\r\nZ: ok\r\n\r\nBODY'


@pytest.mark.parametrize('mode,expected,edits,obfuscated,appended', [
    ('normal', REQUEST.encode(), 0, 0, 0),
    ('strip', REQUEST.replace('X-Remove : gone\r\n', '').encode(), 1, 0, 0),
    ('lf', REQUEST.replace('\r\n', '\n').encode(), 0, 0, 0),
    ('obfuscate1', REQUEST.replace('Transfer-Encoding:', 'Transfer-Encoding :').encode(), 0, 1, 0),
    ('obfuscate2', REQUEST.replace('Transfer-Encoding:', '\tTransfer-Encoding:').encode(), 0, 1, 0),
    ('obfuscate3', REQUEST.replace('Transfer-Encoding:', 'Transfer_Encoding:').encode(), 0, 1, 0),
    ('added', REQUEST.replace('\r\n\r\n', '\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n').encode(), 3, 0, 0),
    ('injected', REQUEST.replace('\r\n\r\n', '\r\nX-Test: a\0b\r\n\r\n').encode() + b'\0TAIL', 1, 0, 1),
])
@pytest.mark.parametrize('capacity', [0, 1, 15, 64, 512])
def test_http_mutations_preserve_exact_bytes_with_bounded_output(data_binary, mode, expected, edits, obfuscated, appended, capacity):
    counts, payload = invoke(data_binary, 'http', mode, REQUEST, capacity)
    assert counts == (1, int(mode != 'normal'), 1, edits, obfuscated, appended)
    assert payload == expected[:capacity]


@pytest.mark.parametrize('input_text', ['', 'GET /', 'GET / HTTP/1.1\r\nX: y\r\n'])
def test_incomplete_headers_never_publish_rewritten_bytes(data_binary, input_text):
    assert invoke(data_binary, 'http', 'added', input_text, 512) == ((0, 1, 0, 0, 0, 0), b'')


@pytest.mark.parametrize('mode', ['obfuscate1', 'obfuscate2', 'obfuscate3'])
def test_missing_colon_is_preserved_without_reading_beyond_the_header(data_binary, mode):
    request = 'GET / HTTP/1.1\r\nTransfer-Encoding\r\n\r\n'
    assert invoke(data_binary, 'http', mode, request, 512)[1] == request.encode()


@pytest.mark.parametrize('partial', [0, 1])
@pytest.mark.parametrize('kind,complete,threshold,release', [
    ('header', True, -1, None), ('header', True, 0, None),
    ('header', True, 1, 1), ('header', True, 20, 20), ('header', True, 21, None),
    ('header', False, 1, None), ('header', False, 4, None),
    ('body', True, -1, None), ('body', True, 0, None),
    ('body', True, 1, 25), ('body', True, 4, 28), ('body', True, 5, None),
    ('body', False, -1, None), ('body', False, 0, None),
    ('body', False, 1, 1), ('body', False, 4, 4), ('body', False, 5, None),
])
def test_hold_thresholds_preserve_unreleased_boundaries(data_binary, kind, partial, threshold, complete, release):
    message = 'GET / HTTP/1.1\r\nX: y\r\n\r\nABCD' if complete else 'BODY'
    expected = 9999 if release is None else (0, release)[partial]
    assert invoke(data_binary, 'hold', kind, message, threshold, partial)[0] == (int(release is not None), expected)

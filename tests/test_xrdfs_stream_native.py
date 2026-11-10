"""Streaming commands preserve content, error status and bounded retry behavior."""

from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def stream_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('xrdfs-stream')
    binary = output / 'xrdfs'
    plan = client_make(root / 'client', '-n', 'xrdfs', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout.replace('\\\n', ' '), binary)
    entry = output / 'entry.o'
    subprocess.run(['objcopy', '--redefine-sym', 'main=brix_cli_test_main',
                    str(root / 'client/apps/fs/xrdfs.o'), str(entry)], check=True)
    command[command.index('apps/fs/xrdfs.o')] = str(entry)
    command += ['-I.', str(root / 'tests/c/xrdfs_stream_native_test.c')]
    names = ('brix_rfile_open_read', 'brix_rfile_close', 'brix_rfile_pread',
        'brix_rfile_drain_to_fd', 'brix_stat', 'brix_resilient_window_ms',
        'brix_status_retryable', 'brix_reconnect_home', 'brix_mono_ns',
        'nanosleep', 'malloc', 'realloc', 'fwrite', 'fflush', 'brix_query_cksum',
        'brix_rfile_slurp', 'brix_report_err', 'rate_pace', 'brix_rfile_open_write',
        'brix_rfile_pwrite', 'brix_vfs_open', 'brix_vfs_close', 'brix_vfs_abort',
        'brix_vfs_commit', 'brix_vfs_pread', 'brix_vfs_pwrite', 'read', 'write')
    command += ['-Wl,--wrap=' + name for name in names]
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def invoke(binary, arguments, mode='normal', text='one\ntwo\nthree\n'):
    result = subprocess.run([str(binary), mode, text, *arguments],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = [line for line in result.stderr.splitlines() if line.startswith('RESULT ')]
    assert len(rows) == 1, result.stderr
    return tuple(map(int, rows[0].split()[1:])), result.stdout


@pytest.mark.parametrize('arguments,expected', [
    (['cat', 'file'], 'one\ntwo\nthree\n'), (['cat', '-z', 'zstd', 'a', 'b'], 'one\ntwo\nthree\n' * 2),
    (['head', '-n', '1', 'file'], 'one\n'), (['head', '-n', '0', 'file'], ''),
    (['head', '-c', '5', 'file'], 'one\nt'), (['tail', '-n', '1', 'file'], 'three\n'),
    (['tail', '-c', '4', 'file'], 'ree\n'), (['tail', '-c', '99', 'file'], 'one\ntwo\nthree\n'),
    (['grep', '-i', '-n', '^T', 'file'], '2:two\n3:three\n'),
    (['dd', 'if=file', 'bs=2', 'skip=2', 'count=2', 'rate=1G'], 'two\n')])
def test_stream_commands_emit_exact_selected_bytes(stream_binary, arguments, expected):
    counts, output = invoke(stream_binary, arguments)
    assert counts[0] == 0 and counts[1] == counts[2]
    assert output == expected


@pytest.mark.parametrize('mode', ['normal', 'fragmented'])
def test_grep_reassembles_long_lines_across_chunks(stream_binary, mode):
    text = 'x' * 256 + '\nMATCH' + 'y' * 300 + '\n'
    counts, output = invoke(stream_binary, ['grep', '-n', 'MATCH', 'file'], mode, text)
    assert counts[0] == 0 and output == '2:' + text.splitlines()[1] + '\n'


@pytest.mark.parametrize('arguments,expected', [(['cat'], 50), (['head'], 50), (['tail'], 50),
    (['grep'], 2), (['grep', '[', 'file'], 2), (['hexdump'], 50), (['dd'], 50), (['cmp'], 50),
    (['cat', '-z', 'a&token=x', 'file'], 50), (['cat', '-z', '', 'file'], 50),
    (['cat', '-z', 'x' * 17, 'file'], 50), (['dd', 'file', 'bs=0'], 50),
    (['dd', 'file', 'skip=-1'], 50), (['dd', 'file', 'count=-1'], 50),
    (['dd', 'file', 'rate=-1'], 50)])
def test_invalid_operands_never_open_a_remote_handle(stream_binary, arguments, expected):
    counts, output = invoke(stream_binary, arguments)
    assert counts[:3] == (expected, 0, 0) and output == ''


@pytest.mark.parametrize('arguments,mode,expected', [
    (['cat', 'file'], 'open-error', 52), (['cat', 'file'], 'flush-error', 52),
    (['cat', 'file'], 'drain-error', 52), (['head', '-n', '1', 'file'], 'read-error', 52),
    (['head', '-n', '1', 'file'], 'stdout-error', 52),
    (['head', '-c', '1', 'file'], 'drain-error', 52),
    (['tail', '-n', '1', 'file'], 'stat-error', 52),
    (['tail', '-n', '1', 'file'], 'open-error', 52),
    (['tail', '-n', '1', 'file'], 'allocate-error', 52),
    (['tail', '-n', '1', 'file'], 'read-error', 52),
    (['tail', '-c', '1', 'file'], 'drain-error', 52),
    (['grep', 'one', 'file'], 'grow-error', 2), (['grep', 'one', 'file'], 'read-error', 2),
    (['grep', 'one', 'file'], 'open-error', 52), (['hexdump', 'file'], 'open-error', 52),
    (['hexdump', 'file'], 'read-error', 52), (['dd', 'file'], 'open-error', 52),
    (['dd', 'file'], 'read-error', 52), (['dd', 'file'], 'stdout-error', 52)])
def test_stream_errors_preserve_failure_and_close_open_handles(stream_binary, arguments, mode, expected):
    counts, _ = invoke(stream_binary, arguments, mode)
    assert counts[0] == expected and counts[1] - counts[2] == int(mode == 'open-error')


@pytest.mark.parametrize('mode,expected,opens,closes,reconnects', [
    ('normal', 0, 1, 1, 0), ('shrink', 0, 1, 1, 0), ('replaced', 0, 2, 2, 0),
    ('reopen-error', -1, 2, 1, 0), ('read-error', -1, 1, 1, 0),
    ('stat-error', -1, 1, 1, 0), ('allocate-error', -1, 1, 1, 0),
    ('open-error', -1, 1, 0, 0), ('stat-retry', 0, 1, 1, 1),
    ('stat-deadline', -1, 1, 1, 1)])
def test_follow_retains_one_handle_and_bounded_reconnect_window(stream_binary, mode, expected, opens, closes, reconnects):
    counts, _ = invoke(stream_binary, ['follow'], mode)
    assert counts[:3] == (expected, opens, closes) and counts[5] == reconnects


@pytest.mark.parametrize('mode,expected,fragment,slurps', [
    ('checksum', 0, '', 0), ('checksum-different', 1, 'checksum adler32', 0),
    ('normal', 0, '', 2), ('different-byte', 1, 'byte 3', 2),
    ('different-size', 1, 'EOF (sizes', 2), ('slurp-first', 52, '', 1),
    ('slurp-second', 52, '', 2)])
def test_compare_falls_back_to_exact_bytes_and_reports_first_difference(stream_binary, mode, expected, fragment, slurps):
    counts, output = invoke(stream_binary, ['cmp', 'a', 'b'], mode)
    assert counts[0] == expected and counts[6] == slurps and fragment in output


@pytest.mark.parametrize('verb', ['upload', 'download'])
@pytest.mark.parametrize('arguments', [[], ['bs=0', 'a', 'b'], ['rate=-1', 'a', 'b'],
    ['--io-uring=bad', 'a', 'b'], ['--io-uring', 'bad', 'a', 'b']])
def test_invalid_transfer_options_cannot_open_local_or_remote_files(stream_binary, verb, arguments):
    counts, _ = invoke(stream_binary, [verb, *arguments])
    assert counts[0] == 50 and counts[1] == counts[7] == 0


@pytest.mark.parametrize('verb,arguments,mode,expected,local,closed,commits,aborts', [
    ('upload', ['local', 'remote'], 'normal', 0, 1, 1, 0, 0),
    ('upload', ['-', 'remote'], 'pipe-interrupt', 0, 0, 0, 0, 0),
    ('upload', ['-', 'remote'], 'pipe-error', 1, 0, 0, 0, 0),
    ('upload', ['local', 'remote'], 'local-open', 50, 1, 0, 0, 0),
    ('upload', ['local', 'remote'], 'open-error', 52, 1, 1, 0, 0),
    ('upload', ['local', 'remote'], 'allocate-error', 51, 1, 1, 0, 0),
    ('upload', ['local', 'remote'], 'read-error', 1, 1, 1, 0, 0),
    ('upload', ['local', 'remote'], 'remote-write', 52, 1, 1, 0, 0),
    ('download', ['remote', 'local'], 'normal', 0, 1, 1, 1, 0),
    ('download', ['remote'], 'normal', 0, 1, 1, 1, 0),
    ('download', ['/'], 'normal', 50, 0, 0, 0, 0),
    ('download', ['remote', 'local'], 'local-open', 50, 1, 0, 0, 0),
    ('download', ['remote', 'local'], 'open-error', 52, 1, 1, 0, 1),
    ('download', ['remote', 'local'], 'allocate-error', 51, 1, 1, 0, 1),
    ('download', ['remote', 'local'], 'read-error', 52, 1, 1, 0, 1),
    ('download', ['remote', 'local'], 'local-write', 1, 1, 1, 0, 1),
    ('download', ['remote', 'local'], 'commit-error', 1, 1, 1, 1, 0),
    ('download', ['remote', '-'], 'pipe-short', 0, 0, 0, 0, 0),
    ('download', ['remote', '-'], 'pipe-interrupt', 0, 0, 0, 0, 0),
    ('download', ['remote', '-'], 'pipe-error', 1, 0, 0, 0, 0),
    ('download', ['remote', '-'], 'pipe-zero', 1, 0, 0, 0, 0)])
def test_transfer_failure_preserves_ownership_and_atomic_destination(stream_binary, verb, arguments, mode, expected, local, closed, commits, aborts):
    counts, output = invoke(stream_binary, [verb, 'bs=3', 'rate=1G', *arguments], mode)
    assert counts[0] == expected and counts[7:11] == (local, closed, commits, aborts)
    if expected == 0 and verb == 'download' and arguments[-1] == '-':
        assert output == 'one\ntwo\nthree\n'


@pytest.mark.parametrize('uring', ['on', 'off', 'auto'])
@pytest.mark.parametrize('spaced', [False, True])
def test_download_carries_force_and_io_uring_to_local_storage(stream_binary, uring, spaced):
    flags = ['--io-uring', uring] if spaced else ['--io-uring=' + uring]
    counts, _ = invoke(stream_binary, ['download', '-f', *flags, 'remote', 'local'])
    assert counts[0] == 0 and counts[12] == 10
    assert counts[13] == {'off': 2, 'on': 1, 'auto': 0}[uring]

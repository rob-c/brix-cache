"""Native benchmark worker failures, cleanup, reporting, and bounded workloads."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def benchmark(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('storascan-bench')
    main = output / 'main.o'
    renamed = subprocess.run(['objcopy', '--redefine-sym', 'main=storascan_main',
        str(root / 'client/apps/scan/xrdstorascan.o'), str(main)],
        capture_output=True, text=True, timeout=30)
    assert renamed.returncode == 0, renamed.stderr
    binary = output / 'xrdstorascan'
    plan = client_make(root / 'client', '-n', 'xrdstorascan', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    index = command.index('apps/scan/xrdstorascan.o')
    command[index:index + 1] = [str(main), str(root / 'tests/c/storascan_bench_native_test.c')]
    wrappers = ['brix_connect', 'brix_close', 'brix_stat', 'brix_file_open_read',
                'brix_file_read', 'brix_file_close', 'brix_mono_ns', 'pthread_create',
                'pthread_join', 'malloc', 'calloc', 'strdup']
    command += ['-Wl,--wrap=' + name for name in wrappers]
    linked = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert linked.returncode == 0, linked.stdout + linked.stderr
    return binary


def bench(benchmark, flags=(), fault='', size=32):
    return subprocess.run([str(benchmark), fault, str(size), 'xrdstorascan', 'bench',
        'root://fixture.invalid/data', '--block', '8', '--parallel', '1',
        '--count', '4', *flags], capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize('pattern', ['seq', 'random'])
@pytest.mark.parametrize('size,expected_bytes,expected_ops', [(32, 32, 4), (4, 16, 4), (0, 0, 1)])
def test_bounded_reads_preserve_offsets_bytes_and_latency(benchmark, pattern, size,
                                                         expected_bytes, expected_ops):
    result = bench(benchmark, ['--pattern', pattern, '--json'], size=size)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record['bytes'] == expected_bytes and record['ops'] == expected_ops
    assert record['p50_ms'] == record['p95_ms'] == record['p99_ms'] == 50
    assert record['pattern'] == pattern and record['parallel'] == 1


@pytest.mark.parametrize('fault,hint', [('worker-connect', 'connect:'), ('open', 'open:'),
    ('read', 'read:'), ('thread', 'pthread_create'), ('one-thread', 'pthread_create'),
    ('workers-allocation', 'out of memory'), ('threads-allocation', 'out of memory'),
    ('latency-allocation', 'out of memory'), ('buffer-allocation', 'out of memory'),
    ('merge-allocation', 'out of memory')])
def test_worker_errors_never_emit_success_record_and_release_resources(benchmark, fault, hint):
    result = bench(benchmark, ['--json'], fault=fault)
    assert result.returncode == 3, result.stderr
    assert result.stdout == '' and hint in result.stderr


@pytest.mark.parametrize('fault', ['connect', 'stat'])
def test_preflight_refusals_start_no_workers(benchmark, fault):
    result = bench(benchmark, ['--json'], fault=fault)
    assert result.returncode > 0 and result.stdout == ''
    assert 'opens=0 reads=0 threads=0' in result.stderr


def test_one_failed_worker_still_joins_every_started_worker(benchmark):
    result = bench(benchmark, ['--parallel', '2', '--json'], fault='one-thread')
    assert result.returncode == 3 and result.stdout == ''
    assert 'opens=1 reads=2 threads=1' in result.stderr


def test_matrix_continues_after_failed_cell(benchmark):
    result = bench(benchmark, ['--block', '8,16', '--json'], fault='buffer-allocation')
    assert result.returncode == 3
    record = json.loads(result.stdout)
    assert record['block'] == 16 and record['ops'] == 4 and record['bytes'] == 64


def test_duration_budget_is_finite_and_last_count_overrides_it(benchmark):
    duration = bench(benchmark, ['--duration', '1', '--json'])
    assert duration.returncode == 0, duration.stderr
    assert 0 < json.loads(duration.stdout)['ops'] < 20
    count = bench(benchmark, ['--duration', '1', '--count', '2', '--json'])
    assert count.returncode == 0 and json.loads(count.stdout)['ops'] == 2


def test_text_report_identifies_workload_and_percentiles(benchmark):
    result = bench(benchmark, ['--op', 'read'])
    assert result.returncode == 0, result.stderr
    assert 'size=32 bytes  pattern=seq  count' in result.stdout
    assert 'MiB/s' in result.stdout and 'p99_ms' in result.stdout
    assert '50.000' in result.stdout


@pytest.mark.parametrize('flags', [['--op', 'write'], ['--block', '0'], ['--parallel', '-1'],
    ['--block', 'bad'], ['--parallel', ''], ['--pattern', 'invalid'], ['--unknown'],
    ['second-url'], ['--op'], ['--block']])
def test_bad_arguments_make_no_connection(benchmark, flags):
    result = bench(benchmark, flags)
    assert result.returncode == 64 and result.stdout == ''
    assert 'connects=0 opens=0 reads=0 threads=0' in result.stderr


def test_list_allocation_refusal_does_not_connect(benchmark):
    result = bench(benchmark, fault='list-allocation')
    assert result.returncode == 64
    assert 'connects=0 opens=0 reads=0 threads=0' in result.stderr

"""Exercise packet-label encoding and latency rendering without live services."""

from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


def _run(binary, *arguments):
    result = subprocess.run([str(binary), *map(str, arguments)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture(scope='module')
def pmark_binary(native_compile):
    source = Path(__file__).parent / 'c/pmark_flowlabel_native_test.c'
    return native_compile('pmark-flowlabel-contract', source.read_text())


@pytest.mark.parametrize('experiment,activity,expected', [
    (1, 1, 0x20004), (3, 14, 196664), (1023, 63, 0x3FEFC),
], ids=['probe-minimum', 'cms-wire-value', 'community-width'])
def test_scitags_wire_encoding(pmark_binary, experiment, activity, expected):
    """Keep the published wire examples and leave every entropy bit clear."""
    _run(pmark_binary, 'encode', experiment, activity, expected)


@pytest.mark.parametrize('case', ['probe-success', 'probe-denied', 'lease'])
def test_flowlabel_syscall_contract(pmark_binary, case):
    """Check labels, cached probe refusal, and metric outcomes through stubs."""
    _run(pmark_binary, case)


@pytest.fixture(scope='module')
def latency_binary(native_compile):
    source = Path(__file__).parent / 'c/latency_export_native_test.c'
    return native_compile(
        'latency-export-contract', source.read_text(),
        ['src/observability/metrics/unified.c'],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


@pytest.mark.parametrize('microseconds,seconds,bucket', [
    (0, '0.000000', 0), (1, '0.000001', 0), (1_500_000, '1.500000', 7),
], ids=['zero', 'fractional-second', 'over-one-second'])
def test_latency_export_seconds(latency_binary, microseconds, seconds, bucket):
    """Render the real sum and bucket labels with microsecond precision."""
    lines = _run(latency_binary, microseconds, bucket).splitlines()
    assert f'brix_io_latency_seconds_sum{{proto="stream",op="read"}} {seconds}' in lines
    assert 'brix_io_latency_seconds_count{proto="stream",op="read"} 1' in lines
    finite = ['0.001000', '0.005000', '0.010000', '0.050000',
              '0.100000', '0.500000', '1.000000', '5.000000']
    expected = [f'brix_io_latency_seconds_bucket{{proto="stream",op="read",le="{bound}"}} '
                f'{int(index >= bucket)}' for index, bound in enumerate([*finite, '+Inf'])]
    assert lines[:-2] == expected
    assert len(lines) == len(expected) + 2

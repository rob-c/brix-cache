"""Raw query lookup preserves explicit decoding, bounds and policy refusals."""

from pathlib import Path
import subprocess

import pytest

from cmdscripts.object_unit_layout import NGX_SRC
from test_platform_linux_native import native_compile  # noqa: F401


@pytest.fixture(scope='module')
def scan_binary(native_compile):
    """Link the production scanner, URI decoder and nginx comparator."""
    root = Path(__file__).resolve().parents[1]
    return native_compile('http-query-scan',
        (root / 'tests/c/http_query_scan_test.c').read_text(),
        ['src/core/http/http_query.c', 'src/core/compat/uri.c', 'src/core/compat/hex.c',
         str(NGX_SRC / 'src/core/ngx_string.c')],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


def scan(binary, operation, query, key='key', capacity=64, flags=0):
    """Return the public status and decoded bytes; native canaries must hold."""
    result = subprocess.run([str(binary), operation, query, key, str(capacity),
                             str(flags)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    status, encoded = result.stdout.strip().split(':')
    return int(status), bytes.fromhex(encoded)


@pytest.mark.parametrize('query,flags,expected', [
    ('key=value', 0, b'value'), ('other=x&key=value&tail=z', 0, b'value'),
    ('bare&&key=a=b&', 0, b'a=b'), ('KEY=value', 1, b'value'),
    ('key=%41%6a%AF', 2, b'Aj\xaf'), ('key=%41%6a%AF', 34, b'Aj\xaf'),
    ('key=a+b', 2, b'a+b'), ('key=a+b', 6, b'a b'),
    ('key=a+b', 38, b'a b'), ('key=%2B', 6, b'+'),
    ('key=%Q1%1Q%', 2, b'%Q1%1Q%'), ('key=%Q1%1Q%', 34, b'%Q1%1Q%'),
    ('key=', 16, b''), ('key=', 18, b''), ('key=%2Fetc', 0, b'%2Fetc'),
    ('key=first&key=second', 0, b'first'),
])
def test_raw_lookup_decoding_is_explicit(scan_binary, query, flags, expected):
    """Literal and decoded modes preserve separators, case and plus policy."""
    assert scan(scan_binary, 'get', query, flags=flags) == (1, expected)


@pytest.mark.parametrize('capacity', [1, 2, 4, 8])
@pytest.mark.parametrize('flags', [32, 34, 38])
def test_truncation_is_bounded_and_terminated(scan_binary, capacity, flags):
    """Explicit truncation fits exactly; the driver checks untouched canaries."""
    assert scan(scan_binary, 'get', 'key=abcdefgh', capacity=capacity,
                flags=flags) == (1, b'abcdefgh'[:capacity - 1])


@pytest.mark.parametrize('query,capacity,flags,expected', [
    ('', 64, 0, 0), ('other=x', 64, 0, 0), ('KEY=x', 64, 0, 0),
    ('key', 64, 0, 0), ('key=', 64, 0, 0), ('key=x', 0, 0, 0),
    ('key=abcd', 4, 0, -1), ('key=%41%42', 2, 2, -1),
    ('key=x', 1, 2, -1), ('key=%00', 64, 10, -1),
    ('key=%00', 64, 42, -1), ('key=longvalue%00', 2, 42, -1),
])
def test_refused_values_do_not_overrun_output(scan_binary, query, capacity,
                                             flags, expected):
    """Overflow and NUL remain errors, including NUL after a truncated prefix."""
    assert scan(scan_binary, 'get', query, capacity=capacity, flags=flags)[0] == expected


@pytest.mark.parametrize('operation', [
    'null-key', 'null-output', 'has-null-key', 'decoded-null-key',
    'decoded-null-query',
])
def test_invalid_arguments_are_refused(scan_binary, operation):
    assert scan(scan_binary, operation, 'key=value') == (0, b'')


@pytest.mark.parametrize('query,flags,expected', [
    ('key', 0, 1), ('key=', 0, 0), ('key=x', 64, 1),
    ('KEY', 1, 1), ('KEY', 0, 0), ('other&key', 0, 1),
    ('keyextra', 64, 0), ('', 64, 0),
])
def test_presence_distinguishes_bare_keys_and_values(scan_binary, query,
                                                  flags, expected):
    assert scan(scan_binary, 'has', query, flags=flags) == (expected, b'')


@pytest.mark.parametrize('query,flags,expected', [
    ('%6bey=x', 0, 1), ('%4B%45%59=x', 1, 1), ('%4B%45%59=x', 0, 0),
    ('other=x&key=y', 0, 1), ('keyextra=x', 0, 0), ('', 0, 0),
    ('other=x', 0, 0), ('key+extra=x', 0, 0),
])
def test_policy_probe_matches_decoded_names(scan_binary, query, flags, expected):
    assert scan(scan_binary, 'decoded', query, flags=flags) == (expected, b'')


@pytest.mark.parametrize('name', ['', '%', '%0', '%GG', '%0G', '%G0',
                                 '%00', 'x%00y', 'x' * 256, '&&'])
def test_malformed_names_fail_closed_before_policy_allocation(scan_binary, name):
    """An undecodable name must not evade a sensitive-key presence gate."""
    assert scan(scan_binary, 'decoded', name + '=value') == (1, b'')

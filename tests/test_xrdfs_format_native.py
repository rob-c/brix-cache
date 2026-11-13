"""CLI reports preserve JSON boundaries, numeric values and strict parsing outcomes."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command


@pytest.fixture(scope='module')
def xrdfs_format(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('xrdfs-format')
    binary = output / 'xrdcksum'
    plan = client_make(root / 'client', '-n', 'xrdcksum', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    driver = str(root / 'tests/c/xrdfs_format_native_test.c')
    command[command.index('apps/cksum/xrdcksum.o')] = driver
    command = [part for part in command if not part.startswith('apps/cksum/')]
    command.insert(command.index(driver) + 1, 'apps/fs/xrdfs_fmt.o')
    command.append('-I.')
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def invoke(binary, operation, value, option=0):
    result = subprocess.run([str(binary), operation, value, str(option)],
                            env=dict(os.environ, TZ='UTC'), capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.rstrip('\n')


@pytest.mark.parametrize('path', ['/ordinary', '/quote"\n\t\\name', '/unicode-δ'])
@pytest.mark.parametrize('extended', [False, True])
def test_json_preserves_hostile_strings_and_exact_numbers(xrdfs_format, path, extended):
    result = json.loads(invoke(xrdfs_format, 'json', path, int(extended)))
    # The CLI's documented wire-name contract escapes each byte as U+00XX,
    # preserving arbitrary POSIX filename bytes rather than assuming UTF-8.
    assert result['path'].encode('latin-1') == os.fsencode(path)
    assert result['size'] == 9007199254740991
    assert result['is_dir'] is True and result['mtime'] == 0
    if extended:
        assert (result['mode'], result['owner'], result['group']) == ('04755', 'owner"\n', 'group\\name')
    else:
        assert {'mode', 'owner', 'group'}.isdisjoint(result)


@pytest.mark.parametrize('extended', [False, True])
def test_text_time_and_extended_fields_are_consistent(xrdfs_format, extended):
    output = invoke(xrdfs_format, 'text', '/ordinary', int(extended))
    assert 'MTime:  1970-01-01 00:00:00 +0000' in output
    assert ('CTime:' in output) == extended
    assert ('ATime:' in output) == extended
    assert ('Mode:   04755' in output) == extended


@pytest.mark.parametrize('stamp,expected', [('200001020304.05', 946782245),
    ('6901020304', -31438560), ('6801020304', 3092699040), ('200001020304', 946782240)])
def test_touch_timestamp_uses_posix_year_pivot(xrdfs_format, stamp, expected):
    assert int(invoke(xrdfs_format, 'touch', stamp)) == expected


@pytest.mark.parametrize('stamp', ['', 'a', '200001020304.x1', '200001020304.1',
    '200001020304.001', '200001020304x', '1' * 32, '20000102030.00', '196912312359.59'])
def test_invalid_timestamp_preserves_output_storage(xrdfs_format, stamp):
    assert invoke(xrdfs_format, 'touch', stamp) == 'invalid'


@pytest.mark.parametrize('value,expected', [('rwxr-xr-x', 0o755), ('---------', 0),
    ('r--------', 0o400), ('755', 0o755), ('04755', 0o4755), ('invalid', -1),
    ('rwxr-xrx-', -1), ('888', -1), ('-1', -1), ('', -1)])
def test_permission_parser_preserves_symbolic_and_octal_forms(xrdfs_format, value, expected):
    assert int(invoke(xrdfs_format, 'chmod', value)) == expected


@pytest.mark.parametrize('value,expected', [('0', '0'), ('18446744073709551615', '18446744073709551615'),
    ('18446744073709551616', 'invalid'), ('-1', 'invalid'), ('12x', 'invalid'),
    ('', 'invalid'), ('<null>', 'invalid')])
def test_unsigned_parser_refuses_overflow_without_publishing_value(xrdfs_format, value, expected):
    assert invoke(xrdfs_format, 'integer', value) == expected


@pytest.mark.parametrize('value,expected', [('unknown', '-1 -1 -1 -1 -1'),
    ('oss.space=100&oss.free=30&oss.used=70&oss.maxf=20', '0 100 30 70 20'),
    ('oss.free=19', '0 -1 19 -1 -1')])
def test_space_reply_retains_absent_fields(xrdfs_format, value, expected):
    assert invoke(xrdfs_format, 'space', value) == expected


@pytest.mark.parametrize('value,expected', [('.', 1), ('..', 1), ('.hidden', 0), ('...', 0), ('', 0)])
def test_dot_filter_does_not_hide_real_entries(xrdfs_format, value, expected):
    assert int(invoke(xrdfs_format, 'dot', value)) == expected


@pytest.mark.parametrize('capacity', [1, 2, 8, 256])
@pytest.mark.parametrize('flags', [0, 255])
def test_flag_rendering_respects_output_capacity(xrdfs_format, capacity, flags):
    result = invoke(xrdfs_format, 'flags', str(flags), capacity)
    assert len(result) < capacity
    if flags == 0:
        assert result == 'none'[:capacity - 1]


def test_unrepresentable_calendar_time_falls_back_to_epoch(xrdfs_format):
    assert invoke(xrdfs_format, 'time', str(2**63 - 1)) == f'Time: {2**63 - 1}'

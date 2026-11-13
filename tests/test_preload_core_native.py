"""Execute configured preload objects without interposing the pytest process."""

import errno
import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU ELF symbol renaming')


def preload_object_argument(name):
    return name.endswith('.pic.o') and (name.startswith('preload/') or '/preload_' in name)


def preload_objects(root):
    plan = client_make(root / 'client', '-n', '-B', 'libbrixposix_preload.so',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    logical = plan.stdout.replace('\\\n', ' ')
    links = '\n'.join(line for line in logical.splitlines() if '-o libbrixposix_preload.so ' in line)
    command = private_link_command(links, Path('libbrixposix_preload.so'))
    return [root / 'client' / name for name in filter(preload_object_argument, command)]


def public_preload_symbol(name):
    helpers = {'map_path', 'slot_of', 'fill_stat', 'ensure_conn'}
    return name not in helpers and not name.startswith('brix')


def preload_symbol_mapping(objects, output):
    inspected = subprocess.run(['nm', '--defined-only', *map(str, objects)],
                                capture_output=True, text=True, timeout=30)
    assert inspected.returncode == 0, inspected.stderr
    names = {line.split()[-1] for line in inspected.stdout.splitlines() if ' T ' in line}
    exports = sorted(filter(public_preload_symbol, names))
    mapping = output / 'symbols'
    mapping.write_text(''.join(f'{name} probe_{name}\n' for name in exports))
    return mapping


def renamed_preload_objects(root, output):
    objects = preload_objects(root)
    assert len(objects) >= 6
    mapping = preload_symbol_mapping(objects, output)
    copied = []
    for index, original in enumerate(objects):
        target = output / f'preload-{index}.o'
        result = subprocess.run(['objcopy', '--redefine-syms=' + str(mapping), str(original), str(target)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        copied.append(str(target))
    return copied


@pytest.fixture(scope='module')
def preload_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('preload-native')
    objects = renamed_preload_objects(root, output)
    binary = output / 'xrdcksum'
    plan = client_make(root / 'client', '-n', 'xrdcksum', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    position = command.index('apps/cksum/xrdcksum.o')
    command[position:position + 1] = [str(root / 'tests/c/preload_core_native_test.c'), *objects]
    command = [arg for arg in command if not arg.startswith('apps/cksum/')]
    names = ('brix_connect', 'brix_conn_usable', 'brix_rfile_open_read', 'brix_rfile_open_write',
             'brix_stat', 'brix_rfile_pread', 'brix_rfile_pwrite', 'brix_rfile_close',
             'brix_dirlist', 'calloc', 'fopencookie')
    command += ['-Wl,--wrap=' + name for name in names]
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.fixture
def preload(preload_binary):
    def run(action='open', fault='', path='/v/file', flags=0, expected=0, detail='',
            mapping='/v=root://fixture.invalid/base', force=2):
        env = dict(os.environ, BRIX_PRELOAD_FAULT=fault, BRIX_PRELOAD_FORCE=str(force))
        env.pop('BRIX_VMP', None)
        if mapping is not None:
            env['BRIX_VMP'] = mapping
        result = subprocess.run([str(preload_binary), action, path, str(flags), str(expected), str(detail)],
                                env=env, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('action', ['open', 'openat'])
@pytest.mark.parametrize('fault', ['', 'read', 'stat', 'close', 'fork'])
def test_read_cursor_permissions_and_lazy_reconnect(preload, action, fault):
    output = preload(action=action, fault=fault)
    assert ('connects=2' if fault == 'fork' else 'connects=1') in output
    assert 'opens=2' in output


@pytest.mark.parametrize('action', ['open', 'openat'])
@pytest.mark.parametrize('flags,force', [(os.O_WRONLY, 2), (os.O_WRONLY | os.O_CREAT, 1),
    (os.O_WRONLY | os.O_TRUNC, 1), (os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0)])
@pytest.mark.parametrize('fault', ['', 'write'])
def test_write_force_cursor_and_direction_refusal(preload, action, flags, force, fault):
    preload(action=action, flags=flags, force=force, fault=fault)


@pytest.mark.parametrize('action', ['open', 'openat'])
@pytest.mark.parametrize('flags', [os.O_RDONLY, os.O_WRONLY])
@pytest.mark.parametrize('fault,error', [('connect', errno.EIO), ('open', errno.EACCES)])
def test_failed_open_preserves_error_without_shadow_descriptor(preload, action, flags, fault, error):
    preload(action=action, flags=flags, fault=fault, expected=-1, detail=error)


@pytest.mark.parametrize('fault,expected', [('', 0), ('stat', -1), ('connect', -1)])
def test_all_mapped_metadata_entrypoints_use_same_policy(preload, fault, expected):
    preload(action='stat', fault=fault, expected=expected)


def test_exhausted_descriptor_table_can_recover(preload):
    preload(action='full')


@pytest.mark.parametrize('mapping,path,expected', [
    ('/v=root://fixture.invalid/base', '/v/file', '/base/file'),
    ('/v///=root://fixture.invalid/base///', '/v/file', '/base/file'),
    ('/v=root://fixture.invalid', '/v/file', '/file'),
    ('/v=root://fixture.invalid/', '/v', '/'),
    ('/v=root://fixture.invalid/base', '/v', '/base/'),
])
def test_prefix_and_base_normalization(preload, mapping, path, expected):
    preload(action='map', mapping=mapping, path=path, flags=128, expected=1, detail=expected)


@pytest.mark.parametrize('path', ['<null>', 'relative', '/vdata/file', '/other/file'])
def test_nonmatching_paths_never_divert(preload, path):
    preload(action='map', path=path, flags=128)


@pytest.mark.parametrize('mapping', [None, '', 'no-equals', 'x' * 256 + '=root://fixture.invalid',
                                   '/v=root://fixture.invalid:bad', '/v=root://'])
def test_missing_or_invalid_mapping_stays_disabled(preload, mapping):
    preload(action='map', flags=128, mapping=mapping)


@pytest.mark.parametrize('capacity', [0, 1, 10])
def test_mapping_requires_space_for_full_path_and_terminator(preload, capacity):
    preload(action='map', flags=capacity)


@pytest.mark.parametrize('fault,error', [('', 0), ('empty', 0), ('dir-full', 0),
    ('listing', errno.EACCES), ('connect', errno.EIO), ('allocation', errno.ENOMEM)])
def test_directory_snapshot_cursors_and_registry_limits(preload, fault, error):
    preload(action='directory', fault=fault, expected=error)


@pytest.mark.parametrize('mode', ['r', 'rb', 'w', 'wb'])
def test_real_stdio_reads_and_writes_remote_bytes(preload, mode):
    preload(action='stdio', detail=mode, force=1)


@pytest.mark.parametrize('mode', ['', '<null>', 'a', 'a+', 'r+', 'w+', 'x'])
def test_unsupported_stdio_mode_never_falls_back_to_local_path(preload, mode):
    preload(action='stdio', detail=mode, expected=errno.ENOTSUP)


@pytest.mark.parametrize('fault,mode,error', [('cookie', 'r', errno.ENOMEM),
    ('connect', 'r', errno.EIO), ('open', 'w', errno.EACCES),
    ('read', 'r', 0), ('write', 'w', 0), ('reopen', 'r', 0)])
def test_stdio_errors_and_freopen_preserve_ownership(preload, fault, mode, error):
    preload(action='stdio', fault=fault, detail=mode, expected=error, force=1)

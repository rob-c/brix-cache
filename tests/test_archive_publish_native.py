"""Archive publication and recall verify exact ZIP bytes and failed-copy cleanup."""

import errno
import os
from pathlib import Path
import subprocess
import zipfile

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def archive(server_native_compile):
    names = ['fsync', 'rename', 'malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc']
    return server_native_compile('archive-publish', 'tests/c/archive_publish_native_test.c',
        ['-I' + str(Path(__file__).resolve().parents[1] / 'tests/c')] +
        [f'-Wl,--wrap={name}' for name in names])


def invoke(binary, root, action='compose', mode='normal', key='/dataset/.brix-dataset-complete'):
    result = subprocess.run([str(binary), action, mode, str(root), key],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return {key: int(value) for key, value in
            (line.split('=', 1) for line in result.stdout.splitlines())}


def dataset(root, entries):
    directory = root / '.online/dataset'
    directory.mkdir(parents=True)
    (directory / '.brix-dataset-complete').touch()
    for name, content in entries.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return directory


@pytest.mark.parametrize('count', [0, 1, 70])
def test_sealed_archive_and_index_preserve_sorted_members(archive, tmp_path, count):
    entries = {f'part/{n:03d}': bytes(range(n)) for n in range(count)}
    directory = dataset(tmp_path, entries)
    (directory / 'outside-link').symlink_to('/etc/passwd')
    os.mkfifo(directory / 'pipe')
    result = invoke(archive, tmp_path)
    assert result['rc'] == 0 and result['migrations'] == 2
    with zipfile.ZipFile(tmp_path / '.online/dataset.brixarc.zip') as packed:
        assert packed.namelist() == sorted(entries)
        assert {name: packed.read(name) for name in packed.namelist()} == entries
    assert not list(tmp_path.rglob('*.tmp'))


@pytest.mark.parametrize('mode', ['realloc', 'strdup', 'calloc', 'archive-sync', 'archive-rename', 'migrate-archive'])
def test_early_archive_failure_leaves_dataset_unsealed(archive, tmp_path, mode):
    directory = dataset(tmp_path, {'file': b'original'})
    result = invoke(archive, tmp_path, mode=mode)
    assert result['rc'] == -1 and not (tmp_path / '.arcidx/dataset.idx').exists()
    assert not (tmp_path / '.online/dataset.brixarc.zip').exists()
    assert (directory / 'file').read_bytes() == b'original'
    assert not list(tmp_path.rglob('*.tmp'))


@pytest.mark.parametrize('mode', ['index-sync', 'index-rename', 'migrate-marker'])
def test_post_migration_failure_retains_recoverable_archive(archive, tmp_path, mode):
    dataset(tmp_path, {'file': b'original'})
    result = invoke(archive, tmp_path, mode=mode)
    assert result['rc'] == -1
    with zipfile.ZipFile(tmp_path / '.online/dataset.brixarc.zip') as packed:
        assert packed.read('file') == b'original'
    assert not list(tmp_path.rglob('*.tmp'))


def test_second_compose_cannot_replace_a_sealed_dataset(archive, tmp_path):
    dataset(tmp_path, {'file': b'original'})
    assert invoke(archive, tmp_path)['rc'] == 0
    before = (tmp_path / '.online/dataset.brixarc.zip').read_bytes()
    result = invoke(archive, tmp_path)
    assert result['rc'] == -1 and result['errno'] == errno.EEXIST and result['migrations'] == 0
    assert (tmp_path / '.online/dataset.brixarc.zip').read_bytes() == before


def test_excessive_directory_depth_is_refused_before_publication(archive, tmp_path):
    directory = dataset(tmp_path, {})
    for _ in range(65):
        directory = directory / 'd'
        directory.mkdir()
    result = invoke(archive, tmp_path)
    assert result['rc'] == -1 and result['errno'] == errno.ELOOP and result['migrations'] == 0


@pytest.mark.parametrize('indexed', [False, True])
@pytest.mark.parametrize('mode', ['normal', 'realloc'])
def test_extract_rebuilds_missing_index_and_preserves_member_bytes(archive, tmp_path, indexed, mode):
    dataset(tmp_path, {})
    with zipfile.ZipFile(tmp_path / '.online/dataset.brixarc.zip', 'w') as packed:
        packed.writestr('member', b'exact archived bytes')
        packed.writestr('../escape', b'forbidden')
    if indexed:
        (tmp_path / '.arcidx').mkdir()
        (tmp_path / '.arcidx/dataset.idx').write_text('member\t20\t0\t0\n')
    result = invoke(archive, tmp_path, 'extract', mode, '/dataset/member')
    assert result['rc'] == 0 and result['purges'] == 0
    assert (tmp_path / '.online/dataset/member').read_bytes() == b'exact archived bytes'
    assert not (tmp_path / '.online/escape').exists()
    if mode == 'normal':
        assert (tmp_path / '.arcidx/dataset.idx').is_file()


def damaged_archive(tmp_path, variant):
    dataset(tmp_path, {})
    path = tmp_path / '.online/dataset.brixarc.zip'
    with zipfile.ZipFile(path, 'w') as packed:
        packed.writestr({'missing-member': 'different'}.get(variant, 'member'), b'original bytes')
    if variant == 'corrupt':
        path.write_bytes(path.read_bytes().replace(b'original bytes', b'corrupt! bytes'))
    if variant == 'invalid-container':
        path.write_bytes(b'invalid zip')


@pytest.mark.parametrize('variant', ['corrupt', 'missing-member', 'create-failure', 'invalid-container'])
def test_failed_extract_never_leaves_partial_member(archive, tmp_path, variant):
    damaged_archive(tmp_path, variant)
    mode = {'create-failure': 'create'}.get(variant, 'normal')
    result = invoke(archive, tmp_path, 'extract', mode, '/dataset/member')
    assert result['rc'] == -1 and not (tmp_path / '.online/dataset/member').exists()
    assert result['purges'] == int(variant == 'corrupt')

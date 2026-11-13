"""Missing-path resolution preserves names, bounds and export confinement."""

import stat
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def resolver(server_native_compile):
    return server_native_compile('path-resolution', 'tests/c/path_resolution_native_test.c')


def invoke(binary, root, path, operation='resolve', options=0, capacity=4096, result='result'):
    process = subprocess.run([str(binary), operation, str(root), str(path), str(options),
                              str(capacity), result], capture_output=True, text=True, timeout=10)
    assert process.returncode == 0, process.stdout + process.stderr
    summary, *resolved = process.stdout.splitlines()
    return dict((key, int(value)) for key, value in
                (field.split('=') for field in summary.split())), resolved


@pytest.mark.parametrize('operation', ['resolve', 'tail'])
def test_absent_leaf_directly_under_root_keeps_its_name(resolver, operation):
    path = '/brix-test-absent-leaf-a629b3'
    info, actual = invoke(resolver, '/', path, operation, options=1)
    assert info == {'status': 0, 'confined': 1, 'type': -2} and actual == [path]


@pytest.mark.parametrize('operation', ['resolve', 'tail', 'parents'])
@pytest.mark.parametrize('result', ['result', 'no-result'])
def test_new_leaf_under_existing_parent_retains_canonical_parent(resolver, tmp_path, operation, result):
    path = tmp_path / 'new-leaf'
    info, actual = invoke(resolver, tmp_path, path if operation != 'resolve' else '/new-leaf',
                          operation, options=1, result=result)
    assert info['status'] == 0 and actual == [str(path)]
    assert info['confined'] == (result == 'result')


@pytest.mark.parametrize('operation', ['tail', 'parents', 'finish'])
def test_symlink_parent_cannot_escape_export(resolver, tmp_path, operation):
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'outside').symlink_to(tmp_path, target_is_directory=True)
    candidate = root / 'outside/new-leaf' if operation != 'finish' else tmp_path / 'new-leaf'
    info, actual = invoke(resolver, root, candidate, operation, options=3)
    assert info['status'] == 1 and info['confined'] == 0 and actual == []


@pytest.mark.parametrize('path,expected', [('relative', 1), ('/tmp/', 1),
                                         ('a' * 4096, 3)])
def test_invalid_missing_tail_is_refused(resolver, path, expected):
    info, actual = invoke(resolver, '/', path, 'tail')
    assert info['status'] == expected and actual == []


@pytest.mark.parametrize('operation', ['resolve', 'tail', 'parents', 'finish'])
@pytest.mark.parametrize('capacity,expected', [(0, 4), (1, 3), (8, 3)])
def test_too_small_output_does_not_overrun_or_publish_a_path(resolver, tmp_path, operation, capacity, expected):
    path = '/new-leaf' if operation == 'resolve' else tmp_path / 'new-leaf'
    info, actual = invoke(resolver, tmp_path, path, operation, options=3, capacity=capacity)
    assert info['status'] == expected and info['confined'] == 0 and actual == []


def test_missing_parent_is_distinct_from_missing_leaf(resolver, tmp_path):
    info, actual = invoke(resolver, tmp_path, tmp_path / 'absent/leaf', 'tail')
    assert info['status'] == 2 and actual == []


def test_recursive_missing_suffix_is_retained(resolver, tmp_path):
    info, actual = invoke(resolver, tmp_path, '/absent/parent/leaf', options=2)
    assert info == {'status': 0, 'confined': 1, 'type': -2}
    assert actual == [str(tmp_path / 'absent/parent/leaf')]


@pytest.mark.parametrize('directory,expected', [(True, 0), (False, 1)])
def test_directory_requirement_uses_actual_file_type(resolver, tmp_path, directory, expected):
    target = tmp_path / 'target'
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b'data')
    info, actual = invoke(resolver, tmp_path, target, 'finish', options=4)
    assert info['status'] == expected
    assert actual == ([str(target)] if directory else [])
    if directory:
        assert info['type'] == stat.S_IFDIR

"""Bad reference output must fail a test without exhausting its validation host."""
import pytest
import ast
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from lib_py.reference_host import (
    fixture_read_bytes, reference_read_bytes, reference_write_target,
)


def _unbounded_read_call(node):
    """Identify direct EOF reads; fixed-size probes remain a separate contract."""
    return (isinstance(node.func, ast.Attribute)
            and node.func.attr in ('read', 'read_bytes')
            and not node.args and not node.keywords)


@pytest.mark.parametrize('path', sorted([
    *Path(__file__).parent.glob('test_conf_*.py'),
    *Path(__file__).parent.glob('_test_conf_*helpers*.py'),
    Path(__file__).with_name('_test_aio_helpers.py'),
    Path(__file__).with_name('test_file_api.py'),
    Path(__file__).with_name('_test_file_api_helpers.py'),
]), ids=lambda path: path.name)
def test_differential_corpora_cannot_read_unbounded_fixture_output(path):
    """A broken reference's sparse extent must never become a VM-sized read."""
    tree = ast.parse(path.read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert not any(_unbounded_read_call(node) for node in calls)


@pytest.mark.parametrize('content', [b'', bytes(range(256)) * 4])
def test_reference_fixture_read_is_byte_exact(tmp_path, content):
    path = tmp_path / 'payload'
    path.write_bytes(content)
    assert fixture_read_bytes(path, limit=len(content)) == content


def test_missing_reference_fixture_remains_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        fixture_read_bytes(tmp_path / 'missing')


def test_oversized_sparse_reference_output_is_refused_before_read(tmp_path):
    path = tmp_path / 'sparse'
    with path.open('wb') as stream:
        stream.truncate(1 << 40)
    with pytest.raises(AssertionError, match='fixture size 1099511627776 exceeds'):
        fixture_read_bytes(path)


def test_reference_fixture_growth_is_not_silently_truncated(tmp_path, monkeypatch):
    import lib_py.reference_host as module

    path = tmp_path / 'growing'
    path.write_bytes(b'ab')
    observed_stat = module.os.fstat

    def grow_after_stat(descriptor):
        result = observed_stat(descriptor)
        with path.open('ab') as stream:
            stream.write(b'cdef')
        return result

    monkeypatch.setattr(module.os, 'fstat', grow_after_stat)
    with pytest.raises(AssertionError, match='fixture changed'):
        fixture_read_bytes(path)


class _ReferenceFile:
    """Observe the public handle calls without depending on XrdCl internals."""

    def __init__(self, content, size, *, stat_ok=True, read_ok=True):
        self.content = content
        self.size = size
        self.stat_ok = stat_ok
        self.read_ok = read_ok
        self.calls = []

    def stat(self):
        self.calls.append(('stat',))
        return (SimpleNamespace(ok=self.stat_ok, message='stat diagnostic'),
                SimpleNamespace(size=self.size))

    def read(self, *, offset, size):
        self.calls.append(('read', offset, size))
        return (SimpleNamespace(ok=self.read_ok, message='read diagnostic'),
                self.content[offset:offset + size])


@pytest.mark.parametrize('content', [b'', bytes(range(256)) * 4])
def test_remote_reference_read_is_byte_exact_and_explicitly_bounded(content):
    stream = _ReferenceFile(content, len(content))
    assert reference_read_bytes(stream, len(content)) == content
    assert stream.calls == [('stat',), ('read', 0, len(content) + 1)]


@pytest.mark.parametrize('reported_size', [-1, 0, 3, 192 * 1024 ** 4])
def test_remote_reference_bad_extent_fails_before_any_data_read(reported_size):
    stream = _ReferenceFile(b'ab', reported_size)
    with pytest.raises(AssertionError, match='differs from expected 2'):
        reference_read_bytes(stream, 2)
    assert stream.calls == [('stat',)]


@pytest.mark.parametrize('content', [b'a', b'abc'])
def test_remote_reference_read_cannot_hide_short_or_growing_output(content):
    stream = _ReferenceFile(content, 2)
    with pytest.raises(AssertionError, match='fixture changed'):
        reference_read_bytes(stream, 2)
    assert stream.calls == [('stat',), ('read', 0, 3)]


@pytest.mark.parametrize('operation', ['stat', 'read'])
def test_remote_reference_errors_are_not_reclassified_as_empty_data(operation):
    flags = {operation + '_ok': False}
    stream = _ReferenceFile(b'ab', 2, **flags)
    with pytest.raises(AssertionError, match=operation + ' diagnostic'):
        reference_read_bytes(stream, 2)


@pytest.mark.parametrize('expected_size', [-1, 128 * 1024 * 1024 + 1])
def test_remote_reference_bad_budget_fails_before_touching_handle(expected_size):
    stream = _ReferenceFile(b'', 0)
    with pytest.raises(AssertionError, match='read budget'):
        reference_read_bytes(stream, expected_size)
    assert stream.calls == []


class _ReferenceNamespace:
    """Keep an unrelated object while observing endpoint-scoped cleanup."""

    def __init__(self, *, ok=True, error=0):
        self.objects = {'/foreign-object': b'untouched'}
        self.calls = []
        self.status = SimpleNamespace(ok=ok, errno=error, message='remove diagnostic')

    def rm(self, path, *, timeout):
        self.calls.append((path, timeout))
        self.objects.pop(path, None)
        return self.status, None


def test_remote_reference_write_target_is_unique_and_cleans_only_owned_names():
    filesystem = _ReferenceNamespace()
    with reference_write_target(filesystem) as first:
        with reference_write_target(filesystem) as second:
            assert first != second
            assert first.startswith('aio-write-') and first.endswith('.bin')
            assert '/' not in first and '/' not in second
            filesystem.objects['/' + first] = b'first'
            filesystem.objects['/' + second] = b'second'
    assert filesystem.calls == [('/' + second, 5), ('/' + first, 5)]
    assert filesystem.objects == {'/foreign-object': b'untouched'}


def test_remote_reference_write_target_is_removed_after_writer_failure():
    filesystem = _ReferenceNamespace()
    with pytest.raises(RuntimeError, match='writer failed'):
        with reference_write_target(filesystem) as name:
            filesystem.objects['/' + name] = b'partial'
            raise RuntimeError('writer failed')
    assert filesystem.calls == [('/' + name, 5)]
    assert filesystem.objects == {'/foreign-object': b'untouched'}


def test_remote_reference_missing_target_is_already_clean():
    filesystem = _ReferenceNamespace(ok=False, error=3011)
    with reference_write_target(filesystem) as name:
        pass
    assert filesystem.calls == [('/' + name, 5)]


@pytest.mark.parametrize('error', [0, 3010, 3007])
def test_remote_reference_cleanup_errors_cannot_be_silenced(error):
    filesystem = _ReferenceNamespace(ok=False, error=error)
    with pytest.raises(AssertionError, match='remove diagnostic'):
        with reference_write_target(filesystem):
            pass


@pytest.mark.parametrize('optimization', [[], ['-O']], ids=['normal', 'optimized'])
def test_fixture_read_budgets_survive_python_optimization(tmp_path, optimization):
    """Resource safety must not disappear when Python removes assertions."""
    path = tmp_path / 'two-bytes'
    path.write_bytes(b'ab')
    script = '''
import sys
from lib_py.reference_host import fixture_read_bytes, reference_read_bytes

def require_refusal(operation):
    try:
        operation()
    except AssertionError:
        return
    raise SystemExit('fixture read budget disappeared')

require_refusal(lambda: fixture_read_bytes(sys.argv[1], limit=1))
require_refusal(lambda: reference_read_bytes(None, 2, limit=1))
'''
    environment = dict(os.environ, PYTHONPATH=str(Path(__file__).parent))
    result = subprocess.run([sys.executable, *optimization, '-c', script, str(path)],
                            env=environment, capture_output=True, text=True,
                            timeout=5, check=False)
    assert result.returncode == 0, result.stdout + result.stderr

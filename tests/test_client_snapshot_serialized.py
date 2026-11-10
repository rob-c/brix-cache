"""Private executable copies share the build writer's lock."""

from pathlib import Path
import threading

import pytest

from brix_suite import client_build


def executable(path, content='complete'):
    path.write_text(content)
    path.chmod(0o755)
    return path


def test_snapshot_waits_for_a_paused_nonempty_linker_output(tmp_path):
    source = executable(tmp_path / 'driver', 'partial')
    target = tmp_path / 'snapshot'
    started, completed = threading.Event(), threading.Event()
    errors = []
    def copy():
        started.set()
        try:
            client_build.client_snapshot(tmp_path, source, target)
        except BaseException as error:
            errors.append(error)
        finally:
            completed.set()
    with client_build._tree_lock(tmp_path):
        worker = threading.Thread(target=copy)
        worker.start()
        assert started.wait(5)
        assert not completed.wait(.1)
        source.write_text('complete')
    worker.join(5)
    assert completed.is_set() and not errors
    assert target.read_text() == 'complete'
    assert target.stat().st_mode & 0o111
    source.write_text('rebuilt')
    assert target.read_text() == 'complete'


@pytest.mark.parametrize('kind', ['missing', 'empty', 'not-executable', 'directory'])
def test_invalid_source_preserves_destination_and_releases_lock(tmp_path, kind):
    source, target = tmp_path / 'driver', tmp_path / 'snapshot'
    target.write_text('untouched')
    invalid_source(source, kind)
    with pytest.raises((OSError, ValueError)):
        client_build.client_snapshot(tmp_path, source, target)
    assert target.read_text() == 'untouched'
    valid = executable(tmp_path / 'valid')
    assert client_build.client_snapshot(tmp_path, valid, target) == target
    assert target.read_text() == 'complete'


def invalid_source(source, kind):
    if kind == 'directory':
        source.mkdir()
    elif kind != 'missing':
        executable(source, '' if kind == 'empty' else 'complete')
        if kind == 'not-executable':
            source.chmod(0o600)


def test_untrusted_lock_cannot_copy_an_executable(tmp_path):
    source = executable(tmp_path / 'driver')
    target = tmp_path / 'snapshot'
    lock_target = tmp_path / 'protected'
    lock_target.write_text('untouched')
    lock = Path(client_build.make_lock_path(tmp_path))
    lock.symlink_to(lock_target)
    try:
        with pytest.raises(OSError):
            client_build.client_snapshot(tmp_path, source, target)
        assert not target.exists() and lock_target.read_text() == 'untouched'
    finally:
        lock.unlink()

"""Real harmless processes prove helper detection cannot reap a suite runner."""

from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from brix_suite import orphans


@contextmanager
def _process(arguments, root, **environment):
    """Keep each child in its own test root and always reap our exact Popen."""
    process = subprocess.Popen(
        [sys.executable, *arguments],
        env=dict(os.environ, TEST_ROOT=str(root), **environment),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def test_python_script_helper_is_reaped(tmp_path):
    """A real repository helper still follows TEST_ROOT ownership."""
    with _process(['-u', str(Path(__file__).resolve()), '--idle'], tmp_path) as child:
        assert child.pid in dict(orphans.find_orphans(tmp_path))
        assert orphans.kill_orphans(tmp_path) == []
        assert child.wait(timeout=5) < 0


def test_test_path_argument_is_not_a_helper(tmp_path):
    """A data argument naming this tree never turns Python -c into a daemon."""
    args = ['-c', 'import time; time.sleep(120)', str(Path(__file__).resolve())]
    with _process(args, tmp_path) as child:
        assert child.pid not in dict(orphans.find_orphans(tmp_path))
        assert orphans.kill_orphans(tmp_path) == []
        assert child.poll() is None


def test_operator_module_with_ignore_option_is_protected(tmp_path):
    """The suite module's --ignore path cannot cause it to be killed as a helper."""
    package = tmp_path / 'cmdscripts'
    package.mkdir()
    (package / '__init__.py').write_text('')
    (package / 'operator_runtime.py').write_text('import time; time.sleep(120)\n')
    args = ['-m', 'cmdscripts.operator_runtime',
            '--ignore=' + str(Path(__file__).resolve())]
    with _process(args, tmp_path, PYTHONPATH=str(tmp_path)) as child:
        assert child.pid not in dict(orphans.find_orphans(tmp_path))
        with pytest.raises(orphans.ForeignLaneError):
            orphans.kill_orphans(tmp_path)
        assert child.poll() is None


@pytest.mark.parametrize('entry', ['script', 'module'])
def test_operator_entrypoint_is_never_a_helper(monkeypatch, entry):
    """Both supported spellings remain harnesses even inside the tests tree."""
    script = Path(__file__).parent / 'cmdscripts' / 'operator_runtime.py'
    arguments = [sys.executable, str(script)] if entry == 'script' else [
        sys.executable, '-m', 'cmdscripts.operator_runtime']
    monkeypatch.setattr(orphans, '_process_argv', lambda pid: arguments)
    monkeypatch.setattr(orphans, '_environ', lambda pid: b'TEST_ROOT=/tmp/owned\0')
    command = ' '.join(arguments)
    assert orphans._is_harness_cmd(command)
    assert not orphans._helper_matches(900001, 'python', command)


if __name__ == '__main__':
    time.sleep(120)

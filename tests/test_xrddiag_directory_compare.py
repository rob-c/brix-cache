"""The diagnostic directory oracle compares name sets and reports inaccessible peers."""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from settings import DATA_ROOT
from test_xrddiag import ANON_URL, _run, xrddiag  # noqa: F401


pytestmark = [pytest.mark.serial, pytest.mark.registry_server('main')]


@pytest.fixture
def compare_directories(xrddiag):
    with TemporaryDirectory(prefix='diag-compare-', dir=DATA_ROOT) as directory:
        root = Path(directory)
        for name in ('left', 'right'):
            target = root / name
            target.mkdir()
            (target / 'alpha').write_bytes(b'first')
            (target / 'beta').write_bytes(b'second')
        yield root


def compare(root):
    base = f'{ANON_URL}/{root.name}'
    return _run('compare', base + '/left', '--vs-reference', base + '/right')


def test_equal_directory_names_match(compare_directories):
    result = compare(compare_directories)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '[PASS] dirlist-set' in result.stdout
    assert 'A=2 B=2 entries' in result.stdout


@pytest.mark.parametrize('difference', ['count', 'name'])
def test_directory_name_differences_are_reported(compare_directories, difference):
    right = compare_directories / 'right'
    (right / 'beta').unlink()
    if difference == 'name':
        (right / 'zeta').write_bytes(b'second')
    result = compare(compare_directories)
    assert result.returncode == 1, result.stdout + result.stderr
    assert '[FAIL] dirlist-set' in result.stdout


def test_missing_reference_cannot_report_a_match(compare_directories):
    right = compare_directories / 'right'
    for child in right.iterdir():
        child.unlink()
    right.rmdir()
    result = compare(compare_directories)
    assert result.returncode == 1, result.stdout + result.stderr
    assert '[FAIL] stat' in result.stdout

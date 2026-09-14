"""Collect exact parametrized identities without running fixtures or any fleet."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.harness.xdist_groups import materialize_xdist_group
from conftest_part3 import _force_xdist_group


class _Item:
    def __init__(self, nodeid, groups=()):
        self._nodeid = nodeid
        self.markers = [pytest.mark.xdist_group(group).mark for group in groups]

    @property
    def nodeid(self):
        return self._nodeid

    def iter_markers(self, name):
        return self.markers if name == 'xdist_group' else []

    def add_marker(self, marker, append=True):
        self.markers.append(marker.mark)


@pytest.mark.parametrize('original,expected', [
    ('test_one', 'test_one'),
    ('test_one[value@tag-posix]', 'test_one[value@tag-posix]'),
    ('test_one[value@tag-posix]@old', 'test_one[value@tag-posix]'),
    ('test_one[left]@right-posix]@old', 'test_one[left]@right-posix]'),
    ('test_one[value@tag]@old@another', 'test_one[value@tag]'),
    ('test_one@old', 'test_one'),
])
def test_group_materialization_preserves_parameter_identity(original, expected):
    item = _Item('tests/test_fixture.py::' + original, ('zeta', 'alpha'))
    materialize_xdist_group(item)
    target = 'tests/test_fixture.py::' + expected + '@alpha_zeta'
    assert item.nodeid == target
    materialize_xdist_group(item)
    assert item.nodeid == target, 'materialization must be idempotent'


def test_missing_group_does_not_rewrite_a_unique_identity():
    original = 'tests/test_fixture.py::test_one[identity@parameter]'
    item = _Item(original)
    materialize_xdist_group(item)
    assert item.nodeid == original


def test_forced_group_reuses_parameter_safe_materialization():
    item = _Item('tests/test_fixture.py::test_one[identity@parameter]@stale', ('stale',))
    _force_xdist_group(item, 'shared-owner')
    assert item.nodeid == 'tests/test_fixture.py::test_one[identity@parameter]@shared-owner'
    materialize_xdist_group(item)
    assert item.nodeid.endswith('[identity@parameter]@shared-owner')


_COLLECTOR = '''
import json
import os
from pathlib import Path
from brix_suite.harness.xdist_groups import materialize_xdist_group

def pytest_collection_modifyitems(items):
    for item in items:
        materialize_xdist_group(item)

def pytest_collection_finish(session):
    rows = []
    for item in session.items:
        params = getattr(getattr(item, "callspec", None), "params", {})
        rows.append({"nodeid": item.nodeid,
                     "parameters": {k: v for k, v in params.items() if isinstance(v, str)},
                     "byte_lengths": {k: len(v) for k, v in params.items() if isinstance(v, bytes)}})
    Path(os.environ["BRIX_GROUP_COLLECT_OUTPUT"]).write_text(json.dumps(rows))
'''


def _collect_only(tmp_path, selector):
    """The child loads just our hook and pytest; every fixture stays unexecuted."""
    (tmp_path / 'group_probe.py').write_text(_COLLECTOR)
    config = tmp_path / 'pytest.ini'
    config.write_text('[pytest]\nmarkers =\n    xdist_group\n    timeout\n    uses_lifecycle_harness\n')
    output = tmp_path / 'collected.json'
    env = os.environ.copy()
    env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', TEST_SKIP_SERVER_SETUP='1', TEST_OWN_FLEET='0',
               TEST_ROOT=str(tmp_path / 'private-root'), BRIX_GROUP_COLLECT_OUTPUT=str(output))
    imports = [str(tmp_path), str(Path(__file__).resolve().parent),
               str(Path(__file__).resolve().parents[1] / 'brixtest/src')]
    env['PYTHONPATH'] = os.pathsep.join(imports + [env.get('PYTHONPATH', '')])
    proc = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '--noconftest',
                           '-p', 'group_probe', '-c', str(config), '--rootdir', str(tmp_path),
                           '-o', 'addopts=', '-q', str(selector)],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(output.read_text())


def test_byte_parameter_at_sign_does_not_collapse_the_plane_axis(tmp_path):
    source = tmp_path / 'test_owned_collection.py'
    source.write_text('''
import pytest
pytestmark = pytest.mark.xdist_group("owned-group")
@pytest.fixture
def forbidden():
    raise AssertionError("collection must not execute fixtures")
@pytest.mark.parametrize("plane", ["posix", "posix_tls", "pblock", "pblock_tls"])
@pytest.mark.parametrize("payload", [b"before@after"])
def test_cells(forbidden, plane, payload):
    raise AssertionError("collection must not execute test bodies")
''')
    rows = _collect_only(tmp_path, source)
    assert len(rows) == len({row['nodeid'] for row in rows}) == 4
    assert {row['parameters']['plane'] for row in rows} == {'posix', 'posix_tls', 'pblock', 'pblock_tls'}
    assert all('before@after-' in row['nodeid'] and row['nodeid'].endswith(']@owned-group') for row in rows)


def test_real_tls_whole_get_collects_all_eight_unique_cells(tmp_path):
    source = Path(__file__).with_name('test_tls_sendfile_matrix.py')
    rows = _collect_only(tmp_path, str(source) + '::test_whole_get_is_byte_exact')
    assert len(rows) == len({row['nodeid'] for row in rows}) == 8
    expected = {(name, plane) for name in ('small.bin', 'big.bin')
                for plane in ('posix', 'posix_tls', 'pblock', 'pblock_tls')}
    assert {(row['parameters']['name'], row['parameters']['plane']) for row in rows} == expected
    _assert_tls_case_labels_and_payloads(rows)


def _assert_tls_case_labels_and_payloads(rows):
    assert {row['byte_lengths']['payload'] for row in rows} == {16_384, 262_921}
    assert all(len(row['nodeid']) < 200 and row['nodeid'].endswith(']@lc-tls-sendfile') for row in rows)

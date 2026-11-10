"""Real GCC/LCOV captures distinguish absent execution from corrupt profiles."""

from pathlib import Path
import shutil
import shlex
import subprocess
import sys

import pytest

from tools.ci import coverage, coverage_merge


pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or not shutil.which('gcc') or not shutil.which('lcov'),
    reason='requires Linux GCC and LCOV')


@pytest.fixture
def production_inventory(tmp_path):
    """Build a real unexecuted production inventory in an isolated source tree."""
    root = tmp_path / 'repo'
    source = root / 'src/branch.c'
    source.parent.mkdir(parents=True)
    source.write_text('int main(int argc, char **argv) {\n'
                      '    (void) argv;\n'
                      '    if (argc == 2) { return 0; }\n'
                      '    return 7;\n}\n')
    objects = root / 'objects'
    objects.mkdir()
    subprocess.run(['gcc', '--coverage', '-O0', '-fprofile-abs-path', str(source),
                    '-o', str(objects / 'server')], check=True, capture_output=True)
    initial = tmp_path / 'initial.info'
    coverage._capture(str(root), [str(objects)], str(initial), initial=True)
    return root, source, objects, initial


def test_standalone_execution_counts_without_server_execution(production_inventory,
                                                            tmp_path):
    """Real unit hits cover the unchanged inventory with an empty server stream."""
    root, source, objects, initial = production_inventory
    units = tmp_path / 'units'
    units.mkdir()
    binary = units / 'unit'
    subprocess.run(['gcc', '--coverage', '-O0', '-fprofile-abs-path', str(source),
                    '-o', str(binary)], check=True, capture_output=True)
    assert subprocess.run([str(binary), 'success']).returncode == 0
    assert subprocess.run([str(binary)]).returncode == 7
    server, unit = tmp_path / 'server.info', tmp_path / 'unit.info'
    coverage._capture(str(root), [str(objects)], str(server))
    coverage._capture(str(root), [str(units)], str(unit))
    report = tmp_path / 'final.info'
    coverage_merge.merge_execution(initial, [server, unit], report)
    assert server.read_text() == ''
    assert coverage_merge.line_rate(report) == '100.0'


def test_no_execution_cannot_pass_the_requested_floor(production_inventory,
                                                     tmp_path):
    """Empty captures retain every unexecuted line and fail the real gate."""
    root, _source, objects, initial = production_inventory
    empty, report = tmp_path / 'empty.info', tmp_path / 'final.info'
    coverage._capture(str(root), [str(objects)], str(empty))
    coverage_merge.merge_execution(initial, [empty], report)
    assert coverage_merge.line_rate(report) == '0.0'
    assert coverage._coverage_verdict(0, coverage_merge.line_rate(report), '90') == 1


def test_corrupt_profile_is_not_treated_as_absent(production_inventory, tmp_path):
    """A malformed counter file must surface LCOV's failure, never a zero report."""
    root, _source, objects, _initial = production_inventory
    note, = objects.glob('*.gcno')
    note.with_suffix('.gcda').write_bytes(b'not a gcov counter file')
    output = tmp_path / 'must-not-exist.info'
    with pytest.raises(SystemExit) as failure:
        coverage._capture(str(root), [str(objects)], str(output))
    assert failure.value.code != 0
    assert not output.exists()


@pytest.mark.parametrize('relative', ['tests/driver.c', 'client/tests/driver.c'])
def test_fixture_only_execution_cannot_raise_production_coverage(
        production_inventory, tmp_path, relative):
    """A valid test-only capture is empty and cannot satisfy the production gate."""
    root, _source, _objects, initial = production_inventory
    driver = root / relative
    driver.parent.mkdir(parents=True, exist_ok=True)
    driver.write_text('int main(void) { return 0; }\n')
    units = tmp_path / 'fixture-counters'
    units.mkdir()
    binary = units / 'driver'
    subprocess.run(['gcc', '--coverage', '-O0', '-fprofile-abs-path', str(driver),
                    '-o', str(binary)], check=True, capture_output=True)
    assert subprocess.run([str(binary)]).returncode == 0
    capture, merged = tmp_path / 'fixture.info', tmp_path / 'merged.info'
    coverage._capture(str(root), [str(units)], str(capture))
    assert list(coverage_merge._records(capture)) == []
    coverage_merge.merge_execution(initial, [capture], merged)
    assert coverage_merge.line_rate(merged) == '0.0'
    assert coverage._coverage_verdict(0, coverage_merge.line_rate(merged), '90') == 1


@pytest.fixture
def shared_build(tmp_path, monkeypatch):
    """Place real production notes where the shared client archive builds them."""
    root = tmp_path / 'repo'
    for relative in ['src', 'client', 'shared/xrdproto/build', 'nginx/objs', 'tests', 'report']:
        (root / relative).mkdir(parents=True)
    source = root / 'src/branch.c'
    source.write_text('int main(int argc, char **argv) {\n'
                      '    (void) argv;\n'
                      '    if (argc == 2) { return 0; }\n'
                      '    return 7;\n}\n')
    binary = root / 'shared/xrdproto/build/consumer'
    subprocess.run(['gcc', '--coverage', '-O0', '-fprofile-abs-path', str(source),
                    '-o', str(binary)], check=True, capture_output=True)
    monkeypatch.setenv('COVERAGE_PRIVILEGED', '0')
    monkeypatch.setenv('COVERAGE_MIN', '0')
    return root, binary


def collect_shared(root, command):
    return coverage._run_and_capture(str(root), str(root / 'nginx'),
                                     str(root / 'report'), command)


def test_shared_archive_execution_is_captured_and_old_hits_are_reset(shared_build):
    root, binary = shared_build
    assert subprocess.run([str(binary)]).returncode == 7
    assert collect_shared(root, shlex.join([str(binary), 'success'])) == 0
    source, rows = next(coverage_merge._records(root / 'report/coverage.info'))
    assert source == str(root / 'src/branch.c')
    counts = {int(row[3:].split(',')[0]): int(row.split(',')[1])
              for row in rows if row.startswith('DA:')}
    assert counts[3] > 0 and counts[4] == 0


def test_shared_consumer_failure_still_fails_the_collector(shared_build):
    root, binary = shared_build
    assert collect_shared(root, shlex.join([str(binary)])) == 7
    assert float(coverage_merge.line_rate(root / 'report/coverage.info')) > 0


def test_corrupt_shared_counter_cannot_be_ignored(shared_build):
    root, binary = shared_build
    counter, = binary.parent.glob('*.gcno')
    script = f'from pathlib import Path; Path({str(counter.with_suffix(".gcda"))!r}).write_bytes(b"bad")'
    with pytest.raises(SystemExit) as failure:
        collect_shared(root, shlex.join([sys.executable, '-c', script]))
    assert failure.value.code != 0


@pytest.mark.parametrize('relative,in_inventory', [
    ('tests/c/smoke.c', False), ('lib/tests/helper.c', True),
    ('apps/test_cli.c', True),
])
def test_client_test_directory_is_not_production_coverage(tmp_path, relative,
                                                         in_inventory):
    """Exclude only the actual fixture directory, retaining similarly named code."""
    root = tmp_path / 'repo'
    source = root / 'src/production.c'
    source.parent.mkdir(parents=True)
    source.write_text('int production(void) { return 0; }\n')
    consumer = root / 'client' / relative
    consumer.parent.mkdir(parents=True)
    consumer.write_text('int production(void);\n'
                        'int main(void) { return production(); }\n')
    objects = root / 'objects'
    objects.mkdir()
    binary = objects / 'consumer'
    subprocess.run(['gcc', '--coverage', '-O0', '-fprofile-abs-path',
                    str(source), str(consumer), '-o', str(binary)],
                    check=True, capture_output=True)
    assert subprocess.run([str(binary)]).returncode == 0
    for initial in (True, False):
        report = tmp_path / f'coverage-{initial}.info'
        coverage._capture(str(root), [str(objects)], str(report), initial=initial)
        sources = {name for name, _rows in coverage_merge._records(report)}
        assert str(source) in sources
        assert (str(consumer) in sources) == in_inventory

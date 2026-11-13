"""Append real Linux root tests to an explicitly enabled coverage run.

Run only on a disposable test host/container: the existing fixtures provision
temporary accounts and exercise namespaces/network rules. coverage.py invokes
this through sudo after the ordinary suite; counters are never reset here.
"""

from pathlib import Path
import argparse
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))


def _selection():
    """Use the existing root contract suites plus finite native broker tests."""
    tests = ROOT / 'tests'
    selected = sorted(tests.glob('test_mu_*.py'))
    selected += [tests / name for name in (
        'test_impersonation_gridmap_root.py', 'test_pblock_group_multiuser.py',
        'test_pblock_privilege_drop.py', 'test_worker_deescalation_root.py',
        'test_chkpoint_recover_export.py', 'mu_authz_lib/test_accounts_selftest.py',
        'test_fault_proxy_privileged.py', 'test_worker_bounding_native.py',
        'test_fault_privileged_finite.py',
        'test_impersonation_finite_native.py', 'test_coverage_compiler.py')]
    return list(map(str, selected))


def _prepare_counters(directories):
    """Let uid-switched workers append to this disposable instrumented build."""
    for directory in directories:
        for note in directory.rglob('*.gcno'):
            data = note.with_suffix('.gcda')
            data.touch(exist_ok=True)
            data.chmod(0o666)


def _finish_counters(directories, units):
    """Remove unexecuted empty placeholders and return reports to the caller."""
    for directory in directories:
        for data in directory.rglob('*.gcda'):
            if data.stat().st_size == 0:
                data.unlink()
    if 'SUDO_UID' in os.environ:
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        for path in [units, *units.rglob('*')]:
            os.chown(path, uid, gid, follow_symlinks=False)


def _read_namespace_ranges(path):
    """Reject malformed delegation before selecting an unused ID range."""
    entries = []
    for row in path.read_text().splitlines():
        if not row.strip():
            continue
        owner, first, count = row.split(':')
        first, count = int(first), int(count)
        if first < 0 or count <= 0:
            raise ValueError('invalid subordinate ID range')
        entries.append((owner, first, count))
    return entries


def _prepare_namespace_ranges(username, locations):
    """Delegate a private namespace range without replacing existing mappings."""
    for path, option in locations:
        entries = _read_namespace_ranges(path)
        if any(owner == username and count >= 65536 for owner, _first, count in entries):
            continue
        first = max([100000, *(start + count for _owner, start, count in entries)])
        last = first + 65535
        if last >= 2**32 - 1:
            raise ValueError('no subordinate ID range available')
        subprocess.run(['usermod', option, f'{first}-{last}', username], check=True)


def _prepare_namespace_identity():
    """Prepare only the invoking test user's mappings on this disposable host."""
    import pwd
    username = pwd.getpwuid(int(os.environ.get('SUDO_UID', os.getuid()))).pw_name
    _prepare_namespace_ranges(username, [(Path('/etc/subuid'), '--add-subuids'),
                                         (Path('/etc/subgid'), '--add-subgids')])


def _run_root_group():
    """Use a distinct test root, PKI and the canonical serial fleet teardown."""
    from cmdscripts import operator_runtime as runtime
    from brix_suite.security.pki import blitz_test_pki
    from brix_suite.security.tokens.manifest import fleet_artifacts
    from settings import TOKENS_DIR

    root = Path(os.environ['TEST_ROOT'])
    if not runtime._prepare_test_root(root):
        return 1
    blitz_test_pki()
    fleet_artifacts(TOKENS_DIR)
    common = ['-ra', '-q', '-p', 'no:randomly', '-p', 'no:rerunfailures',
              '-o', 'addopts=', '--tb=short']
    success = runtime._suite_serial_lane(root, _selection(), common)
    return 0 if success else 1


def main(arguments=()):
    """Refuse accidental use outside an active, explicitly enabled Linux run."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('privileged coverage requires Linux root')
    if os.environ.get('COVERAGE_PRIVILEGED') != '1':
        raise RuntimeError('set COVERAGE_PRIVILEGED=1 on a disposable test host')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--counters-only', choices=('prepare', 'finish'))
    options = parser.parse_args(arguments)
    units = Path(os.environ['BRIX_COVERAGE_COUNTERS']).resolve(strict=True)
    os.environ['PATH'] = str(units / 'bin') + os.pathsep + os.environ['PATH']
    directories = [Path(os.environ['NGINX_SRC']) / 'objs',
                   ROOT / 'client', ROOT / 'shared']
    if options.counters_only == 'finish':
        _finish_counters(directories, units)
        return 0
    if options.counters_only == 'prepare':
        _prepare_namespace_identity()
    _prepare_counters(directories)
    if options.counters_only == 'prepare':
        return 0
    root = os.environ.get('TEST_ROOT', '/tmp/xrd-test') + '-root'
    os.environ.update(TEST_ROOT=root, TMPDIR=root + '/tmp')
    Path(os.environ['TMPDIR']).mkdir(parents=True, exist_ok=True)
    try:
        return _run_root_group()
    finally:
        _finish_counters(directories, units)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))

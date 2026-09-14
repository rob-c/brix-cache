"""Pure-Python PAL runner shared by the platform and integration entrypoints."""

import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-p', '--platform', choices=('linux', 'darwin', 'windows', 'arm64', 'x86_64'))
    parser.add_argument('--performance', action='store_true')
    parser.add_argument('--coverage', action='store_true', help='Report Python harness coverage; requires pytest-cov')
    parser.add_argument('--html', action='store_true', help='Write HTML results; requires pytest-html')
    parser.add_argument('--junit', action='store_true')
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument('-q', '--quiet', action='store_true')
    verbosity.add_argument('-v', '--verbose', action='store_true')
    return parser


def _host():
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {'aarch64': 'arm64', 'amd64': 'x86_64'}.get(machine, machine)
    return system, arch


def _targets(directory, integration, system, arch):
    if integration:
        return [directory / 'test_phase3_integration.py']
    specific = {
        ('linux', 'arm64'): 'test_arm64_linux.py',
        ('darwin', 'arm64'): 'test_arm64_macos.py',
    }
    names = ['test_pal_api.py']
    if system == 'windows':
        names.append('test_windows.py')
    elif (system, arch) in specific:
        names.append(specific[system, arch])
    return [directory / name for name in names]


def _report_args(options, output):
    result = []
    if options.coverage:
        result += ['--cov=pal_test_helpers', '--cov-report=term-missing',
                   '--cov-report=html:' + str(output / 'coverage')]
    if options.html:
        result += ['--html=' + str(output / 'report.html'), '--self-contained-html']
    if options.junit or os.environ.get('CI') == 'true':
        result += ['--junitxml=' + str(output / 'results.xml')]
    return result


def command(options, integration, directory, system, arch):
    """Build argv only; no collection, dependency installs, or server actions."""
    targets = _targets(directory, integration, system, arch)
    if options.performance:
        # The integration suite's performance class is the actual owner; its
        # cases do not carry the old shell runner's nonexistent performance mark.
        targets = [str(directory / 'test_phase3_integration.py') + '::TestPerformanceRegression']
    return ([sys.executable, '-m', 'pytest', *map(str, targets),
             '-q' if options.quiet else '-v', '--tb=short']
            + _report_args(options, directory / 'test_results'))


def _environment(directory):
    env = os.environ.copy()
    root = directory.parents[1]
    imports = [str(directory), str(directory.parent), str(root / 'brixtest/src')]
    if env.get('PYTHONPATH'):
        imports.append(env['PYTHONPATH'])
    env['PYTHONPATH'] = os.pathsep.join(imports)
    return env


def main(argv=None, *, integration=False):
    parser = _parser()
    options = parser.parse_args(argv)
    system, arch = _host()
    if system not in ('linux', 'darwin', 'windows'):
        parser.error(f'unsupported host platform: {system}')
    if options.platform and options.platform not in (system, arch):
        parser.error(f'{options.platform} tests require that host; current host is {system}/{arch}')
    directory = Path(__file__).resolve().parent
    (directory / 'test_results').mkdir(exist_ok=True)
    result = subprocess.run(command(options, integration, directory, system, arch),
                            cwd=directory, env=_environment(directory), check=False)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode

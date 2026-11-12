#!/usr/bin/env python3
"""Keep the disposable Linux coverage workload separate from its CI agent.

Run each phase in a bounded systemd service with its own PID/proc namespace.
Keep the network shared for existing Docker oracles and their host listeners.
Only selected noncredential environment variables reach the service.
"""

import argparse
import os
from pathlib import Path
import pwd
import subprocess
import sys


def _environment(environment):
    names = ('PATH', 'PYTHONPATH', 'PYTHONUNBUFFERED', 'CI', 'GITHUB_ACTIONS',
             'NGINX_SRC', 'TEST_ROOT', 'COVERAGE_OUT', 'COVERAGE_MIN',
             'COVERAGE_PRIVILEGED', 'COVERAGE_TEST_CMD', 'COVERAGE_USERNS_PROFILE',
             'BRIX_CVMFS_APPARMOR_PROFILE', 'PYTEST_ADDOPTS')
    return [f'{name}={environment[name]}' for name in names if name in environment]


def _command(stage, root, python, username, memory_bytes, environment):
    # Leave at least a quarter of physical RAM outside this workload's cgroup.
    limit = memory_bytes * 3 // 4
    return ['sudo', '-n', 'systemd-run', '--wait', '--pipe', '--collect',
            '--property=MemoryAccounting=yes', f'--property=MemoryMax={limit}',
            '--property=MemorySwapMax=0', '--property=OOMPolicy=kill',
            '--property=Nice=5', f'--working-directory={root}',
            '/usr/bin/unshare', '--mount', '--pid', '--fork', '--kill-child',
            '--mount-proc', '/usr/bin/tini', '--',
            '/usr/sbin/runuser', '-u', username, '--',
            '/usr/bin/env', *_environment(environment), python,
            str(root / 'tools/ci/coverage.py'), '--stage', stage]


def _snapshot():
    for command in (['free', '-h'], ['df', '-h', '/', '/tmp/brix-coverage-fs']):
        subprocess.run(command, check=False)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'ordinary', 'privileged', 'userns', 'report'))
    options = parser.parse_args(arguments)
    if sys.platform != 'linux' or os.getuid() == 0:
        raise RuntimeError('coverage host wrapper requires an unprivileged Linux caller')
    root = Path(__file__).resolve().parents[2]
    memory = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
    command = _command(options.stage, root, sys.executable,
                       pwd.getpwuid(os.getuid()).pw_name, memory, os.environ)
    _snapshot()
    try:
        return subprocess.run(command, check=False).returncode
    finally:
        _snapshot()


if __name__ == '__main__':
    raise SystemExit(main())

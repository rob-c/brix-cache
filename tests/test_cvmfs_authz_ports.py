"""Private repo fixtures must stay inside their suite's reserved port lane."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('base', [10000, 11000, 12000])
def test_authz_fixture_uses_reserved_ports(base):
    """Relocating the suite must move both mock and nginx without overlap."""
    root = Path(__file__).resolve().parents[1]
    script = '''
import json
import test_cvmfs_repo_authz as authz
from conformance_common import PORT_BLOCKS
block = authz._BLOCK
print(json.dumps({'base': PORT_BLOCKS['srv_authz'],
                  'mocks': [block.mock() for _ in range(10)],
                  'nginx': [block.nginx() for _ in range(10)]}))
for allocate in (block.mock, block.nginx):
    try:
        allocate()
    except RuntimeError:
        continue
    raise AssertionError('allocation escaped reserved block')
'''
    env = dict(os.environ, TEST_PORT_START=str(base), PYTHONPATH=str(root / 'tests'))
    env.pop('CVMFS_CONFORMANCE_PORT_BASE', None)
    result = subprocess.run([sys.executable, '-c', script], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    ports = json.loads(result.stdout)
    assert base < ports['base'] < base + 3000
    assert ports['mocks'] == list(range(ports['base'], ports['base'] + 10))
    assert ports['nginx'] == list(range(ports['base'] + 10, ports['base'] + 20))

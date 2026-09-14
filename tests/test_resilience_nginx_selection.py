"""Resilience prerequisites use the selected build without starting a server."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('case', ['selected', 'missing', 'explicit-override'])
def test_resilience_prerequisite_tracks_the_selected_nginx(tmp_path, case):
    """An existing build is usable, an absent one stays absent, overrides survive."""
    selected = tmp_path / 'selected-nginx'
    override = tmp_path / 'override-nginx'
    if case != 'missing':
        selected.touch()
    override.touch()
    root = Path(__file__).resolve().parent
    env = dict(os.environ, TEST_NGINX_BIN=str(selected), TEST_SKIP_SERVER_SETUP='1')
    env['PYTHONPATH'] = os.pathsep.join((str(root), str(root / 'resilience')))
    env.pop('RESIL_NGINX_BIN', None)
    expected = selected
    if case == 'explicit-override':
        env['RESIL_NGINX_BIN'] = str(override)
        expected = override
    probe = subprocess.run(
        [sys.executable, '-c',
         'import json, os, servers; '
         'print(json.dumps([servers.NGINX_BIN, os.path.isfile(servers.NGINX_BIN)]))'],
        env=env, capture_output=True, text=True, timeout=20, check=True,
    )
    assert json.loads(probe.stdout) == [str(expected), case != 'missing']

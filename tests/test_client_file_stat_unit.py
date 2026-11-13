"""The public handle-stat helper must reject malformed and cross-stream replies."""

from pathlib import Path
import subprocess

import pytest

from brix_suite.client_build import client_make


@pytest.mark.parametrize('target', ['file-stat-unit', 'redir-registry-unit'])
def test_native_client_protocol_contract(tmp_path, target):
    client = Path(__file__).resolve().parents[1] / 'client'
    build = client_make(client, target, f'BINDIR={tmp_path}',
                        capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stdout + build.stderr
    result = subprocess.run([str(tmp_path / target.replace('-', '_'))], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'ALL PASS' in result.stdout

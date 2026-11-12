"""Execute the workflow fragments which previously failed on GitHub runners."""

import json
import os
from pathlib import Path
import subprocess
import tarfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow_step(workflow, job, name):
    doc = yaml.safe_load((ROOT / '.github/workflows' / workflow).read_text())
    return next(step['run'] for step in doc['jobs'][job]['steps'] if step.get('name') == name)


def test_release_bundle_is_written_beside_its_checksum(tmp_path):
    """GNU tar's -C changes its input directory, not its archive output path."""
    packages = tmp_path / 'dist/fedora44'
    packages.mkdir(parents=True)
    (packages / 'client.rpm').write_bytes(b'fixture-package')
    run = _workflow_step('packages.yml', 'rpm', 'Create a collision-free release bundle')
    run = run.replace('${{ matrix.distro }}', 'fedora44')
    subprocess.run(['bash', '-eu', '-c', run], cwd=tmp_path, check=True, capture_output=True)
    output = tmp_path / 'dist/brix-cache-fedora44-arm64.tar.gz'
    with tarfile.open(output) as archive:
        assert archive.extractfile('./client.rpm').read() == b'fixture-package'
    subprocess.run(['shasum', '-a', '256', '-c', output.name + '.sha256'],
                   cwd=output.parent, check=True, capture_output=True)
    assert not (tmp_path.parent / output.name).exists()


@pytest.mark.parametrize('selection,expected', [
    ('all', ['linux-x86_64', 'linux-arm64', 'macos-intel', 'macos-arm64']),
    ('linux-arm64', ['linux-arm64']), ('macos-intel', ['macos-intel']), ('windows', []),
])
def test_platform_matrix_is_valid_single_line_github_output(tmp_path, selection, expected):
    output = tmp_path / 'github-output'
    run = _workflow_step('platform-matrix.yml', 'platform-detect', 'Set matrix configuration')
    subprocess.run(['bash', '-eu', '-c', run], cwd=tmp_path, check=True, capture_output=True,
                   env={**os.environ, 'SELECTED_PLATFORM': selection, 'GITHUB_OUTPUT': str(output)})
    line, = output.read_text().splitlines()
    key, value = line.split('=', 1)
    assert key == 'matrix'
    assert [row['platform'] for row in json.loads(value)['include']] == expected

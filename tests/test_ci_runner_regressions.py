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


def _native_step(name):
    doc = yaml.safe_load((ROOT / '.github/actions/build-native/action.yml').read_text())
    return next(step['run'] for step in doc['runs']['steps'] if step.get('name') == name)


def _mac_sdk(tmp_path, **overrides):
    brew = tmp_path / 'brew'
    brew.write_text('#!/bin/sh\n'
                    'test "$1" = install && exit 0\n'
                    'test "$2" = "${BROKEN_FORMULA:-}" && exit 1\n'
                    'printf "/selected/%s\\n" "$2"\n')
    brew.chmod(0o755)
    output = tmp_path / 'sdk-environment'
    environment = {**os.environ, 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH'],
                   'GITHUB_ENV': str(output), 'PKG_CONFIG_PATH': '/caller/pkgconfig', **overrides}
    subprocess.run(['bash', '-eu', '-c', _native_step('Install macOS SDK')],
                   env=environment, check=True, capture_output=True)
    return dict(line.split('=', 1) for line in output.read_text().splitlines())


def _detect_native_flags(tmp_path, sdk, features):
    platform = tmp_path / 'platform.json'
    platform.write_text(json.dumps({
        'optimization_flags': {'march': ['-march=native'], 'mtune': ['-mtune=native']},
        'recommendations': {'enable_lto': 'thin'},
    }))
    run = _native_step('Detect platform features').split('\n', 1)[1]
    run = run.replace('/tmp/platform.json', str(platform))
    output = tmp_path / 'compiler-environment'
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('BRIX_CI_SDK_')}
    subprocess.run(['bash', '-eu', '-c', run], check=True, capture_output=True,
                   env={**environment, **sdk, 'APPLY_FEATURES': features, 'GITHUB_ENV': str(output)})
    return dict(line.split('=', 1) for line in output.read_text().splitlines())


def _expected_native_flags(mac_sdk, features):
    expected_compile = ['-I/selected/openssl@4/include'] if mac_sdk else []
    expected_link = ['-L/selected/openssl@4/lib', '-Wl,-rpath,/selected/openssl@4/lib'] if mac_sdk else []
    if features == 'true':
        expected_compile.extend(['-march=native', '-mtune=native', '-flto=thin'])
        expected_link.append('-flto=thin')
    return expected_compile, expected_link


@pytest.mark.parametrize('features', ['true', 'false'])
@pytest.mark.parametrize('mac_sdk', [True, False])
def test_native_cpu_detection_preserves_the_selected_tls_sdk(tmp_path, features, mac_sdk):
    sdk = _mac_sdk(tmp_path) if mac_sdk else {}
    selected = _detect_native_flags(tmp_path, sdk, features)
    expected_compile, expected_link = _expected_native_flags(mac_sdk, features)
    assert selected['BRIX_CI_CC_OPT'].split() == expected_compile
    assert selected['BRIX_CI_LD_OPT'].split() == expected_link


def test_native_sdk_keeps_the_callers_dependency_search_path(tmp_path):
    sdk = _mac_sdk(tmp_path)
    assert sdk['PKG_CONFIG_PATH'].startswith('/selected/bzip2/lib/pkgconfig:')
    assert sdk['PKG_CONFIG_PATH'].endswith('/caller/pkgconfig')


def test_missing_openssl_sdk_stops_before_emitting_compiler_flags(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        _mac_sdk(tmp_path, BROKEN_FORMULA='openssl@4')
    assert not (tmp_path / 'sdk-environment').exists()

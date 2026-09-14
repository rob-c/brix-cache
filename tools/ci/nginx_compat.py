#!/usr/bin/env python3
"""Build and exercise isolated nginx targets: stock AlmaLinux 9, 1.28.3, latest.

Latest means nginx.org's current mainline release, resolved once per invocation.
Each target retains configure/build/test logs and a JSON report with its exact
version and artifact hashes. Requires Python 3.12, CMake, the module dependencies
and the focused pytest dependencies documented in BUILD.md. Installs nothing.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

REPO = Path(__file__).resolve().parents[2]
DOWNLOADS = 'https://nginx.org/en/download.html'
VERSION = r'[0-9]+\.[0-9]+\.[0-9]+'
MODULE_NAMES = ('ngx_stream_brix_module.so', 'ngx_http_brix_xrdhttp_filter_module.so')


def target_name(value):
    """Accept only named targets or a numeric release, never a URL or path."""
    if value in ('alma9', 'latest') or re.fullmatch(VERSION, value):
        return value
    raise argparse.ArgumentTypeError('target must be alma9, latest or X.Y.Z')


def positive_jobs(value):
    """Reject invalid job counts before creating a build tree."""
    count = int(value)
    if count < 1:
        raise argparse.ArgumentTypeError('jobs must be positive')
    return count


def mainline_version(page):
    """Resolve only the mainline section; fail if upstream changes its format."""
    section = re.search(r'<h4>\s*Mainline version\s*</h4>(.*?)(?:<h4>|$)', page, re.S)
    if section is None:
        raise ValueError('nginx download page has no mainline section')
    match = re.search(r'href="/download/nginx-(' + VERSION + r')\.tar\.gz"', section[1])
    if match is None:
        raise ValueError('nginx mainline section has no release tarball')
    return match[1]


def resolve_targets(targets):
    """Freeze latest once while retaining independently runnable pinned targets."""
    latest, error = None, None
    if 'latest' in targets:
        latest, error = resolve_latest()
    return [(target, latest, error) if target == 'latest' else (target, target, None)
            for target in targets]


def resolve_latest():
    """Keep a discovery failure local to latest and report its missing coverage."""
    try:
        with urllib.request.urlopen(DOWNLOADS, timeout=30) as response:
            return mainline_version(response.read().decode('utf-8')), None
    except (OSError, ValueError) as error:
        return None, error


@contextmanager
def exclusive_lock(path):
    """Serialize writers using one persistent lock inode, refusing symlinks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        if os.fstat(lock.fileno()).st_uid != os.getuid():
            raise PermissionError(f'Lock belongs to another user: {path}')
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def migration_lock_path():
    """Fixed regression ports need a host/user lock across all checkout roots."""
    return Path('/tmp') / f'brix-nginx-compat-{os.getuid()}.migration.lock'


def source_version(source):
    """Read the version of the actual source tree chosen for configuration."""
    header = (source / 'src/core/nginx.h').read_text()
    match = re.search(r'^#define\s+NGINX_VERSION\s+"(' + VERSION + r')"', header, re.M)
    if match is None:
        raise ValueError(f'Cannot read nginx version in {source}')
    return match[1]


def digest(path):
    """Record immutable artifact identity without loading large modules at once."""
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fetch_source(version, cache):
    """Serialize each cached release through download, extraction and verification."""
    with exclusive_lock(cache / f'.nginx-{version}.lock'):
        return fetch_source_locked(version, cache)


def fetch_source_locked(version, cache):
    """Download official HTTPS sources and unpack into a fresh temporary tree."""
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f'nginx-{version}.tar.gz'
    source = cache / f'nginx-{version}'
    if not archive.exists():
        url = f'https://nginx.org/download/nginx-{version}.tar.gz'
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read()
        pending = archive.with_suffix('.pending')
        pending.write_bytes(content)
        pending.replace(archive)
    if not source.exists():
        with tempfile.TemporaryDirectory(prefix='unpack-', dir=cache) as temporary:
            with tarfile.open(archive) as bundle:
                bundle.extractall(temporary, filter='data')
            extracted = Path(temporary) / source.name
            if source_version(extracted) != version:
                raise ValueError(f'Archive version differs from requested {version}')
            extracted.rename(source)
    if source_version(source) != version:
        raise ValueError(f'Source cache version differs from requested {version}')
    return source, digest(archive)


def stock_source():
    """Require genuine AlmaLinux 9 and matching installed nginx/SDK releases."""
    release = platform.freedesktop_os_release()
    if release.get('ID') != 'almalinux' or not re.fullmatch(
            r'9(?:\.[0-9]+)*', release.get('VERSION_ID', '')):
        raise ValueError('alma9 target requires an AlmaLinux 9 host')
    versions = []
    for package in ('nginx', 'nginx-mod-devel'):
        result = subprocess.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', package],
                                capture_output=True, text=True, check=True)
        versions.append(result.stdout.strip())
    if versions[0] != versions[1]:
        raise ValueError(f'nginx and nginx-mod-devel releases differ: {versions}')
    source = Path('/usr/src') / f'nginx-{versions[0]}'
    return source, versions[0]


def run_logged(command, log, env):
    """Retain the exact command and fail at its exit status, naming the log."""
    print(f'  {log.name}', flush=True)
    with log.open('w') as output:
        output.write(json.dumps([str(word) for word in command]) + '\n')
        output.flush()
        result = subprocess.run(command, cwd=REPO, env=env, stdout=output,
                                stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'command exited {result.returncode}; see {log}')


def artifacts(build, stock):
    """Pair every module with its matching nginx binary and stream core."""
    modules = build / 'modules'
    if stock:
        binary = Path('/usr/sbin/nginx')
        stream = Path('/usr/lib64/nginx/modules/ngx_stream_module.so')
    else:
        binary = modules / 'nginx'
        stream = modules / 'ngx_stream_module.so'
    paths = [binary, stream] + [modules / name for name in MODULE_NAMES]
    require_artifacts(paths)
    return binary, stream, modules


def require_artifacts(paths):
    """Fail early when any expected binary or dynamic module was not produced."""
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f'Missing build artifact: {path}')


def build_target(source, directory, stock, jobs, env):
    """Drive the existing CMake/nginx source lists and prove incrementalism."""
    build = directory / 'build'
    command = ['cmake', '-S', str(REPO), '-B', str(build),
               f'-DNGINX_SRC_DIR={source}', '-DBRIX_BUILD_CLIENT=OFF',
               '-DBRIX_BUILD_CEPH_TOOLS=OFF', f'-DBRIX_BUILD_JOBS={jobs}',
               f'-DBRIX_BUILD_NGINX={not stock}']
    run_logged(command, directory / 'configure.log', env)
    make = ['cmake', '--build', str(build), '--target', 'nginx-modules', f'-j{jobs}']
    run_logged(make, directory / 'build.log', env)
    binary, stream, modules = artifacts(build, stock)
    watched = [modules / name for name in MODULE_NAMES]
    watched += [] if stock else [binary, stream]
    check_incremental(make, watched, directory, env)
    return binary, stream, modules


def check_incremental(command, watched, directory, env):
    """A second build must leave all expected output timestamps unchanged."""
    before = {path: path.stat().st_mtime_ns for path in watched}
    run_logged(command, directory / 'incremental.log', env)
    if before != {path: path.stat().st_mtime_ns for path in watched}:
        raise RuntimeError('Incremental build rebuilt an nginx artifact')


def validate_target(binary, stream, modules, directory, env, xrdcp):
    """Exercise HTTP and the existing cross-worker root protocol regressions."""
    smoke = [sys.executable, str(REPO / 'tools/ci/nginx_compat_smoke.py'),
             '--nginx', str(binary), '--module-dir', str(modules),
             '--stream-module', str(stream), '--work-dir', str(directory / 'smoke')]
    if xrdcp:
        smoke += ['--xrdcp', str(xrdcp)]
    run_logged(smoke, directory / 'smoke.log', env)
    test_env = {**env, 'TEST_SKIP_SERVER_SETUP': '1',
                'TEST_ROOT': str(directory / 'test-runtime'),
                'TEST_NGINX_BIN': str(binary),
                'TEST_NGINX_LOAD_MODULES': os.pathsep.join(
                    str(path) for path in [stream] + [modules / name for name in MODULE_NAMES]),
                'PYTHONPATH': str(REPO / 'tests')}
    tests = [sys.executable, '-m', 'pytest', 'tests/test_bind_migration.py', '-v', '-x']
    # This existing regression suite owns fixed ledger ports across versions.
    with exclusive_lock(migration_lock_path()):
        run_logged(tests, directory / 'migration.log', test_env)


def run_target(target, version, options, resolution_error=None):
    """Hold the output lock before touching reports, build state or runtime files."""
    name = target if target == 'alma9' or version is None else f'nginx-{version}'
    directory = options.build_root / name
    with exclusive_lock(directory / '.target.lock'):
        return run_target_locked(target, version, options, directory, resolution_error)


def run_target_locked(target, version, options, directory, resolution_error):
    """Publish a fresh verdict; an unsuccessful rerun cannot leave stale PASS."""
    stock = target == 'alma9'
    report = {'target': target, 'version': version, 'status': 'running'}
    report_path = directory / 'result.json'
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    env = {**os.environ, 'BRIX_ENABLE_IO_URING': '1'}
    try:
        if resolution_error is not None:
            raise resolution_error
        if stock:
            source, release = stock_source()
            version = source_version(source)
            archive_hash = None
        else:
            source, archive_hash = fetch_source(version, options.source_cache)
            release = version
        report.update(version=version, release=release, source=str(source),
                      source_sha256=archive_hash)
        print(f'{target}: nginx {release} ({directory})', flush=True)
        binary, stream, modules = build_target(source, directory, stock, options.jobs, env)
        validate_target(binary, stream, modules, directory, env, options.xrdcp)
        identity = subprocess.run([str(binary), '-V'], capture_output=True,
                                  text=True, check=True)
        report['nginx_build'] = identity.stderr
        report['artifacts'] = {str(path): digest(path) for path in
                               [binary, stream] + [modules / name for name in MODULE_NAMES]}
        report['status'] = 'passed'
    except (OSError, ValueError, RuntimeError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{target}: PASS', flush=True)
    return report


def arguments(argv):
    """Validate CLI options before resolving sources or creating build outputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=target_name, action='append',
                        help='repeat to select targets; default: alma9, 1.28.3, latest')
    parser.add_argument('--build-root', type=Path, default=REPO / 'build/nginx-compat')
    parser.add_argument('--source-cache', type=Path, default=REPO / 'build/nginx-sources')
    parser.add_argument('--jobs', type=positive_jobs, default=os.cpu_count() or 1)
    parser.add_argument('--xrdcp', type=Path, help='also test this reference client with root://')
    options = parser.parse_args(argv)
    options.build_root = options.build_root.resolve()
    options.source_cache = options.source_cache.resolve()
    if sys.version_info < (3, 12):
        parser.error('Python 3.12 or newer is required')
    options.target = options.target or ['alma9', '1.28.3', 'latest']
    return options


def main(argv=None):
    """Run one selected target or the default three-version compatibility matrix."""
    options = arguments(argv)
    failed = False
    for target, version, resolution_error in resolve_targets(options.target):
        try:
            run_target(target, version, options, resolution_error)
        except (OSError, ValueError, RuntimeError, tarfile.TarError,
                subprocess.SubprocessError) as error:
            print(f'nginx compatibility: FAIL: {target}: {error}', file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())

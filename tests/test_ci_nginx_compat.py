"""Exercise nginx compatibility orchestration without downloads or compilation.

Local source archives and command fakes cover release selection, confinement,
stock SDK agreement, incremental artifacts, and durable failure reports. Run:
TEST_SKIP_SERVER_SETUP=1 TEST_ROOT=/tmp/brix-nginx-compat-unit PYTHONPATH=tests \
build/test-venv/bin/python3.12 -m pytest --noconftest tests/test_ci_nginx_compat.py -v
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from threading import Event
from types import SimpleNamespace

import pytest


@pytest.fixture
def driver(monkeypatch):
    """Load the CLI independently and make unexpected network access fail."""
    path = Path(__file__).resolve().parents[1] / 'tools/ci/nginx_compat.py'
    spec = importlib.util.spec_from_file_location('nginx_compat_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def refuse_network(*args, **kwargs):
        """Keep source and release tests entirely local."""
        pytest.fail('Compatibility unit test attempted network access')

    monkeypatch.setattr(module.urllib.request, 'urlopen', refuse_network)
    monkeypatch.setattr(module.platform, 'freedesktop_os_release',
                        lambda: {'ID': 'almalinux', 'VERSION_ID': '9.6'})
    return module


@pytest.fixture
def source_archive(tmp_path):
    """Create a minimal real nginx source archive, optionally with bad members."""
    def create(version='1.28.3', header_version=None, extra=None):
        """Return a cache containing the selected release archive."""
        cache = tmp_path / 'sources'
        cache.mkdir(exist_ok=True)
        header = f'#define NGINX_VERSION "{header_version or version}"\n'.encode()
        with tarfile.open(cache / f'nginx-{version}.tar.gz', 'w:gz') as bundle:
            member = tarfile.TarInfo(f'nginx-{version}/src/core/nginx.h')
            member.size = len(header)
            bundle.addfile(member, io.BytesIO(header))
            if extra is not None:
                bundle.addfile(extra, io.BytesIO(b'') if extra.isfile() else None)
        return cache

    return create


@pytest.fixture
def options(tmp_path):
    """Keep each target's source cache and reports inside its fixture tree."""
    return SimpleNamespace(build_root=tmp_path / 'matrix',
                           source_cache=tmp_path / 'sources', jobs=2, xrdcp=None)


def test_latest_resolves_mainline_once_even_when_stable_is_listed_first(driver, monkeypatch):
    """Stable and unrelated release links cannot substitute for mainline."""
    page = b'''<a href="/download/nginx-9.99.99.tar.gz">unrelated</a>
        <h4>Stable version</h4><a href="/download/nginx-1.28.3.tar.gz">stable</a>
        <h4>Mainline version</h4><a href="/download/nginx-1.31.0.tar.gz">mainline</a>
        <h4>Legacy versions</h4><a href="/download/nginx-1.26.3.tar.gz">legacy</a>'''
    requests = []

    def download(url, timeout):
        """Record upstream lookups while returning a local page."""
        requests.append((url, timeout))
        return io.BytesIO(page)

    monkeypatch.setattr(driver.urllib.request, 'urlopen', download)
    assert driver.resolve_targets(['latest', '1.28.3', 'latest']) == [
        ('latest', '1.31.0', None), ('1.28.3', '1.28.3', None),
        ('latest', '1.31.0', None)]
    assert requests == [('https://nginx.org/en/download.html', 30)]


@pytest.mark.parametrize('page', [
    '<h4>Stable version</h4><a href="/download/nginx-1.28.3.tar.gz">stable</a>',
    '<h4>Mainline version</h4>Unavailable<h4>Stable version</h4>'
    '<a href="/download/nginx-1.28.3.tar.gz">stable</a>',
])
def test_missing_mainline_tarball_fails_without_falling_back_to_stable(driver, page):
    """An upstream layout change must produce a failure rather than false coverage."""
    with pytest.raises(ValueError, match='mainline'):
        driver.mainline_version(page)


def test_pinned_targets_do_not_lookup_latest(driver):
    """An explicitly pinned matrix remains runnable without the download page."""
    assert driver.resolve_targets(['alma9', '1.28.3']) == [
        ('alma9', 'alma9', None), ('1.28.3', '1.28.3', None)]


@pytest.mark.parametrize('target', [
    '../1.28.3', '/tmp/nginx', 'https://example.invalid/1.28.3',
    '1.28.3/../../outside', '1.28.3;touch outside', '1.28.3\n', '1.28.3?x=1',
])
def test_cli_refuses_target_paths_urls_and_shell_fragments(driver, tmp_path, target):
    """Untrusted target text cannot become a source URL or filesystem path."""
    build = tmp_path / 'not-created'
    with pytest.raises(SystemExit) as error:
        driver.main(['--target', target, '--build-root', str(build)])
    assert error.value.code == 2
    assert not build.exists()


@pytest.mark.parametrize('jobs', ['0', '-1', 'many'])
def test_invalid_job_count_fails_before_preparing_targets(driver, tmp_path, jobs):
    """Invalid resource limits cannot silently invoke an unrestricted build."""
    build = tmp_path / 'not-created'
    with pytest.raises(SystemExit) as error:
        driver.main(['--target', '1.28.3', '--jobs', jobs, '--build-root', str(build)])
    assert error.value.code == 2
    assert not build.exists()


def test_cached_archive_extracts_requested_version_and_records_its_digest(driver, source_archive):
    """The reported source identity describes the archive actually extracted."""
    cache = source_archive()
    source, archive_hash = driver.fetch_source('1.28.3', cache)
    assert driver.source_version(source) == '1.28.3'
    assert archive_hash == hashlib.sha256((cache / 'nginx-1.28.3.tar.gz').read_bytes()).hexdigest()
    assert driver.fetch_source('1.28.3', cache) == (source, archive_hash)


def test_archive_with_different_header_version_is_never_published(driver, source_archive):
    """A renamed archive cannot claim coverage for the requested release."""
    cache = source_archive(header_version='1.20.1')
    with pytest.raises(ValueError, match='Archive version'):
        driver.fetch_source('1.28.3', cache)
    assert not (cache / 'nginx-1.28.3').exists()
    assert not list(cache.glob('unpack-*'))


def test_existing_source_cache_version_is_checked_on_every_run(driver, source_archive):
    """A stale or replaced extraction cannot bypass release validation."""
    cache = source_archive()
    source, _ = driver.fetch_source('1.28.3', cache)
    (source / 'src/core/nginx.h').write_text('#define NGINX_VERSION "1.20.1"\n')
    with pytest.raises(ValueError, match='Source cache version'):
        driver.fetch_source('1.28.3', cache)


@pytest.mark.parametrize('link', [False, True], ids=['parent-traversal', 'escaping-symlink'])
def test_archive_cannot_write_or_link_outside_extraction(driver, source_archive, tmp_path, link):
    """Reject both direct traversal and symlink escapes before publishing sources."""
    member = tarfile.TarInfo('../escape')
    if link:
        member.name = 'nginx-1.28.3/escape'
        member.type = tarfile.SYMTYPE
        member.linkname = '../../escape'
    cache = source_archive(extra=member)
    with pytest.raises(tarfile.FilterError):
        driver.fetch_source('1.28.3', cache)
    assert not (cache / 'escape').exists()
    assert not (tmp_path / 'escape').exists()
    assert not (cache / 'nginx-1.28.3').exists()
    assert not list(cache.glob('unpack-*'))


@pytest.mark.parametrize('sdk_release', ['1.20.1-24.el9_6.3', '1.20.1-23.el9'])
def test_stock_sdk_requires_exact_installed_package_release(driver, monkeypatch, sdk_release):
    """Even matching nginx versions cannot hide an RPM release mismatch."""
    queried = []

    def rpm(command, **kwargs):
        """Model the two installed RPMs without consulting the host."""
        queried.append(command[-1])
        assert command[:4] == ['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}']
        assert kwargs['check']
        release = '1.20.1-24.el9_6.3' if command[-1] == 'nginx' else sdk_release
        return subprocess.CompletedProcess(command, 0, stdout=release)

    monkeypatch.setattr(driver.subprocess, 'run', rpm)
    if sdk_release == '1.20.1-24.el9_6.3':
        assert driver.stock_source() == (
            Path('/usr/src/nginx-1.20.1-24.el9_6.3'), sdk_release)
    else:
        with pytest.raises(ValueError, match='releases differ'):
            driver.stock_source()
    assert queried == ['nginx', 'nginx-mod-devel']


def _write_build_artifacts(modules, names, missing):
    """Publish fake compiler outputs, optionally missing one required artifact."""
    modules.mkdir(parents=True)
    for name in names:
        if name != missing:
            (modules / name).write_bytes(name.encode())


@pytest.fixture
def build_commands(driver, monkeypatch):
    """Replace compiler invocations with realistic output files and timestamps."""
    def install(changed=None, missing=None):
        """Optionally replace an output on the second build or omit one entirely."""
        logs = []

        def run(command, log, env):
            """Create target artifacts only at the corresponding build stage."""
            logs.append(log.name)
            modules = log.parent / 'build/modules'
            if log.name == 'build.log':
                names = (*driver.MODULE_NAMES, 'nginx', 'ngx_stream_module.so')
                _write_build_artifacts(modules, names, missing)
            if log.name == 'incremental.log' and changed is not None:
                artifact = modules / changed
                stamp = artifact.stat().st_mtime_ns + 1_000_000
                os.utime(artifact, ns=(stamp, stamp))

        monkeypatch.setattr(driver, 'run_logged', run)
        return logs

    return install


def test_incremental_build_preserves_every_runtime_artifact(driver, build_commands, tmp_path):
    """A second successful build must leave the matching binary and modules intact."""
    logs = build_commands()
    binary, stream, modules = driver.build_target(tmp_path / 'source', tmp_path, False, 2, {})
    assert binary == modules / 'nginx'
    assert stream == modules / 'ngx_stream_module.so'
    assert logs == ['configure.log', 'build.log', 'incremental.log']


@pytest.mark.parametrize('changed', [
    'ngx_stream_brix_module.so', 'ngx_http_brix_xrdhttp_filter_module.so',
    'nginx', 'ngx_stream_module.so',
])
def test_incremental_build_fails_if_any_runtime_artifact_is_rebuilt(
        driver, build_commands, tmp_path, changed):
    """Rewriting any runtime output defeats the matrix's incremental guarantee."""
    build_commands(changed=changed)
    with pytest.raises(RuntimeError, match='Incremental build rebuilt'):
        driver.build_target(tmp_path / 'source', tmp_path, False, 2, {})


def test_successful_compiler_exit_without_required_module_fails(driver, build_commands, tmp_path):
    """A nominally successful build is insufficient when a module was not produced."""
    build_commands(missing='ngx_http_brix_xrdhttp_filter_module.so')
    with pytest.raises(FileNotFoundError, match='ngx_http_brix_xrdhttp_filter_module.so'):
        driver.build_target(tmp_path / 'source', tmp_path, False, 2, {})


@pytest.mark.parametrize('exit_code', [0, 7])
def test_command_logs_preserve_output_argv_and_failure_status(driver, tmp_path, exit_code):
    """Commands retain useful diagnostics and pass shell metacharacters literally."""
    marker = tmp_path / 'must-not-exist'
    literal = f'$(touch {marker})'
    command = [sys.executable, '-c',
               'import sys; print(sys.argv[1]); print("diagnostic", file=sys.stderr); '
               f'sys.exit({exit_code})', literal]
    log = tmp_path / 'command.log'
    if exit_code:
        with pytest.raises(RuntimeError, match=r'command exited 7; see .*command.log'):
            driver.run_logged(command, log, dict(os.environ))
    else:
        driver.run_logged(command, log, dict(os.environ))
    lines = log.read_text().splitlines()
    assert json.loads(lines[0]) == command
    assert literal in lines and 'diagnostic' in lines
    assert not marker.exists()


def test_pass_report_identifies_validated_artifacts(driver, source_archive, options,
                                                  build_commands, monkeypatch):
    """A pass is published only after validation of the outputs recorded by digest."""
    options.source_cache = source_archive()
    build_commands()
    validations = []
    monkeypatch.setattr(driver, 'validate_target', lambda *args: validations.append(args))
    identities = []

    def identity(command, **kwargs):
        """Report the fixture binary's build identity without executing it."""
        identities.append(command)
        return subprocess.CompletedProcess(command, 0, stderr='nginx version: nginx/1.28.3\n')

    monkeypatch.setattr(driver.subprocess, 'run', identity)
    report = driver.run_target('1.28.3', '1.28.3', options)
    assert report['status'] == 'passed'
    assert len(validations) == 1
    assert identities == [[str(validations[0][0]), '-V']]
    assert report['nginx_build'] == 'nginx version: nginx/1.28.3\n'
    assert len(report['artifacts']) == 4
    for name, expected in report['artifacts'].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected
    stored = json.loads((options.build_root / 'nginx-1.28.3/result.json').read_text())
    assert stored == report


@pytest.mark.parametrize('failure_stage', ['source', 'build', 'validation'])
def test_failed_rerun_replaces_old_pass_even_before_building(
        driver, source_archive, options, build_commands, monkeypatch, failure_stage):
    """Failures at every stage overwrite stale successful reports and artifact hashes."""
    options.source_cache = source_archive()
    directory = options.build_root / 'nginx-1.28.3'
    directory.mkdir(parents=True)
    report_path = directory / 'result.json'
    report_path.write_text(json.dumps({'status': 'passed', 'artifacts': {'old': 'digest'}}))
    build_commands()

    def fail(*args):
        """Model a failed tool without starting a compiler or server."""
        raise RuntimeError(f'{failure_stage} failed')

    monkeypatch.setattr(driver, 'validate_target', lambda *args: None)
    if failure_stage == 'source':
        source, _ = driver.fetch_source('1.28.3', options.source_cache)
        (source / 'src/core/nginx.h').write_text('#define NGINX_VERSION "1.20.1"\n')
        expected = 'Source cache version'
    else:
        monkeypatch.setattr(driver, 'build_target' if failure_stage == 'build'
                            else 'validate_target', fail)
        expected = f'{failure_stage} failed'
    with pytest.raises((RuntimeError, ValueError), match=expected):
        driver.run_target('1.28.3', '1.28.3', options)
    report = json.loads(report_path.read_text())
    assert report['status'] == 'failed'
    assert expected in report['error']
    assert 'artifacts' not in report


def test_invalid_archive_has_concise_cli_failure_and_failed_report(driver, options, capsys):
    """Corrupt downloads fail cleanly instead of leaving an old verdict or traceback."""
    options.source_cache.mkdir()
    (options.source_cache / 'nginx-1.28.3.tar.gz').write_bytes(b'not a tar archive')
    assert driver.main(['--target', '1.28.3', '--build-root', str(options.build_root),
                        '--source-cache', str(options.source_cache)]) == 1
    stderr = capsys.readouterr().err
    assert 'nginx compatibility: FAIL:' in stderr
    assert 'Traceback' not in stderr
    report = json.loads((options.build_root / 'nginx-1.28.3/result.json').read_text())
    assert report['status'] == 'failed'


@pytest.mark.parametrize('release', [
    {'ID': 'rocky', 'VERSION_ID': '9.6', 'ID_LIKE': 'almalinux'},
    {'ID': 'almalinux', 'VERSION_ID': '10.0'},
    {'ID': 'almalinux', 'VERSION_ID': '9other'},
    {'ID': 'almalinux'}, {},
])
def test_stock_target_rejects_other_hosts_before_querying_packages(driver, monkeypatch, release):
    """Matching RPM names must not label another distribution as AlmaLinux 9."""
    monkeypatch.setattr(driver.platform, 'freedesktop_os_release', lambda: release)

    def refuse_rpm(*args, **kwargs):
        """Host identity must be established before consulting installed packages."""
        pytest.fail('Queried RPMs on a host outside the alma9 target')

    monkeypatch.setattr(driver.subprocess, 'run', refuse_rpm)
    with pytest.raises(ValueError, match='AlmaLinux 9 host'):
        driver.stock_source()


@pytest.mark.parametrize('failed', [None, 'alma9', '1.28.3', 'latest'])
def test_matrix_attempts_every_target_and_preserves_aggregate_failure(
        driver, monkeypatch, failed):
    """One target's failure cannot hide the remaining requested coverage."""
    attempted = []
    monkeypatch.setattr(driver, 'resolve_latest', lambda: ('1.31.0', None))

    def run(target, version, options, resolution_error):
        """Record each independent target and optionally fail its build."""
        attempted.append((target, version))
        if target == failed:
            raise RuntimeError('fixture build failed')

    monkeypatch.setattr(driver, 'run_target', run)
    assert driver.main([]) == int(failed is not None)
    assert attempted == [('alma9', 'alma9'), ('1.28.3', '1.28.3'), ('latest', '1.31.0')]


@pytest.mark.parametrize('error', [OSError('offline'), ValueError('missing mainline')])
def test_latest_discovery_failure_retains_other_targets_and_writes_failed_report(
        driver, monkeypatch, options, error):
    """Offline discovery still checks stock/pinned and leaves explicit latest failure."""
    attempted = []
    original = driver.run_target

    def unavailable(*args, **kwargs):
        """Model the upstream page being unavailable without using the network."""
        raise error

    def run(target, version, selected, resolution_error):
        """Let latest publish its real failure while observing the other targets."""
        attempted.append(target)
        if target == 'latest':
            return original(target, version, selected, resolution_error)

    monkeypatch.setattr(driver.urllib.request, 'urlopen', unavailable)
    monkeypatch.setattr(driver, 'run_target', run)
    assert driver.main(['--target', 'latest', '--target', 'alma9', '--target', '1.28.3',
                        '--build-root', str(options.build_root)]) == 1
    assert attempted == ['latest', 'alma9', '1.28.3']
    report = json.loads((options.build_root / 'latest/result.json').read_text())
    assert report == {'target': 'latest', 'version': None, 'status': 'failed', 'error': str(error)}


def _assert_lock_held(driver, path):
    """An independent descriptor must fail to acquire a lock held by the driver."""
    with path.open('a') as contender:
        with pytest.raises(BlockingIOError):
            driver.fcntl.flock(contender, driver.fcntl.LOCK_EX | driver.fcntl.LOCK_NB)


@pytest.mark.parametrize('fails', [False, True])
def test_exclusive_lock_serializes_descriptors_and_releases_after_error(driver, tmp_path, fails):
    """Both normal and failed operations release the same persistent lock inode."""
    path = tmp_path / '.lock'
    try:
        with driver.exclusive_lock(path):
            _assert_lock_held(driver, path)
            if fails:
                raise RuntimeError('operation failed')
    except RuntimeError:
        assert fails
    with path.open('a') as contender:
        driver.fcntl.flock(contender, driver.fcntl.LOCK_EX | driver.fcntl.LOCK_NB)
    assert path.is_file()


def test_exclusive_lock_rejects_symlink_without_touching_destination(driver, tmp_path):
    """A planted shared lock path cannot redirect file access to another inode."""
    victim = tmp_path / 'victim'
    victim.write_text('keep')
    path = tmp_path / '.lock'
    path.symlink_to(victim)
    with pytest.raises(OSError):
        with driver.exclusive_lock(path):
            pytest.fail('Followed a symlink lock')
    assert victim.read_text() == 'keep'


def _observe_lock_attempt(driver, monkeypatch, selected):
    """Expose when a contender reaches the real blocking flock, without sleeps."""
    attempted = Event()
    original = driver.exclusive_lock

    @contextmanager
    def observe(path):
        """Signal the selected resource only; retain actual OS lock semantics."""
        if path == selected:
            attempted.set()
        with original(path):
            yield

    monkeypatch.setattr(driver, 'exclusive_lock', observe)
    return original, attempted


def test_cache_lock_prevents_reading_or_extracting_a_contended_version(
        driver, monkeypatch, source_archive):
    """Another invocation's unfinished cache work remains inaccessible until unlock."""
    cache = source_archive()
    path = cache / '.nginx-1.28.3.lock'
    original, attempted = _observe_lock_attempt(driver, monkeypatch, path)
    with ThreadPoolExecutor(max_workers=1) as workers:
        with original(path):
            pending = workers.submit(driver.fetch_source, '1.28.3', cache)
            assert attempted.wait(5)
            assert not (cache / 'nginx-1.28.3').exists()
        source, expected_hash = pending.result(timeout=5)
    assert driver.fetch_source('1.28.3', cache) == (source, expected_hash)
    assert not list(cache.glob('unpack-*'))
    assert not list(cache.glob('*.pending'))


def test_output_lock_preserves_existing_report_until_previous_invocation_finishes(
        driver, monkeypatch, options):
    """A same-version latest alias waits before overwriting reports or source access."""
    directory = options.build_root / 'nginx-1.28.3'
    directory.mkdir(parents=True)
    report = directory / 'result.json'
    report.write_text('existing report')
    path = directory / '.target.lock'
    original, attempted = _observe_lock_attempt(driver, monkeypatch, path)

    def fail_source(*args):
        """Prove the output lock spans source preparation and releases on failure."""
        _assert_lock_held(driver, path)
        raise RuntimeError('source failed')

    monkeypatch.setattr(driver, 'fetch_source', fail_source)
    with ThreadPoolExecutor(max_workers=1) as workers:
        with original(path):
            pending = workers.submit(driver.run_target, 'latest', '1.28.3', options)
            assert attempted.wait(5)
            assert report.read_text() == 'existing report'
        with pytest.raises(RuntimeError, match='source failed'):
            pending.result(timeout=5)
    assert json.loads(report.read_text())['status'] == 'failed'
    with original(path):
        _assert_lock_held(driver, path)


def test_migration_lock_path_ignores_checkout_build_root_and_temporary_directory(
        driver, monkeypatch, tmp_path):
    """Fixed ledger ports require a stable user/host path even across workspaces."""
    before = driver.migration_lock_path()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    monkeypatch.setattr(driver, 'REPO', tmp_path)
    assert driver.migration_lock_path() == before
    assert before == Path('/tmp') / f'brix-nginx-compat-{os.getuid()}.migration.lock'


def test_migration_commands_from_distinct_build_roots_hold_one_shared_lock(
        driver, monkeypatch, tmp_path):
    """Every fixed-port command holds the same real lock throughout execution."""
    path = tmp_path / '.migration.lock'
    monkeypatch.setattr(driver, 'migration_lock_path', lambda: path)
    observed = []

    def run(command, log, env):
        """Check the child command's critical section without starting any servers."""
        if log.name == 'migration.log':
            _assert_lock_held(driver, path)
            observed.append(log.parent)

    monkeypatch.setattr(driver, 'run_logged', run)
    roots = [tmp_path / 'first/nginx-1.28.3', tmp_path / 'second/nginx-1.28.3']
    for directory in roots:
        driver.validate_target(Path('nginx'), Path('stream'), Path('modules'), directory, {}, None)
    assert observed == roots

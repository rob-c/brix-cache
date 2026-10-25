"""Build-plan and reporting contracts do not require a VM or a running fleet."""
import json
import errno
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ci import freebsd_native, native_suite
from brix_suite.launcher import control_operations


def test_registry_settings_exports_phase_env_knobs():
    import settings

    assert settings.REGISTRY_ROOT.endswith("registry")
    assert settings.REGISTRY_MANIFEST.endswith("manifest.json")
    assert isinstance(settings.REGISTRY_START, bool)
    assert isinstance(settings.REGISTRY_KEEP_LOGS, bool)
    assert isinstance(settings.TEST_PORT_START, int)


def test_endpoint_honours_spec_host_and_brackets_ipv6_url():
    """Readiness uses the declared host and brackets IPv6 URL literals."""
    from server_registry import NginxInstanceSpec, endpoint_for

    spec = NginxInstanceSpec(name="v6-probe-smoke", template="unused.conf",
                             port=19321, host="::1")  # net-literal-allow: IPv6 endpoint construction under test
    endpoint = endpoint_for(spec)
    assert endpoint.host == "::1"  # net-literal-allow: IPv6 endpoint host under test
    assert endpoint.url == "root://[::1]:19321/"  # net-literal-allow: IPv6 endpoint URL formatting under test


def test_endpoint_defaults_to_settings_host_without_spec_host():
    from server_registry import NginxInstanceSpec, endpoint_for
    import settings

    spec = NginxInstanceSpec(name="v4-probe-smoke", template="unused.conf", port=19322)
    endpoint = endpoint_for(spec)
    assert endpoint.host == settings.HOST
    assert endpoint.url == f"root://{settings.HOST}:19322/"


def test_freebsd_build_plan_builds_real_server_and_clients(tmp_path):
    commands = freebsd_native.build_commands(tmp_path / "sdk", tmp_path / "build", 4)
    assert "-DBRIX_BUILD_NGINX=ON" in commands[0]
    assert "-DBRIX_BUILD_CLIENT=ON" in commands[0]
    assert commands[1][-2:] == ["--parallel", "4"]
    assert not any("test_pal.c" in argument for command in commands for argument in command)


def test_freebsd_native_toolchain_precedes_installed_gnu_binutils():
    """A GNU ld in /usr/local/bin must not change FreeBSD module/ASan semantics."""
    selected = freebsd_native.native_environment({'PATH': '/usr/local/bin:/usr/bin'})
    assert selected['PATH'].split(':').index('/usr/bin') < selected['PATH'].split(':').index('/usr/local/bin')
    assert selected['CC'] == '/usr/bin/cc'
    assert selected['LD'] == '/usr/bin/ld'


def test_freebsd_native_toolchain_preserves_explicit_compiler_and_crypto_sdk():
    """An explicit SDK is never replaced by an implicitly discovered default."""
    supplied = {'CC': '/selected/clang', 'CXX': '/selected/clang++',
                'PKG_CONFIG_PATH': '/selected/crypto/lib/pkgconfig', 'PATH': '/tools'}
    selected = freebsd_native.native_environment(supplied)
    assert selected['CC'] == supplied['CC'] and selected['CXX'] == supplied['CXX']
    assert selected['PKG_CONFIG_PATH'] == supplied['PKG_CONFIG_PATH']
    assert supplied['PATH'] == '/tools'


def test_freebsd_native_path_never_adds_implicit_current_directory():
    """Security-negative: empty PATH entries must not become executable search roots."""
    path = freebsd_native.native_environment({'PATH': ':/usr/local/bin::'})['PATH'].split(':')
    assert '' not in path
    assert path.count('/usr/local/bin') == 1


def test_native_nginx_includes_the_real_external_authorization_module():
    """Auth subrequests must load in native builds, not become skipped coverage."""
    helper = Path(__file__).resolve().parents[1] / 'cmake/BrixNginxBuild.sh.in'
    assert '--with-http_auth_request_module' in helper.read_text()


def test_freebsd_flags_cannot_change_when_foreign_package_tools_are_installed():
    """RPM fixture coverage is independent of the native server's compiler ABI."""
    cmake = Path(__file__).resolve().parents[1] / 'CMakeLists.txt'
    assert 'if(RPM_EXECUTABLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")' in cmake.read_text()


@pytest.mark.parametrize("host,expected", [
    ("freebsd15", ["src/platform/freebsd/xattr_wrapper.c"]),
    ("linux", []), ("darwin", []),
])
def test_standalone_publishers_link_the_native_xattr_adapter(host, expected):
    from cmdscripts.compile_run import pal_xattr_sources

    assert pal_xattr_sources(host) == expected


def test_unknown_publisher_host_cannot_borrow_linux_xattr_semantics():
    from cmdscripts.compile_run import pal_xattr_sources

    with pytest.raises(ValueError, match="unsupported native PAL host"):
        pal_xattr_sources("unknown")


def _set_inherited_sdk_paths(monkeypatch, selected):
    for variable in ('TEST_NGINX_BUILD_DIR', 'NGX_BUILD', 'NGX_MAKEFILE'):
        if selected is None:
            monkeypatch.delenv(variable, raising=False)
        else:
            monkeypatch.setenv(variable, selected)


@pytest.mark.parametrize('inherited_headers', [None, '', '/foreign/old-sdk/objs'])
def test_freebsd_validation_pins_only_the_selected_outputs(tmp_path, monkeypatch, inherited_headers):
    _set_inherited_sdk_paths(monkeypatch, inherited_headers)
    build, scratch = tmp_path / "build", tmp_path / "test"
    env = freebsd_native.validation_environment(build, scratch)
    assert env["TEST_NGINX_BIN"] == str(build / "modules/nginx")
    assert env["TEST_REGISTRY_ROOT"] == str(scratch / "registry")
    assert env["TEST_NGINX_OBJS"] == str(build / "modules")
    assert env["TEST_NGINX_BUILD_DIR"] == str(build / "modules")
    assert env["NGX_BUILD"] == str(build / "nginx-src")
    assert env["NGX_MAKEFILE"] == str(build / "modules/Makefile")
    assert env["PYTHONPYCACHEPREFIX"] == str(scratch / "pycache")
    assert len(env["TEST_NGINX_LOAD_MODULES"].split(":")) == 3
    assert env["TEST_XRDCP_BIN"] != env["TEST_REF_XRDCP_BIN"]
    assert env["PATH"].split(":")[0] == str(freebsd_native.Path(
        freebsd_native.sys.executable).parent)


@pytest.mark.parametrize('inherited_output', [None, '', '/foreign/untrusted-sdk/missing'])
def test_freebsd_dynamic_tests_pin_the_selected_build(tmp_path, monkeypatch, inherited_output):
    """Missing, invalid and foreign paths cannot borrow unrelated dynamic artifacts."""
    dynamic_outputs = {
        'BRIX_DYN_NGINX_BIN': 'nginx',
        'BRIX_DYN_STREAM_SO': 'ngx_stream_brix_module.so',
        'BRIX_DYN_FILTER_SO': 'ngx_http_brix_xrdhttp_filter_module.so',
        'BRIX_DYN_NGX_STREAM_MODULE': 'ngx_stream_module.so',
    }
    for variable in dynamic_outputs:
        if inherited_output is None:
            monkeypatch.delenv(variable, raising=False)
        else:
            monkeypatch.setenv(variable, inherited_output)
    build = tmp_path / 'build'
    environment = freebsd_native.validation_environment(build, tmp_path / 'scratch')
    for variable, artifact in dynamic_outputs.items():
        assert environment[variable] == str(build / 'modules' / artifact)


@pytest.mark.parametrize("level", ["contracts", "full", "privileged"])
def test_freebsd_validation_always_runs_a_wire_smoke_first(tmp_path, level):
    commands = freebsd_native.validation_commands(tmp_path, level)
    assert commands[0][-1].endswith("/tools/ci/smoke.py")
    assert len(commands) == (3 if level == "privileged" else 2)
    assert ("--output" in commands[1]) == (level == "full")
    assert ("--include-suite-jobs" in commands[1]) == (level == "full")


@pytest.fixture
def privileged_validation_command(tmp_path):
    return freebsd_native.validation_commands(tmp_path, 'privileged')[-1]


def test_privileged_validation_selects_real_identity_proofs(privileged_validation_command):
    """Root must actually exercise mapping and cross-user authorization."""
    selected = [Path(argument).name for argument in privileged_validation_command
                if argument.endswith('.py')]
    required = {'test_impersonation_gridmap_root.py', 'test_mu_authz_cachetransp.py',
                'test_pblock_group_multiuser.py', 'test_pblock_privilege_drop.py',
                'test_worker_deescalation_root.py', 'test_chkpoint_recover_export.py'}
    assert required <= set(selected)
    assert any(argument.endswith('test_freebsd_native.py::'
        'test_native_non_devfs_device_nodes_cannot_access_devices')
        for argument in privileged_validation_command)


def test_privileged_validation_never_selects_the_broad_suite(privileged_validation_command):
    """Root is not a privilege bypass for arbitrary test modules."""
    allowed = {'test_impersonation_gridmap_root.py', 'test_accounts_selftest.py',
               'test_pblock_group_multiuser.py', 'test_pblock_privilege_drop.py',
               'test_worker_deescalation_root.py', 'test_chkpoint_recover_export.py'}
    for argument in privileged_validation_command:
        if '::' in argument:
            assert argument.endswith('test_freebsd_native.py::'
                'test_native_non_devfs_device_nodes_cannot_access_devices')
        elif argument.endswith('.py'):
            name = Path(argument).name
            assert name.startswith('test_mu_') or name in allowed


def test_privileged_validation_retains_counted_evidence(privileged_validation_command, tmp_path):
    """JUnit and conservation evidence use the selected build's report path."""
    assert '--junitxml=' + str(tmp_path / 'native-privileged.xml') in privileged_validation_command
    assert 'tools.ci.native_suite' in privileged_validation_command


def test_privileged_validation_does_not_parallelize_account_mutations(privileged_validation_command):
    assert '-n' not in privileged_validation_command


@pytest.mark.parametrize('uid,no_build', [(1000, True), (0, False)])
def test_privileged_lane_refuses_nonroot_or_root_builds(monkeypatch, tmp_path, uid, no_build):
    """Neither skipped ownership checks nor root-owned build outputs are valid evidence."""
    monkeypatch.setattr(freebsd_native.platform, 'system', lambda: 'FreeBSD')
    monkeypatch.setattr(freebsd_native.platform, 'release', lambda: '15.1')
    monkeypatch.setattr(freebsd_native.os, 'geteuid', lambda: uid)
    arguments = ['--nginx-source', str(tmp_path), '--build-dir', str(tmp_path / 'build'),
                 '--test-level', 'privileged'] + (['--no-build'] if no_build else [])
    with pytest.raises(SystemExit) as failure:
        freebsd_native._arguments(arguments)
    assert failure.value.code == 2


@pytest.mark.parametrize("host,family,user", [
    ("127.0.0.1", "v4", None), ("::1", "v6", None),  # net-literal-allow: explicit endpoint-family vectors, never dialled
    ("127.0.0.1", "v4", "reference-user"),  # net-literal-allow: IPv4 reference-listener argument vector
])
def test_reference_listener_matches_its_declared_endpoint(tmp_path, host, family, user):
    from brix_suite.launcher.start_operations import _xrootd_argv

    config = tmp_path / "reference.cfg"
    config.write_text("all.export /\n")
    launcher = SimpleNamespace(_xrootd_runas_user=lambda config, log: user)
    command = _xrootd_argv(launcher, "/installed/xrootd", config, tmp_path / "log", host)
    assert command[0] == "/installed/xrootd"
    assert command[command.index("-I") + 1] == family
    assert ("-R" in command) == bool(user)


@pytest.mark.parametrize("level", ["contracts", "full"])
def test_freebsd_test_root_keeps_reference_unix_sockets_short(tmp_path, monkeypatch, level):
    requested, commands = [], []

    def allocate(**options):
        requested.append(options)
        return str(tmp_path)

    monkeypatch.setattr(freebsd_native.tempfile, "mkdtemp", allocate)
    monkeypatch.setattr(freebsd_native.subprocess, "run",
                        lambda command, **options: commands.append((command, options)))
    freebsd_native._validate_target(tmp_path / "deep/build/tree", level)
    assert requested == [dict(prefix="bf-", dir="/tmp")]
    assert all(options["env"]["TEST_ROOT"] == str(tmp_path)
               for command, options in commands)


def test_native_report_counts_errors_failures_skips_and_success(tmp_path):
    report = tmp_path / "results.xml"
    report.write_text('<testsuites><testsuite><testcase/>'
        '<testcase><failure/></testcase><testcase><error/></testcase>'
        '<testcase><skipped/></testcase></testsuite></testsuites>')
    assert native_suite.report_counts([report]) == dict(tests=4, passed=1, failed=1,
                                                       errors=1, skipped=1)


def test_native_report_refuses_malformed_or_missing_evidence(tmp_path):
    report = tmp_path / "broken.xml"
    report.write_text("not XML")
    with pytest.raises(native_suite.ET.ParseError):
        native_suite.report_counts([report])
    with pytest.raises(FileNotFoundError):
        native_suite.report_counts([tmp_path / "absent.xml"])


def test_native_runner_keeps_kill_attribution_before_lane_cleanup(monkeypatch, tmp_path):
    """A later registry cleanup cannot erase the reason the prior lane stopped."""
    root, reports = tmp_path / 'lane', tmp_path / 'reports'
    (root / 'registry').mkdir(parents=True)
    reports.mkdir()
    report = reports / 'lane-1.xml'
    report.write_text('<testsuite/>')
    (root / 'kill-diag.log').write_text('owned teardown traceback')
    (root / 'registry/.fleet-sentinel-abort').write_text('shared fleet lost')
    monkeypatch.setenv('TEST_ROOT', str(root))
    monkeypatch.setenv('TEST_REGISTRY_ROOT', str(root / 'registry'))
    native_suite._retain_lane_diagnostics(report)
    assert (reports / 'lane-1.kill-diag.log').read_text() == 'owned teardown traceback'
    assert (reports / 'lane-1.sentinel.txt').read_text() == 'shared fleet lost'


def test_optional_diagnostics_are_bounded_and_missing_files_are_not_invented(tmp_path):
    """Keep the recent diagnostic tail without manufacturing successful evidence."""
    source, target = tmp_path / 'source', tmp_path / 'tail'
    source.write_bytes(b'0123456789abcdef')
    native_suite._copy_diagnostic_tail(source, target, limit=8)
    assert target.read_bytes() == b'89abcdef'
    native_suite._copy_diagnostic_tail(tmp_path / 'absent', tmp_path / 'not-created')
    assert not (tmp_path / 'not-created').exists()


def test_diagnostic_symlink_cannot_import_an_unrelated_file(monkeypatch, tmp_path):
    """A fixture cannot redirect evidence capture outside its selected lane."""
    root = tmp_path / 'lane'
    root.mkdir()
    outside = tmp_path / 'unrelated'
    outside.write_text('not a lane diagnostic')
    (root / 'kill-diag.log').symlink_to(outside)
    report = tmp_path / 'lane-1.xml'
    report.write_text('<testsuite/>')
    monkeypatch.setenv('TEST_ROOT', str(root))
    monkeypatch.setenv('TEST_REGISTRY_ROOT', str(root / 'registry'))
    native_suite._retain_lane_diagnostics(report)
    assert not (tmp_path / 'lane-1.kill-diag.log').exists()


def test_native_runner_preserves_scheduler_and_error_verdict(tmp_path, monkeypatch):
    calls = []

    def original(selection, parallel, common, timeout=None):
        calls.append((selection, parallel, common, timeout))
        return False

    def run(arguments):
        assert arguments[:2] == ["-n", "2"]
        assert "--nginx-load-module" in arguments
        assert "--include-suite-jobs" in arguments
        runner._pytest_lane(["tests"], ["-n", "2"], ["-q"], timeout=12)
        runner._pytest_lane(["tests"], [], ["-q"])
        return 1

    runner = SimpleNamespace(_pytest_lane=original, run_suite=run)
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", str(tmp_path / "selected.so"))
    code, reports = native_suite.execute_suite(runner, tmp_path, 2, True)
    assert code == 1 and runner._pytest_lane is original
    assert reports == [tmp_path / "lane-1.xml", tmp_path / "lane-2.xml"]
    assert calls[0][-1] == 12
    assert calls[0][2][-1] == "--junitxml=" + str(reports[0])


def test_native_runner_restores_scheduler_after_exception(tmp_path):
    def original(*args, **kwargs):
        return True

    def broken(arguments):
        raise RuntimeError("failed preflight")

    runner = SimpleNamespace(_pytest_lane=original, run_suite=broken)
    with pytest.raises(RuntimeError, match="failed preflight"):
        native_suite.execute_suite(runner, tmp_path, 1)
    assert runner._pytest_lane is original


@pytest.mark.parametrize("content,original,expected", [
    ("<testsuite><testcase/></testsuite>", 0, 0),
    ("<testsuite/>", 0, 1),
    ("<testsuite><testcase/></testsuite>", -9, -9),
    ("<testsuite><testcase><error/></testcase></testsuite>", 0, 1),
])
def test_native_report_cannot_hide_empty_runs_or_failure_exit_codes(
        tmp_path, content, original, expected):
    report = tmp_path / "lane-1.xml"
    report.write_text(content)
    report.with_suffix('.progress.json').write_text(json.dumps(dict(
        collected=1, completed=1, session_finished=True, exit_status=0)))
    args = SimpleNamespace(include_suite_jobs=False)
    code = native_suite._finalize_report(tmp_path, [report], original,
                                         native_suite.time.monotonic(), args)
    assert code == expected
    assert json.loads((tmp_path / "summary.json").read_text())["exit_code"] == expected


def _check_finished_live_evidence(record):
    assert record["session_finished"] is True
    assert record["exit_status"] == 1
    assert record["outcomes"] == dict(passed=1, failed=1, errors=1, skipped=1)


def test_live_evidence_retains_failures_errors_and_skips(tmp_path):
    observer = native_suite._LiveEvidence(tmp_path / "lane-1.xml")
    for name, phase, failed, skipped in (
        ("ok", "call", False, False), ("bad", "call", True, False),
        ("setup", "setup", True, False), ("skip", "setup", False, True),
        ("ok", "teardown", False, False),
    ):
        observer.pytest_runtest_logreport(SimpleNamespace(nodeid=name, when=phase,
            failed=failed, skipped=skipped, longreprtext="diagnostic"))
    observer.pytest_sessionfinish(None, 1)
    report = json.loads((tmp_path / "lane-1.progress.json").read_text())
    assert report["live_observation"] is True
    assert report["completed"] == 4
    _check_finished_live_evidence(report)
    failures = (tmp_path / "lane-1.failures.jsonl").read_text().splitlines()
    assert [json.loads(row)["outcome"] for row in failures] == ["failed", "errors"]


def test_live_evidence_reused_path_starts_a_fresh_journal_and_verdict(tmp_path):
    """A previous pass or failure is never attributed to a subsequent run."""
    report = tmp_path / 'lane.xml'
    for suffix in ('.failures.jsonl', '.progress.json'):
        report.with_suffix(suffix).write_text('previous-run-evidence')
    observer = native_suite._LiveEvidence(report)
    assert not report.with_suffix('.progress.json').exists()
    observer.pytest_runtest_logreport(SimpleNamespace(nodeid='fresh', when='call',
        failed=True, skipped=False, longreprtext='current failure'))
    record = json.loads(report.with_suffix('.failures.jsonl').read_text())
    assert record['nodeid'] == 'fresh'
    assert json.loads(report.with_suffix('.progress.json').read_text())['session_finished'] is False


def test_live_evidence_cannot_clear_a_directory_as_a_report(tmp_path):
    """An invalid output owner fails closed instead of recursively cleaning it."""
    report = tmp_path / 'lane.xml'
    directory = report.with_suffix('.failures.jsonl')
    directory.mkdir()
    (directory / 'canary').write_text('unrelated')
    with pytest.raises(OSError) as failure:
        native_suite._LiveEvidence(report)
    assert failure.value.errno in (errno.EISDIR, errno.EPERM)
    assert (directory / 'canary').read_text() == 'unrelated'


@pytest.mark.parametrize('suffix', ['.failures.jsonl', '.progress.json'])
def test_live_evidence_does_not_truncate_a_stale_symlink_target(tmp_path, suffix):
    """A leftover link cannot redirect report initialization onto another file."""
    report, outside = tmp_path / 'lane.xml', tmp_path / 'outside'
    outside.write_text('outside-canary')
    report.with_suffix(suffix).symlink_to(outside)
    observer = native_suite._LiveEvidence(report)
    observer.pytest_runtest_logreport(SimpleNamespace(nodeid='fresh', when='call',
        failed=True, skipped=False, longreprtext='current failure'))
    assert outside.read_text() == 'outside-canary'
    assert not report.with_suffix(suffix).is_symlink()


@pytest.mark.parametrize('record,expected', [
    (dict(collected=3, completed=3, session_finished=True, exit_status=0), True),
    (dict(collected=3, completed=3, session_finished=True, exit_status=1), True),
    (dict(collected=3, completed=2, session_finished=True, exit_status=0), False),
    (dict(collected=3, completed=4, session_finished=True, exit_status=0), False),
    (dict(collected=3, completed=3, session_finished=True, exit_status=2), False),
    (dict(collected=3, completed=3, session_finished=False, exit_status=0), False),
    (dict(collected=0, completed=0, session_finished=True, exit_status=0), False),
    (dict(collected=True, completed=True, session_finished=True, exit_status=0), False),
    (dict(collected=1, completed=1, session_finished=True, exit_status=False), False),
    ([], False), (None, False),
])
def test_execution_evidence_requires_a_finished_conserved_lane(tmp_path, record, expected):
    report = tmp_path / 'lane-1.xml'
    report.with_suffix('.progress.json').write_text(json.dumps(record))
    assert native_suite._lane_execution_complete(report) is expected


@pytest.mark.parametrize('content', [None, 'not JSON', '{}'])
def test_junit_alone_cannot_make_an_interrupted_native_run_green(tmp_path, content):
    report = tmp_path / 'lane-1.xml'
    report.write_text('<testsuite><testcase/></testsuite>')
    if content is not None:
        report.with_suffix('.progress.json').write_text(content)
    code = native_suite._finalize_report(tmp_path, [report], 0,
        native_suite.time.monotonic(), SimpleNamespace(include_suite_jobs=False))
    summary = json.loads((tmp_path / 'summary.json').read_text())
    assert code == 1
    assert summary['reports_complete'] is True
    assert summary['execution_complete'] is False


@pytest.mark.parametrize("worker,report,expected", [
    (False, "lane-1.xml", 1), (True, "lane-1.xml", 0), (False, None, 0),
    (False, "", 0),
])
def test_live_evidence_is_registered_only_by_the_reporting_controller(
        worker, report, expected):
    registered = []
    config = SimpleNamespace(option=SimpleNamespace(xmlpath=report),
        pluginmanager=SimpleNamespace(register=lambda *args: registered.append(args)))
    if worker:
        config.workerinput = {}
    native_suite.pytest_configure(config)
    assert len(registered) == expected


@pytest.mark.parametrize("outcome", [0, 1, "fuse3 metadata unavailable"])
def test_live_cvmfs_uses_the_canonical_native_builder(tmp_path, monkeypatch, outcome):
    import subprocess
    from cmdscripts import cvmfs_driver_units, cvmfs_live_ext

    called = []

    def build(binary):
        called.append(binary)
        if isinstance(outcome, str):
            return outcome
        return subprocess.CompletedProcess([], outcome, stdout="", stderr="compile failed")

    monkeypatch.setattr(cvmfs_driver_units, "_compile_brixcvmfs", build)
    run = SimpleNamespace(root=tmp_path)
    if outcome == 0:
        assert cvmfs_live_ext._ensure_brixcvmfs(run) == tmp_path / "brixcvmfs"
    else:
        error = cvmfs_live_ext.LiveSkip if isinstance(outcome, str) else cvmfs_live_ext.LiveFailure
        with pytest.raises(error):
            cvmfs_live_ext._ensure_brixcvmfs(run)
    assert called == [tmp_path / "brixcvmfs"]
def test_stopped_master_pidfile_is_retired_without_removing_its_logs(tmp_path):
    pidfile = tmp_path / 'nginx.pid'
    log = tmp_path / 'error.log'
    pidfile.write_text('704\n')
    log.write_text('retained diagnostic history\n')
    launcher = type('Launcher', (), {
        '_read_pid': lambda self, path: int(Path(path).read_text()),
        '_process_exited': lambda self, pid: True})()
    control_operations._unlink_exited_master_pidfile(launcher, str(pidfile), 704)
    assert not pidfile.exists()
    assert log.read_text() == 'retained diagnostic history\n'


def test_live_master_pidfile_cannot_be_retired(tmp_path):
    pidfile = tmp_path / 'nginx.pid'
    pidfile.write_text('704\n')
    launcher = type('Launcher', (), {
        '_read_pid': lambda self, path: 704,
        '_process_exited': lambda self, pid: False})()
    control_operations._unlink_exited_master_pidfile(launcher, str(pidfile), 704)
    assert pidfile.read_text() == '704\n'


def test_successor_master_pidfile_cannot_be_retired(tmp_path):
    pidfile = tmp_path / 'nginx.pid'
    pidfile.write_text('705\n')
    launcher = type('Launcher', (), {'_read_pid': lambda self, path: 705})()
    control_operations._unlink_exited_master_pidfile(launcher, str(pidfile), 704)
    assert pidfile.read_text() == '705\n'


def test_fresh_prefix_cannot_reuse_history_from_a_readonly_tree(tmp_path):
    prefix = tmp_path / 'subject'
    (prefix / 'logs').mkdir(parents=True)
    (prefix / 'logs/error.log').write_text('old scrub pass\n')
    ca = prefix / 'public-ca'
    ca.mkdir()
    (ca / 'anchor.pem').write_text('public fixture')
    ca.chmod(0o555)
    retired = control_operations.retire_inactive_prefix(prefix, prefix / 'logs/nginx.pid')
    assert not prefix.exists()
    assert (retired / 'logs/error.log').read_text() == 'old scrub pass\n'
    (retired / 'public-ca').chmod(0o755)


def test_prefix_with_a_live_marker_is_never_moved(tmp_path):
    prefix = tmp_path / 'subject'
    (prefix / 'logs').mkdir(parents=True)
    marker = prefix / 'logs/nginx.pid'
    marker.write_text('704\n')
    assert control_operations.retire_inactive_prefix(prefix, marker) is None
    assert marker.read_text() == '704\n'
    assert list(tmp_path.glob('*.history-*')) == []


def test_foreign_pidfile_cannot_authorize_prefix_retirement(tmp_path):
    prefix = tmp_path / 'subject'
    prefix.mkdir()
    with pytest.raises(ValueError, match='exact server prefix'):
        control_operations.retire_inactive_prefix(prefix, tmp_path / 'foreign/logs/nginx.pid')
    assert prefix.exists()


def test_gsi_fixture_accepts_a_free_port(monkeypatch):
    import _test_gsi_handshake_helpers as helper

    monkeypatch.setattr(helper, 'pids_on_port', lambda port: [])
    assert helper._free_port(4554) is None


@pytest.mark.parametrize(('host', 'expected'), [
    ('freebsd15', 'xrootd.async nosf\n'), ('freebsd', 'xrootd.async nosf\n'),
    ('linux', ''), ('darwin', ''), ('unknown', ''),
    ('linux\nsec.protbind * none', ''),
])
def test_reference_transport_policy_never_changes_authentication(host, expected):
    from lib_py.reference_host import reference_transport_directives

    assert reference_transport_directives(host) == expected


@pytest.mark.parametrize(('host', 'expected'), [
    ('freebsd15', 'xrootd.async off nosf\n'), ('linux', 'xrootd.async off\n'),
    ('darwin', 'xrootd.async off\n'),
])
def test_reference_transport_policy_preserves_explicit_async_disable(host, expected):
    from lib_py.reference_host import reference_transport_directives

    assert reference_transport_directives(host, disable_async=True) == expected


@pytest.mark.parametrize('host', ['freebsd15', 'linux', 'darwin'])
def test_registry_reference_policy_preserves_auth_and_trust(tmp_path, monkeypatch, host):
    from brix_suite.launcher.start_operations import _render_xrootd_config
    from lib_py import reference_host

    config = tmp_path / 'reference.cfg'
    protected = 'sec.protocol gsi -certdir:/private/test-ca\nsec.protbind * only gsi\n'
    namespace = {'REGISTRY_STRICT_TEMPLATES': True,
                 'render_config_to_path': lambda *args, **kwargs: config.write_text(protected)}
    monkeypatch.setattr(reference_host, 'sys', SimpleNamespace(platform=host))
    _render_xrootd_config(SimpleNamespace(template='fixture'), config, {}, namespace)
    extra = '\nxrootd.async nosf\n' if host == 'freebsd15' else ''
    assert config.read_text() == protected + extra


def test_registry_reference_render_error_cannot_be_reported_as_success(tmp_path):
    from brix_suite.launcher.start_operations import _render_xrootd_config

    def broken_renderer(*args, **kwargs):
        raise OSError('fixture render refused')

    namespace = {'REGISTRY_STRICT_TEMPLATES': True, 'render_config_to_path': broken_renderer}
    config = tmp_path / 'reference.cfg'
    with pytest.raises(OSError, match='fixture render refused'):
        _render_xrootd_config(SimpleNamespace(template='fixture'), config, {}, namespace)
    assert not config.exists()


def test_gsi_fixture_cannot_signal_a_foreign_listener(monkeypatch):
    import _test_gsi_handshake_helpers as helper
    from types import SimpleNamespace

    signalled = []
    monkeypatch.setattr(helper, 'pids_on_port', lambda port: [123456])
    monkeypatch.setattr(helper, 'os', SimpleNamespace(kill=lambda *args: signalled.append(args)))
    with pytest.raises(RuntimeError, match='occupied GSI fixture port'):
        helper._free_port(4554)
    assert signalled == []


def test_gsi_fixture_reaps_its_owned_child_after_forced_stop():
    import _test_gsi_handshake_helpers as helper
    import subprocess

    class Child:
        def __init__(self):
            self.calls = []

        def terminate(self):
            self.calls.append('terminate')

        def kill(self):
            self.calls.append('kill')

        def wait(self, timeout):
            self.calls.append('wait')
            if len(self.calls) == 2:
                raise subprocess.TimeoutExpired('owned fixture', timeout)
            return 0

    child = Child()
    helper._terminate(child)
    assert child.calls == ['terminate', 'wait', 'kill', 'wait']


def _freebsd_workflow_step():
    import yaml

    root = Path(__file__).resolve().parents[1]
    contents = (root / '.github/workflows/freebsd.yml').read_text()
    workflow = yaml.load(contents, Loader=yaml.BaseLoader)
    return workflow['jobs']['native']['steps'][1]['with']


def test_freebsd_full_ci_provisions_only_explicit_loopback_aliases():
    prepare = _freebsd_workflow_step()['prepare']
    assert "ipaddress.ip_address(address).is_loopback" in prepare
    assert "for worker in range(10)" in prepare
    assert "f'127.0.0.{number}' for number in range(2, 10)" in prepare
    assert "'lo0', 'inet', address + '/32', 'alias'" in prepare


@pytest.mark.parametrize('package', ['dpkg', 'py312-crc32c'])
def test_freebsd_ci_provisions_the_optional_validation_dependencies(package):
    """A clean CI VM must carry the package loader and independent digest oracle."""
    prepare = _freebsd_workflow_step()['prepare']
    install = prepare.split('pkg install -y', 1)[1].split('pw useradd', 1)[0]
    assert package in install.split()


def test_freebsd_root_kernel_proof_is_separate_from_ordinary_server_tests():
    run = _freebsd_workflow_step()['run']
    proof = run.index('test_native_non_devfs_device_nodes_cannot_access_devices')
    ordinary = run.index('python tools/ci/freebsd_native.py')
    assert proof < ordinary
    assert '--noconftest' in run
    assert 'native-device-policy.xml' in run


def test_freebsd_ci_does_not_relax_kernel_or_worker_security_to_enable_coverage():
    step = _freebsd_workflow_step()
    script = step['prepare'] + step['run']
    for forbidden in ('nonlocalbind', 'enable_unsafe', 'IGNORE_UNKNOWN', 'user root;'):
        assert forbidden not in script


def test_freebsd_default_cache_provisioning_is_scoped_to_the_test_account():
    prepare = _freebsd_workflow_step()['prepare']
    assert 'install -d -m 0700 -o brixvalidate -g brixvalidate /var/lib/brixcvmfs' in prepare
    assert not any(command in prepare for command in (
        'chmod 777 /var/lib', 'chown -R brixvalidate /var/lib'))


def test_freebsd_ci_bounds_arc_without_assuming_the_guest_uses_zfs():
    prepare = _freebsd_workflow_step()['prepare']
    assert 'if sysctl -n vfs.zfs.arc.max >/dev/null 2>&1; then' in prepare
    assert 'brix_arc_bytes=$(($(sysctl -n hw.physmem) / 8))' in prepare
    assert 'sysctl "vfs.zfs.arc.max=$brix_arc_bytes"' in prepare

from pathlib import Path
import os
import subprocess
import sys

import pytest

from cmdscripts import operator_runtime
from cmdscripts.operator_runtime import run_checks

pytestmark = pytest.mark.xdist_group("cmd-operator-runtime")


@pytest.fixture(autouse=True)
def _restore_operator_environment():
    """Keep runner configuration tests from poisoning later suite modules."""
    names = (
        "TEST_NGINX_BIN", "NGINX_BIN", "TEST_BRIX_BIN", "BRIX_BIN",
        "XROOTD_BIN", "REF_BIN", "TEST_NGINX_LOAD_MODULES", "TEST_OWN_FLEET",
        "TEST_ROOT", "PYTHONPATH", "TMPDIR",
    )
    before = {name: operator_runtime.os.environ.get(name) for name in names}
    yield
    for name, value in before.items():
        if value is None:
            operator_runtime.os.environ.pop(name, None)
        else:
            operator_runtime.os.environ[name] = value


def test_operator_runtime_ports_are_importable(tmp_path: Path):
    results = run_checks(tmp_path)
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)


def test_operator_runtime_module_defines_dispatch_before_direct_execution():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parent)
    proc = subprocess.run(
        [sys.executable, "-m", "cmdscripts.operator_runtime", "not-a-runner"],
        cwd=Path(__file__).parents[1], env=env, capture_output=True, text=True,
        timeout=30,
    )
    assert proc.returncode == 1
    assert "unknown operator runtime port: not-a-runner" in proc.stdout
    assert "NameError" not in proc.stderr


def test_sanitizer_binary_detection_accepts_plain_binary(tmp_path):
    binary = tmp_path / "nginx"
    binary.write_bytes(b"ELF plain nginx")
    assert operator_runtime._is_sanitized_binary(str(binary)) is False


def test_sanitizer_binary_detection_rejects_asan_binary(tmp_path):
    binary = tmp_path / "nginx-asan"
    binary.write_bytes(b"ELF\x00libasan.so.8\x00")
    assert operator_runtime._is_sanitized_binary(str(binary)) is True


def test_sanitizer_binary_detection_missing_path_is_safe(tmp_path):
    assert operator_runtime._is_sanitized_binary(
        str(tmp_path / "missing-nginx")) is False


def test_pytest_lane_passes_through_a_green_run(monkeypatch):
    calls = []
    monkeypatch.setattr(operator_runtime, "_run_stream",
                        lambda argv, **k: (calls.append(argv), 0)[1])
    assert operator_runtime._pytest_lane(["tests"], ["-n", "4"], ["-q"]) is True
    assert len(calls) == 1
    assert calls[0][-4:] == ["tests", "-n", "4", "-q"]


def test_pytest_lane_fails_fast_with_no_retry(monkeypatch):
    """A first-pass failure is final: no --lf rerun may launder it away."""
    calls = []
    monkeypatch.setattr(operator_runtime, "_run_stream",
                        lambda argv, **k: (calls.append(argv), 1)[1])
    assert operator_runtime._pytest_lane(["tests"], ["-n", "4"], ["-q"]) is False
    assert len(calls) == 1, "retry ladder must stay dead"
    assert "--lf" not in calls[0]


def test_pytest_lane_composes_selection_main_common_in_order(monkeypatch):
    seen = {}
    monkeypatch.setattr(operator_runtime, "_run_stream",
                        lambda argv, **k: (seen.setdefault("argv", argv), 0)[1])
    operator_runtime._pytest_lane(["a", "b"], ["c"], ["d"])
    assert seen["argv"][-4:] == ["a", "b", "c", "d"]
    assert seen["argv"][:3][-2:] == ["-m", "pytest"]


def test_serial_lane_disables_ini_xdist_options_without_unloading_plugin(monkeypatch):
    calls = []
    monkeypatch.setattr(operator_runtime, "_pytest_lane",
                        lambda selection, main, common, **kw: calls.append((selection, main, common)) or True)

    assert operator_runtime._serial_lane(["tests/serial.py"], ["-q"]) is True
    assert calls == [(["tests/serial.py"], ["-n", "0", "-o", "addopts="], ["-q"])]


def test_prepare_test_root_creates_missing_parents(tmp_path: Path):
    test_root = tmp_path / "missing" / "suite-root"

    assert operator_runtime._prepare_test_root(test_root) is True
    assert test_root.is_dir()


def test_prepare_test_root_accepts_existing_directory(tmp_path: Path):
    assert operator_runtime._prepare_test_root(tmp_path) is True
    assert tmp_path.is_dir()


def test_prepare_test_root_rejects_file(capsys, tmp_path: Path):
    test_root = tmp_path / "not-a-directory"
    test_root.write_text("occupied", encoding="utf-8")

    assert operator_runtime._prepare_test_root(test_root) is False
    assert f"cannot create TEST_ROOT={test_root}" in capsys.readouterr().err


def _executable(path: Path):
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_suite_binary_args_propagate_to_all_helper_names(monkeypatch, tmp_path: Path):
    nginx = _executable(tmp_path / "custom-nginx")
    xrootd = _executable(tmp_path / "custom-xrootd")
    monkeypatch.setattr(operator_runtime, "teardown_test_fleet", lambda root: None)
    monkeypatch.setattr(operator_runtime, "_existing", lambda paths: [])
    monkeypatch.setattr(operator_runtime, "_pytest_lane", lambda *args, **kw: True)

    assert operator_runtime.run_suite([
        "--fast", "--nginx-bin", str(nginx), "--xrootd-bin", str(xrootd),
    ]) == 0
    assert operator_runtime.os.environ["TEST_NGINX_BIN"] == str(nginx)
    assert operator_runtime.os.environ["NGINX_BIN"] == str(nginx)
    for name in ("TEST_BRIX_BIN", "BRIX_BIN", "XROOTD_BIN", "REF_BIN"):
        assert operator_runtime.os.environ[name] == str(xrootd)


def test_explicit_first_percent_is_one_no_retry_sample_lane(monkeypatch, tmp_path: Path):
    nginx = _executable(tmp_path / "custom-nginx")
    xrootd = _executable(tmp_path / "custom-xrootd")
    calls = []
    monkeypatch.setattr(operator_runtime, "teardown_test_fleet", lambda root: None)
    monkeypatch.setattr(operator_runtime, "_existing", lambda paths: [])
    monkeypatch.setattr(
        operator_runtime, "_pytest_lane",
        lambda selection, main, common, **kw: calls.append((selection, main, common)) or True,
    )

    assert operator_runtime.run_suite([
        "-n", "8", "--first-percent", "10",
        "--nginx-bin", str(nginx), "--xrootd-bin", str(xrootd),
    ]) == 0
    assert len(calls) == 1
    selection, main, common = calls[0]
    assert selection[-1] == "--first-percent=10"
    assert main == ["-n", "8", "--dist", "loadgroup"]
    assert ["-p", "no:rerunfailures"] == common[4:6]
    # positional pinning stops here: the crash-storm bound
    # (--max-worker-restart=8) sits between the plugin kills and the ini reset.
    ini_reset = common.index("-o")
    assert all(("--max-worker-restart=8" in common,
                common[ini_reset:ini_reset + 2] == ["-o", "addopts="])), common


def test_default_suite_runs_full_parallel_and_serial_lanes(monkeypatch, tmp_path: Path):
    nginx = _executable(tmp_path / "custom-nginx")
    xrootd = _executable(tmp_path / "custom-xrootd")
    calls = []
    monkeypatch.setattr(operator_runtime, "teardown_test_fleet", lambda root: None)
    monkeypatch.setattr(operator_runtime, "_existing", lambda paths: [])
    monkeypatch.setattr(operator_runtime, "_pytest_lane",
                        lambda selection, main, common, **kw: calls.append((selection, main, common)) or True)

    assert operator_runtime.run_suite([
        "-n", "20", "--nginx-bin", str(nginx), "--xrootd-bin", str(xrootd),
    ]) == 0
    assert len(calls) == 2
    assert "--first-percent=10" not in calls[0][0]
    assert calls[0][1] == ["-n", "20", "--dist", "loadgroup"]
    assert calls[1][1][:2] == ["-n", "0"]


def test_suite_rejects_missing_nginx_before_cleanup(monkeypatch, tmp_path: Path):
    xrootd = _executable(tmp_path / "xrootd")
    cleaned = []
    monkeypatch.setattr(operator_runtime, "clean_test_fleet", cleaned.append)

    rc = operator_runtime.run_suite([
        "--fast", "--nginx-bin", str(tmp_path / "missing"),
        "--xrootd-bin", str(xrootd),
    ])
    assert rc == 2
    assert cleaned == []


def test_suite_rejects_missing_xrootd_before_cleanup(monkeypatch, tmp_path: Path):
    nginx = _executable(tmp_path / "nginx")
    cleaned = []
    monkeypatch.setattr(operator_runtime, "clean_test_fleet", cleaned.append)

    rc = operator_runtime.run_suite([
        "--fast", "--nginx-bin", str(nginx),
        "--xrootd-bin", str(tmp_path / "missing"),
    ])
    assert rc == 2
    assert cleaned == []


def test_nginx_dynamic_modules_are_auto_discovered_in_load_order(tmp_path: Path):
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    names = (
        "ngx_stream_module.so",
        "ngx_stream_brix_module.so",
        "ngx_http_brix_xrdhttp_filter_module.so",
    )
    for name in names:
        (module_dir / name).write_bytes(b"module")
    nginx = tmp_path / "nginx"
    nginx.write_text(
        f"#!/bin/sh\necho 'configure arguments: --with-stream=dynamic "
        f"--modules-path={module_dir}' >&2\n",
        encoding="utf-8",
    )
    nginx.chmod(0o755)

    assert operator_runtime._configure_nginx_modules(str(nginx), []) is True
    assert operator_runtime.os.environ["TEST_NGINX_LOAD_MODULES"].split(
        operator_runtime.os.pathsep
    ) == [str(module_dir / name) for name in names]


def test_explicit_nginx_dynamic_modules_preserve_requested_order(tmp_path: Path):
    modules = [tmp_path / "core.so", tmp_path / "brix.so"]
    for module in modules:
        module.write_bytes(b"module")

    assert operator_runtime._configure_nginx_modules(
        "/unused/nginx", [str(module) for module in modules],
    ) is True
    assert operator_runtime.os.environ["TEST_NGINX_LOAD_MODULES"].split(
        operator_runtime.os.pathsep
    ) == [str(module) for module in modules]


def test_explicit_project_modules_prepend_discovered_distro_stream_module(tmp_path: Path):
    module_dir = tmp_path / "distro-modules"
    module_dir.mkdir()
    stream = module_dir / "ngx_stream_module.so"
    stream.write_bytes(b"stream")
    project = [tmp_path / "ngx_stream_brix_module.so",
               tmp_path / "ngx_http_brix_xrdhttp_filter_module.so"]
    for module in project:
        module.write_bytes(b"project")
    nginx = tmp_path / "nginx"
    nginx.write_text(
        f"#!/bin/sh\necho 'configure arguments: --with-stream=dynamic "
        f"--modules-path={module_dir}' >&2\n",
        encoding="utf-8",
    )
    nginx.chmod(0o755)

    assert operator_runtime._configure_nginx_modules(
        str(nginx), [str(module) for module in project],
    ) is True
    assert operator_runtime.os.environ["TEST_NGINX_LOAD_MODULES"].split(
        operator_runtime.os.pathsep
    ) == [str(stream), *[str(module) for module in project]]


def test_dynamic_nginx_rejects_foreign_explicit_stream_module(tmp_path: Path):
    own_stream = tmp_path / "ngx_stream_module.so"
    foreign_stream = tmp_path / "foreign" / "ngx_stream_module.so"
    foreign_stream.parent.mkdir()
    own_stream.write_bytes(b"own")
    foreign_stream.write_bytes(b"foreign")
    nginx = tmp_path / "nginx"
    nginx.write_text(
        "#!/bin/sh\necho 'configure arguments: --with-stream=dynamic' >&2\n",
        encoding="utf-8",
    )
    nginx.chmod(0o755)

    assert operator_runtime._configure_nginx_modules(
        str(nginx), [str(foreign_stream)]
    ) is False


def test_missing_explicit_nginx_dynamic_module_is_rejected(tmp_path: Path):
    assert operator_runtime._configure_nginx_modules(
        "/unused/nginx", [str(tmp_path / "missing.so")],
    ) is False


def test_clean_test_fleet_reaps_only_exact_root(monkeypatch, tmp_path: Path):
    lane = tmp_path / "lane-a"
    killed = []
    monkeypatch.setattr(operator_runtime.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(operator_runtime, "_pgrep_name",
                        lambda name: [900001, 900002] if name == "nginx" else [])
    monkeypatch.setattr(
        operator_runtime, "_process_cmdline",
        lambda pid: f"nginx -p {lane}/registry/main" if pid == 900001
        else f"nginx -p {tmp_path}/lane-b/registry/main",
    )
    monkeypatch.setattr(operator_runtime, "_safe_kill",
                        lambda pid, sig=operator_runtime.signal.SIGTERM: killed.append((pid, sig)))
    # clean_test_fleet has a SECOND, port-band reap stage (kill_pid_list over
    # pids_in_port_range) that is NOT scoped to test_root.  Under the ambient
    # TEST_PORT_START it would kill the live shared fleet — neutralise it here as
    # test_clean_test_fleet_reaps_known_listener_on_selected_ladder does.
    monkeypatch.setattr("lib_py.util.pids_in_port_range", lambda *a, **k: [])
    monkeypatch.setattr("lib_py.util.kill_pid_list", lambda pids: killed.extend(pids))

    operator_runtime.clean_test_fleet(lane)

    assert killed == [(900001, operator_runtime.signal.SIGTERM)]


def test_clean_test_fleet_does_not_use_legacy_shared_tmp_markers(monkeypatch, tmp_path: Path):
    killed = []
    monkeypatch.setattr(operator_runtime.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(operator_runtime, "_pgrep_name", lambda name: [900003])
    monkeypatch.setattr(operator_runtime, "_process_cmdline",
                        lambda pid: "xrootd -c /tmp/xrd/another-lane.cfg")
    monkeypatch.setattr(operator_runtime, "_safe_kill",
                        lambda pid, sig=operator_runtime.signal.SIGTERM: killed.append(pid))
    # Neutralise the unscoped port-band reap stage so it can't touch the live
    # shared fleet under the ambient TEST_PORT_START (see the note above).
    monkeypatch.setattr("lib_py.util.pids_in_port_range", lambda *a, **k: [])
    monkeypatch.setattr("lib_py.util.kill_pid_list", lambda pids: killed.extend(pids))

    operator_runtime.clean_test_fleet(tmp_path / "mine")

    assert killed == []


def test_clean_test_fleet_reaps_known_listener_on_selected_ladder(monkeypatch, tmp_path: Path):
    killed = []
    monkeypatch.setattr(operator_runtime.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(operator_runtime, "_pgrep_name", lambda name: [])
    monkeypatch.setattr(operator_runtime, "_process_cmdline",
                        lambda pid: "nginx: worker process")
    monkeypatch.setattr(operator_runtime.Path, "resolve",
                        lambda self: Path("/usr/sbin/nginx"))
    monkeypatch.setattr("lib_py.util.pids_in_port_range",
                        lambda start, end: [900004])
    monkeypatch.setattr("lib_py.util.kill_pid_list", lambda pids: killed.extend(pids))

    operator_runtime.clean_test_fleet(tmp_path / "mine")

    assert killed == [900004]


def test_suite_lane_tears_down_after_success(monkeypatch, tmp_path: Path):
    events = []
    monkeypatch.setattr(operator_runtime, "_pytest_lane", lambda *a, **kw: events.append("run") or True)
    monkeypatch.setattr(operator_runtime, "teardown_test_fleet",
                        lambda root: events.append(("stop", root)))

    assert operator_runtime._suite_lane(tmp_path, ["tests"], [], []) is True
    assert events == ["run", ("stop", tmp_path)]


def test_suite_lane_tears_down_after_failure(monkeypatch, tmp_path: Path):
    events = []
    monkeypatch.setattr(operator_runtime, "_pytest_lane", lambda *a, **kw: False)
    monkeypatch.setattr(operator_runtime, "teardown_test_fleet",
                        lambda root: events.append(root))

    assert operator_runtime._suite_lane(tmp_path, ["tests"], [], []) is False
    assert events == [tmp_path]


def test_suite_lane_tears_down_after_interrupt(monkeypatch, tmp_path: Path):
    events = []
    monkeypatch.setattr(operator_runtime, "_pytest_lane",
                        lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    monkeypatch.setattr(operator_runtime, "teardown_test_fleet",
                        lambda root: events.append(root))

    with pytest.raises(KeyboardInterrupt):
        operator_runtime._suite_lane(tmp_path, ["tests"], [], [])
    assert events == [tmp_path]

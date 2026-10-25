from pathlib import Path
import subprocess

import pytest

from cmdscripts.cvmfs_driver_units import run_checks

pytestmark = pytest.mark.xdist_group("cmd-cvmfs_driver_units")


@pytest.mark.parametrize("name", ["core", "client", "walk", "xorf", "bundle", "dict", "pack", "pathidx", "build"])
def test_cvmfs_driver_unit_ports(tmp_path: Path, name: str):
    results = run_checks(tmp_path, [name])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)


@pytest.mark.timeout(120)   # compiles brixcvmfs + mkrepo, forges a repo, live-mounts
def test_brixcvmfs_check_port(tmp_path: Path):
    results = run_checks(tmp_path, ["check"])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)


@pytest.mark.parametrize("code", [0, 1, -9])
def test_mkrepo_compile_includes_legacy_crypto_and_refuses_compiler_failure(
        tmp_path, monkeypatch, code):
    from cmdscripts import cvmfs_driver_units as units

    compiled, following = [], []

    def compile_fixture(output, arguments, **options):
        compiled.append(arguments)
        return subprocess.CompletedProcess([], code, stdout="", stderr="compile refused")

    def compile_client(output):
        following.append(output)
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    monkeypatch.setattr(units, "compile_binary", compile_fixture)
    monkeypatch.setattr(units, "_compile_brixcvmfs", compile_client)
    verdict = units._compile_check_binaries({"mkrepo": tmp_path / "mkrepo",
                                            "brixcvmfs": tmp_path / "client"})
    assert compiled[0][compiled[0].index("src") - 1] == "-I"
    assert bool(following) == (code == 0)
    if code == 0:
        assert verdict is None
    else:
        assert verdict[0] is False and "compile refused" in verdict[1]


@pytest.mark.parametrize("directory", ["web root", "web;not-a-command"])
def test_fixture_http_server_uses_the_selected_interpreter(tmp_path, monkeypatch, directory):
    from cmdscripts import cvmfs_driver_units as units

    calls = []
    monkeypatch.setattr(units.subprocess, "Popen",
                        lambda command, **options: calls.append((command, options)))
    units._start_check_server(tmp_path / directory, 2222)
    command, options = calls[0]
    assert command[:3] == [units.sys.executable, "-m", "http.server"]
    assert options["cwd"] == str(tmp_path / directory)
    assert not options.get("shell")


def test_fixture_interpreter_failure_is_not_replaced_by_another_python(tmp_path, monkeypatch):
    from cmdscripts import cvmfs_driver_units as units

    def missing(command, **options):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(units.subprocess, "Popen", missing)
    with pytest.raises(FileNotFoundError):
        units._start_check_server(tmp_path, 2222)

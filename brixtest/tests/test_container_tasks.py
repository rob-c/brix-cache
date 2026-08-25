"""One-shot Docker/Podman execution contracts for managed Task resources."""

from pathlib import Path

import pytest

from brixtest import (
    CommandResult,
    Placement,
    ResourceLimits,
    case,
    identity,
    task,
)
from brixtest.errors import SpecError
from brixtest.runtime.manager import CaseManager


def _definition(*resources):
    @case(*resources, observe=(), keep="always")
    def declared(run):
        return None

    return declared.__brixtest_case__


@pytest.mark.parametrize("runtime", ["docker", "podman"])
def test_container_task_uses_disposable_executor_and_archives_streams(
    tmp_path, monkeypatch, runtime,
):
    observed = {}
    digest = "registry.test/task@sha256:" + "a" * 64
    prepare = task(
        "prepare", command=("prepare", "--once"), env={"MODE": "test"},
        placement=Placement(
            backend=runtime, image=digest,
            resources=ResourceLimits(cpu=0.5, memory_bytes=8 << 20, pids=16),
        ),
    )

    def completed(self, *argv, **options):
        observed.update({"argv": tuple(argv), "options": options})
        return CommandResult(tuple(argv), 0, "prepared\n", "diagnostic\n", 0.01)

    monkeypatch.setattr("brixtest.runtime.executors.CommandRunner.run", completed)
    manager = CaseManager(
        _definition(prepare), "tasks::%s" % runtime, root=tmp_path / "run",
    )
    run = manager.start()

    assert observed["argv"][:3] == (runtime, "run", "--rm")
    assert observed["argv"][-2:] == prepare.command
    assert run.task(prepare).stdout == "prepared\n"
    logs = tmp_path / "run" / "runtime" / "tasks" / "prepare" / "logs"
    assert (logs / "0001.stdout.log").read_text() == "prepared\n"
    assert (logs / "0001.stderr.log").read_text() == "diagnostic\n"
    manager.set_outcome("passed")
    manager.close()


def test_container_task_rejects_mutable_image_before_creating_run(tmp_path):
    unsafe = task(
        "unsafe", command=("true",),
        placement=Placement(backend="docker", image="task:latest"),
    )
    root = tmp_path / "run"
    with pytest.raises(SpecError, match="digest pinned"):
        CaseManager(_definition(unsafe), "tasks::mutable", root=root)
    assert not root.exists()


def test_container_task_translates_identity_before_spawn(
    tmp_path, monkeypatch,
):
    observed = {}
    runner = identity("runner", uid=1001, gid=1002, capabilities=("chown",))
    digest = "registry.test/task@sha256:" + "b" * 64
    secured = task(
        "secured", command=("true",),
        placement=Placement(
            backend="docker", image=digest, identity=runner,
        ),
    )
    def completed(self, *argv, **options):
        observed["argv"] = tuple(argv)
        return CommandResult(tuple(argv), 0, "", "", 0.01)

    monkeypatch.setattr("brixtest.runtime.executors.CommandRunner.run", completed)
    root = Path(tmp_path / "run")
    manager = CaseManager(_definition(runner, secured), "tasks::identity", root=root)
    manager.start()
    assert observed["argv"][observed["argv"].index("--user") + 1] == "1001:1002"
    assert observed["argv"][observed["argv"].index("--cap-add") + 1] == "CHOWN"
    manager.close()


def test_process_task_translates_identity_before_spawn(tmp_path, monkeypatch):
    observed = {}
    runner = identity("runner", uid=1001, gid=1002)
    secured = task(
        "secured", command=("true",), placement=Placement(identity=runner),
    )

    def completed(self, *argv, **options):
        observed["argv"] = tuple(argv)
        return CommandResult(tuple(argv), 0, "", "", 0.01)

    monkeypatch.setattr("brixtest.runtime.managed.CommandRunner.run", completed)
    monkeypatch.setattr(
        "brixtest.runtime.launcher_identity.shutil.which", lambda name: "/usr/bin/setpriv",
    )
    root = Path(tmp_path / "run")
    manager = CaseManager(
        _definition(runner, secured), "tasks::process-identity", root=root,
    )
    manager.start()
    assert observed["argv"][:2] == ("setpriv", "--no-new-privs")
    assert observed["argv"][-1] == "true"
    manager.close()

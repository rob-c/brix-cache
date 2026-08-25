"""Container server lifecycle translation contracts."""

import pytest

from brixtest import CaseManager, Lifecycle, Placement, case, server
from brixtest.errors import SpecError, TemplateError

_IMAGE = "registry.test/server@sha256:" + "a" * 64


def _manager(tmp_path, runtime: str):
    origin = server(
        "origin", command=("/server", "--foreground"),
        placement=Placement(backend=runtime, image=_IMAGE),
        lifecycle=Lifecycle(
            shutdown_command=("/serverctl", "stop", "{port}"),
        ),
    )

    @case(origin, observe=())
    def declared(run):
        pass

    manager = CaseManager(
        declared.__brixtest_case__, "unit::%s-lifecycle" % runtime,
        root=tmp_path / "run",
    )
    manager.workspace.mkdir(parents=True)
    return manager, origin


@pytest.mark.parametrize("runtime", ("docker", "podman"))
def test_declared_shutdown_runs_inside_the_owned_container(tmp_path, monkeypatch, runtime):
    monkeypatch.setattr(
        "brixtest.runtime.launchers.shutil.which", lambda name: "/usr/bin/" + name,
    )
    manager, origin = _manager(tmp_path, runtime)
    _launcher, plan, shutdown = manager._local_launch_plan(
        origin, {"port": 19000}, {}, (), (),
    )
    assert shutdown == (
        runtime, "exec", plan.metadata["container_name"],
        "/serverctl", "stop", "19000",
    )
    assert plan.cleanup_argv == (
        runtime, "rm", "--force", plan.metadata["container_name"],
    )


def test_container_shutdown_rejects_unresolved_template_values(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "brixtest.runtime.launchers.shutil.which", lambda name: "/usr/bin/" + name,
    )
    manager, origin = _manager(tmp_path, "docker")
    with pytest.raises(TemplateError, match="port"):
        manager._local_launch_plan(origin, {}, {}, (), ())


def test_oci_group_member_executes_inside_one_owned_container(tmp_path, monkeypatch):
    placement = Placement(backend="docker", image=_IMAGE, group="stack")
    origin = server("origin", command=("/origin",), placement=placement)
    monitor = server("monitor", command=("/monitor",), placement=placement)

    @case(origin, monitor, observe=())
    def declared(run):
        pass

    monkeypatch.setattr(
        "brixtest.runtime.launchers.shutil.which", lambda name: "/usr/bin/" + name,
    )
    manager = CaseManager(
        declared.__brixtest_case__, "unit::oci-group", root=tmp_path / "run",
    )
    manager.workspace.mkdir(parents=True)
    _launcher, anchor, _shutdown = manager._local_launch_plan(
        origin, {}, {}, (), (),
    )
    _launcher, member, _shutdown = manager._local_launch_plan(
        monitor, {}, {}, (), (), group_anchor=anchor,
    )
    assert member.argv[:2] == ("docker", "exec")
    assert member.metadata["container_name"] == anchor.metadata["container_name"]
    assert member.argv[-1] == "/monitor" and not member.cleanup_argv


def test_oci_group_rejects_conflicting_container_policy_before_mutation(tmp_path):
    origin = server(
        "origin", command=("/origin",),
        placement=Placement(backend="docker", image=_IMAGE, group="stack"),
    )
    monitor = server(
        "monitor", command=("/monitor",),
        placement=Placement(
            backend="docker", image=_IMAGE, group="stack", labels={"role": "monitor"},
        ),
    )

    @case(origin, monitor, observe=())
    def declared(run):
        pass

    root = tmp_path / "rejected"
    with pytest.raises(SpecError, match="must share image"):
        CaseManager(declared.__brixtest_case__, "unit::bad-oci-group", root=root)
    assert not root.exists()

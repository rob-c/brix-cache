"""Contracts for typed infrastructure declarations and side-effect-free plans."""

import json
import socket
import sys

from pathlib import Path

import pytest

from brixtest import (
    Environment,
    Identity,
    Resource,
    Task,
    Volume,
    binary,
    case,
    endpoint,
    environment,
    file_artifact,
    identity,
    mount,
    probe,
    resource,
    server,
    task,
    token_auth,
    volume,
)
from brixtest.errors import SpecError
from brixtest.planning import compile_case, validate_capabilities
from brixtest.planning.model import GraphEdge
from brixtest.pytest_design import _describe_plan
from brixtest.resources import Placement
from brixtest.resources import Reference
from brixtest.runtime.manager import CaseManager


def _definition(*resources, **options):
    @case(*resources, observe=(), **options)
    def declared(run):
        return None

    return declared.__brixtest_case__


def test_managed_factories_return_frozen_typed_resources():
    values = (
        environment("lab"), volume("data"), identity("runner"),
        task("prepare", command=("true",)), resource("store", "ceph"),
    )
    assert tuple(type(item) for item in values) == (
        Environment, Volume, Identity, Task, Resource,
    )
    with pytest.raises(AttributeError):
        values[0].name = "changed"


def test_positional_case_resources_are_inferred_without_keyword_boilerplate():
    lab = environment("lab")
    data = volume("data")
    runner = identity("runner")
    prepare = task("prepare", command=("true",))
    store = resource("store", "ceph")
    definition = _definition(lab, data, runner, prepare, store)
    assert definition.resource_names["environments"] == ("lab",)
    assert definition.resource_names["volumes"] == ("data",)
    assert definition.resource_names["identities"] == ("runner",)
    assert definition.resource_names["tasks"] == ("prepare",)
    assert definition.resource_names["managed_resources"] == ("store",)


def test_mounting_volume_infers_it_into_the_case():
    data = volume("data")
    origin = server("origin", command=("true",), mounts=(mount(data, "data"),))
    definition = _definition(origin)
    assert definition.volumes == (data,)


def test_task_output_and_provider_output_are_typed_references():
    prepare = task("prepare", command=("true",), outputs={"binary": "server"})
    store = resource("store", "ceph")
    assert prepare.output("binary").key == "task_prepare_binary"
    assert store.ref("claim").key == "resource_store_claim"
    with pytest.raises(SpecError, match="known"):
        prepare.output("missing")


def test_environment_rejects_unknown_address_family():
    with pytest.raises(SpecError, match="environment.family"):
        environment("lab", family="ipx")


def test_device_volume_requires_an_explicit_source():
    with pytest.raises(SpecError, match="volume.source"):
        volume("fuse", kind="device")


def test_device_capability_is_negotiated_before_resource_creation():
    fuse = volume("fuse", kind="device", source="/dev/fuse")
    local_graph = compile_case(_definition(fuse), "local")
    with pytest.raises(SpecError, match=r"storage.device.*backend local"):
        validate_capabilities(local_graph.nodes)
    validate_capabilities(compile_case(_definition(fuse), "docker").nodes)


def test_user_namespace_capability_selects_process_and_podman():
    runner = identity("runner", user_namespace=True)
    validate_capabilities(compile_case(_definition(runner), "local").nodes)
    validate_capabilities(compile_case(_definition(runner), "podman").nodes)
    with pytest.raises(SpecError, match=r"identity.userns.*backend docker"):
        validate_capabilities(compile_case(_definition(runner), "docker").nodes)


def test_identity_rejects_invalid_id_map_rows():
    with pytest.raises(SpecError, match="identity.uid_map"):
        identity("runner", user_namespace=True, uid_map=((0, 1000, 0),))


def test_task_rejects_escaping_output_paths():
    with pytest.raises(SpecError, match="task.outputs"):
        task("prepare", command=("true",), outputs={"binary": "../server"})


def test_placement_references_must_be_declared_by_the_case():
    origin = server(
        "origin", command=("true",), placement=Placement(environment="missing"),
    )
    with pytest.raises(SpecError, match="placement.environment"):
        _definition(origin)


def test_endpoint_family_and_exposure_are_validated():
    selected = endpoint("monitor", protocol="udp", family="dual", exposure="environment")
    assert (selected.protocol, selected.family, selected.exposure) == (
        "udp", "dual", "environment",
    )
    with pytest.raises(SpecError, match="endpoint.exposure"):
        endpoint(exposure="world")


def test_server_replica_count_is_positive():
    assert server("origin", command=("true",), replicas=3).replicas == 3
    with pytest.raises(SpecError, match="server.replicas"):
        server("origin", command=("true",), replicas=0)


def test_graph_contains_typed_placement_dependency_and_mount_edges():
    lab = environment("lab")
    runner = identity("runner")
    data = volume("data")
    prepare = task("prepare", command=("true",), placement=Placement(environment=lab))
    origin = server(
        "origin", command=("true",), depends_on=(prepare.name,),
        mounts=(mount(data, "data"),),
        placement=Placement(environment=lab, identity=runner),
    )
    graph = compile_case(_definition(lab, runner, data, prepare, origin))
    rows = {(edge.source, edge.target, edge.relation) for edge in graph.edges}
    assert ("task:prepare", "server:origin", "ready-before") in rows
    assert ("environment:lab", "server:origin", "places") in rows
    assert ("identity:runner", "server:origin", "identifies") in rows
    assert ("volume:data", "server:origin", "mounts") in rows
    assert ("server:origin", "task:prepare", "tears-down-before") in rows


def test_graph_dependency_has_connectivity_and_reverse_teardown_edges():
    database = server("database", command=("true",))
    origin = server("origin", command=("true",), depends_on=(database,))
    rows = {
        (edge.source, edge.target, edge.relation)
        for edge in compile_case(_definition(database, origin)).edges
    }
    assert ("server:database", "server:origin", "ready-before") in rows
    assert ("server:origin", "server:database", "connects-to") in rows
    assert ("server:origin", "server:database", "tears-down-before") in rows
    with pytest.raises(SpecError, match="graph edge relation"):
        GraphEdge("server:origin", "server:database", "maybe")


def test_graph_fingerprint_is_stable_and_changes_with_effective_declaration():
    first = compile_case(_definition(server("origin", command=("true",))))
    same = compile_case(_definition(server("origin", command=("true",))))
    changed = compile_case(_definition(server("origin", command=("true",), replicas=2)))
    assert first.fingerprint == same.fingerprint
    assert first.fingerprint != changed.fingerprint


def test_dependency_cycle_is_rejected_by_planning():
    first = task("first", command=("true",), depends_on=("second",))
    second = task("second", command=("true",), depends_on=("first",))
    with pytest.raises(SpecError, match="acyclic"):
        compile_case(_definition(first, second))


def test_kubernetes_ipv6_capability_is_negotiated():
    origin = server(
        "origin", command=("true",), endpoints=(endpoint(family="ipv6"),),
    )
    graph = compile_case(_definition(origin), "kubernetes")
    validate_capabilities(graph.nodes)


def test_plan_redacts_authentication_secrets():
    auth = token_auth("issuer", secret="do-not-archive")
    encoded = str(compile_case(_definition(auth)).as_dict())
    assert "do-not-archive" not in encoded


def test_case_manager_archives_normalized_plan(tmp_path):
    definition = _definition(keep="always")
    manager = CaseManager(definition, "planning::evidence", root=tmp_path / "run")
    manager.start()
    manager.set_outcome("passed")
    manager.close()
    summary = json.loads((tmp_path / "run" / "summary.json").read_text())
    plan = next(
        row for row in summary["evidence"]["artifacts"]
        if row["name"] == "resource-plan.json"
    )
    assert plan["role"] == "resource-plan"
    assert len(plan["sha256"]) == 64
    journal = (tmp_path / "run" / "evidence" / "journal.jsonl").read_text()
    assert '"resource-plan"' in journal


def test_compilation_does_not_create_files(tmp_path):
    target = tmp_path / "must-not-exist"
    build = task("build", command=("touch", str(target)))
    compile_case(_definition(build))
    assert not target.exists()


def test_local_tasks_publish_verified_outputs_and_results(tmp_path):
    prepare = task(
        "prepare",
        command=(
            sys.executable, "-c",
            "from pathlib import Path; Path('message.txt').write_text('ready')",
        ),
        outputs={"message": "message.txt"},
    )
    consume = task(
        "consume", depends_on=(prepare,),
        command=(
            sys.executable, "-c",
            "import pathlib,sys; pathlib.Path('copy.txt').write_text(pathlib.Path(sys.argv[1]).read_text())",
            prepare.output("message"),
        ),
        outputs={"copy": "copy.txt"},
    )
    manager = CaseManager(
        _definition(prepare, consume, keep="always"),
        "managed::tasks", root=tmp_path / "run",
    )
    run = manager.start()
    assert run.task(prepare).ok
    assert run.task_output(consume, "copy").read_text() == "ready"
    assert run.tasks["consume"].stdout == ""
    manager.set_outcome("passed")
    manager.close()
    summary = json.loads((tmp_path / "run" / "summary.json").read_text())
    assert len(summary["tasks"]["consume"]["outputs"]["copy"]["sha256"]) == 64


def test_writable_volume_is_shared_by_managed_tasks(tmp_path):
    data = volume("data", kind="shared")
    mounted = mount(data, "data", read_only=False)
    write = task(
        "write", mounts=(mounted,),
        command=(
            sys.executable, "-c",
            "import os,pathlib; pathlib.Path(os.environ['MOUNT_DATA'],'value').write_text('shared')",
        ),
    )
    manager = CaseManager(
        _definition(data, write, keep="always"),
        "managed::volume", root=tmp_path / "run",
    )
    run = manager.start()
    assert (run.volume(data) / "value").read_text() == "shared"
    manager.set_outcome("passed")
    manager.close()


def test_missing_declared_task_output_fails_setup(tmp_path):
    missing = task(
        "missing", command=(sys.executable, "-c", "pass"),
        outputs={"required": "absent.txt"},
    )
    manager = CaseManager(
        _definition(missing, keep="always"),
        "managed::missing", root=tmp_path / "run",
    )
    with pytest.raises(SpecError, match="regular non-symlink"):
        manager.start()


def test_symlink_task_output_is_rejected(tmp_path):
    unsafe = task(
        "unsafe",
        command=(
            sys.executable, "-c",
            "import os; os.symlink('/etc/passwd', 'escape.txt')",
        ),
        outputs={"escape": "escape.txt"},
    )
    manager = CaseManager(
        _definition(unsafe, keep="always"),
        "managed::symlink", root=tmp_path / "run",
    )
    with pytest.raises(SpecError, match="regular non-symlink"):
        manager.start()


def test_planning_rejects_impossible_task_lifetimes():
    origin = server("origin", command=("true",))
    prepare = task("prepare", command=("true",), depends_on=(origin,))
    with pytest.raises(SpecError, match="finalization tasks"):
        compile_case(_definition(origin, prepare))


def test_volume_quota_fails_before_case_directory_creation(tmp_path):
    data = volume("data", size=1024)
    target = tmp_path / "run"
    with pytest.raises(SpecError, match="storage.quota"):
        CaseManager(_definition(data), "managed::quota", root=target)
    assert not target.exists()


def test_service_filesystem_is_binary_safe_confined_and_journaled(tmp_path):
    data = volume("data", kind="shared")
    origin = server(
        "origin",
        command=(sys.executable, "-c", "import time; time.sleep(30)"),
        mounts=(mount(data, "data", read_only=False),),
        probe=probe("none"),
    )
    manager = CaseManager(
        _definition(data, origin, keep="always"),
        "managed::filesystem", root=tmp_path / "run",
    )
    run = manager.start()
    filesystem = run.server(origin).fs
    filesystem.mkdir("nested")
    filesystem.write_bytes("nested/payload.bin", b"\x00\xffBriX")
    assert filesystem.read_bytes("nested/payload.bin") == b"\x00\xffBriX"
    assert filesystem.list("nested") == ("payload.bin",)
    assert filesystem.stat("nested/payload.bin")["size"] == 6
    filesystem.write_text(run.volume(data) / "shared.txt", "volume")
    assert (run.volume(data) / "shared.txt").read_text() == "volume"
    manager.set_outcome("passed")
    manager.close()
    journal = (tmp_path / "run" / "evidence" / "journal.jsonl").read_text()
    assert '"filesystem-operation"' in journal
    assert '"sha256"' in journal


def test_service_filesystem_rejects_traversal_and_escaping_symlinks(tmp_path):
    origin = server(
        "origin",
        command=(sys.executable, "-c", "import time; time.sleep(30)"),
        probe=probe("none"),
    )
    manager = CaseManager(
        _definition(origin, keep="always"),
        "managed::filesystem-security", root=tmp_path / "run",
    )
    filesystem = manager.start().server(origin).fs
    with pytest.raises(SpecError, match="escapes"):
        filesystem.read_text("../../../../etc/passwd")
    with pytest.raises(SpecError, match="must remain"):
        filesystem.symlink("/etc/passwd", "escape")
    with pytest.raises(SpecError, match="service root"):
        filesystem.remove(".", recursive=True)
    manager.set_outcome("passed")
    manager.close()


def _ipv6_server(family):
    code = (
        "import socket,sys;"
        "s=socket.socket(socket.AF_INET6);"
        "s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,int(sys.argv[3]));"
        "s.bind((sys.argv[1],int(sys.argv[2])));s.listen();"
        "exec('while True:\\n c,_=s.accept()\\n c.close()')"
    )
    return server(
        "origin", command=(
            sys.executable, "-u", "-c", code, "{host}", "{port}",
            "0" if family == "dual" else "1",
        ),
        endpoints=(endpoint("primary", family=family),),
    )


def test_ipv6_only_endpoint_uses_real_ipv6_socket_and_url(tmp_path):
    origin = _ipv6_server("ipv6")
    manager = CaseManager(
        _definition(origin, keep="always"),
        "managed::ipv6", root=tmp_path / "run",
    )
    service = manager.start().server(origin)
    assert service.host == "::1"
    assert service.url().startswith("http://[::1]:")
    with socket.create_connection(service.address(), timeout=1.0):
        pass
    manager.set_outcome("passed")
    manager.close()


def test_dual_stack_endpoint_accepts_ipv4_and_ipv6_on_one_port(tmp_path):
    origin = _ipv6_server("dual")
    manager = CaseManager(
        _definition(origin, keep="always"),
        "managed::dual", root=tmp_path / "run",
    )
    service = manager.start().server(origin)
    with socket.create_connection(("127.0.0.1", service.port()), timeout=1.0):
        pass
    with socket.create_connection(("::1", service.port()), timeout=1.0):
        pass
    assert service.endpoint()["host"] == "::1"
    manager.set_outcome("passed")
    manager.close()


def test_design_explains_effective_plan_and_missing_capabilities():
    class Terminal:
        def __init__(self):
            self.lines = []

        def write_line(self, value):
            self.lines.append(value)

    origin = server(
        "origin", command=("true",),
        endpoints=(endpoint("primary", family="ipv6"),),
    )
    terminal = Terminal()
    _describe_plan(terminal, _definition(origin, backend="kubernetes"))
    text = "\n".join(terminal.lines)
    assert "plan schema=1 fingerprint=" in text
    assert "node server:origin" in text
    assert "missing=" not in text




def test_task_outputs_become_immutable_binary_and_artifact_inputs(tmp_path):
    code = (
        "import os,pathlib;"
        "pathlib.Path('server').write_text('#!/usr/bin/env python3\\nimport time\\ntime.sleep(30)\\n');"
        "os.chmod('server',0o755);pathlib.Path('payload').write_text('built')"
    )
    build = task(
        "build", command=(sys.executable, "-c", code),
        outputs={"server": "server", "payload": "payload"},
    )
    executable = binary(
        "built_server", path=build.output("server"), discover_libraries=False,
    )
    payload = file_artifact("built_payload", build.output("payload"))
    origin = server(
        "origin", command=(executable,), depends_on=(build,), probe=probe("none"),
    )
    definition = _definition(build, executable, payload, origin, keep="always")
    graph = compile_case(definition)
    edges = {(row.source, row.target, row.relation) for row in graph.edges}
    assert ("task:build", "binary:built_server", "produces") in edges
    assert ("task:build", "artifact:built_payload", "produces") in edges
    manager = CaseManager(definition, "managed::deferred-inputs", root=tmp_path / "run")
    run = manager.start()
    assert run.binary(executable).verify()
    assert run.artifact(payload).read_text() == "built"
    source = run.task_output(build, "server")
    source.write_text("changed after capture")
    assert run.binary(executable).verify()
    manager.set_outcome("passed")
    manager.close()


def test_deferred_input_must_name_a_real_non_finalizer_output():
    prepare = task("prepare", command=("true",), outputs={"value": "value"})
    missing = binary(
        "missing", path=Reference("task", "prepare", "output", "other"),
    )
    with pytest.raises(SpecError, match="declared task output"):
        _definition(prepare, missing)
    finalize = task(
        "cleanup", command=("true",), phase="finalize", outputs={"value": "value"},
    )
    late = file_artifact("late", finalize.output("value"))
    with pytest.raises(SpecError, match="finalization"):
        _definition(finalize, late)

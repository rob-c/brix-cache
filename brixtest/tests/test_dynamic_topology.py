"""Derived fleets, shared lifetimes, and provenance correlation contracts."""

import json
import os
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from brixtest import (
    Placement,
    binary,
    case,
    client,
    environment,
    identity,
    mount,
    server,
    static_config,
    text_artifact,
    volume,
)
from brixtest.archive import archive_server_log
from brixtest.errors import CaseRunError, SpecError
from brixtest.evidence.model import iter_entities
from brixtest.runtime.manager import Service
from brixtest.runtime.topology import injected_services
from brixtest.topology.model import derive, pool_definition, pool_key
from brixtest.topology.broker import RemoteTopology, TopologyBroker


def _declaration(config: Path, *, suffix: str = ""):
    item = server(
        "origin", command=[sys.executable, "-c", "import time;time.sleep(10)"],
        config=static_config(config), ports=["primary"], scope="session",
        env={"SUFFIX": suffix},
    )

    @case(servers=[item], observe=[])
    def declared(run):
        pass

    return item, declared.__brixtest_case__


def test_server_scope_defaults_to_case_and_supports_pytest_lifetimes(tmp_path):
    local = server("local", command=["true"], config=static_config(tmp_path / "x"))
    assert local.scope == "case"
    assert server(
        "shared", command=["true"], config=static_config(tmp_path / "x"),
        scope="module",
    ).scope == "module"
    assert server(
        "worker_local", command=["true"], config=static_config(tmp_path / "x"),
        scope="worker",
    ).scope == "worker"
    with pytest.raises(SpecError, match=r"server\.scope"):
        server("bad", command=["true"], config=static_config(tmp_path / "x"), scope="global")


def test_collection_groups_equal_session_server_graphs(tmp_path):
    config = tmp_path / "origin.conf"
    config.write_text("same\n")
    _, first = _declaration(config)
    _, second = _declaration(config)
    plans = derive([("test_a.py::test_a", first), ("test_b.py::test_b", second)])
    assert len(plans) == 1
    assert plans[0].tests == ("test_a.py::test_a", "test_b.py::test_b")
    assert plans[0].definition.clients == ()


def test_collection_splits_different_server_definitions(tmp_path):
    config = tmp_path / "origin.conf"
    config.write_text("same\n")
    _, first = _declaration(config, suffix="a")
    _, second = _declaration(config, suffix="b")
    assert len(derive([("test_a", first), ("test_b", second)])) == 2


@pytest.mark.parametrize("scope,left,right,expected", [
    ("module", "pkg/test_a.py::test_one", "pkg/test_a.py::test_two", 1),
    ("module", "pkg/test_a.py::test_one", "pkg/test_b.py::test_two", 2),
    ("package", "pkg/test_a.py::test_one", "pkg/test_b.py::test_two", 1),
    ("class", "pkg/test_a.py::TestAPI::test_one", "pkg/test_a.py::TestAPI::test_two", 1),
    ("class", "pkg/test_a.py::TestAPI::test_one", "pkg/test_a.py::TestOther::test_two", 2),
])
def test_collection_derives_pytest_familiar_scope_domains(
    tmp_path, scope, left, right, expected,
):
    config = tmp_path / "origin.conf"
    config.write_text("same\n")
    item = server(
        "origin", command=[sys.executable, "-c", "pass"],
        config=static_config(config), scope=scope,
    )

    @case(servers=[item], observe=[])
    def declared(run):
        pass

    plans = derive([(left, declared.__brixtest_case__), (right, declared.__brixtest_case__)])
    assert len(plans) == expected
    assert {plan.scope for plan in plans} == {scope}


def test_xdist_worker_namespace_produces_distinct_physical_pool_identity(tmp_path):
    config = tmp_path / "origin.conf"
    config.write_text("same\n")
    _, definition = _declaration(config)
    left = derive([("test_a.py::test_one", definition)], namespace="gw0")[0]
    right = derive([("test_a.py::test_one", definition)], namespace="gw1")[0]
    assert left.key != right.key
    assert left.domain.endswith("worker:gw0")
    assert right.domain.endswith("worker:gw1")


def test_pool_fingerprint_includes_config_content(tmp_path):
    config = tmp_path / "origin.conf"
    config.write_text("first\n")
    _, definition = _declaration(config)
    before = pool_key(definition)
    config.write_text("second\n")
    assert pool_key(definition) != before


def test_pool_fingerprint_includes_binary_runtime_data(tmp_path):
    config = tmp_path / "origin.conf"
    config.write_text("same\n")
    executable = tmp_path / "server"
    executable.write_text("binary\n")
    runtime = tmp_path / "plugin.conf"
    runtime.write_text("first\n")
    captured = binary(
        "server", path=executable,
        runtime_files={"/etc/server/plugin.conf": runtime},
    )
    origin = server(
        "origin", command=(captured,), config=static_config(config),
        scope="session",
    )

    @case(origin, captured, observe=())
    def declared(run):
        return None

    before = pool_key(declared.__brixtest_case__)
    runtime.write_text("second\n")
    assert pool_key(declared.__brixtest_case__) != before


def test_topology_broker_rejects_unauthenticated_worker(tmp_path):
    broker = TopologyBroker(tmp_path / "session")
    settings = broker.worker_settings("gw0", 1)
    remote = RemoteTopology(
        str(settings["address"]), "00" * 32, str(settings["worker"]),
    )
    try:
        with pytest.raises(CaseRunError, match="digest sent was rejected"):
            remote.register([], 1)
    finally:
        broker.close()


def test_pool_fingerprint_includes_effective_identity_volume_and_environment(tmp_path):
    config = tmp_path / "origin.conf"
    config.write_text("same\n")

    def declared(uid, size, family):
        runner = identity("runner", uid=uid, gid=uid)
        data = volume("data", size=size)
        realm = environment("realm", family=family, isolated=False)
        origin = server(
            "origin", command=("true",), config=static_config(config),
            scope="session", mounts=(mount(data, "data", read_only=False),),
            placement=Placement(identity=runner, environment=realm),
        )

        @case(origin, runner, data, realm, observe=())
        def selected(run):
            return None

        return selected.__brixtest_case__

    baseline = declared(1000, 0, "ipv4")
    assert pool_key(baseline) != pool_key(declared(1001, 0, "ipv4"))
    assert pool_key(baseline) != pool_key(declared(1000, 4096, "ipv4"))
    assert pool_key(baseline) != pool_key(declared(1000, 0, "ipv6"))
    pooled = pool_definition(baseline)
    assert pooled.identities == baseline.identities
    assert pooled.volumes == baseline.volumes
    assert pooled.environments == baseline.environments


def test_pool_fingerprint_ignores_test_only_clients_and_artifacts(tmp_path):
    config = tmp_path / "origin.conf"
    config.write_text("same\n")
    item = server(
        "origin", command=["true"], config=static_config(config), scope="session",
    )

    @case(item, client("first", command=["true"]),
          text_artifact("unused", "one"), observe=[])
    def first(run):
        pass

    @case(item, client("second", command=["false"]),
          text_artifact("other", "two"), observe=[])
    def second(run):
        pass

    assert pool_key(first.__brixtest_case__) == pool_key(second.__brixtest_case__)
    plan = derive([
        ("test_a.py::test_one", first.__brixtest_case__),
        ("test_b.py::test_two", second.__brixtest_case__),
    ])
    assert len(plan) == 1
    assert plan[0].definition.clients == () and plan[0].definition.artifacts == ()


def test_session_server_cannot_depend_on_case_server(tmp_path):
    config = static_config(tmp_path / "origin.conf")
    local = server("local", command=["true"], config=config)
    shared = server(
        "shared", command=["true"], config=config, scope="session", depends_on=[local]
    )
    with pytest.raises(SpecError, match="only depend"):
        case(servers=[local, shared])


def test_injected_service_preserves_instance_identity(tmp_path, monkeypatch):
    manifest = {"services": {"origin": {
        "instance_id": "instance-1", "pool_id": "pool-1", "host": "127.0.0.1",
        "ports": {"http": 1234, "primary": 1234}, "config": str(tmp_path / "c"),
        "log": str(tmp_path / "l"), "workdir": str(tmp_path / "w"),
        "started_at_epoch": 42,
    }}}
    monkeypatch.setenv("BRIXTEST_SHARED_SERVERS_JSON", json.dumps(manifest))
    resolved = injected_services(Service)["origin"]
    assert resolved.instance_id == "instance-1" and resolved.scope == "session"
    assert resolved.url(role="http") == "http://127.0.0.1:1234/"


def test_server_log_archive_is_identity_addressed_and_hashed(tmp_path):
    source = tmp_path / "origin.log"
    source.write_text("one physical log\n")
    row = archive_server_log(tmp_path / "session", source, "instance-1", server_name="origin")
    assert row["server_instance_id"] == "instance-1"
    assert row["artifact_id"] == "sha256:" + row["sha256"]
    assert row["relative"] == "logs/instances/instance-1/origin.log"


def test_topology_entities_include_pool_instance_log_and_metrics():
    service = {
        "instance_id": "i1", "name": "origin", "scope": "session", "ports": {},
        "log_artifact": {"name": "origin.log", "sha256": "a" * 64},
    }
    payload = {"session_id": "s1", "tests": [], "topology": {"pools": [{
        "pool_id": "p1", "services": {"origin": service},
        "result": {"metrics": {"samples": [{"name": "server.cpu", "value": 1}]},
                   "evidence": {"resources": [], "spans": [], "artifacts": [],
                                "findings": [], "provenance": {"runtime": {}}}},
    }]}}
    entities = [row["entity"] for row in iter_entities(payload)]
    assert entities == [
        "session", "server-pool", "server-instance", "log", "metric", "provenance",
    ]


def _run_shared_suite(
    tmp_path: Path, *, xdist: bool = False, scope: str = "session",
) -> subprocess.CompletedProcess:
    (tmp_path / "origin.json.in").write_text(
        '{"host":"{host}","port":{port},"message":"shared"}\n'
    )
    (tmp_path / "server.py").write_text(
        "import json,sys\n"
        "from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer\n"
        "config=json.load(open(sys.argv[1]))\n"
        "class H(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  body=(config['message']+self.path).encode();self.send_response(200)\n"
        "  self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)\n"
        " def log_message(self,fmt,*args): print(fmt%args,flush=True)\n"
        "ThreadingHTTPServer((config['host'],config['port']),H).serve_forever()\n"
    )
    (tmp_path / "test_shared.py").write_text(
        "import sys,urllib.request\n"
        "from pathlib import Path\n"
        "from brixtest import case,file_artifact,server,tcp,template_config\n"
        "HERE=Path(__file__).parent\n"
        "CODE=file_artifact('server_code',HERE/'server.py')\n"
        "ORIGIN=server('origin',command=[sys.executable,'{artifact_server_code}','{config}'],"
        "config=template_config('origin.json.in'),ports=['http'],readiness=tcp('http'),"
        f"scope={scope!r})\n"
        "@case(servers=[ORIGIN],artifacts=[CODE],keep='never')\n"
        "def test_one(run):\n"
        f" s=run.server(ORIGIN);assert s.scope=={scope!r};assert urllib.request.urlopen(s.url(path='/one')).read()==b'shared/one'\n"
        "@case(servers=[ORIGIN],artifacts=[CODE],keep='never')\n"
        "def test_two(run):\n"
        " s=run.server(ORIGIN);assert urllib.request.urlopen(s.url(path='/two')).read()==b'shared/two'\n"
    )
    source = Path(__file__).resolve().parents[1] / "src"
    env = dict(os.environ)
    for name in tuple(env):
        if name.startswith("BRIXTEST_"):
            env.pop(name)
    env.update({
        "PYTHONPATH": str(source), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPYCACHEPREFIX": str(tmp_path / "pycache"),
        "BRIXTEST_RUNS": str(tmp_path / "runs"),
    })
    argv = [
        sys.executable, "-m", "pytest", str(tmp_path / "test_shared.py"),
        "-p", "brixtest.pytest_plugin", "-q",
    ]
    if xdist:
        argv.extend(("-p", "xdist.plugin", "-n", "2"))
    return subprocess.run(
        argv,
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=45, check=False,
    )


def test_shared_server_end_to_end_has_one_log_and_two_links(tmp_path):
    result = _run_shared_suite(tmp_path)
    assert (result.returncode, "multi-threaded, use of fork()" in result.stderr) == (0, False), (
        result.stdout + result.stderr
    )
    session_path = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    session = json.loads(session_path.read_text())
    assert (session["counts"], len(session["topology"]["pools"])) == ({"passed": 2}, 1)
    pool = session["topology"]["pools"][0]
    service = pool["services"]["origin"]
    _assert_service_metadata(session_path, service)
    attempts = [case_row["attempts"][0] for case_row in session["tests"]]
    _assert_shared_attempts(attempts, service)
    log = session_path.parent / service["log_artifact"]["relative"]
    assert (log.is_file(), "/one" in log.read_text(), "/two" in log.read_text()) == (
        True, True, True,
    )
    with socket.socket() as connection_test:
        assert connection_test.connect_ex((service["host"], service["ports"]["http"])) != 0
    _assert_shared_archive(session_path, service)
    _assert_shared_report(session_path, service)


def test_xdist_workers_consume_one_controller_owned_session_server(tmp_path):
    pytest.importorskip("xdist")
    result = _run_shared_suite(tmp_path, xdist=True)
    assert result.returncode == 0, result.stdout + result.stderr
    session_path = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    session = json.loads(session_path.read_text())
    assert (session["counts"], len(session["topology"]["pools"])) == (
        {"passed": 2}, 1,
    )
    pool = session["topology"]["pools"][0]
    assert sorted(pool["tests"]) == [
        "test_shared.py::test_one", "test_shared.py::test_two",
    ]
    assert len({
        row["attempts"][0]["servers"][0]["instance_id"]
        for row in session["tests"]
    }) == 1


def test_explicit_worker_scope_creates_one_instance_per_consuming_xdist_worker(tmp_path):
    pytest.importorskip("xdist")
    result = _run_shared_suite(tmp_path, xdist=True, scope="worker")
    assert result.returncode == 0, result.stdout + result.stderr
    session_path = next((tmp_path / "runs" / "metrics").glob("*/session.json"))
    session = json.loads(session_path.read_text())
    instances = {
        row["attempts"][0]["servers"][0]["instance_id"]
        for row in session["tests"]
    }
    assert (session["counts"], len(session["topology"]["pools"]), len(instances)) == (
        {"passed": 2}, 2, 2,
    )


def _assert_service_metadata(session_path, service):
    observed = (
        service["config_filename"], len(service["config_source_sha256"]),
        len(service["config_declared_sha256"]), service["config_sha256"],
    )
    expected = ("server.conf", 64, 64, service["config_artifact"]["sha256"])
    assert observed == expected
    config_object = session_path.parent / service["config_artifact"]["object"]
    expected_text = '{"host":"127.0.0.1","port":%d,"message":"shared"}\n' % (
        service["ports"]["http"]
    )
    assert config_object.read_text() == expected_text


def _assert_shared_attempts(attempts, service):
    instance_ids = {row["servers"][0]["instance_id"] for row in attempts}
    log_paths = {row["servers"][0]["log_artifact"]["relative"] for row in attempts}
    assert (instance_ids, log_paths) == (
        {service["instance_id"]}, {service["log_artifact"]["relative"]},
    )


def _assert_shared_archive(session_path, service):
    connection = sqlite3.connect(str(session_path.parent / "archive.sqlite3"))
    try:
        pool_count = connection.execute("select count(*) from evidence_server_pools").fetchone()[0]
        instance_count = connection.execute(
            "select count(*) from evidence_server_instances"
        ).fetchone()[0]
        port_json, filename, config_hash = connection.execute(
            "select ports, config_filename, config_sha256 from evidence_server_instances"
        ).fetchone()
        link_count = connection.execute(
            "select count(*) from evidence_test_server_links"
        ).fetchone()[0]
        log_count = connection.execute(
            "select count(*) from logs where nodeid like '@shared/%'"
        ).fetchone()[0]
        assert (
            pool_count, instance_count, json.loads(port_json), (filename, config_hash),
            link_count, log_count,
        ) == (1, 1, service["ports"], ("server.conf", service["config_sha256"]), 2, 1)
    finally:
        connection.close()


def _assert_shared_report(session_path, service):
    report = (session_path.parent / "report.html").read_text()
    assert (
        "Server instances" in report,
        "http=%d" % service["ports"]["http"] in report,
        service["config_sha256"][:16] in report,
    ) == (True, True, True)

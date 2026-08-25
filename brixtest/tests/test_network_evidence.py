"""Normalized network provenance and checksum contracts."""

from types import SimpleNamespace

from brixtest import Placement, endpoint, environment, host_mapping, server
from brixtest.runtime.network_evidence import network_snapshot
from brixtest.runtime.replica import Replica
from brixtest.runtime.service import Service


def _manager(tmp_path):
    database = server("database", command=("true",), endpoints=(endpoint("db", port=5432),))
    origin = server(
        "origin", command=("true",), depends_on=(database,),
        endpoints=(endpoint("http", port=8080, family="dual", exposure="external"),),
        placement=Placement(environment="cluster", network_policy="declared"),
    )
    service = Service(
        "origin", "127.0.0.1", {"http": 18080, "primary": 18080},
        tmp_path / "config", tmp_path / "log", tmp_path,
        protocols={"http": "tcp"},
        replicas=(Replica("origin-abc", "10.0.0.4", {"http": 8080}),),
    )
    definition = SimpleNamespace(
        environments=(environment("cluster", backend="kubernetes", family="dual"),),
        hosts=(host_mapping("origin", "origin.test", address="127.0.0.8"),),
        servers=(database, origin),
    )
    return SimpleNamespace(
        definition=definition, _services={"origin": service}, backend_name="minikube",
    )


def test_network_snapshot_correlates_internal_external_dns_route_and_policy(tmp_path):
    snapshot = network_snapshot(_manager(tmp_path))
    endpoint_record = snapshot["services"][0]["endpoints"][0]

    assert endpoint_record["internal"] == {"host": "origin", "port": 8080}
    assert endpoint_record["external"] == {"host": "127.0.0.1", "port": 18080}
    assert snapshot["routes"] == [{"source": "origin", "target": "database"}]
    assert snapshot["dns"][0]["hostname"] == "origin.test"
    assert snapshot["policies"][1]["policy"] == "declared"
    assert snapshot["services"][0]["gateway"]["supervised"] is True
    assert len(snapshot["sha256"]) == 64


def test_network_snapshot_checksum_changes_with_realized_allocation(tmp_path):
    manager = _manager(tmp_path)
    first = network_snapshot(manager)
    service = manager._services["origin"]
    object.__setattr__(service, "ports", {"http": 28080, "primary": 28080})
    second = network_snapshot(manager)

    assert first["sha256"] != second["sha256"]
    assert "BEARER_TOKEN" not in str(second)


def test_network_snapshot_distinguishes_binary_udp_gateway(tmp_path):
    manager = _manager(tmp_path)
    declaration = manager.definition.servers[1]
    object.__setattr__(declaration.endpoints[0], "protocol", "udp")
    snapshot = network_snapshot(manager)
    gateway = snapshot["services"][0]["endpoints"][0]["gateway"]
    assert gateway == {"kind": "kubectl-exec-udp", "supervised": True}

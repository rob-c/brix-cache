"""Realized networking and provider identities are first-class evidence rows."""

import json
import sqlite3

import pytest

from brixtest.archive import write_sqlite_archive
from brixtest.evidence.model import iter_entities
from brixtest.evidence.search import documents


def _payload():
    extra = {
        "resource_graph": {
            "fingerprint": "graph-1", "nodes": [{
                "id": "identity:reader", "kind": "identity", "name": "reader",
                "backend": "kubernetes", "environment": "cluster",
                "attributes": {"service_account": "reader", "permissions": {"pods": ["get"]}},
            }], "edges": [],
        },
        "network": {
            "environments": [{"name": "cluster", "namespace": "case-a"}],
            "dns": [{"name": "origin", "hostname": "origin.test", "address": "10.0.0.8"}],
            "routes": [{"source": "reader", "target": "origin"}],
            "policies": [{"server": "origin", "policy": "declared"}],
            "services": [{
                "name": "origin", "endpoints": [{
                    "name": "https", "protocol": "tcp", "family": "ipv4",
                    "internal": {"host": "origin", "port": 8443},
                    "external": {"host": "127.0.0.1", "port": 41234},
                    "gateway": {"kind": "kubectl-port-forward", "supervised": True},
                }],
                "replicas": [{"name": "origin-0", "uid": "pod-uid", "host": "10.1.0.4"}],
            }],
        },
        "provider_resources": {"ceph": {
            "ownership": {"objects": [{
                "api_version": "ceph.rook.io/v1", "kind": "CephCluster",
                "namespace": "case-a", "name": "ceph", "uid": "ceph-uid",
                "owner": "ceph", "instance": "case-uid",
            }]},
            "output_names": ["storage_class"],
            "metadata": {"operator_uid": "operator-uid", "storage_class_uid": "sc-uid"},
        }},
    }
    attempt = {
        "attempt_id": "a1", "trial": 0, "warmup": False, "outcome": "passed",
        "metrics": [], "resources": [], "spans": [], "artifacts": [], "logs": [],
        "servers": [], "findings": [], "provenance": {"extra": extra},
    }
    return {
        "schema": 2, "session_id": "s1", "tests": [{
            "schema": 2, "session_id": "s1", "nodeid": "test.py::test_case",
            "outcome": "passed", "attempts": [attempt],
        }],
    }


@pytest.mark.parametrize("entity", (
    "resource-node", "network-environment", "dns-record", "network-route",
    "network-policy", "network-endpoint", "service-replica",
    "provider-object", "storage-identity",
))
def test_realized_resource_kind_is_queryable(entity):
    assert entity in {row["entity"] for row in iter_entities(_payload())}


def test_realized_endpoint_retains_internal_and_external_addresses():
    endpoint = next(
        row for row in iter_entities(_payload())
        if row["entity"] == "network-endpoint"
    )
    assert endpoint["internal"] == {"host": "origin", "port": 8443}
    assert endpoint["external"]["port"] == 41234


def test_realized_provider_retains_storage_and_kubernetes_identity():
    provider = next(
        row for row in iter_entities(_payload())
        if row["entity"] == "provider-object"
    )
    assert (provider["uid"], provider["resource"]) == ("ceph-uid", "ceph")


def test_realization_entities_reach_sqlite_and_search_unchanged(tmp_path):
    payload = _payload()
    database = write_sqlite_archive(payload, tmp_path, tmp_path / "archive.sqlite3")
    connection = sqlite3.connect(str(database))
    try:
        raw = connection.execute(
            "select payload from evidence_entities where entity='service-replica'"
        ).fetchone()[0]
        assert json.loads(raw)["uid"] == "pod-uid"
        assert connection.execute(
            "select count(*) from evidence_entities where entity like 'network-%'"
        ).fetchone()[0] == 4
    finally:
        connection.close()
    exported = {row["document"]["entity"] for row in documents(payload)}
    assert {"network-endpoint", "provider-object", "storage-identity"} <= exported

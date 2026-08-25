"""Confined, UID-aware Kubernetes operations for resource providers."""

import json
import subprocess

import pytest

from brixtest.errors import SpecError
from brixtest.runtime.provider_kubernetes import bind_kubernetes_provider_api
from brixtest.runtime.providers import ProviderContext


class _Evidence:
    def __init__(self):
        self.events = []

    def event(self, kind, payload):
        self.events.append((kind, payload))


class _Backend:
    namespace = "case-owned"

    def __init__(self):
        self.owner = type("Owner", (), {"evidence": _Evidence()})()
        self._namespace_uid = "case-uid"
        self.documents = []
        self.uid = "uid-1"
        self.deleted = []

    def _run(self, *argv, **options):
        if "create" in argv:
            self.documents.extend(json.loads(options["input_text"])["items"])
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "get" in argv:
            resource = argv[argv.index("get") + 1]
            kind, name = resource.split("/", 1)
            payload = {
                "apiVersion": "example.test/v1", "kind": kind,
                "metadata": {
                    "name": name, "namespace": self.namespace, "uid": self.uid,
                    "labels": {
                        "brixtest.dev/provider-resource": "ceph",
                        "brixtest.dev/test-instance": self._namespace_uid,
                    },
                },
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        self.deleted.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, "", "")


def _context(tmp_path, backend):
    context = ProviderContext("unit::crd", tmp_path, "kubernetes", object(), object())
    bind_kubernetes_provider_api(context, backend)
    return context


def test_provider_applies_namespaced_custom_object_with_owned_uid(tmp_path):
    backend = _Backend()
    objects = _context(tmp_path, backend).kubernetes()
    identities = objects.apply("ceph", [{
        "apiVersion": "example.test/v1", "kind": "Widget",
        "metadata": {"name": "storage"}, "spec": {"capacity": "1Gi"},
    }])
    document = backend.documents[0]
    assert document["metadata"]["namespace"] == "case-owned"
    assert document["metadata"]["labels"]["brixtest.dev/provider-resource"] == "ceph"
    assert document["metadata"]["labels"]["brixtest.dev/test-instance"] == "case-uid"
    assert identities[0]["uid"] == "uid-1"
    assert backend.owner.evidence.events[0][0] == "provider-kubernetes-object"
    objects.delete(identities[0])
    assert "delete" in backend.deleted[0][0]


def test_provider_refuses_cluster_scope_and_foreign_namespaces(tmp_path):
    objects = _context(tmp_path, _Backend()).kubernetes()
    with pytest.raises(SpecError, match="namespace-scoped"):
        objects.apply("ceph", [{
            "apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "escape"},
        }])
    with pytest.raises(SpecError, match="owned case namespace"):
        objects.apply("ceph", [{
            "apiVersion": "example.test/v1", "kind": "Widget",
            "metadata": {"name": "escape", "namespace": "other"},
        }])


def test_provider_delete_refuses_replaced_object_uid(tmp_path):
    backend = _Backend()
    objects = _context(tmp_path, backend).kubernetes()
    identity = objects.apply("ceph", [{
        "apiVersion": "example.test/v1", "kind": "Widget",
        "metadata": {"name": "storage"},
    }])[0]
    backend.uid = "replacement"
    with pytest.raises(SpecError, match="owned UID"):
        objects.delete(identity)


def test_provider_can_discover_but_not_claim_external_prerequisite(tmp_path):
    backend = _Backend()
    payload = _context(tmp_path, backend).kubernetes().discover(
        "deployment", "rook-ceph-operator", namespace="rook-ceph",
    )
    assert payload["metadata"]["uid"] == "uid-1"
    event = backend.owner.evidence.events[-1]
    assert event[0] == "provider-kubernetes-discovery"
    assert event[1]["namespace"] == "rook-ceph"


def test_provider_cannot_use_cluster_operations_during_planning(tmp_path):
    context = ProviderContext("unit::plan", tmp_path, "kubernetes", object(), object())
    with pytest.raises(SpecError, match="only during"):
        context.kubernetes()


def test_partial_identity_capture_rolls_back_every_created_object(tmp_path):
    backend = _Backend()
    original = backend._run
    reads = 0

    def fail_second_read(*argv, **options):
        nonlocal reads
        if "get" in argv:
            reads += 1
            if reads == 2:
                raise RuntimeError("transient identity read failure")
        return original(*argv, **options)

    backend._run = fail_second_read
    objects = _context(tmp_path, backend).kubernetes()
    with pytest.raises(RuntimeError, match="identity read"):
        objects.apply("ceph", [
            {"apiVersion": "example.test/v1", "kind": "Widget", "metadata": {"name": name}}
            for name in ("one", "two")
        ])
    assert len(backend.deleted) == 2


def test_provider_creation_is_exclusive_and_never_overwrites_existing_object(tmp_path):
    backend = _Backend()

    def refuse_create(*argv, **options):
        if "create" in argv:
            raise RuntimeError("already exists")
        payload = {
            "apiVersion": "example.test/v1", "kind": "Widget",
            "metadata": {
                "name": "storage", "namespace": backend.namespace,
                "uid": "foreign", "labels": {},
            },
        }
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    backend._run = refuse_create
    objects = _context(tmp_path, backend).kubernetes()
    with pytest.raises(RuntimeError, match="already exists"):
        objects.apply("ceph", [{
            "apiVersion": "example.test/v1", "kind": "Widget",
            "metadata": {"name": "storage"},
        }])
    assert backend.deleted == []


def test_provider_orphan_journal_recovers_and_uid_guards_cleanup(tmp_path):
    backend = _Backend()
    objects = _context(tmp_path, backend).kubernetes()
    identity = objects.apply("ceph", [{
        "apiVersion": "example.test/v1", "kind": "Widget",
        "metadata": {"name": "storage"},
    }])[0]
    recovered = _context(tmp_path, backend).kubernetes()
    assert recovered.orphans("ceph") == (identity,)
    assert recovered.cleanup_orphans("ceph") == (identity,)
    assert recovered.orphans("ceph") == ()
    assert backend.owner.evidence.events[-1][0] == "provider-kubernetes-orphan-cleaned"

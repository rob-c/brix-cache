"""Provider object evidence remains structured, bounded, and correlated."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from brixtest.errors import SpecError
from brixtest.runtime.provider_observation import provider_observation


class _Evidence:
    def __init__(self):
        self.logs = []

    def attach_text(self, name, text, **metadata):
        row = {"name": name, "text": text, **metadata}
        self.logs.append(row)
        return {"name": name, "sha256": "a" * 64, **metadata}


class _Backend:
    namespace = "case"

    def __init__(self):
        self.owner = SimpleNamespace(evidence=_Evidence())

    def _run(self, *argv, **options):
        if "events" in argv:
            value = {"items": [{"reason": "Provisioned"}]}
        elif "pods" in argv and "get" in argv:
            value = {"items": [{
                "metadata": {"name": "ceph-a", "uid": "pod-1"},
                "status": {"containerStatuses": [{
                    "name": "mon", "ready": True, "restartCount": 1,
                    "state": {"running": {"startedAt": "now"}},
                }]},
            }]}
        elif "logs" in argv:
            return subprocess.CompletedProcess(argv, 0, "ceph output\n", "")
        else:
            return subprocess.CompletedProcess(argv, 0, "ceph-a mon 1m 32Mi\n", "")
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")


def _identity():
    return {
        "api_version": "ceph.rook.io/v1", "kind": "CephCluster",
        "namespace": "case", "name": "ceph", "owner": "storage",
        "instance": "case-uid", "uid": "object-uid",
    }


def test_provider_observation_correlates_events_metrics_status_and_log_checksums():
    backend = _Backend()
    result = provider_observation(
        backend, _identity(), {"status": {"phase": "Ready"}},
        "rook_cluster=case",
    )
    assert result["events"]["items"][0]["reason"] == "Provisioned"
    assert result["workloads"]["metrics"].startswith("ceph-a")
    assert len(result["workloads"]["logs"]) == 2
    assert result["workloads"]["logs"][0]["sha256"] == "a" * 64
    assert result["workloads"]["containers"][0]["pod_uid"] == "pod-1"


def test_provider_observation_rejects_non_exact_selector_syntax():
    with pytest.raises(SpecError, match="exact label selector"):
        provider_observation(
            _Backend(), _identity(), {}, "rook_cluster in (case,foreign)",
        )

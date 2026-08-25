"""Kubernetes workloads stop before provider objects and namespace teardown."""

from brixtest.runtime.manager_operations import CaseManagerOperationsMixin


class _Kubernetes:
    def __init__(self, calls):
        self.calls = calls

    def quiesce(self):
        self.calls.append("workloads")


class _Manager(CaseManagerOperationsMixin):
    def __init__(self):
        self.calls = []
        self._kubernetes = _Kubernetes(self.calls)

    def _close_providers(self):
        self.calls.append("providers")

    def _stop_case_backend(self):
        self.calls.append("namespace")

    def _collect_case_backend(self):
        self.calls.append("backend-evidence")


def test_kubernetes_teardown_preserves_reverse_dependency_order():
    manager = _Manager()
    errors = []
    manager._teardown_runtime_resources(errors)
    assert errors == []
    assert manager.calls == ["workloads", "providers", "namespace", "backend-evidence"]

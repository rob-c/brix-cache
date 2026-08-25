"""Provider lifecycles remain active on Kubernetes case backends."""

from brixtest.runtime.kubernetes_lifecycle import _prepare_managed_resources


class _Providers:
    def __init__(self, calls):
        self.calls = calls

    def start_ready(self):
        self.calls.append("providers")

    def ensure_complete(self):
        self.calls.append("complete")


class _Managed:
    def __init__(self, calls):
        self.calls = calls

    def run_phase(self, phase):
        self.calls.append(phase)


def test_kubernetes_interleaves_task_outputs_and_provider_dependencies():
    calls = []
    owner = type("Owner", (), {
        "_providers": _Providers(calls), "_managed": _Managed(calls),
    })()
    _prepare_managed_resources(owner)
    assert calls == ["providers", "prepare", "providers", "init", "providers", "complete"]

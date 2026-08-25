"""Contracts for transactional provider-managed infrastructure."""

import json

import pytest

from brixtest import (
    ProviderContext,
    ProviderInstance,
    ProviderPlan,
    case,
    register_extension,
    resource,
)
from brixtest.errors import CaseRunError, SpecError
from brixtest.runtime.manager import CaseManager
from brixtest.testing import check_managed_resource_provider_contract


def _definition(*resources, **options):
    @case(*resources, observe=(), **options)
    def declared(run):
        return None

    return declared.__brixtest_case__


class _UnitResourceProvider:
    def __init__(self, *, fail_ready=False, fail_collect=False):
        self.calls = []
        self.fail_ready = fail_ready
        self.fail_collect = fail_collect

    def validate(self, declaration):
        self.calls.append(("validate", declaration.name))

    def plan(self, declaration, context):
        self.calls.append(("plan", declaration.name))
        return ProviderPlan(declaration.name, declaration.kind, {"version": 1})

    def create(self, plan, context):
        self.calls.append(("create", plan.name))
        marker = context.resource_root(plan.name) / "owned"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("ready")
        return ProviderInstance(
            plan.name, plan.provider, {"marker": str(marker)},
            {"endpoint": "provider://%s" % plan.name}, {"version": 1},
        )

    def ready(self, instance, context, timeout):
        self.calls.append(("ready", instance.name))
        if self.fail_ready:
            raise RuntimeError("not ready")

    def collect(self, instance, context):
        self.calls.append(("collect", instance.name))
        if self.fail_collect:
            raise RuntimeError("collection failed")
        return {"healthy": True}

    def destroy(self, instance, context):
        self.calls.append(("destroy", instance.name))


def test_provider_resource_has_transactional_lifecycle_outputs_and_evidence(tmp_path):
    provider = _UnitResourceProvider()
    register_extension("resource", "unitinfra", provider, replace=True)
    store = resource("store", "unitinfra", capacity="1Gi")
    manager = CaseManager(
        _definition(store, keep="always"),
        "provider::lifecycle", root=tmp_path / "run",
    )
    run = manager.start()
    assert run.resource(store).outputs["endpoint"] == "provider://store"
    assert run.resources == {"store": run.resource("store")}
    assert manager._render_value(store.ref("endpoint")) == "provider://store"
    manager.set_outcome("passed")
    manager.close()
    assert [name for name, _resource in provider.calls] == [
        "validate", "plan", "create", "ready", "collect", "destroy",
    ]
    summary = json.loads((tmp_path / "run" / "summary.json").read_text())
    assert summary["resources"]["store"]["ownership"]["marker"].endswith("/owned")
    journal = (tmp_path / "run" / "evidence" / "journal.jsonl").read_text()
    assert '"provider-resource"' in journal


def test_provider_readiness_failure_rolls_back_created_instance(tmp_path):
    provider = _UnitResourceProvider(fail_ready=True)
    register_extension("resource", "unitfailure", provider, replace=True)
    manager = CaseManager(
        _definition(resource("store", "unitfailure"), keep="always"),
        "provider::rollback", root=tmp_path / "run",
    )
    with pytest.raises(CaseRunError, match="not ready"):
        manager.start()
    assert ("destroy", "store") in provider.calls


def test_provider_collection_failure_still_destroys_owned_resource(tmp_path):
    provider = _UnitResourceProvider(fail_collect=True)
    register_extension("resource", "unitcollect", provider, replace=True)
    manager = CaseManager(
        _definition(resource("store", "unitcollect"), keep="always"),
        "provider::collect", root=tmp_path / "run",
    )
    manager.start()
    with pytest.raises(CaseRunError, match="collection failed"):
        manager.close()
    assert provider.calls[-1] == ("destroy", "store")


def test_managed_provider_has_reusable_complete_lifecycle_contract(tmp_path):
    provider = _UnitResourceProvider()
    declaration = resource("store", "unitinfra")
    context = ProviderContext(
        "provider::contract", tmp_path / "providers", "local", object(), object(),
    )
    assert check_managed_resource_provider_contract(
        provider, declaration, context,
    ) == []
    assert [name for name, _resource in provider.calls] == [
        "validate", "plan", "create", "ready", "collect", "destroy",
    ]


def test_provider_instance_requires_explicit_ownership():
    with pytest.raises(SpecError, match="at least one"):
        ProviderInstance("store", "unitinfra", {})


@pytest.mark.parametrize("field", ["name", "provider"])
def test_provider_plan_rejects_empty_identity(field):
    values = {"name": "store", "provider": "unitinfra"}
    values[field] = ""
    with pytest.raises(SpecError, match="non-empty text"):
        ProviderPlan(values["name"], values["provider"], {})

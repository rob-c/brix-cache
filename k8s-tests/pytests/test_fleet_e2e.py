"""Topology scenarios — dry-run report lines are pure Python (each scenario_*
returns its description); live deploy-and-verify is @e2e via the topology fixture.
Was fleet/chaos/cms/dedicated/auth_authority e2e bats."""
import pytest

from labkit.scenarios import DRY_RUN, LIVE
from labtools import lab


def _dry_lines(scenario):
    if scenario == "readonly":
        return lab.scenario_dedicated("readonly")
    if scenario == "authorities":
        return lab.scenario_authorities()
    return getattr(lab, f"scenario_{scenario}")()


@pytest.mark.parametrize("scenario", DRY_RUN, ids=DRY_RUN)
def test_scenario_dry_run_names_expected_targets(monkeypatch, scenario):
    monkeypatch.setenv("XRD_LAB_DRY_RUN", "1")
    lines = " ".join(_dry_lines(scenario))
    assert all(token in lines for token in DRY_RUN[scenario])


@pytest.mark.e2e
@pytest.mark.parametrize("profile", LIVE, ids=LIVE)
def test_live_topology_round_trip(topology, profile):
    topology(profile).ok().shows(*LIVE[profile][1])

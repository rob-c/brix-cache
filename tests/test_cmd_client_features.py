import os

import pytest

from cmdscripts import client_features


def test_client_features_scenarios_are_importable():
    assert set(client_features.SCENARIOS) == {
        "all",
        "cat-compress",
        "cksum-tree",
        "diag-json",
        "dryrun-filters",
        "journal",
        "mirror-delete",
        "remove-source",
        "sync-modes",
        "tail-follow",
        "xrdfs-json",
        "xrdfs-rm",
        "xrdfs-uring",
    }


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize("scenario", sorted(client_features.SECTIONS))
def test_client_features_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip client-features live scenarios")
    missing = client_features.missing_binaries()
    if missing:
        pytest.skip(f"client binaries missing: {', '.join(missing)}")
    assert client_features.SCENARIOS[scenario]() == 0

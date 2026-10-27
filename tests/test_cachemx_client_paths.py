"""Cross-host native-client selection for the cache-matrix harness."""

import os

import _cachemx as cachemx


def test_cachemx_client_path_defaults_to_checkout(monkeypatch):
    """Default: an unset override resolves beneath the checkout client tree."""
    monkeypatch.delenv("TEST_XRDCP_BIN", raising=False)

    selected = cachemx.configured_client_path("TEST_XRDCP_BIN", "xrdcp")

    assert selected == os.path.join(cachemx.REPO, "client", "bin", "xrdcp")


def test_cachemx_client_path_honors_cross_host_override(monkeypatch):
    """Success: an explicit native-client path wins over a foreign checkout."""
    native = "/var/tmp/native-client/bin/xrdfs"
    monkeypatch.setenv("TEST_XRDFS_BIN", native)

    selected = cachemx.configured_client_path("TEST_XRDFS_BIN", "xrdfs")

    assert selected == native


def test_cachemx_client_path_ignores_empty_override(monkeypatch):
    """Error guard: an empty override falls back to an executable candidate."""
    monkeypatch.setenv("TEST_XRDSSSADMIN_BIN", "")

    selected = cachemx.configured_client_path(
        "TEST_XRDSSSADMIN_BIN", "xrdsssadmin-brix")

    assert selected == os.path.join(
        cachemx.REPO, "client", "bin", "xrdsssadmin-brix")

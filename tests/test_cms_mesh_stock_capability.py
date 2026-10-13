"""Host capability gates for the stock-cmsd cells of the CMS mesh."""

import brix_suite.mesh.cms_mesh_lib as mesh


def test_non_darwin_stock_cms_is_enabled(monkeypatch):
    monkeypatch.delenv("TEST_STOCK_CMS_INTEROP", raising=False)
    monkeypatch.setattr(mesh.sys, "platform", "linux")
    monkeypatch.setattr(mesh, "CMSD_BIN", "/opt/homebrew/bin/cmsd")
    assert mesh.stock_cms_interop_supported()


def test_homebrew_darwin_stock_cms_is_disabled(monkeypatch):
    monkeypatch.delenv("TEST_STOCK_CMS_INTEROP", raising=False)
    monkeypatch.setattr(mesh.sys, "platform", "darwin")
    monkeypatch.setattr(mesh, "BRIX_BIN", "/opt/homebrew/bin/xrootd")
    monkeypatch.setattr(mesh, "CMSD_BIN", "/opt/homebrew/bin/cmsd")
    assert not mesh.stock_cms_interop_supported()


def test_explicit_override_controls_darwin_probe(monkeypatch):
    monkeypatch.setattr(mesh.sys, "platform", "darwin")
    monkeypatch.setattr(mesh, "CMSD_BIN", "/opt/homebrew/bin/cmsd")
    monkeypatch.setenv("TEST_STOCK_CMS_INTEROP", "1")
    assert mesh.stock_cms_interop_supported()
    monkeypatch.setenv("TEST_STOCK_CMS_INTEROP", "0")
    assert not mesh.stock_cms_interop_supported()

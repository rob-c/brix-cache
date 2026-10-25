"""Keep the independent stock server's helper separate from the tested CLI."""

from brix_suite.catalogue import _shared as catalogue


def test_reference_helper_does_not_use_the_client_under_test(monkeypatch, tmp_path):
    reference = tmp_path / "reference"
    reference.mkdir()
    helper = reference / "xrdcp"
    helper.touch()
    helper.chmod(0o755)
    monkeypatch.delenv("TEST_REF_XRDCP_BIN", raising=False)
    monkeypatch.setenv("XRDCP_BIN", "/tested/native/xrdcp")
    monkeypatch.setattr(catalogue.S, "BRIX_BIN", str(reference / "xrootd"))
    import shutil
    monkeypatch.setattr(shutil, "which", lambda binary: str(reference / "xrootd"))
    assert catalogue._xrdcp_bin() == str(helper)


def test_an_explicit_missing_reference_helper_does_not_fall_back(monkeypatch):
    import shutil
    monkeypatch.setenv("TEST_REF_XRDCP_BIN", "/missing/official/xrdcp")
    monkeypatch.setattr(shutil, "which", lambda _binary: None)
    assert catalogue._xrdcp_bin() == "/missing/official/xrdcp"


def test_path_fallback_is_independent_of_the_test_override(monkeypatch):
    import shutil
    monkeypatch.delenv("TEST_REF_XRDCP_BIN", raising=False)
    monkeypatch.setenv("XRDCP_BIN", "/tested/native/xrdcp")
    monkeypatch.setattr(catalogue.S, "BRIX_BIN", "/missing/reference/xrootd")
    monkeypatch.setattr(shutil, "which", lambda binary: "/stock/bin/xrdcp" if binary == "xrdcp" else None)
    assert catalogue._xrdcp_bin() == "/stock/bin/xrdcp"


def test_hostile_origin_comparison_uses_the_selected_reference_not_a_linux_path(
        monkeypatch, tmp_path):
    """Discovering /usr/local or Homebrew must never substitute BriX's client."""
    import importlib.util
    from pathlib import Path

    reference = tmp_path / "official-xrdcp"
    reference.touch()
    reference.chmod(0o755)
    monkeypatch.setenv("TEST_REF_XRDCP_BIN", str(reference))
    monkeypatch.setenv("XRDCP_BIN", "/unrelated/client-under-test")
    source = Path(__file__).with_name("test_official_vs_brix_cache_faults.py")
    spec = importlib.util.spec_from_file_location("reference_path_probe", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.OFFICIAL_XRDCP == str(reference)

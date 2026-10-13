"""Host-specific fixed-fleet capability selection."""
from types import SimpleNamespace

from brix_suite import host_caps


def test_prepare_command_tracks_worker_exec_pal(monkeypatch):
    for platform, unavailable in (("darwin", True), ("win32", True),
                                  ("linux", False)):
        monkeypatch.setattr(host_caps.sys, "platform", platform)
        host_caps.template_unavailable_reason.cache_clear()
        reason = host_caps.template_unavailable_reason(
            "nginx_prepare_command.conf")
        assert (reason is not None) is unavailable
    host_caps.template_unavailable_reason.cache_clear()


def test_missing_kdc_tooling_drops_kdc_and_dependants(monkeypatch):
    from brix_suite.security import kdc

    monkeypatch.setattr(kdc, "krb5_tools_available", lambda: False)
    specs = [
        SimpleNamespace(name="krb5-kdc", kind="external", template="",
                        requires=()),
        SimpleNamespace(name="krb5", kind="nginx", template="",
                        requires=("krb5-kdc",)),
        SimpleNamespace(name="main", kind="nginx", template="",
                        requires=()),
    ]
    kept, dropped = host_caps.filter_available(specs)
    assert [spec.name for spec in kept] == ["main"]
    assert "MIT KDC tooling" in dropped["krb5-kdc"]
    assert dropped["krb5"].startswith("requires krb5-kdc:")

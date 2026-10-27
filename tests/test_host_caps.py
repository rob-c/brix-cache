"""Host-specific fixed-fleet capability selection."""
from types import SimpleNamespace
import pytest

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


def test_operator_can_isolate_a_broken_native_reference(monkeypatch):
    monkeypatch.setenv("BRIX_NATIVE_REFERENCE", "off")
    host_caps.kind_unavailable_reason.cache_clear()
    assert "remote-reference lane" in host_caps.kind_unavailable_reason("xrootd")
    assert "remote-reference lane" in host_caps.kind_unavailable_reason("xrdhttp")
    assert host_caps.kind_unavailable_reason("nginx") is None
    host_caps.kind_unavailable_reason.cache_clear()


@pytest.mark.parametrize("value", ["", "remote", "disabled", "OFF"])
def test_unrecognized_reference_modes_never_silently_drop_coverage(
        monkeypatch, value):
    monkeypatch.setenv("BRIX_NATIVE_REFERENCE", value)
    monkeypatch.setattr(host_caps.shutil, "which", lambda _binary: "/usr/bin/xrootd")
    host_caps.kind_unavailable_reason.cache_clear()
    assert host_caps.kind_unavailable_reason("xrootd") is None
    host_caps.kind_unavailable_reason.cache_clear()


@pytest.mark.parametrize("directive", ["brix_prepare_command", "brix_frm_stagecmd",
                                      "brix_frm_purge_polprog", "brix_cms_perf_pgm",
                                      "brix_cms_fsxeq"])
def test_worker_program_capabilities_match_the_host(monkeypatch, directive):
    for platform in ("linux", "darwin"):
        monkeypatch.setattr(host_caps.sys, "platform", platform)
        reason = host_caps.configuration_unavailable_reason(f"stream {{ {directive} /bin/true; }}")
        assert (reason is not None) is (platform == "darwin")


def test_comments_and_quoted_values_cannot_disable_a_working_server(monkeypatch):
    monkeypatch.setattr(host_caps.sys, "platform", "darwin")
    assert host_caps.configuration_unavailable_reason(
        '# brix_prepare_command /bin/false;\nset $note "brix_frm_stagecmd /bin/true";') is None
    host_caps.template_unavailable_reason.cache_clear()
    assert host_caps.template_unavailable_reason("nginx_prepare_staging.conf") is None


@pytest.mark.parametrize("backend", ["frm://exec/data", "tape://hpss/data", "frm://cta/data"])
def test_external_mss_backends_are_capability_gated(monkeypatch, backend):
    monkeypatch.setattr(host_caps.sys, "platform", "darwin")
    assert host_caps.configuration_unavailable_reason(f"brix_storage_backend {backend};")


@pytest.mark.parametrize("text", ['brix_storage_backend posix:/tmp/frm://exec;',
                                  'brix_storage_backend frm://executor/data;',
                                  'brix_frm_stagecmd "unterminated'])
def test_unrelated_or_malformed_config_is_left_to_nginx(monkeypatch, text):
    monkeypatch.setattr(host_caps.sys, "platform", "darwin")
    assert host_caps.configuration_unavailable_reason(text) is None

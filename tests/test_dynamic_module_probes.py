"""Hermetic feature and hardening coverage for selected nginx dynamic modules."""

import os
import subprocess

import pytest

import server_launcher
import test_build_hardening as hardening
from brix_suite.catalogue import _shared as catalogue


def _artifact(root, name):
    """Create an inert artifact whose path can be selected by a probe."""
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path


@pytest.fixture
def kerberos_probe(monkeypatch, tmp_path):
    """Replace ldd and the binary freezer without touching a running fleet."""
    source = _artifact(tmp_path, "source/nginx")
    frozen = _artifact(tmp_path, "frozen/nginx")
    monkeypatch.setattr(catalogue.S, "NGINX_BIN", str(source))
    monkeypatch.setattr(server_launcher, "_nginx_bin", lambda: str(frozen))
    monkeypatch.delenv("TEST_NGINX_LOAD_MODULES", raising=False)
    responses = {}
    calls = []

    def fake_ldd(argv, **_kwargs):
        calls.append(argv[1])
        response = responses.get(argv[1], (0, "libc.so.6 => /lib/libc.so.6"))
        if isinstance(response, BaseException):
            raise response
        return subprocess.CompletedProcess(argv, response[0], response[1])

    monkeypatch.setattr(catalogue.subprocess, "run", fake_ldd)
    return str(frozen), responses, calls


def test_static_kerberos_uses_frozen_binary(kerberos_probe):
    """A statically linked BriX build retains its existing feature coverage."""
    frozen, responses, calls = kerberos_probe
    responses[frozen] = (0, "libkrb5.so.3 => /lib64/libkrb5.so.3 (address)")
    assert catalogue._nginx_has_krb5(), "frozen nginx's Kerberos was missed"
    assert calls == [frozen], "feature probe read the mutable build binary"


def test_dynamic_module_enables_kerberos(monkeypatch, tmp_path, kerberos_probe):
    """A distro nginx discovers Kerberos through its selected BriX module."""
    frozen, responses, calls = kerberos_probe
    module = str(_artifact(tmp_path, "ngx_stream_brix_module.so"))
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", module)
    responses[module] = (0, "libkrb5.so.3 => /lib64/libkrb5.so.3 (address)")
    assert catalogue._nginx_has_krb5(), "selected module's Kerberos was missed"
    assert calls == [frozen, module], "probe did not follow the selected artifacts"


@pytest.mark.parametrize("response", [
    (1, "libkrb5.so.3 => /lib64/libkrb5.so.3"),
    (0, "libkrb5.so.3 => not found"),
    (0, "libk5crypto.so.3 => /lib64/libk5crypto.so.3"),
    FileNotFoundError("ldd is unavailable"),
    subprocess.TimeoutExpired("ldd", 10),
])
def test_unusable_kerberos_dependency_is_not_enabled(kerberos_probe, response):
    """Failed probes and unresolved or unrelated libraries cannot enable a tier."""
    frozen, responses, _calls = kerberos_probe
    responses[frozen] = response
    assert not catalogue._nginx_has_krb5(), "unusable dependency enabled Kerberos"


def test_unconfigured_module_does_not_enable_kerberos(tmp_path, kerberos_probe):
    """An unrelated artifact on disk cannot change the selected server's features."""
    frozen, responses, calls = kerberos_probe
    module = str(_artifact(tmp_path, "ngx_stream_brix_module.so"))
    responses[module] = (0, "libkrb5.so.3 => /lib64/libkrb5.so.3")
    assert not catalogue._nginx_has_krb5(), "unloaded module enabled Kerberos"
    assert calls == [frozen], "probe inspected an unselected module"


def test_missing_nginx_does_not_probe_modules(monkeypatch, tmp_path, kerberos_probe):
    """A missing server cannot become available because a module exists."""
    _frozen, _responses, calls = kerberos_probe
    monkeypatch.setattr(catalogue.S, "NGINX_BIN", str(tmp_path / "missing"))
    assert not catalogue._nginx_has_krb5(), "missing nginx enabled a fleet tier"
    assert not calls, "missing server should stop dependency probing"


@pytest.fixture
def module_build(monkeypatch, tmp_path):
    """Isolate discovery from the host's modules and inherited source choices."""
    monkeypatch.setattr(hardening, "REPO", tmp_path)
    monkeypatch.setattr(hardening.glob, "glob", lambda _pattern: [])
    for name in ("TEST_NGINX_LOAD_MODULES", "NGX_SRC", "NGINX_SRC"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def test_hardening_checks_both_selected_modules(monkeypatch, module_build):
    """The stream and HTTP filter artifacts are checked; nginx core is excluded."""
    core = _artifact(module_build, "ngx_stream_module.so")
    stream = _artifact(module_build, "ngx_stream_brix_module.so")
    http = _artifact(module_build, "ngx_http_brix_xrdhttp_filter_module.so")
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES",
                       os.pathsep.join(map(str, (core, stream, http))))
    inspected = []
    monkeypatch.setattr(hardening, "_check_module_hardening", inspected.append)
    hardening.test_module_so_is_relro_now()
    assert inspected == [stream, http], "not all selected BriX modules were checked"


def test_hardening_finds_current_cmake_artifacts(module_build):
    """An ordinary local CMake build is discoverable without runner selection."""
    module = _artifact(module_build, "build/modules/ngx_stream_brix_module.so")
    assert hardening._find_module_sos() == [module], "CMake module was missed"


@pytest.mark.parametrize("variable", ["NGX_SRC", "NGINX_SRC"])
def test_hardening_honors_selected_source(monkeypatch, module_build, variable):
    """A configured source choice takes precedence over another CMake build."""
    _artifact(module_build, "build/modules/ngx_stream_brix_module.so")
    source = module_build / "selected"
    module = _artifact(source, "objs/ngx_stream_brix_module.so")
    monkeypatch.setenv(variable, str(source))
    assert hardening._find_module_sos() == [module], "selected source was ignored"


def test_missing_selected_module_fails_without_fallback(monkeypatch, module_build):
    """A stale explicit path cannot pass using a different build's artifact."""
    _artifact(module_build, "build/modules/ngx_stream_brix_module.so")
    missing = module_build / "missing/ngx_stream_brix_module.so"
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", str(missing))
    with pytest.raises(AssertionError, match="selected module is missing"):
        hardening.test_module_so_is_relro_now()


@pytest.mark.parametrize("output, missing", [
    ("BIND_NOW", "RELRO"),
    ("GNU_RELRO\nNOWHERE", "BIND_NOW"),
])
def test_selected_unhardened_module_fails(monkeypatch, module_build, output, missing):
    """Finding a selected artifact does not bypass its ELF hardening checks."""
    module = _artifact(module_build, "ngx_http_brix_xrdhttp_filter_module.so")
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", str(module))
    monkeypatch.setattr(hardening, "_readelf", lambda _path: output)
    with pytest.raises(AssertionError, match=f"missing {missing}"):
        hardening.test_module_so_is_relro_now()

"""Config-generation logic — catalog lint/render + import-config marker mapping.

Tests call labtools functions directly (the tools/*.sh are thin wrappers over
these). Pure and fast — no subprocess, no filesystem side effects.
"""
import re

import pytest

from labkit import paths
from labtools import catalog, import_config, mega_config


# -- catalog ---------------------------------------------------------------
def test_catalog_lints_clean(catalog_yaml):
    assert catalog.lint(catalog_yaml) == []


def test_catalog_flags_a_missing_config(tmp_file):
    bad = tmp_file("bad.yaml", "scenarios:\n  bogus:\n    configKey: does_not_exist\n"
                               "    ports: [{name: x, port: 1}]\n")
    assert any("does_not_exist" in p for p in catalog.lint(bad))


def test_catalog_flags_duplicate_ports(tmp_file):
    bad = tmp_file("dup.yaml", "scenarios:\n  d:\n    configKey: crl\n"
                               "    ports: [{name: a, port: 5}, {name: b, port: 5}]\n")
    assert any("DUP PORT" in p for p in catalog.lint(bad))


def test_scenario_render_resolves_auth_and_role(catalog_yaml):
    args = catalog.render(catalog_yaml, "crl", "brix-scn")
    assert "role.name=crl" in args
    assert "role.configKey=crl" in args
    assert "role.auth.crlUrl=http://brix-scn-grid-ca:8080/crl/test-user.crl.pem" in args
    assert "role.auth.caBundle=brix-scn-ca-bundle" in args


# -- import-config marker mapping ------------------------------------------
def test_import_config_maps_standard_markers():
    out = import_config.convert("listen {PORT}; root {DATA_DIR}; ssl_certificate {SERVER_CERT};")
    assert "{{ (index .Values.role.ports 0).port }}" in out
    assert "{{ .Values.role.data.root }}" in out
    assert import_config.unmapped(out) == []


def test_import_config_flags_unmapped_markers():
    out = import_config.convert("brix_proxy_upstream {UPSTREAM_PORT};")
    assert import_config.unmapped(out) == ["{UPSTREAM_PORT}"]


# -- mega config generator -------------------------------------------------
def test_mega_config_folds_extras_into_one_server():
    text = mega_config.build()
    assert len(re.findall(r"(?m)^stream \{", text)) == 1
    assert len(re.findall(r"(?m)^http \{", text)) == 1
    for port in (11094, 11095, 11097, 8443, 9100, 11102, 11104, 12988, 22017):
        assert f"listen {port}" in text


def test_committed_mega_config_matches_generator():
    # the checked-in fleet-mega.conf must equal build() — regenerate if this fails
    assert paths.config("fleet-mega.conf").read_text() == mega_config.build()


@pytest.mark.e2e
def test_mega_config_validates_with_nginx_t():
    from labkit.images import nginx_t_mega
    assert nginx_t_mega() == 0

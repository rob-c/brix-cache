"""TLS, VOMS, and Kerberos declaration validation (031-040)."""

import pytest

from brixtest import kerberos_auth, tls_auth, voms_auth
from brixtest.errors import SpecError


def test_031_tls_hostname_and_aliases_are_normalized():
    item = tls_auth(hostname="Server.Test.", aliases=("Alias.Test.",))
    assert item.hostname == "server.test" and item.aliases == ("alias.test",)


def test_032_tls_rejects_invalid_hostname():
    with pytest.raises(SpecError, match="hostname"):
        tls_auth(hostname="bad_name.test")


def test_033_tls_rejects_duplicate_canonical_alias():
    with pytest.raises(SpecError, match="exclude hostname"):
        tls_auth(hostname="server.test", aliases=("server.test",))


def test_034_tls_key_size_is_bounded():
    with pytest.raises(SpecError, match="key_bits"):
        tls_auth(key_bits=1024)


def test_035_voms_default_fqan_uses_vo():
    item = voms_auth(vo="atlas")
    assert item.fqans == ("/atlas/Role=NULL/Capability=NULL",)


def test_036_voms_rejects_foreign_fqan():
    with pytest.raises(SpecError, match="FQAN"):
        voms_auth(vo="atlas", fqans=("/cms/Role=NULL",))


def test_037_voms_port_is_validated():
    with pytest.raises(SpecError, match="TCP port"):
        voms_auth(port=70000)


def test_038_kerberos_normalizes_domain_and_hostname():
    item = kerberos_auth(domain="Auth.Test.", hostname="KDC.Auth.Test.")
    assert item.domain == "auth.test" and item.hostname == "kdc.auth.test"


def test_039_kerberos_realm_must_be_uppercase():
    with pytest.raises(SpecError, match="uppercase"):
        kerberos_auth(realm="lower.test")


def test_040_kerberos_service_is_service_hostname_pair():
    with pytest.raises(SpecError, match="service/hostname"):
        kerberos_auth(service="server.auth.test")

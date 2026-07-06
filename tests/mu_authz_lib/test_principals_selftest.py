"""Self-test for the principal cast (needs CA + openssl + tokens; no root)."""
import os

import pytest

from mu_authz_lib import principals, ports


@pytest.fixture(scope="module", autouse=True)
def _pki():
    if not os.path.exists(os.path.join(ports.MU.CA_DIR, "ca.pem")):
        from pki_helpers import blitz_test_pki
        blitz_test_pki()


def test_cast_has_expected_members():
    cast = principals.build_cast()
    for who in ("svc", "alice", "bob", "carol", "mallory", "collide", "squashed"):
        assert who in cast, f"missing principal {who}"


def test_carol_is_the_sharp_leak_probe():
    cast = principals.build_cast()
    # carol shares alice's VO (cms) — she passes the VO gate but must be denied by authdb.
    assert cast["carol"].vo == cast["alice"].vo == "cms"
    assert cast["carol"].has_voms


def test_collide_shares_alices_uid():
    cast = principals.build_cast()
    assert cast["collide"].uid == cast["alice"].uid
    assert cast["collide"].krb_princ == "alice@TEST.REALM"


def test_each_active_principal_has_matched_creds():
    cast = principals.build_cast()
    for p in cast.values():
        if p.name == "squashed":
            continue
        assert p.proxy and os.path.exists(p.proxy), f"{p.name} missing proxy"
        assert p.token and os.path.exists(p.token), f"{p.name} missing token"
        assert p.s3_key and p.s3_secret, f"{p.name} missing s3 key"

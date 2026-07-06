"""Self-test for the policy renderer (unprivileged; needs the cast for DNs)."""
import os

import pytest

from mu_authz_lib import policy, principals, ports


@pytest.fixture(scope="module", autouse=True)
def _pki():
    if not os.path.exists(os.path.join(ports.MU.CA_DIR, "ca.pem")):
        from pki_helpers import blitz_test_pki
        blitz_test_pki()


def test_render_is_consistent_across_backends():
    cast = principals.build_cast()
    pol = policy.Policy(path="/cms/secret.dat", allow=["alice"], deny=["bob", "carol"],
                        vo="cms", scope_prefix="storage.read:/cms")
    out = policy.render_policy(pol, cast)

    authdb = open(out["authdb"]).read()
    assert "brixtest_alice" in authdb and "/cms/secret.dat" in authdb
    # carol (same VO, denied) must NOT get an authdb grant.
    assert "brixtest_carol" not in authdb

    gridmap = open(out["gridmap"]).read()
    assert cast["alice"].dn in gridmap and "brixtest_alice" in gridmap
    # the collide principal's Kerberos name maps to the same account as alice.
    assert "alice@TEST.REALM" in gridmap

    s3 = open(out["s3keys"]).read()
    assert cast["alice"].s3_key in s3 and cast["carol"].s3_key in s3

    vo = open(out["vo"]).read()
    assert "/cms" in vo and "cms" in vo

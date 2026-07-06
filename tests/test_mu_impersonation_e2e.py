"""F6 — real setfsuid byte-ownership + cross-principal uid collapse (threats T6, T11).

The C unit tests/c/idmap_collapse_test.c covers the mapping decisions; these e2e tests prove
the runtime behavior under the privileged fleet: a write lands owned by the mapped uid, and a
principal that collapses onto another's uid gets exactly that identity's access — no more.

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_impersonation_e2e.py -v
"""
import pytest

from mu_authz_lib import fleet
from mu_authz_lib.adapters import measure_root
from mu_authz_lib.putter import put_as, export_stat


@pytest.mark.privileged
def test_written_file_owned_by_mapped_uid(mu_fleet, cast):
    """A write as alice creates an export object owned by alice's real uid (impersonation)."""
    ok = put_as(cast["alice"], "/cms/alice_wrote.dat", b"hello-from-alice", proto="root")
    assert ok, "authorized write as alice must succeed"
    st = export_stat("/cms/alice_wrote.dat")
    assert st.st_uid == cast["alice"].uid, (
        f"written bytes owned by uid {st.st_uid}, expected alice's uid {cast['alice'].uid}")


@pytest.mark.privileged
def test_collapsed_principal_gets_mapped_identitys_access(mu_fleet, cast):
    """`collide` (a distinct principal mapping to alice's uid) must get exactly alice's
    access on the direct server — the collapse grants alice's identity, nothing more."""
    url = fleet.url("root", "direct")
    v_alice = measure_root(url, "/cms/secret.dat", "read", principal=cast["alice"])
    v_collide = measure_root(url, "/cms/secret.dat", "read", principal=cast["collide"])
    assert v_collide == v_alice, (
        f"collapsed principal must equal its mapped identity's access: "
        f"collide={v_collide} alice={v_alice}")

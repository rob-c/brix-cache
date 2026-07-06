"""F9 — write-back attribution + S3↔root scope parity (threats T5, T10).

Two properties: (1) S3 must reach the same authorization verdict as root for the same
identity/path — S3 authorizing on SigV4 identity alone, without scope/authdb parity, is a
poisoning surface (RED today); (2) a user's write is attributable to that user (the written
object is owned by the mapped uid).

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_writeback_attr.py -v
"""
import pytest

from mu_authz_lib import fleet
from mu_authz_lib.oracle import authoritative
from mu_authz_lib.adapters import measure_s3
from mu_authz_lib.putter import put_as, export_stat

_DENIED = ["carol", "bob"]


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("subject", _DENIED)
def test_s3_honors_scope_like_root(mu_fleet, cast, subject):
    """S3's verdict for a subject must equal root's verdict for the same identity/path."""
    root_v = authoritative("root", "/cms/secret.dat", "read", cast[subject])
    s3_v = measure_s3(fleet.url("s3", "direct"), "/cms/secret.dat", "read",
                      principal=cast[subject])
    assert s3_v == root_v, f"S3 scope parity broken for {subject}: s3={s3_v} root={root_v}"


@pytest.mark.privileged
def test_writeback_attributed_to_writer(mu_fleet, cast):
    """A write-through as alice produces an object owned by alice's uid (attribution)."""
    ok = put_as(cast["alice"], "/cms/alice_wb.dat", b"writeback-bytes", proto="root")
    assert ok, "authorized write-through as alice must succeed"
    st = export_stat("/cms/alice_wb.dat")
    assert st.st_uid == cast["alice"].uid, (
        f"written-back bytes owned by uid {st.st_uid}, expected alice's {cast['alice'].uid}")

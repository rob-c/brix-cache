"""
test_audit15e_checksum_s3.py — checksum-on-write over an s3:// storage
backend (audit §B2.11 residual, testsuite-combinatorial-coverage-audit
2026-08-15: `brix_webdav_checksum_on_write` was tested over posix and, in
tranche 4, through a write-through stage tier — but never over the sd_remote
s3:// driver, whose write session is driver-backed, with no kernel fd).

One instance (nginx_audit15e_cks3.conf): a brix_s3 origin over posix, and a
front with /ck/ (WebDAV over s3:// + adler32 on write), /px/ (the SAME
directive over a posix export — the control), and /ro/ (the /ck/ shape with
allow_write off).

DEFECT CANDIDATE #7 — the ingest checksum is silently dropped over a
driver-backed backend.  `webdav_put_persist_checksums`
(src/protocols/webdav/put_body.c:65-71) re-opens the just-committed object
with `brix_vfs_open_fd(log, conf->common.root_canon, path, O_RDONLY, 0)` — a
posix-confined open on the LOGICAL export path.  For an s3:// backend no
such file exists, the open fails, and the helper returns early; because it
is best-effort the PUT still answers 201.  The landed object carries only
the crc64nvme the S3 origin plane records for itself — nowhere is the
operator-requested adler32.  Same root-cause family as defect #6 (the async
queue drain): a logical-path posix primitive standing in for the driver.

DEFECT CANDIDATE #8 — a WebDAV PUT over the s3:// backend intermittently
500s.  The lock-state probe `webdav_lock_xattr_read`
(src/protocols/webdav/prop_xattr.c:238-258) walks the parent chain and
tolerates every "this backend has no xattrs" errno (ENODATA/ENOATTR/ENOENT/
ENOTSUP/EOPNOTSUPP/ENOSYS/EACCES/EPERM) by declining and letting the write
proceed — but NOT EIO, which is what the remote driver reports here
("brix_webdav: getxattr lock on \"/\" failed (5: Input/output error)").  The
write is then refused with a 500 for a lock probe that is advisory by
construction.  Once a worker starts reporting it, it keeps reporting it, so
the failure is sticky per worker and a run sees a mix of 201s and 500s.  A
second face of the same instability: with an nginx `thread_pool` configured
(the PUT aio path) the request can instead commit the object and never
answer at all — which is why this template declares no pool.

Cases:
  * characterisation + fail-closed invariant — twelve sequential PUTs: every
    non-2xx is a 500 carrying the getxattr-lock EIO signature in error.log,
    and every failed PUT leaves NO object in the store (defect #8 is
    fail-closed, not a partial write)
  * success + defect pin #7 — a PUT that lands round-trips through the front,
    and no adler32 digest exists anywhere in the store afterwards: a total
    loss, not a relocation.  Inverts on fix.
  * control — /px/, same directive over posix, DOES persist
    `user.XrdCks.adler32` with the correct value: pin #7 is a statement
    about the backend, not about the directive
  * security-negative — the read-only s3 location refuses PUT and DELETE and
    the seeded object in the store is untouched
"""

import os
import time
import zlib
from pathlib import Path

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST

def _check_test_defect8_put_refusals_are_500_and_fail_closed_2(codes):
    assert any(c in (201, 204) for c in codes), (codes, DEFECT8)

def _check_test_defect8_put_refusals_are_500_and_fail_closed_1(codes, ep):
    assert EIO_NEEDLE in _errlog(ep), \
        ("the front 500ed a PUT over the s3:// backend for a reason "
         "other than the lock-probe EIO — re-diagnose defect #8", codes)


pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15e-cks3")]

PAYLOAD = b"audit15e-checksum-s3-payload " * 32
WANT = format(zlib.adler32(PAYLOAD) & 0xFFFFFFFF, "08x")

EIO_NEEDLE = "getxattr lock on"

DEFECT7 = ("DEFECT CANDIDATE #7 has been FIXED: checksum-on-write now "
           "persists over a driver-backed backend (put_body.c:65 no longer "
           "needs a posix fd at the logical path) — invert this pin: assert "
           f"the object carries user.XrdCks.adler32 == {WANT}.")

DEFECT8 = ("DEFECT CANDIDATE #8: the PUT was refused because the advisory "
           "lock-xattr probe hit EIO from the remote driver "
           "(prop_xattr.c:250 tolerates every other 'no xattrs here' errno). "
           "If that is fixed, this helper's retries become unnecessary.")


@pytest.fixture()
def cks3(lifecycle, tmp_path):
    s3dir = tmp_path / "s3"
    posix_root = tmp_path / "px"
    # The wire path keeps the location prefix: /px/x.bin resolves to
    # <POSIX_ROOT>/px/x.bin, and the posix writer will not create the parent.
    for d in (s3dir, posix_root / "px"):
        d.mkdir(parents=True)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15e-cks3",
        template="nginx_audit15e_cks3.conf",
        protocol="http",
        data_root=str(s3dir),
        template_values={"BIND_HOST": HOST,
                         "S3_DIR": str(s3dir),
                         "POSIX_ROOT": str(posix_root),
                         "S3_ACCESS_KEY": "audit15e-access",
                         "S3_SECRET_KEY": "audit15e-secret-key-0123456789"},
        reason="audit-15e checksum-on-write over an s3:// backend"))
    return ep, s3dir, posix_root


def _url(port, path):
    return f"http://{HOST}:{port}{path}"


def _xattr(path, alg="adler32"):
    try:
        return os.getxattr(path, f"user.XrdCks.{alg}").decode(errors="replace")
    except OSError:
        return None


def _errlog(ep):
    return (Path(ep.prefix) / "logs" / "error.log").read_text(errors="replace")


def _put_landing(ep, path, attempts=10):
    """PUT until one attempt is accepted, working around defect #8 (which is
    sticky per worker, so a retry can land on a healthy one).  Returns the
    accepted response; fails loudly if the backend never accepts the write,
    because then the #7 question below cannot be answered at all."""
    last = None
    for _ in range(attempts):
        last = requests.put(_url(ep.port, path), data=PAYLOAD, timeout=20)
        if last.status_code in (201, 204):
            return last
        assert last.status_code == 500, (last.status_code, last.text[:200])
        time.sleep(0.2)
    raise AssertionError(
        f"{attempts} PUTs to {path} were all refused with 500 — {DEFECT8}")


def test_defect8_put_refusals_are_500_and_fail_closed(cks3):
    ep, s3dir, _ = cks3
    codes = []
    for i in range(12):
        r = requests.put(_url(ep.port, f"/ck/probe{i}.bin"), data=PAYLOAD,
                         timeout=20)
        codes.append(r.status_code)
        if r.status_code not in (201, 204):
            # Fail-closed: a refused PUT must leave nothing behind.
            def _assert_test_defect8_put_refusals_are_500_and_fail_closed_1():
                assert r.status_code == 500, (r.status_code, r.text[:200])
                assert not (s3dir / "ck" / f"probe{i}.bin").exists(), \
                    "a refused PUT left a partial object in the store"

            _assert_test_defect8_put_refusals_are_500_and_fail_closed_1()
    if any(c == 500 for c in codes):
        _check_test_defect8_put_refusals_are_500_and_fail_closed_1(codes, ep)
    # Whatever the mix, at least one write must get through: a backend that
    # refuses every write is a harder failure than the one pinned here.
    _check_test_defect8_put_refusals_are_500_and_fail_closed_2(codes)


def test_defect7_ingest_checksum_lost_over_s3_backend(cks3):
    ep, s3dir, _ = cks3
    _put_landing(ep, "/ck/pin.bin")
    landed = s3dir / "ck" / "pin.bin"
    assert landed.read_bytes() == PAYLOAD, "the object did not land in the store"
    g = requests.get(_url(ep.port, "/ck/pin.bin"), timeout=20)
    assert g.status_code == 200 and g.content == PAYLOAD, g.status_code

    assert _xattr(landed) is None, (DEFECT7, _xattr(landed))
    # ... and it is a LOSS, not a relocation: no object anywhere in the store
    # carries the requested digest (the crc64nvme the S3 origin plane records
    # for itself is the only checksum present).
    for p in s3dir.rglob("*"):
        if p.is_file():
            assert _xattr(p) is None, (DEFECT7, str(p))


def test_posix_control_persists_the_same_directive(cks3):
    ep, _, posix_root = cks3
    r = requests.put(_url(ep.port, "/px/ctl.bin"), data=PAYLOAD, timeout=20)
    assert r.status_code in (201, 204), (r.status_code, r.text[:200])
    landed = posix_root / "px" / "ctl.bin"
    assert landed.read_bytes() == PAYLOAD
    got = _xattr(landed)
    assert got is not None, \
        "the posix control lost the ingest checksum too — the directive " \
        "itself is broken, so defect #7's attribution needs revisiting"
    assert got.split()[0] == WANT, (got, WANT)


def test_readonly_s3_location_refuses_mutations(cks3):
    ep, s3dir, _ = cks3
    # Seed straight into the posix-backed object store: the write gate fires
    # at the access phase, so this test must not depend on defect #8's mood.
    (s3dir / "ro").mkdir(parents=True, exist_ok=True)
    (s3dir / "ro" / "seed.bin").write_bytes(PAYLOAD)

    r = requests.put(_url(ep.port, "/ro/new.bin"), data=PAYLOAD, timeout=20)
    assert r.status_code == 403, (r.status_code, r.text[:200])
    assert not (s3dir / "ro" / "new.bin").exists()

    d = requests.delete(_url(ep.port, "/ro/seed.bin"), timeout=20)
    assert d.status_code == 403, (d.status_code, d.text[:200])
    assert (s3dir / "ro" / "seed.bin").read_bytes() == PAYLOAD, \
        "the read-only location's DELETE reached the object store"

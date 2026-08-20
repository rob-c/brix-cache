"""
test_audit15d_checksum_stage.py — checksum-on-write through a write-through
stage tier (audit §B2.11, testsuite-combinatorial-coverage-audit 2026-08-15:
`brix_webdav_checksum_on_write` was only ever tested against a plain posix
export; whether the ingest checksum survives a stage-tier flush to the origin
had never been asked).

One instance, two planes (nginx_audit15d_ckstage.conf): a WebDAV posix ORIGIN
and a WebDAV front whose backend is that origin with `brix_stage on` +
`brix_stage_flush sync` (close blocks until the origin has the object).  The
/ck/ location adds `brix_webdav_checksum_on_write adler32`; /plain/ is the
no-checksum control with its own export + stage store (tiers are keyed by
export root — sharing one would share ONE tier).

DEFECT-CANDIDATE PIN — the checksum does not survive the flush.  On a plain
posix export the PUT leaves `user.XrdCks.adler32` on the landed file
(test_checksum_on_write.py::test_on_write_persists_xattr).  Through the WT
tier the ingest checksum is computed and a setxattr is attempted on the
logical export path (visible as op:"xattr" in brix_access_json), but the
flush's origin-side PUT carries only the bytes: the origin copy lands with an
EMPTY xattr list and the spool copy — wherever the xattr may have gone — is
deleted by the stage move.  The ingest checksum vanishes entirely.
test_checksum_lost_across_stage_flush_defect_pin asserts that loss and must
be inverted when the flush propagates the checksum.

Cases:
  * success — a PUT through the WT tier lands byte-exact on the origin, the
    sync flush drains the spool, and the GET round-trips through the front
  * defect pin — the flushed origin copy carries no checksum xattr
  * control — the /plain/ location behaves identically without the directive
    (so the pin above is about xattr loss, not about broken flushes)
  * error — a GET for an object that exists nowhere is a clean 404 through
    the tier
"""

import os
import zlib

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15d-ckstage")]

PAYLOAD = b"audit15d-checksum-stage-payload " * 32


@pytest.fixture()
def ckstage(lifecycle, tmp_path):
    origin = tmp_path / "origin"
    export = tmp_path / "export"
    stage = tmp_path / "stage"
    # The wire path keeps the location prefix (/ck/, /plain/), and the flush's
    # origin PUT will not create a missing parent collection — pre-create both.
    for d in (origin / "ck", origin / "plain", export / "ck",
              export / "plain", stage / "ck", stage / "plain"):
        d.mkdir(parents=True)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15d-ckstage",
        template="nginx_audit15d_ckstage.conf",
        protocol="http",
        data_root=str(origin),
        template_values={"BIND_HOST": HOST,
                         "ORIGIN_ROOT": str(origin),
                         "EXPORT_ROOT": str(export),
                         "STAGE_ROOT": str(stage)},
        reason="audit-15d checksum-on-write through a WT stage tier"))
    return ep.port, origin, stage


def _url(port, path):
    return f"http://{HOST}:{port}{path}"


def _xattr(path, alg="adler32"):
    try:
        return os.getxattr(path, f"user.XrdCks.{alg}").decode(errors="replace")
    except OSError:
        return None


def test_put_through_wt_stage_lands_on_origin(ckstage):
    port, origin, stage = ckstage
    r = requests.put(_url(port, "/ck/a.bin"), data=PAYLOAD, timeout=30)
    assert r.status_code in (201, 204), (r.status_code, r.text)
    landed = origin / "ck" / "a.bin"
    assert landed.read_bytes() == PAYLOAD
    # `brix_stage_flush sync` means the spool is drained by the time the PUT
    # answers — the stage move deleted the local copy.
    assert not [p for p in (stage / "ck").rglob("*") if p.is_file()]
    g = requests.get(_url(port, "/ck/a.bin"), timeout=30)
    assert g.status_code == 200 and g.content == PAYLOAD, g.status_code


def test_checksum_lost_across_stage_flush_defect_pin(ckstage):
    # DEFECT-CANDIDATE PIN (see module docstring): invert to
    # `_xattr(landed) == want` when the flush propagates the ingest checksum.
    port, origin, stage = ckstage
    r = requests.put(_url(port, "/ck/pin.bin"), data=PAYLOAD, timeout=30)
    assert r.status_code in (201, 204), (r.status_code, r.text)
    landed = origin / "ck" / "pin.bin"
    assert landed.read_bytes() == PAYLOAD
    want = format(zlib.adler32(PAYLOAD) & 0xFFFFFFFF, "08x")
    assert _xattr(landed) is None, \
        (f"origin copy carries a checksum — flush propagation fixed? "
         f"invert this pin (expected {want})", _xattr(landed))
    assert not os.listxattr(landed), os.listxattr(landed)
    # ... and it is a LOSS, not a relocation: no surviving copy anywhere in
    # the tier carries the xattr (the spool file was deleted by the move).
    for p in (stage.rglob("*")):
        if p.is_file():
            assert _xattr(p) is None, (str(p), _xattr(p))


def test_plain_control_flush_identical_without_directive(ckstage):
    port, origin, stage = ckstage
    r = requests.put(_url(port, "/plain/b.bin"), data=PAYLOAD, timeout=30)
    assert r.status_code in (201, 204), (r.status_code, r.text)
    landed = origin / "plain" / "b.bin"
    assert landed.read_bytes() == PAYLOAD
    assert _xattr(landed) is None
    g = requests.get(_url(port, "/plain/b.bin"), timeout=30)
    assert g.status_code == 200 and g.content == PAYLOAD, g.status_code


def test_missing_object_404_through_tier(ckstage):
    port, origin, stage = ckstage
    g = requests.get(_url(port, "/ck/nope.bin"), timeout=30)
    assert g.status_code == 404, (g.status_code, g.text[:200])

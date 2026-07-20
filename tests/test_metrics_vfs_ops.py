"""
test_metrics_vfs_ops.py — Prometheus coverage for the VFS sweep's new op labels.

The Tier-2 VFS extension added two unified-metric operations —
brix_io_ops_total{op="xattr"} and {op="copy"} — and routed S3/WebDAV xattr,
copy, and staged-write paths through the metered VFS surface. This suite drives
each path over the live S3 endpoint and asserts the matching io_ops_total series
exists and increments (the delta over /metrics is the only end-to-end proof the
op enum, the label table, and the call-site wiring all line up).

Covers per the 3-tests rule:
  - success:       tagging => op="xattr", CopyObject => op="copy",
                   PutObject => op="write" (staged commit)
  - error/negative: CopyObject from a missing source neither 2xx's nor books an
                   op="copy",status="ok"

Run: PYTHONPATH=tests pytest tests/test_metrics_vfs_ops.py -v
"""

import pytest

requests = pytest.importorskip("requests")

from settings import NGINX_S3_PORT, HOST          # noqa: E402
from metrics_helpers import Snapshot, fetch         # noqa: E402

S3 = f"http://{HOST}:{NGINX_S3_PORT}"
BUCKET = "testbucket"
OP_METRIC = "brix_io_ops_total"


def _obj(key):
    return f"{S3}/{BUCKET}/{key}"


def _op_ok(snap, op, after=None):
    return snap.delta(OP_METRIC, {"proto": "s3", "op": op, "status": "ok"},
                      after=after)


def test_tagging_books_xattr_op():
    """PUT ?tagging routes through brix_vfs_setxattr -> op="xattr"."""
    requests.put(_obj("vfsop_tag.bin"), data=b"d", timeout=10)
    snap = Snapshot()
    r = requests.put(_obj("vfsop_tag.bin") + "?tagging",
                     data='<Tagging><TagSet><Tag><Key>k</Key>'
                          '<Value>v</Value></Tag></TagSet></Tagging>',
                     timeout=10)
    assert r.status_code in (200, 204), r.text[:200]
    assert _op_ok(snap, "xattr") >= 1


def test_copyobject_books_copy_op():
    """CopyObject routes through brix_vfs_copy -> op="copy"."""
    requests.put(_obj("vfsop_cp_src.bin"), data=b"copy-src" * 100, timeout=10)
    snap = Snapshot()
    r = requests.put(_obj("vfsop_cp_dst.bin"), timeout=10,
                     headers={"x-amz-copy-source": f"/{BUCKET}/vfsop_cp_src.bin"})
    assert r.status_code in (200, 201), r.text[:200]
    assert _op_ok(snap, "copy") >= 1


def test_putobject_books_write_op_on_staged_commit():
    """PutObject's staged commit routes through brix_vfs_staged_commit ->
    op="write"."""
    snap = Snapshot()
    r = requests.put(_obj("vfsop_put.bin"), data=b"staged-write" * 500,
                     timeout=10)
    assert r.status_code in (200, 201), r.text[:200]
    assert _op_ok(snap, "write") >= 1


def test_served_get_books_no_error_xattr():
    """A served GET probes the optional usermeta/tagging xattrs; an absent
    attribute (ENODATA) is an expected negative lookup and must book
    op="xattr",status="ok" — NOT status="other" (the pre-fix quirk: every
    served GET logged a failed xattr line)."""
    requests.put(_obj("vfsop_get_plain.bin"), data=b"plain", timeout=10)
    snap = Snapshot()
    r = requests.get(_obj("vfsop_get_plain.bin"), timeout=10)
    assert r.status_code == 200, r.status_code
    after = fetch()
    assert snap.delta(OP_METRIC, {"proto": "s3", "op": "xattr",
                                  "status": "other"}, after=after) == 0
    assert _op_ok(snap, "xattr", after=after) >= 1


def test_get_with_usermeta_roundtrips_and_books_ok_xattr():
    """The metadata-present probe path: x-amz-meta-* set on PUT is echoed on
    GET and the usermeta load books op="xattr",status="ok"."""
    requests.put(_obj("vfsop_get_meta.bin"), data=b"meta", timeout=10,
                 headers={"x-amz-meta-flavor": "umami"})
    snap = Snapshot()
    r = requests.get(_obj("vfsop_get_meta.bin"), timeout=10)
    assert r.status_code == 200, r.status_code
    assert r.headers.get("x-amz-meta-flavor") == "umami"
    assert _op_ok(snap, "xattr") >= 1


def test_get_tagging_missing_object_books_no_ok_xattr():
    """?tagging on a missing object fails before any xattr probe: 404 and no
    op="xattr",status="ok" advance (real failures must stay visible — only the
    expected-absent ENODATA probe is reclassified as ok)."""
    snap = Snapshot()
    r = requests.get(_obj("vfsop_no_such_object.bin") + "?tagging", timeout=10)
    assert r.status_code == 404, r.status_code
    after = fetch()
    assert _op_ok(snap, "xattr", after=after) == 0


def test_copy_missing_source_books_no_ok_copy():
    """A CopyObject whose source does not exist must 404 and must NOT book an
    op="copy",status="ok" (the confined copy fails before any data move)."""
    snap = Snapshot()
    r = requests.put(_obj("vfsop_cp_dst2.bin"), timeout=10,
                     headers={"x-amz-copy-source":
                              f"/{BUCKET}/vfsop_does_not_exist.bin"})
    assert r.status_code == 404, r.status_code
    after = fetch()
    # The "ok" copy series must not have advanced for this failed copy.
    assert _op_ok(snap, "copy", after=after) == 0

"""
tests/test_s3_driver_namespace.py

Phase-92 open-work audit #4 (rest): namespace mutation over an s3:// (sd_remote)
storage backend, exercised through the WebDAV verbs at the HTTP edge and, in
particular, through the DEFAULT staged write path (brix_stage on) — so this suite
also pins the stage decorator's CAP_DIRS|CAP_DIRS_WRITE advertisement, without
which the vfs_rename catalog-mutation gate refuses every MOVE with 403 before it
ever reaches the sd_remote leaf.

Scope — S3 has no directories; BriX models a folder as a zero-byte "path/" marker
object (the standard AWS/MinIO/Ceph-RGW convention). The full driver contract for
every namespace slot (mkdir marker PUT · rename file=CopyObject+DELETE · non-empty
dir rename=ENOTSUP · rmdir marker DELETE · directory-aware stat · fallback_deny
security-neg) is proven hermetically, success/error/security-neg per slot, in the
C unit tests/c/test_sd_remote_rename.c (7 sub-tests) against a fake transport that
honours "key/" markers.

This HTTP suite covers the object-level slice — the MOVE (rename) path and its
guards:

  * success      MOVE file            -> sd_remote_rename (CopyObject + DELETE)
  * error        MOVE missing source  -> rename ENOENT -> 404
  * security-neg MOVE Overwrite:F over existing -> rename noreplace EEXIST -> 412

plus the marker-dependent collection slots (MKCOL/mkdir, directory-aware stat,
object inside a created collection).

Those marker slots were previously skipped here on the premise that the
co-hosted posix-backed brix_s3 origin "cannot store a key ending in '/' (a
staged commit to such a path fails EINVAL), so a 'coll/' marker PUT 500s". That
was true, and it was an ORIGIN BUG rather than a property of the topology: the
S3 server had no folder-marker path at all, on either the write or the read
side. Both were added (s3/put_inner.c: marker PUT creates the directory;
s3/object_meta.c: HEAD of a "prefix/" key reports it) and are covered directly
on the S3 plane by test_s3_folder_marker_put.py — so the marker slots are now
driven here for real. A live MinIO edge (test_sts_minio_live.py's docker-gated
topology) remains the stronger dialect check, and the hermetic per-slot contract
still lives in the C unit above.

Topology (nginx_ce_driver_s3.conf): one nginx hosting a posix-backed brix_s3
ORIGIN plus a WebDAV FRONT whose storage backend is that s3:// origin (staged by
default); the front signs its OUTBOUND leg to the origin with a configured cred.
"""

import os
import socket
import time
import uuid

import pytest

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial,
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-s3-driver-ns")]

BUCKET = "testbucket"
S3_AK = "AKIDS3DRIVERNSTEST1"
S3_SK = "czMtZHJpdmVyLW5hbWVzcGFjZS1tdXRhdGlvbi1zZWNyZXQtdA=="

FRONT_PORT = None
ORIGIN_PORT = None

BODY = (b"s3 namespace mutation payload 0123456789\n" * 64)


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture()
def ns_server(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    global FRONT_PORT, ORIGIN_PORT

    oroot = tmp_path / "origin"
    oroot.mkdir()
    (oroot / BUCKET).mkdir()
    if os.geteuid() == 0:
        os.chmod(oroot, 0o777)
        os.chmod(oroot / BUCKET, 0o777)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-s3-driver-ns",
        template="nginx_ce_driver_s3.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST,
                         "ORIGIN_DIR": str(oroot),
                         "S3_ACCESS_KEY": S3_AK,
                         "S3_SECRET_KEY": S3_SK},
        reason="s3:// namespace mutation (MOVE rename over staged s3://) end-to-end"))

    FRONT_PORT = ep.port
    ORIGIN_PORT = ep.extra_ports["ORIGIN_PORT"]
    if not _wait_port(ORIGIN_PORT):
        pytest.skip("s3-driver-ns origin listener did not come up")
    yield


def _url(key):
    return f"http://{HOST}:{FRONT_PORT}/{key}"


def _req(method, key, **kw):
    return requests.request(method, _url(key), timeout=30, **kw)


def test_move_renames_file(ns_server):
    # success: MOVE = sd_remote_rename (S3 CopyObject + DELETE) THROUGH the staged
    # write path — the source disappears and the destination serves the moved
    # bytes. Also pins the stage decorator's CAP_DIRS_WRITE (else this MOVE 403s at
    # the vfs_rename gate before reaching the sd_remote leaf).
    src = f"nsd_{uuid.uuid4().hex}.bin"
    dst = f"nsd_{uuid.uuid4().hex}.bin"
    assert _req("PUT", src, data=BODY).status_code in (200, 201, 204)

    m = _req("MOVE", src, headers={"Destination": _url(dst)})
    assert m.status_code in (201, 204), f"MOVE: {m.status_code}"

    assert _req("GET", src).status_code == 404, "source survived the MOVE"
    g = _req("GET", dst, headers={"Accept-Encoding": "identity"})
    assert g.status_code == 200 and g.content == BODY, "dest missing moved bytes"


def test_mkcol_creates_marker_collection(ns_server):
    # success (marker slot): MKCOL over an s3:// backend is sd_remote_mkdir — a
    # zero-byte "coll/" marker PUT at the origin. The collection must then be
    # visible to the directory-aware stat (PROPFIND/HEAD) and usable as a prefix.
    coll = f"nsdcoll_{uuid.uuid4().hex}"
    m = _req("MKCOL", coll + "/")
    assert m.status_code == 201, f"MKCOL: {m.status_code} {m.text[:200]}"

    # Directory-aware stat: the driver classifies the path as a directory by
    # probing the marker, so PROPFIND must find the collection it just made.
    p = _req("PROPFIND", coll + "/", headers={"Depth": "0"})
    assert p.status_code in (207, 200), f"PROPFIND on new collection: {p.status_code}"

    # And it is a real prefix: an object lands inside and reads back.
    key = f"{coll}/inside_{uuid.uuid4().hex}.bin"
    assert _req("PUT", key, data=BODY).status_code in (200, 201, 204)
    g = _req("GET", key, headers={"Accept-Encoding": "identity"})
    assert g.status_code == 200 and g.content == BODY, "object inside collection"


def test_mkcol_existing_collection_conflicts(ns_server):
    # error (marker slot): MKCOL on a collection that already exists must be
    # refused (405 Method Not Allowed per RFC 4918), not a silent second 201 —
    # the driver's mkdir HEADs the marker first and reports EEXIST.
    coll = f"nsdcoll_{uuid.uuid4().hex}"
    first = _req("MKCOL", coll + "/")
    assert first.status_code == 201, f"MKCOL: {first.status_code}"

    again = _req("MKCOL", coll + "/")
    assert again.status_code in (405, 409, 412), \
        f"re-MKCOL of an existing collection should be refused, got {again.status_code}"


def test_mkcol_traversal_rejected(ns_server):
    # security-neg (marker slot): a traversal in the collection name must never
    # create a prefix outside the export. Sent through requests' normalizer AND
    # percent-encoded, since only the encoded form survives to the resolver.
    name = f"nsdesc_{uuid.uuid4().hex}"
    m = _req("MKCOL", f"%2e%2e/{name}/")
    assert m.status_code not in (201, 204), \
        f"traversal MKCOL must not create a collection, got {m.status_code}"
    assert _req("PROPFIND", f"{name}/", headers={"Depth": "0"}).status_code == 404


def test_move_missing_source_conflicts(ns_server):
    # error: MOVE of a source that does not exist -> rename ENOENT -> 404. The
    # driver HEADs the source (file then marker), finds neither, and reports
    # not-found rather than silently manufacturing an empty destination.
    src = f"nsd_missing_{uuid.uuid4().hex}.bin"
    dst = f"nsd_{uuid.uuid4().hex}.bin"
    m = _req("MOVE", src, headers={"Destination": _url(dst)})
    assert m.status_code == 404, f"MOVE of missing source should be 404, got {m.status_code}"
    assert _req("GET", dst).status_code == 404, "dest fabricated for a missing source"


def test_move_noreplace_over_existing_conflicts(ns_server):
    # security-neg: MOVE Overwrite:F onto an existing destination must be refused
    # (rename noreplace -> EEXIST -> 412), leaving BOTH objects intact — never a
    # silent clobber of the destination.
    src = f"nsd_{uuid.uuid4().hex}.bin"
    dst = f"nsd_{uuid.uuid4().hex}.bin"
    other = b"pre-existing destination content\n"
    assert _req("PUT", src, data=BODY).status_code in (200, 201, 204)
    assert _req("PUT", dst, data=other).status_code in (200, 201, 204)

    m = _req("MOVE", src,
             headers={"Destination": _url(dst), "Overwrite": "F"})
    assert m.status_code == 412, f"noreplace MOVE should be 412, got {m.status_code}"

    # both survive, unchanged
    assert _req("GET", src).status_code == 200, "source clobbered on refused MOVE"
    g = _req("GET", dst, headers={"Accept-Encoding": "identity"})
    assert g.status_code == 200 and g.content == other, "dest overwritten"

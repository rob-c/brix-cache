"""The ops the unified grid declared but no conformance test ever drove:
op="tpc", op="copy" and op="xattr" — plus the three transport cells the
matrix was missing (S3 over TLS, a stream Range window, and an HTTP plane
whose storage is a REMOTE origin instead of the local posix tree).

WHAT: Value-asserted ledger deltas for third-party copy (pull leg, byte-exact
      against brix_tpc_bytes_total), server-side copy on both WebDAV and S3,
      extended-attribute writes on all three protocols, and the transport
      cells above — each with its error arm and, where the op can be pointed
      off-export, a security-negative.

WHY:  op="tpc" was a declared-but-UNREACHABLE row: the WebDAV op map named it
      for COPY, but the protocol-level op_done is deliberately restricted to
      the data plane, so nothing ever incremented it.  op="copy" was reachable
      but only ever booked status="other" on a driver-backed export, because
      sd_posix_server_copy handed brix_ns_local_copy root-RELATIVE paths where
      it demands absolutes under root_canon (EXDEV → WebDAV 403 / S3 500).
      Both were found by cataloguing the grid rather than the code, which is
      exactly what this file pins so neither can silently regress.
"""

import time

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

DAV = {"proto": "webdav"}
S3 = {"proto": "s3"}
STREAM = {"proto": "stream"}

# The pull leg is a detached curl transfer: its terminal metric lands after
# the 201 is already on the wire, so the ledger needs a beat longer to settle
# than a request-scoped op does.
TPC_SETTLE = 1.5


def snap(mx):
    return cx.Snap(mx.metrics)


def tpc_pull(mx, dest_name, source_url, **extra):
    """COPY + Source: on the one TPC-enabled plane = third-party pull."""
    headers = {"Source": source_url, "Overwrite": "T", "Credential": "none"}
    headers.update(extra)
    return mx.dav_request("davtpc", f"/{dest_name}", method="COPY",
                          headers=headers)


# --------------------------------------------------------------------------
# op="tpc" — the row that had no booking owner
# --------------------------------------------------------------------------

def test_tpc_pull_books_unified_op_and_exact_bytes(mx):
    """A successful HTTP-TPC pull books, in one shot: the unified op="tpc"
    row, the TPC-specific transfer + byte counters (byte-exact against the
    source size), and the WebDAV pull/curl lifecycle events."""
    src = cx.unique_name("tpcsrc")
    payload = mx.seed_local(src, 4096)
    dst = cx.unique_name("tpcdst")
    s = snap(mx)
    st, _, _ = tpc_pull(mx, dst, mx.http_url("davs", f"/{src}"))
    time.sleep(TPC_SETTLE)
    after = cx.mfetch(mx.metrics)

    assert st == 201
    assert (mx.local_data / dst).read_bytes() == payload
    assert s.delta("brix_io_ops_total", {**DAV, "op": "tpc", "status": "ok"},
                   after) == 1
    assert s.delta("brix_tpc_transfers_total",
                   {**DAV, "direction": "pull", "status": "ok"}, after) == 1
    assert s.delta("brix_tpc_bytes_total",
                   {**DAV, "direction": "pull"}, after) == len(payload)
    assert s.delta("brix_webdav_tpc_total", {"event": "pull_started"},
                   after) == 1
    assert s.delta("brix_webdav_tpc_total", {"event": "pull_success"},
                   after) == 1
    assert s.delta("brix_webdav_tpc_total", {"event": "curl_success"},
                   after) == 1


def test_tpc_pull_count_only_no_latency_row(mx):
    """op="tpc" is booked count-only.  A TPC's clock lives in the registry
    across a detached thread, so there is no request-scoped duration to file
    and filing 0us would falsify the lowest latency bucket — assert the
    histogram stays put while the counter moves."""
    src = cx.unique_name("tpcnolat")
    mx.seed_local(src, 1024)
    s = snap(mx)
    st, _, _ = tpc_pull(mx, cx.unique_name("tpcnolatd"),
                        mx.http_url("davs", f"/{src}"))
    time.sleep(TPC_SETTLE)
    after = cx.mfetch(mx.metrics)

    assert st == 201
    assert s.delta("brix_io_ops_total", {**DAV, "op": "tpc", "status": "ok"},
                   after) == 1
    assert s.delta_or_absent("brix_io_latency_seconds_count",
                             {**DAV, "op": "tpc"}, after) == 0


def test_tpc_pull_missing_source_books_error_not_ok(mx):
    """Pull of a source that 404s: the transfer fails, so the unified row and
    the TPC counter both land in their error bucket and no ok row moves."""
    s = snap(mx)
    st, _, _ = tpc_pull(mx, cx.unique_name("tpcmissd"),
                        mx.http_url("davs", f"/{cx.unique_name('tpcgone')}"))
    time.sleep(TPC_SETTLE)
    after = cx.mfetch(mx.metrics)

    assert st >= 400
    assert s.delta_or_absent("brix_io_ops_total",
                             {**DAV, "op": "tpc", "status": "ok"},
                             after) == 0
    assert s.delta_or_absent("brix_tpc_transfers_total",
                             {**DAV, "direction": "pull", "status": "ok"},
                             after) == 0
    assert s.delta_or_absent("brix_tpc_bytes_total",
                             {**DAV, "direction": "pull"}, after) == 0


def test_tpc_pull_cleartext_source_refused_no_op_row(mx):
    """SECURITY-NEGATIVE: the pull leg must be https.  A cleartext Source is
    rejected at header validation — before any egress — so it books
    bad_request and leaves every tpc row untouched."""
    src = cx.unique_name("tpcplain")
    mx.seed_local(src, 512)
    s = snap(mx)
    st, _, _ = tpc_pull(mx, cx.unique_name("tpcplaind"),
                        mx.http_url("dav", f"/{src}"))
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st == 400
    assert s.delta("brix_webdav_tpc_total", {"event": "bad_request"},
                   after) == 1
    assert s.delta_or_absent("brix_webdav_tpc_total", {"event": "curl_started"},
                             after) == 0
    assert s.delta_or_absent("brix_io_ops_total", {**DAV, "op": "tpc",
                                                  "status": "ok"},
                             after) == 0


def test_tpc_copy_without_source_or_destination_is_not_a_transfer(mx):
    """SECURITY-NEGATIVE (input shape): COPY carrying neither Source nor
    Destination is malformed; it must not be treated as a self-copy."""
    s = snap(mx)
    st, _, _ = mx.dav_request("davtpc", f"/{cx.unique_name('tpcbare')}",
                              method="COPY", headers={"Credential": "none"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    # Rejected by the COPY dispatcher before the TPC engine sees it, so this
    # arm is NOT one of the tpc_total{event="bad_request"} cases — the point of
    # the pin is that a header-less COPY books no transfer at all.
    assert st == 400
    assert s.delta_or_absent("brix_io_ops_total",
                             {**DAV, "op": "tpc", "status": "ok"},
                             after) == 0
    assert s.delta_or_absent("brix_tpc_transfers_total",
                             {**DAV, "direction": "pull", "status": "ok"},
                             after) == 0


# --------------------------------------------------------------------------
# op="copy" — server-side copy on a driver-backed export
# --------------------------------------------------------------------------

def test_webdav_local_copy_books_ok(mx):
    """A same-server WebDAV COPY on a cache-decorated posix export: 201, one
    op="copy" ok row with latency.  This booked status="other" until
    sd_posix_server_copy stopped handing relative paths to brix_ns_local_copy."""
    src = cx.unique_name("cpsrc")
    payload = mx.seed_local(src, 640)
    dst = "cp_" + src
    s = snap(mx)
    st, _, _ = mx.dav_request(
        "dav", f"/{src}", method="COPY",
        headers={"Destination": mx.http_url("dav", f"/{dst}"),
                 "Overwrite": "T"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st in (201, 204)
    assert (mx.local_data / dst).read_bytes() == payload
    assert s.delta("brix_io_ops_total", {**DAV, "op": "copy", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_latency_seconds_count", {**DAV, "op": "copy"},
                   after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {**DAV, "op": "copy", "status": "other"},
                             after) == 0


def test_webdav_copy_missing_source_books_not_found(mx):
    """COPY of an absent source: 404, and the copy op lands in not_found —
    not the catch-all other bucket."""
    s = snap(mx)
    st, _, _ = mx.dav_request(
        "dav", f"/{cx.unique_name('cpgone')}", method="COPY",
        headers={"Destination": mx.http_url("dav", "/cp_never"),
                 "Overwrite": "T"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    # The source probe (webdav_copy_probe) is deliberately unmetered — "the
    # COPY op accounts for itself" — so a source that never existed short-
    # circuits with NO copy row at all, neither ok nor not_found.  That is an
    # asymmetry with S3 CopyObject, which does book not_found (below); pinned
    # here so the day it is unified the pin, not a dashboard, notices.
    assert st == 404
    assert s.delta_or_absent("brix_io_ops_total",
                             {**DAV, "op": "copy", "status": "ok"},
                             after) == 0
    assert s.delta_or_absent("brix_io_ops_total",
                             {**DAV, "op": "copy", "status": "not_found"},
                             after) == 0


def test_webdav_copy_escaping_destination_refused(mx):
    """SECURITY-NEGATIVE: a Destination traversing out of the export must be
    refused before any byte moves, and must not book a successful copy."""
    src = cx.unique_name("cpesc")
    mx.seed_local(src, 256)
    s = snap(mx)
    st, _, _ = mx.dav_request(
        "dav", f"/{src}", method="COPY",
        headers={"Destination": mx.http_url("dav", "/../escaped.bin"),
                 "Overwrite": "T"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st >= 400
    assert not (mx.local_data.parent / "escaped.bin").exists()
    assert s.delta_or_absent("brix_io_ops_total",
                             {**DAV, "op": "copy", "status": "ok"},
                             after) == 0


def test_s3_copy_object_books_ok(mx):
    """S3 CopyObject (PUT + x-amz-copy-source) on the anonymous plane books
    the same unified op="copy" row under proto="s3"."""
    src = cx.unique_name("s3cpsrc")
    payload = mx.seed_local(src, 720)
    dst = "cp_" + src
    s = snap(mx)
    st, _, _ = mx.s3_request(
        "s3", dst, method="PUT",
        headers={"x-amz-copy-source": f"/{cx.S3_BUCKET}/{src}"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st == 200
    assert (mx.local_data / dst).read_bytes() == payload
    assert s.delta("brix_io_ops_total", {**S3, "op": "copy", "status": "ok"},
                   after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {**S3, "op": "copy", "status": "other"},
                             after) == 0


def test_s3_copy_object_missing_source_books_not_found(mx):
    """S3 CopyObject naming an absent key: 404, copy books not_found."""
    s = snap(mx)
    st, _, _ = mx.s3_request(
        "s3", cx.unique_name("s3cpdst"), method="PUT",
        headers={"x-amz-copy-source":
                 f"/{cx.S3_BUCKET}/{cx.unique_name('s3cpgone')}"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**S3, "op": "copy", "status": "not_found"}, after) == 1


# --------------------------------------------------------------------------
# op="xattr" — extended attributes across all three protocols
# --------------------------------------------------------------------------

PROPPATCH_SET = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<D:propertyupdate xmlns:D="DAV:" xmlns:X="http://brix.test/ns">'
    '<D:set><D:prop><X:tag>hello</X:tag></D:prop></D:set>'
    '</D:propertyupdate>'
)


def test_webdav_proppatch_books_xattr(mx):
    """PROPPATCH of a dead property is an xattr write: 207 multistatus, one
    op="xattr" ok row with latency."""
    n = cx.unique_name("xattrdav")
    mx.seed_local(n, 128)
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{n}", method="PROPPATCH",
                              data=PROPPATCH_SET.encode(),
                              headers={"Content-Type": "text/xml"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    # Three xattr touches for one dead property (enumerate, write, read-back)
    # plus the one stat the handler needs to resolve the target — the exact
    # shape is the pin: a PROPPATCH must not grow into an unbounded number of
    # xattr ops as the property set grows.
    assert st == 207
    assert s.delta("brix_io_ops_total", {**DAV, "op": "xattr", "status": "ok"},
                   after) == 3
    assert s.delta("brix_io_ops_total", {**DAV, "op": "stat", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_latency_seconds_count", {**DAV, "op": "xattr"},
                   after) == 3


def test_webdav_proppatch_missing_target_books_not_found(mx):
    """PROPPATCH on an absent resource fails at the resolving stat, so the
    not_found lands on op="stat" and no xattr row is booked — the property
    write never happened, and the ledger must not claim it did."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{cx.unique_name('xattrgone')}",
                              method="PROPPATCH", data=PROPPATCH_SET.encode(),
                              headers={"Content-Type": "text/xml"})
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**DAV, "op": "stat", "status": "not_found"}, after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {**DAV, "op": "xattr", "status": "ok"},
                             after) == 0


def test_s3_put_tagging_books_xattr(mx):
    """S3 PutObjectTagging is the S3 spelling of an xattr write."""
    n = cx.unique_name("xattrs3")
    mx.seed_local(n, 128)
    tagging = ('<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag>'
               '</TagSet></Tagging>')
    s = snap(mx)
    st, _, _ = mx.s3_request("s3", n + "?tagging", method="PUT",
                             data=tagging.encode())
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st == 200
    assert s.delta("brix_io_ops_total", {**S3, "op": "xattr", "status": "ok"},
                   after) >= 1


def test_stream_xattr_set_books_xattr(mx):
    """kXR_fattr over root:// books op="xattr" under proto="stream" — the
    third protocol spelling of the same row."""
    n = cx.unique_name("xattrstream")
    mx.seed_origin(n, 128)
    s = snap(mx)
    r = mx.xrdfs("none", "xattr", f"/{n}", "set", "user.k=v")
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert r.returncode == 0, r.stderr
    assert s.delta("brix_io_ops_total",
                   {**STREAM, "op": "xattr", "status": "ok"}, after) >= 1


# --------------------------------------------------------------------------
# Transport cells the matrix was missing
# --------------------------------------------------------------------------

def test_s3_over_tls_ledger_matches_cleartext(mx):
    """SigV4 signs host:port, never the scheme, so the TLS plane's signing
    input is byte-identical to the cleartext one's.  Pin that TLS adds no
    accounting of its own: the same GET books the same rows on both planes."""
    n = cx.unique_name("s3tls")
    payload = mx.seed_local(n, 900)

    s = snap(mx)
    st, body, _ = mx.s3_request("s3sig", n)
    cx.settle()
    plain = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    plain_ops = s.delta("brix_io_ops_total",
                        {**S3, "op": "read", "status": "ok"}, plain)
    plain_bytes = s.delta("brix_io_bytes_read", S3, plain)

    s = snap(mx)
    st, body, _ = mx.s3_request("s3tls", n)
    cx.settle()
    tls = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_ops_total", {**S3, "op": "read", "status": "ok"},
                   tls) == plain_ops
    assert s.delta("brix_io_bytes_read", S3, tls) == plain_bytes


def test_s3_over_tls_unsigned_rejected(mx):
    """SECURITY-NEGATIVE: TLS is not authentication.  An unsigned request to
    the TLS plane is refused exactly as on the cleartext signed plane, and
    books no successful read."""
    n = cx.unique_name("s3tlsneg")
    mx.seed_local(n, 128)
    s = snap(mx)
    st, _, _ = mx.s3_request("s3tls", n, signed=False)
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st == 403
    assert s.delta("brix_io_ops_total",
                   {**S3, "op": "read", "status": "forbidden"}, after) == 1
    assert s.delta_or_absent("brix_io_ops_total",
                             {**S3, "op": "read", "status": "ok"},
                             after) == 0


def test_stream_range_read_books_exact_window(mx):
    """A stream Range read books only the bytes in the window, not the whole
    file — the byte-exact counterpart of the HTTP Range cell."""
    from XRootD import client

    n = cx.unique_name("rangestream")
    payload = mx.seed_origin(n, 4096)
    s = snap(mx)
    f = client.File()
    status, _ = f.open(mx.root_url("none", f"/{n}"))
    assert status.ok, status.message
    try:
        rs, buf = f.read(1000, 250)
        assert rs.ok, rs.message
    finally:
        f.close()
    cx.settle()
    after = cx.mfetch(mx.metrics)

    # The window, not the file: 250 bytes off a 4096-byte object.  Booked on
    # the posix backend ledger — the stream plane's proto-level byte fold only
    # moves once the object is resident, so the backend row is the byte-exact
    # one on a cold read.
    assert bytes(buf) == payload[1000:1250]
    assert s.delta("brix_storage_io_bytes_read", {"backend": "posix"},
                   after) == 250
    assert s.delta("brix_io_ops_total",
                   {**STREAM, "op": "read", "status": "ok"}, after) == 1


def test_webdav_over_remote_origin_miss_then_hit(mx):
    """The one HTTP plane whose storage is a root:// origin rather than the
    local posix tree: first GET misses and fills, second hits — so the
    webdav cache dispositions are measured against a real remote origin
    instead of a local-file fast path."""
    n = cx.unique_name("davorigin")
    payload = mx.seed_origin(n, 800)

    s = snap(mx)
    st, body, _ = mx.dav_request("davo", f"/{n}")
    cx.settle()
    first = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_ops_total", {**DAV, "op": "read", "status": "ok"},
                   first) == 1
    assert s.delta("brix_io_bytes_read", DAV,
                   first) == len(payload)

    s = snap(mx)
    st, body, _ = mx.dav_request("davo", f"/{n}")
    cx.settle()
    second = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_io_bytes_read", DAV,
                   second) == len(payload)


def test_webdav_over_remote_origin_missing_object_404(mx):
    """Error arm of the remote-origin plane: an object absent on the ORIGIN
    surfaces as a 404 booked not_found, not as an origin-side 5xx."""
    s = snap(mx)
    st, _, _ = mx.dav_request("davo", f"/{cx.unique_name('davogone')}")
    cx.settle()
    after = cx.mfetch(mx.metrics)

    assert st == 404
    assert s.delta("brix_io_ops_total",
                   {**DAV, "op": "read", "status": "not_found"}, after) == 1

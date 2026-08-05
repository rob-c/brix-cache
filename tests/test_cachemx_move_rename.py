"""WebDAV MOVE + unified rename accounting — regression suite for the two
rename bugs found while expanding the conformance corpus.

WHAT: Exact ledger assertions for MOVE across success (201 create, 204
      replace), every error arm of the precondition ladder (400/403/404/412),
      the path-traversal security negative, and the native-stream mv rows.

WHY:  Two live bugs are pinned here:
      (1) sd_posix_rename passed export-RELATIVE keys to brix_ns_rename,
          whose contract demands ABSOLUTE paths under root_canon — every
          same-directory MOVE was refused as a cross-root move (EXDEV -> 500).
      (2) MOVE had no slot in the webdav method enum, so its requests/
          responses rows were folded into method="OTHER" — invisible on any
          per-method dashboard.  The OTHER slot moved from index 8 to 9 when
          MOVE claimed 8, so the PATCH test also pins the slot shift.

The HTTP planes share ONE cache instance; every test uses unique names.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

IO = {"proto": "webdav"}
RENAME_OK = {**IO, "op": "rename", "status": "ok"}


def snap(mx):
    return cx.Snap(mx.metrics)


def move(mx, plane, src, dst_path, **headers):
    hdrs = {"Destination": mx.http_url(plane, dst_path)} if dst_path else {}
    hdrs.update(headers)
    return mx.dav_request(plane, src, method="MOVE", headers=hdrs)


# --------------------------------------------------------------------------
# Success paths (regression: EXDEV bug made ALL of these 500)
# --------------------------------------------------------------------------

def test_move_fresh_dest_created_201(mx):
    """MOVE to a fresh name is 201 Created with exactly one unified rename op
    and one real latency observation — the EXDEV-500 regression pin."""
    name = cx.unique_name("mvok")
    mx.seed_local(name, 700)
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{name}", f"/dst_{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total", RENAME_OK, after) == 1
    assert s.delta("brix_io_latency_usec_count", {**IO, "op": "rename"},
                   after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "2xx"}, after) == 1


def test_move_books_method_move_not_other(mx):
    """MOVE books its own method label on both ledger families and leaves
    method="OTHER" untouched — the enum-gap regression pin."""
    name = cx.unique_name("mvlbl")
    mx.seed_local(name, 300)
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{name}", f"/dst_{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_webdav_requests_total", {"method": "MOVE"},
                   after) == 1
    assert s.delta("brix_webdav_requests_total", {"method": "OTHER"},
                   after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "OTHER", "status_class": "2xx"}, after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "OTHER", "status_class": "5xx"}, after) == 0


def test_patch_still_books_other_after_slot_shift(mx):
    """PATCH (unhandled) still lands on method="OTHER" at its NEW enum index
    — a stale string table would misattribute or crash the exporter."""
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", "/whatever", method="PATCH")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 405
    assert s.delta("brix_webdav_requests_total", {"method": "OTHER"},
                   after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "OTHER", "status_class": "4xx"}, after) == 1


def test_move_payload_survives_and_source_gone(mx):
    """The moved object is byte-identical at the destination and the source
    name answers 404 afterwards."""
    name = cx.unique_name("mvbody")
    payload = mx.seed_local(name, 1234)
    st, _, _ = move(mx, "dav", f"/{name}", f"/dst_{name}")
    assert st == 201
    cx.settle()
    st2, body, _ = mx.dav_request("dav", f"/dst_{name}")
    assert st2 == 200 and body == payload
    st3, _, _ = mx.dav_request("dav", f"/{name}")
    assert st3 == 404


def test_move_path_only_destination_201(mx):
    """A path-only (non-absolute-URI) Destination header is accepted and
    books the same single rename op."""
    name = cx.unique_name("mvpath")
    mx.seed_local(name, 400)
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="MOVE",
                              headers={"Destination": f"/dst_{name}"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total", RENAME_OK, after) == 1


def test_move_davs_plane_201(mx):
    """MOVE works on the TLS plane too (the EXDEV bug hit every HTTP plane
    identically — same sd_posix underneath)."""
    name = cx.unique_name("mvtls")
    mx.seed_local(name, 500)
    s = snap(mx)
    st, _, _ = move(mx, "davs", f"/{name}", f"/dst_{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total", RENAME_OK, after) == 1


def test_move_replace_existing_204(mx):
    """MOVE onto an existing destination (default Overwrite:T) replaces it:
    204 No Content, one rename op, destination carries the SOURCE payload."""
    src = cx.unique_name("mvrepsrc")
    dst = cx.unique_name("mvrepdst")
    payload = mx.seed_local(src, 800)
    mx.seed_local(dst, 300)
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{src}", f"/{dst}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 204
    assert s.delta("brix_io_ops_total", RENAME_OK, after) == 1
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "2xx"}, after) == 1
    st2, body, _ = mx.dav_request("dav", f"/{dst}")
    assert st2 == 200 and body == payload


def test_move_collection_carries_children(mx):
    """MOVE of a directory (thread-pool dispatch path) relocates its children
    and books one rename op."""
    d = cx.unique_name("mvdir").replace(".bin", "")
    child = "kid.bin"
    st, _, _ = mx.dav_request("dav", f"/{d}", method="MKCOL")
    assert st == 201
    payload = b"c" * 256
    st, _, _ = mx.dav_request("dav", f"/{d}/{child}", method="PUT",
                              data=payload)
    assert st in (200, 201, 204)
    cx.settle()
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{d}", f"/moved_{d}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total", RENAME_OK, after) == 1
    st2, body, _ = mx.dav_request("dav", f"/moved_{d}/{child}")
    assert st2 == 200 and body == payload


def test_move_cached_source_evicts_exact(mx):
    """MOVE of a CACHED object retires the cached copy: the eviction byte
    counter moves by exactly the object's size (rename evicts both endpoint
    keys, and only the source held bytes)."""
    name = cx.unique_name("mvevict")
    size = 1600
    mx.seed_local(name, size)
    st, _, _ = mx.dav_request("dav", f"/{name}")      # prime the cache
    assert st == 200
    cx.settle()
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{name}", f"/dst_{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_ops_total", RENAME_OK, after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", {"proto": "webdav"},
                   after) == size


def test_move_transfers_no_payload_bytes(mx):
    """A rename is pure namespace: neither io byte ledger moves."""
    name = cx.unique_name("mvnobytes")
    mx.seed_local(name, 2048)
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{name}", f"/dst_{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 201
    assert s.delta("brix_io_bytes_read", IO, after) == 0
    assert s.delta("brix_io_bytes_written", IO, after) == 0


# --------------------------------------------------------------------------
# Error ladder — each arm books MOVE/4xx and NO rename op
# --------------------------------------------------------------------------

def test_move_missing_destination_400(mx):
    """MOVE without a Destination header is 400 and books no rename."""
    name = cx.unique_name("mvnodst")
    mx.seed_local(name, 200)
    s = snap(mx)
    st, _, _ = mx.dav_request("dav", f"/{name}", method="MOVE")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 400
    assert s.delta_or_absent("brix_io_ops_total", RENAME_OK, after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "4xx"}, after) == 1


def test_move_absent_source_404(mx):
    """MOVE of a nonexistent source is 404 with no rename op."""
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{cx.unique_name('mvghost')}",
                    "/mv_wherever.bin")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 404
    assert s.delta_or_absent("brix_io_ops_total", RENAME_OK, after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "4xx"}, after) == 1


def test_move_onto_self_403(mx):
    """MOVE with Destination == source is refused (403) without touching the
    namespace, and the object survives intact."""
    name = cx.unique_name("mvself")
    payload = mx.seed_local(name, 350)
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{name}", f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 403
    assert s.delta_or_absent("brix_io_ops_total", RENAME_OK, after) == 0
    st2, body, _ = mx.dav_request("dav", f"/{name}")
    assert st2 == 200 and body == payload


def test_move_overwrite_false_existing_dest_412(mx):
    """Overwrite: F onto an existing destination is 412 and BOTH objects
    survive with their original payloads."""
    src = cx.unique_name("mvowf")
    dst = cx.unique_name("mvowfdst")
    p_src = mx.seed_local(src, 420)
    p_dst = mx.seed_local(dst, 640)
    s = snap(mx)
    st, _, _ = move(mx, "dav", f"/{src}", f"/{dst}", Overwrite="F")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 412
    assert s.delta_or_absent("brix_io_ops_total", RENAME_OK, after) == 0
    assert s.delta("brix_webdav_responses_total",
                   {"method": "MOVE", "status_class": "4xx"}, after) == 1
    _, b1, _ = mx.dav_request("dav", f"/{src}")
    _, b2, _ = mx.dav_request("dav", f"/{dst}")
    assert b1 == p_src and b2 == p_dst


def test_move_escape_destination_denied(mx):
    """SECURITY: a Destination that path-traverses out of the export root is
    refused (403), books no rename, and the source is untouched — a rename
    is a write primitive and must respect resolve_path confinement."""
    name = cx.unique_name("mvescape")
    payload = mx.seed_local(name, 512)
    s = snap(mx)
    st, _, _ = mx.dav_request(
        "dav", f"/{name}", method="MOVE",
        headers={"Destination": "/../../../etc/mv_owned"})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 403
    assert s.delta_or_absent("brix_io_ops_total", RENAME_OK, after) == 0
    st2, body, _ = mx.dav_request("dav", f"/{name}")
    assert st2 == 200 and body == payload


# --------------------------------------------------------------------------
# Native stream mv — the requests ledger and the error arm
# --------------------------------------------------------------------------

def stream_labels(mx):
    meta = cx.STREAM_PLANES["none"]
    return {"port": str(mx.port(meta["port_key"])), "auth": meta["auth"]}


def test_stream_mv_books_requests_ledger(mx):
    """A successful kXR_mv books one op="mv" ok row on the wire ledger and
    one unified rename op (stream namespace ops act on the ORIGIN)."""
    name = cx.unique_name("smvok")
    mx.seed_origin(name, 640)
    lbl = stream_labels(mx)
    s = snap(mx)
    r = mx.xrdfs("none", "mv", f"/{name}", f"/moved_{name}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "rename", "status": "ok"},
                   after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "mv", "status": "ok"},
        after) == 1
    assert (mx.origin_data / f"moved_{name}").exists()


def test_stream_mv_absent_books_error_rows(mx):
    """kXR_mv of a nonexistent source: one op="mv" error ledger row and one
    rename op with status=not_found — and no ok rows."""
    lbl = stream_labels(mx)
    s = snap(mx)
    r = mx.xrdfs("none", "mv", f"/{cx.unique_name('smvghost')}",
                 "/smv_nowhere.bin")
    assert r.returncode != 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "rename", "status": "not_found"},
                   after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "mv", "status": "error"},
        after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "mv", "status": "ok"},
        after) == 0

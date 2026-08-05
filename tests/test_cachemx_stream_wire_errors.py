"""Per-security-plane wire-ledger ERROR arms for the native stream planes.

The base plane suite pins the happy paths across all four security planes
and the mv arms on the anonymous plane only.  This grid completes the
matrix: for each of {none, gsi, token, sss} it drives mv (fresh + absent
source), mkdir over an existing directory, rm / rmdir of ghosts and a read
of an absent object, asserting the `brix_requests_total{port,auth,op,
status}` wire rows split correctly between ok and error — per plane, so a
regression in one credential route's error accounting cannot hide behind
another's.  Two arms pin deliberate stock-parity idempotence instead of an
error row: mkdir-exists (EEXIST tolerated, do_Mkdir) and rmdir-absent
(ENOENT tolerated, do_Rmdir) both succeed and book ok rows.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

PLANES = sorted(cx.STREAM_PLANES)
AUTHED = [p for p in PLANES if p != "none"]


def snap(mx):
    return cx.Snap(mx.metrics)


def labels(mx, plane):
    meta = cx.STREAM_PLANES[plane]
    return {"port": str(mx.port(meta["port_key"])), "auth": meta["auth"]}


@pytest.mark.parametrize("plane", AUTHED)
def test_mv_ok_books_wire_row(mx, plane):
    """kXR_mv on an authenticated plane: one op="mv" ok wire row plus one
    unified rename op (anonymous-plane arm lives in move_rename)."""
    name = cx.unique_name(f"wmv{plane}")
    mx.seed_origin(name, 640)
    lbl = labels(mx, plane)
    s = snap(mx)
    r = mx.xrdfs(plane, "mv", f"/{name}", f"/moved_{name}")
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


@pytest.mark.parametrize("plane", AUTHED)
def test_mv_absent_books_error_row(mx, plane):
    """kXR_mv of a ghost source on an authenticated plane: one error wire
    row, one rename not_found, zero ok rows."""
    lbl = labels(mx, plane)
    s = snap(mx)
    r = mx.xrdfs(plane, "mv", f"/{cx.unique_name(f'wmvg{plane}')}",
                 "/wmv_nowhere.bin")
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


@pytest.mark.parametrize("plane", PLANES)
def test_mkdir_exists_idempotent_ok_row(mx, plane):
    """mkdir over an existing directory succeeds (EEXIST-tolerant, stock
    do_Mkdir parity — mkdir.c) and books an op="mkdir" ok wire row, never
    an error row."""
    d = cx.unique_name(f"wmkd{plane}")
    lbl = labels(mx, plane)
    r = mx.xrdfs(plane, "mkdir", f"/{d}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    s = snap(mx)
    r = mx.xrdfs(plane, "mkdir", f"/{d}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "mkdir", "status": "ok"},
        after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "mkdir", "status": "error"},
        after) == 0


@pytest.mark.parametrize("plane", PLANES)
def test_rm_absent_books_error_row(mx, plane):
    """rm of a ghost: one op="rm" error wire row, zero ok rows, zero
    unified delete ok ops."""
    lbl = labels(mx, plane)
    s = snap(mx)
    r = mx.xrdfs(plane, "rm", f"/{cx.unique_name(f'wrm{plane}')}")
    assert r.returncode != 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "rm", "status": "error"},
        after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "rm", "status": "ok"},
        after) == 0
    assert s.delta_or_absent(
        "brix_io_ops_total",
        {"proto": "stream", "op": "delete", "status": "ok"}, after) == 0


@pytest.mark.parametrize("plane", PLANES)
def test_rmdir_absent_idempotent_ok_row(mx, plane):
    """rmdir of a ghost directory succeeds (ENOENT-tolerant, stock
    do_Rmdir parity — op_table.c exec_rmdir) and books an op="rmdir" ok
    wire row, never an error row."""
    lbl = labels(mx, plane)
    s = snap(mx)
    r = mx.xrdfs(plane, "rmdir", f"/{cx.unique_name(f'wrd{plane}')}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "rmdir", "status": "ok"},
        after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "rmdir", "status": "error"},
        after) == 0


@pytest.mark.parametrize("plane", PLANES)
def test_read_absent_books_no_ok_rows(mx, plane):
    """xrdcp of a ghost object fails without booking any successful open or
    read — and some error row (open_rd or stat) records the failure."""
    lbl = labels(mx, plane)
    s = snap(mx)
    r = mx.xrdcp_get(plane, f"/{cx.unique_name(f'wget{plane}')}",
                     "/dev/null")
    assert r.returncode != 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "open_rd", "status": "ok"},
        after) == 0
    assert s.delta_or_absent(
        "brix_io_ops_total",
        {"proto": "stream", "op": "read", "status": "ok"}, after) == 0
    errs = (s.delta_or_absent(
                "brix_requests_total",
                {**lbl, "op": "open_rd", "status": "error"}, after)
            + s.delta_or_absent(
                "brix_requests_total",
                {**lbl, "op": "stat", "status": "error"}, after))
    assert errs >= 1

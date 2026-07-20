"""Stage write-back hydration: partial overwrite of an existing backend object.

Regression for the sd_stage_wb_hydrate change: an update-open through the
write-stage tier of an object that already exists on the backend must seed the
stage copy from the backend (source -> store, via the one staging engine's
RECALL mover) BEFORE accepting random writes — the flush replaces the WHOLE
backend object with the staged bytes, so an unhydrated partial overwrite would
silently truncate every region the client did not write.

Topology: one nginx, two stream servers — a plain root:// ORIGIN export and a
GATEWAY composing brix_stage (sync flush) over root://origin.

Covers the mandated triplet:
  success           — update-open + pwrite at an interior offset + close: the
                      origin object keeps its prefix/suffix around the overlay
                      (and read-back through the open handle sees real bytes);
  error/create      — a brand-new object through the gateway is unaffected by
                      hydration (ENOENT on the source -> plain create);
  security-negative — a durable staged copy left by a failed flush is NEWER
                      than the backend object and must NOT be clobbered by
                      hydration: the flushed result is the staged bytes plus
                      the overlay, not the resurrected backend content.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_stage_hydration.py -v -p no:xdist
"""

import os
import shutil
import subprocess

import pytest

from XRootD import client
from XRootD.client.flags import OpenFlags

from settings import NGINX_BIN, free_port, HOST, BIND_HOST
from official_interop_lib import chown_stock, worker_reachable
from server_registry import NginxInstanceSpec

XRDCP = shutil.which("xrdcp")

pytestmark = [pytest.mark.uses_lifecycle_harness]


@pytest.fixture
def hyd(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")

    base = tmp_path
    origin = base / "origin"; origin.mkdir()
    gw = base / "gw"; gw.mkdir()
    stage = base / "stage"; stage.mkdir()
    worker_reachable(origin, gw, stage)

    origin_port = free_port()
    spec = NginxInstanceSpec(
        name="lc-stage-hydration",
        template="nginx_lc_stage_hydration.conf",
        protocol="root",
        template_values={"ORIGIN_PORT": str(origin_port),
                         "ORIGIN_DATA": str(origin),
                         "GW_DATA": str(gw),
                         "STAGE_DIR": str(stage)},
        reason="stage write-back hydration")
    ep = lifecycle.start(spec)

    class S:
        pass
    s = S()
    s.port = ep.port
    s.origin = origin
    s.stage = stage
    return s


def _seed_origin(hyd, name, payload):
    """Create `payload` at the origin export and hand it to the nobody worker
    (the flush writes it back through the origin server's worker)."""
    p = hyd.origin / name
    p.write_bytes(payload)
    chown_stock(str(p))
    return p


def _update_write(port, name, data, offset):
    """kXR update-open + pwrite(data, offset) + close through the gateway.
    Returns the bytes read back from the open handle at [0, 16) before the
    write (read-your-existing-data check), or raises AssertionError."""
    f = client.File()
    st, _ = f.open(f"root://{HOST}:{port}//{name}", OpenFlags.UPDATE)
    assert st.ok, f"gateway update-open failed: {st.message}"
    try:
        rst, head = f.read(0, 16)
        assert rst.ok, f"read-back through the staged handle failed: {rst.message}"
        wst, _ = f.write(data, offset=offset)
        assert wst.ok, f"gateway pwrite failed: {wst.message}"
    finally:
        cst, _ = f.close()
        assert cst.ok, f"gateway close (sync flush) failed: {cst.message}"
    return head


def test_partial_overwrite_preserves_object(hyd):
    """Success: interior overlay — prefix and suffix survive the flush."""
    name = "hyd_update.bin"
    _seed_origin(hyd, name, b"A" * 8192)

    head = _update_write(hyd.port, name, b"B" * 100, 4096)
    assert head == b"A" * 16, \
        "read through the update handle must see the hydrated object bytes"

    got = (hyd.origin / name).read_bytes()
    assert len(got) == 8192, \
        f"flush truncated the object to {len(got)} bytes — hydration lost"
    assert got[:4096] == b"A" * 4096, "prefix clobbered"
    assert got[4096:4196] == b"B" * 100, "overlay missing"
    assert got[4196:] == b"A" * (8192 - 4196), "suffix clobbered"


def test_new_object_create_unaffected(hyd, tmp_path):
    """Error-path/create: ENOENT on the source -> plain create, full upload."""
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    name = "hyd_create.bin"
    src = tmp_path / "payload.bin"
    src.write_bytes(b"N" * 5000)

    r = subprocess.run(
        [XRDCP, "-f", str(src), f"root://{HOST}:{hyd.port}//{name}"],
        capture_output=True, timeout=30)
    assert r.returncode == 0, \
        f"create through the gateway failed: {r.stderr.decode(errors='replace')}"
    assert (hyd.origin / name).read_bytes() == b"N" * 5000


def test_stale_staged_copy_not_clobbered(hyd):
    """Security-negative: a durable staged copy (failed-flush retry state) is
    newer than the backend — hydration must not overwrite it, and the flush
    must publish the staged bytes, not resurrect the backend content."""
    name = "hyd_retry.bin"
    _seed_origin(hyd, name, b"A" * 8192)        # stale backend content
    staged = hyd.stage / name
    staged.write_bytes(b"S" * 2048)             # newer durable staged copy
    chown_stock(str(staged))

    _update_write(hyd.port, name, b"B" * 10, 0)

    got = (hyd.origin / name).read_bytes()
    assert len(got) == 2048, \
        f"flush published {len(got)} bytes — the staged copy was clobbered " \
        "by hydration (backend content resurrected)"
    assert got[:10] == b"B" * 10, "overlay missing"
    assert got[10:] == b"S" * 2038, "staged bytes lost"

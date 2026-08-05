"""Stage write-back tier: hydration of an existing object + the spool namespace.

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

The second half covers the write-back tier's SPOOL namespace
(sd_stage_store_mkparents): the stage store is a private buffer, so the parent
chain of a nested key exists there only if the tier builds it — before that fix a
create-open of ANY subdirectory key failed kXR_NotFound with a stage tier
configured, because the client's mkdir/mkpath had built the chain in the export
and on the origin, never in the spool.  Triplet: a nested create lands
byte-exact; an unwritable spool fails the open cleanly instead of stranding
bytes; and a traversal key never materialises a directory outside the spool.

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

from settings import NGINX_BIN, HOST, BIND_HOST
from official_interop_lib import chown_stock, worker_reachable
from server_registry import NginxInstanceSpec

XRDCP = shutil.which("xrdcp")

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-stage-hydration")]


@pytest.fixture
def hyd(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")

    base = tmp_path
    origin = base / "origin"; origin.mkdir()
    gw = base / "gw"; gw.mkdir()
    stage = base / "stage"; stage.mkdir()
    worker_reachable(origin, gw, stage)

    spec = NginxInstanceSpec(
        name="lc-stage-hydration",
        template="nginx_lc_stage_hydration.conf",
        protocol="root",
        template_values={"ORIGIN_DATA": str(origin),
                         "GW_DATA": str(gw),
                         "STAGE_DIR": str(stage)},
        reason="stage write-back hydration")
    ep = lifecycle.start(spec)

    class S:
        pass
    s = S()
    s.port = ep.port
    s.origin = origin
    s.gw = gw
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


def test_driver_backed_write_diverts_upload_resume(hyd, tmp_path):
    """The P80.2 resume divert fires for a DRIVER-backed export.

    brix_upload_resume defaults ON, and its skeleton is a local POSIX file under
    the export root — meaningless here, where storage is the root:// origin.  A
    write that kept resume enabled would strand the bytes in a
    `<name>.xrdresume.<hex>.part` inside the gateway export instead of taking the
    whole-object staged seam to the backend.  The divert must key on the driver
    being something other than the DEFAULT POSIX one: every plain `brix_export`
    also owns a default-POSIX census row (phase-68), so a divert that merely
    asks "is a backend registered?" disables staging for ordinary local exports
    (test_shutdown_resume.py::test_upload_resume_stage_dir is that side of it).
    """
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    name = "hyd_divert.bin"
    src = tmp_path / "divert.bin"
    src.write_bytes(b"D" * 4096)

    r = subprocess.run(
        [XRDCP, "-f", str(src), f"root://{HOST}:{hyd.port}//{name}"],
        capture_output=True, timeout=30)
    assert r.returncode == 0, \
        f"driver-backed create failed: {r.stderr.decode(errors='replace')}"

    assert (hyd.origin / name).read_bytes() == b"D" * 4096, \
        "bytes never reached the backend — the write took the local skeleton"
    leftovers = [p.name for p in hyd.gw.iterdir() if ".xrdresume." in p.name]
    assert leftovers == [], \
        f"resume skeleton written under a driver-backed export: {leftovers}"
    assert not (hyd.gw / name).exists(), \
        "the object was published into the gateway export instead of the backend"


def _nested_write(port, name, payload, flags=OpenFlags.NEW | OpenFlags.MAKEPATH):
    """Create `name` (a nested key) through the gateway and return the open status.
    Writes + closes only when the open succeeded, so a refused open is reported
    as such rather than raising."""
    f = client.File()
    st, _ = f.open(f"root://{HOST}:{port}//{name}", flags)
    if not st.ok:
        return st
    try:
        wst, _ = f.write(payload, offset=0)
        assert wst.ok, f"nested pwrite failed: {wst.message}"
    finally:
        cst, _ = f.close()
        assert cst.ok, f"nested close (sync flush) failed: {cst.message}"
    return st


def test_nested_key_lands_through_the_spool(hyd):
    """Success: a create-open of a subdirectory key builds the chain in the
    private stage store and the bytes reach the origin byte-exact."""
    name = "nst/deep/nested.bin"
    payload = b"Q" * 9000

    st = _nested_write(hyd.port, name, payload)
    assert st.ok, f"nested create through the stage tier failed: {st.message}"

    dst = hyd.origin / name
    assert dst.is_file(), \
        "the nested object never reached the origin — the spool open failed"
    assert dst.read_bytes() == payload, "nested object landed corrupt"
    assert (hyd.stage / "nst" / "deep").is_dir(), \
        "the tier did not build the key's parent chain inside the stage store"


def test_nested_create_refused_when_the_spool_is_unwritable(hyd):
    """Error path: the spool mkdir failure surfaces as a failed open — the write
    is never accepted against a spool that cannot hold it."""
    name = "ro_spool/nested.bin"
    os.chmod(hyd.stage, 0o555)
    try:
        st = _nested_write(hyd.port, name, b"Z" * 64)
    finally:
        os.chmod(hyd.stage, 0o755)

    assert not st.ok, \
        "open succeeded although the stage store could not hold the key"
    assert not (hyd.stage / "ro_spool").exists(), "spool chain built anyway"
    assert not (hyd.origin / name).exists(), \
        "bytes reached the origin from a write the spool could not stage"


def test_traversal_key_creates_nothing_outside_the_spool(hyd, tmp_path):
    """Security-negative: a key escaping the export must be refused BEFORE any
    directory is created — neither the spool nor the filesystem above the lab
    roots may gain a component from it."""
    st = _nested_write(hyd.port, "../esc/pwned.bin", b"X" * 32)

    assert not st.ok, "a traversal key was accepted for a staged write"
    for root in (hyd.stage, hyd.gw, hyd.origin, tmp_path):
        assert not (root / "esc").exists(), \
            f"traversal materialised a directory under {root}"
    assert not (tmp_path.parent / "esc").exists(), \
        "traversal escaped the lab root entirely"


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

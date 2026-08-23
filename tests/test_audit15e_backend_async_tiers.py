"""
test_audit15e_backend_async_tiers.py — the durable async backend-op queue
co-resident with storage tiers (audit §B2.12,
testsuite-combinatorial-coverage-audit 2026-08-15: `brix_backend_async on`
appeared in no unit together with `brix_cache_store` or `brix_stage`, though
both subsystems mutate the backend namespace with different durability
windows — async_be paired with NO storage feature at all).

One instance (nginx_audit15e_async_tiers.conf): a WebDAV posix origin and a
front with five locations over it — /rt/ (read-through cache + async queue),
/wt/ (write-through sync-flush stage + async queue), /noq/ (cache tier, NO
queue), /bare/ (remote backend, no tier, no queue), /ro/ (the /rt/ shape with
`brix_allow_write off`).

DEFECT CANDIDATE #6 (pinned here, discovered by this cross): the async queue
drain executes UNLINK/RMDIR through `brix_vfs_unlink_path` /
`brix_vfs_rmdir_path` (src/fs/vfs/vfs_walk.c:320) — posix-confined raw
primitives on root_canon + logical path that never consult the VFS backend
registry — while RENAME alone resolves the driver via
`brix_vfs_backend_resolve` (src/fs/xfer/backend_async_queue.c:174).  So on
ANY export whose truth is a remote/tiered backend, an async MOVE renames
through correctly, but an async DELETE fails against the empty logical export
tree (ENOENT) and the WebDAV render (src/protocols/webdav/namespace.c:282)
answers 404 — for an object a GET serves fine immediately before and after,
and which survives untouched on the origin.  The comment above the enqueue
("The queue drives the same confined-VFS primitive as the sync path") is
false for remote backends: the sync path routes through `brix_ns_delete` and
the driver's delete slot (src/fs/backend/http/sd_http_mutate.c) and works —
as the /noq/ and /bare/ controls prove.

Cases:
  * controls — sync DELETE works on the cache tier without the queue (/noq/)
    and on the bare remote backend (/bare/): 204, origin gone.  These pin the
    attribution to the queue drain, not the tier or the remote driver.
  * DEFECT PIN, cache cross — async DELETE answers 404, the origin object
    survives, and the object still serves.  Inverts on fix.
  * DEFECT PIN, stage cross — same shape through the write-through stage tier.
  * MOVE control — a queued fresh-destination MOVE on the same /rt/ export
    renames the origin object through the resolved driver: the queue CAN
    route through the registry; only its UNLINK/RMDIR arms do not.
  * security-negative — on /ro/ the write gate rejects the DELETE at the
    access phase (403) BEFORE it can enqueue: the origin object survives.
"""

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST

def _check_test_sync_delete_controls_work_without_the_queue_4(cache):
    assert not [p for p in (cache / "noq").rglob("*") if p.is_file()], \
        "sync DELETE answered 204 but left a cache-tier copy behind"

def _check_test_sync_delete_controls_work_without_the_queue_1(plane, r):
    assert r.status_code in (201, 204), (plane, r.status_code, r.text)

def _check_test_sync_delete_controls_work_without_the_queue_2(plane, g):
    assert g.status_code == 200 and g.content == PAYLOAD, (
        plane, g.status_code)

def _check_test_sync_delete_controls_work_without_the_queue_3(cache):
    assert [p for p in (cache / "noq").rglob("*") if p.is_file()], \
        "read-through control returned bytes but nothing was cached"


pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15e-async")]

PAYLOAD = b"audit15e-backend-async-tier-payload " * 16

DEFECT6 = ("DEFECT CANDIDATE #6 has been FIXED: the async queue drain now "
           "reaches the remote/tiered backend for UNLINK (compare "
           "backend_async_queue.c:150 vs :174) — invert this pin: assert "
           "DELETE == 204, origin gone, tier copy gone, re-GET 404.")


@pytest.fixture()
def tiers(lifecycle, tmp_path):
    origin = tmp_path / "origin"
    export = tmp_path / "export"
    cache = tmp_path / "cache"
    stage = tmp_path / "stage"
    journal = tmp_path / "journal"
    # The wire path keeps the location prefix and neither the stage flush's
    # origin PUT nor the queued unlink creates parent collections.
    for d in (origin / "rt", origin / "wt", origin / "ro",
              origin / "noq", origin / "bare",
              export / "rt", export / "wt", export / "ro",
              export / "noq", export / "bare",
              cache / "rt", cache / "ro", cache / "noq",
              stage / "wt", journal):
        d.mkdir(parents=True)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15e-async",
        template="nginx_audit15e_async_tiers.conf",
        protocol="http",
        data_root=str(origin),
        template_values={"BIND_HOST": HOST,
                         "ORIGIN_ROOT": str(origin),
                         "EXPORT_ROOT": str(export),
                         "CACHE_ROOT": str(cache),
                         "STAGE_ROOT": str(stage),
                         "JOURNAL_DIR": str(journal)},
        reason="audit-15e backend_async x cache/stage tier crosses"))
    return ep.port, origin, cache, stage


def _url(port, path):
    return f"http://{HOST}:{port}{path}"


def test_sync_delete_controls_work_without_the_queue(tiers):
    port, origin, cache, _ = tiers
    # Cache tier, no async queue: the sync path routes through the driver.
    for plane in ("noq", "bare"):
        u = _url(port, f"/{plane}/c.bin")
        r = requests.put(u, data=PAYLOAD, timeout=30)
        _check_test_sync_delete_controls_work_without_the_queue_1(plane, r)
        g = requests.get(u, timeout=30)
        _check_test_sync_delete_controls_work_without_the_queue_2(plane, g)
        if plane == "noq":
            # The read-through really did fill BEFORE the delete (so the
            # control exercised the same tier machinery as the defect-pinned
            # /rt/ cross — and the delete's purge of it is checked below).
            _check_test_sync_delete_controls_work_without_the_queue_3(cache)
        d = requests.delete(u, timeout=30)
        def _assert_test_sync_delete_controls_work_without_the_queue_1():
            assert d.status_code == 204, (plane, d.status_code, d.text)
            assert not (origin / plane / "c.bin").exists(), (
                plane, "origin object survived the sync DELETE")

        _assert_test_sync_delete_controls_work_without_the_queue_1()
    # The sync DELETE also purged the tier copy — the exact durability
    # contract the async drain fails to honour on /rt/.
    _check_test_sync_delete_controls_work_without_the_queue_4(cache)


def test_defect6_cache_cross_async_delete_404s_object_survives(tiers):
    port, origin, cache, _ = tiers
    r = requests.put(_url(port, "/rt/a.bin"), data=PAYLOAD, timeout=30)
    assert r.status_code in (201, 204), (r.status_code, r.text)
    assert (origin / "rt" / "a.bin").read_bytes() == PAYLOAD

    g = requests.get(_url(port, "/rt/a.bin"), timeout=30)
    assert g.status_code == 200 and g.content == PAYLOAD, g.status_code
    assert [p for p in (cache / "rt").rglob("*") if p.is_file()], \
        "read-through returned bytes but nothing landed in the cache"

    # The pinned defect: the drain's posix-confined unlink misses the remote
    # backend, ENOENTs against the logical export tree, and renders 404.
    d = requests.delete(_url(port, "/rt/a.bin"), timeout=30)
    assert d.status_code == 404, (d.status_code, DEFECT6)
    assert (origin / "rt" / "a.bin").read_bytes() == PAYLOAD, DEFECT6
    g2 = requests.get(_url(port, "/rt/a.bin"), timeout=30)
    assert g2.status_code == 200 and g2.content == PAYLOAD, (
        g2.status_code, DEFECT6)


def test_defect6_stage_cross_async_delete_404s_object_survives(tiers):
    port, origin, _, stage = tiers
    r = requests.put(_url(port, "/wt/b.bin"), data=PAYLOAD, timeout=30)
    assert r.status_code in (201, 204), (r.status_code, r.text)
    assert (origin / "wt" / "b.bin").read_bytes() == PAYLOAD
    # sync flush: the spool is already drained when the PUT answers.
    assert not [p for p in (stage / "wt").rglob("*") if p.is_file()]

    d = requests.delete(_url(port, "/wt/b.bin"), timeout=30)
    assert d.status_code == 404, (d.status_code, DEFECT6)
    assert (origin / "wt" / "b.bin").read_bytes() == PAYLOAD, DEFECT6
    g2 = requests.get(_url(port, "/wt/b.bin"), timeout=30)
    assert g2.status_code == 200 and g2.content == PAYLOAD, (
        g2.status_code, DEFECT6)


def test_cache_cross_async_move_renames_through(tiers):
    port, origin, _, _ = tiers
    r = requests.put(_url(port, "/rt/mv-src.bin"), data=PAYLOAD, timeout=30)
    assert r.status_code in (201, 204), (r.status_code, r.text)
    g = requests.get(_url(port, "/rt/mv-src.bin"), timeout=30)
    assert g.status_code == 200, g.status_code

    # The drain's RENAME arm resolves the backend driver
    # (backend_async_queue.c:174) — the one queued op that routes correctly
    # on a remote-backed export.  This working while DELETE 404s is the
    # sharpest statement of defect #6.
    m = requests.request(
        "MOVE", _url(port, "/rt/mv-src.bin"), timeout=30,
        headers={"Destination": _url(port, "/rt/mv-dst.bin")})
    assert m.status_code == 201, (m.status_code, m.text)
    assert not (origin / "rt" / "mv-src.bin").exists()
    assert (origin / "rt" / "mv-dst.bin").read_bytes() == PAYLOAD

    assert requests.get(_url(port, "/rt/mv-src.bin"), timeout=30).status_code \
        == 404, "old name still serves after the drained async MOVE"
    g2 = requests.get(_url(port, "/rt/mv-dst.bin"), timeout=30)
    assert g2.status_code == 200 and g2.content == PAYLOAD, g2.status_code


def test_write_gate_rejects_before_enqueue(tiers):
    port, origin, _, _ = tiers
    # Seed directly on the origin: the read-only front cannot PUT.
    (origin / "ro" / "keep.bin").write_bytes(PAYLOAD)
    g = requests.get(_url(port, "/ro/keep.bin"), timeout=30)
    assert g.status_code == 200 and g.content == PAYLOAD, g.status_code

    d = requests.delete(_url(port, "/ro/keep.bin"), timeout=30)
    assert d.status_code == 403, (d.status_code, d.text)
    # Fail-closed: the gate fired at the access phase, before the enqueue —
    # nothing was journalled, nothing drained, the object survives.
    assert (origin / "ro" / "keep.bin").read_bytes() == PAYLOAD

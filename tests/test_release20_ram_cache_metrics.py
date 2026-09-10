"""2.0 readiness F6 — a ``brix_cache_store ram:`` read cache on a root://
export is observable, truthful, and survives a read.

Three defects hid behind one symptom (no cache rows for the RAM store) and
none of them was the exporter's arithmetic:

1. ``brix_cache_occupancy_ratio``, ``brix_cache_bytes`` and
   ``brix_cache_eviction_threshold_ratio`` are keyed on the metrics slot's
   ``cache_enabled`` flag, which handler.c set only for ``brix_cache on``.  The
   2.0 tier grammar (``brix_cache_store``) never sets that flag, so EVERY
   tier-configured export — posix, s3 or ram — emitted none of the three.  A
   composed tier now counts as a cache.
2. The exporter measured the legacy ``brix_cache_export`` root with statvfs(2)
   first and the store second; cache mode requires that root to exist, so a
   RAM tier under cache mode reported the root's filesystem and the store
   branch was unreachable.  It now asks the store first.
3. A root:// read through the RAM store crashed the worker: sd_ram_open kept
   the handle state inline behind the driver object, and the VFS adopts that
   object BY VALUE and frees the heap shell, so sd_ram_pread ran on freed
   memory ("exited on signal 11" in a respawn loop).  Every phase-115 RAM live
   test was WebDAV; the stream path had only ever been parsed.

Legs: rows appear with the export's first accepted connection and total is the cap
(success); used + available tile the cap and used grows on a fill (boundary);
total is the store's cap, not a filesystem (truth negative); a pgread and a
plain read through the store are byte-exact and the worker survives (the
crash shape); the rows carry only port/auth/state labels (security negative,
INVARIANT 8); and the three source pins so none of it can quietly revert.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from _test_release20_metrics_helpers import scrape, series, value, wait_for, wait_port
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-ram")]

REPO = Path(__file__).resolve().parents[1]
EXPORTER = REPO / "src" / "observability" / "metrics" / "stream_cache.c"
HANDLER = REPO / "src" / "protocols" / "root" / "connection" / "handler.c"
BACKENDS = REPO / "src" / "fs" / "backend"
RAM_CAP = 4 * 1024 * 1024
HOT = 256 * 1024
CACHE_FAMILIES = ("brix_cache_occupancy_ratio", "brix_cache_bytes",
                  "brix_cache_eviction_threshold_ratio")


@pytest.fixture
def origin(lifecycle, tmp_path):
    data = tmp_path / "origin"
    data.mkdir()
    (data / "hot.bin").write_bytes(os.urandom(HOT))
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-r20-ram-origin",
        template="nginx_lc_r20_ram_origin.conf",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST},
        reason="2.0 readiness F6: posix origin behind the RAM-cached export",
    ))
    if not wait_port(ep.port):
        pytest.skip("origin instance did not come up")
    return ep


@pytest.fixture
def ram(lifecycle, tmp_path, origin):
    data = tmp_path / "cache"
    data.mkdir()
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-r20-ram-metrics",
        template="nginx_lc_r20_ram_metrics.conf",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "RAM_SIZE": "4m",
                         "ORIGIN_PORT": str(origin.port)},
        reason="2.0 readiness F6: RAM read cache on a root:// export",
    ))
    if not wait_port(ep.extra_ports["METRICS_PORT"]) or not wait_port(ep.port):
        pytest.skip("RAM-cached instance did not come up")
    return ep


def _mport(ep):
    return ep.extra_ports["METRICS_PORT"]


def _row(body, name, port, **extra):
    return value(body, name, port=str(port), **extra)


def _bytes_rows(body, port):
    return {s: _row(body, "brix_cache_bytes", port, state=s)
            for s in ("total", "used", "available")}


def _stat(ep, path="/hot.bin"):
    """A protocol round trip; the slot itself is published at accept time."""
    r = subprocess.run(["xrdfs", f"{HOST}:{ep.port}", "stat", path],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


def _xrdcp(ep, out):
    r = subprocess.run(["xrdcp", "-f", f"root://{HOST}:{ep.port}//hot.bin", str(out)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return out.read_bytes()


def _plain_read(ep):
    """A kXR_read (not pgread) of the whole object through pyxrootd."""
    from XRootD import client
    from XRootD.client.flags import OpenFlags

    f = client.File()
    st, _ = f.open(f"root://{HOST}:{ep.port}//hot.bin", OpenFlags.READ)
    assert st.ok, st.message
    st, data = f.read(offset=0, size=HOT)
    f.close()
    assert st.ok, st.message
    return data


def _worker_pids(ep):
    master = int(Path(ep.pidfile).read_text().strip())
    r = subprocess.run(["pgrep", "-P", str(master)], capture_output=True, text=True)
    return sorted(int(p) for p in r.stdout.split())


def _error_log(ep):
    return (Path(ep.pidfile).parent / "error.log").read_text(errors="replace")


def _published(ep):
    """Rows for the slot. The metrics slot is published when the export accepts
    its first TCP connection (the connection-init hook, before any handshake),
    so the harness's readiness probe already did it; the stat is belt and braces."""
    _stat(ep)

    def rows():
        body = scrape(_mport(ep))
        return body if _row(body, "brix_cache_bytes", ep.port, state="total") else None

    body = wait_for(rows, timeout=10)
    assert body is not None, "cache rows never appeared after the first connection"
    return body


def test_tier_cache_publishes_rows_after_the_first_accepted_connection(ram):
    """Success: all three families are present once the export has accepted a
    connection (the tier grammar alone, no `brix_cache on`), total exactly the
    cap. Before F6 this export had no cache row at all."""
    body = _published(ram)
    ratio = _row(body, "brix_cache_occupancy_ratio", ram.port)
    assert ratio is not None and 0.0 <= ratio <= 1.0
    threshold = _row(body, "brix_cache_eviction_threshold_ratio", ram.port)
    assert threshold is not None and 0.0 <= threshold <= 1.0
    assert _bytes_rows(body, ram.port)["total"] == float(RAM_CAP)


def test_ram_store_rows_tile_the_cap_and_grow_on_fill(ram, tmp_path):
    """Boundary: used + available == total before and after a read-through
    fill, and the fill shows as used >= the object that was cached."""
    before = _bytes_rows(_published(ram), ram.port)
    assert before["used"] + before["available"] == before["total"] == float(RAM_CAP)
    _xrdcp(ram, tmp_path / "out.bin")

    def filled():
        rows = _bytes_rows(scrape(_mport(ram)), ram.port)
        return rows if rows["used"] >= HOT else None

    after = wait_for(filled, timeout=10)
    assert after is not None, "used bytes never reflected the fill"
    assert after["used"] + after["available"] == after["total"] == float(RAM_CAP)
    assert _row(scrape(_mport(ram)), "brix_cache_occupancy_ratio", ram.port) \
        == pytest.approx(after["used"] / RAM_CAP, abs=1e-6)


def test_ram_store_total_is_the_cap_not_a_filesystem(ram, tmp_path):
    """Truth negative: the store has no filesystem; total must be the
    configured cap and must not equal the size of any filesystem the process
    could have stat'ed instead (the origin's data root, the cache's tmp dir)."""
    rows = _bytes_rows(_published(ram), ram.port)
    for candidate in (tmp_path, Path("/")):
        vfs = os.statvfs(candidate)
        assert rows["total"] != float(vfs.f_blocks * vfs.f_frsize), candidate
    assert rows["total"] == float(RAM_CAP)
    assert 0 <= rows["available"] <= rows["total"]


def test_root_pgread_through_a_ram_store_keeps_the_worker(ram, origin, tmp_path):
    """The crash shape: a miss (fill), a hit (served from the store) and a
    plain kXR_read all return the origin's bytes, the worker pid set is the
    same afterwards and error.log records no worker death."""
    expected = (Path(origin.data_root) / "hot.bin").read_bytes()
    _stat(ram)
    workers = _worker_pids(ram)
    assert workers, "no worker under the RAM-cached master"
    assert _xrdcp(ram, tmp_path / "miss.bin") == expected
    assert _xrdcp(ram, tmp_path / "hit.bin") == expected
    assert _plain_read(ram) == expected
    assert _worker_pids(ram) == workers, "the worker was respawned mid-read"
    log = _error_log(ram)
    assert "exited on signal" not in log and "worker process" not in log.replace(
        "start worker process", ""), log[-2000:]


def test_cache_rows_carry_only_port_auth_state_labels(ram):
    """Security negative (INVARIANT 8): no store URL, cache root or path ever
    becomes a label on the cache families."""
    body = _published(ram)
    for family in CACHE_FAMILIES:
        for labels, _ in series(body, family, port=str(ram.port)):
            assert set(labels) <= {"port", "auth", "state"}, (family, labels)
            assert not any("/" in v or ":" in v for v in labels.values()), labels


def test_exporter_asks_the_store_before_the_legacy_root():
    """Source pin: stream_cache_usage consults the store's capacity first and
    the statvfs of the legacy root only as the fallback."""
    src = EXPORTER.read_text()
    body = src[src.index("stream_cache_usage(ngx_uint_t slot"):]
    body = body[:body.index("\n}\n")]
    assert body.index("stream_cache_store_space(slot") < body.index("brix_cache_statvfs(srv->cache_root")
    assert "brix_cstore_freespace(cs, &cap, &avail)" in src
    assert "xcf->metrics_slot == (ngx_int_t) slot" in src


def test_metrics_slot_counts_a_composed_tier_as_a_cache():
    """Source pin: handler.c sets cache_enabled for `brix_cache on` OR a wired
    cache tier, never for the flag alone."""
    src = HANDLER.read_text()
    stmt = re.search(r"srv->cache_enabled = \(mconf->cache\s*\|\|\s*"
                     r"brix_cache_storage_cstore\(mconf\) != NULL\) \? 1 : 0;", src)
    assert stmt, "cache_enabled no longer covers the tier grammar"
    assert '#include "fs/cache/cache_storage.h"' in src


def test_no_heap_shell_driver_keeps_handle_state_inline_behind_the_shell():
    """Source-shape guard for defect 3: a driver whose open hands out a
    heap_shell object must allocate its handle state separately — the adopter
    frees the shell after copying it, so anything behind the shell dies."""
    inline = re.compile(r"\(obj \+ 1\)|\bobj \+ 1\b|\(o \+ 1\)|&obj\[1\]|"
                        r"\(char \*\)\s*obj \+|\(u_char \*\)\s*obj \+")
    offenders = sorted(str(p.relative_to(REPO)) for p in BACKENDS.rglob("*.c")
                       if "heap_shell = 1" in p.read_text()
                       and inline.search(p.read_text()))
    assert offenders == [], offenders

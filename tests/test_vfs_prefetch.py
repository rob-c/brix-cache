"""
Background block prefetch as a generic VFS feature (parity audit §4.1).

A WILLNEED hint through the storage-driver ``read_advise`` slot on a slice
partial-cache object posts a detached thread-pool job that fills the hinted
range's ABSENT blocks from the origin (src/fs/backend/cache/sd_cache_prefetch.c).
Two engines issue the hints: the root:// sequential-read window
(src/protocols/root/read/prefetch.c, now dispatching driver-backed handles)
and the HTTP memory-backed serve loop (src/protocols/shared/file_serve.c).

Layers:
  * TestPrefetchConfig    — brix_cache_prefetch(_window) parse accept/reject.
  * TestRootPlane         — root:// kXR_read engine: window fill beyond the
                            read, window cap, disable-on-random, default-off
                            security negative, background-failure resilience.
  * TestWebdavPlane       — HTTP memory-backed serve loop: successor blocks
                            warmed beyond a range GET + /metrics counters,
                            default-off negative.
"""
import os
import struct
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from _cache_partial_helpers import (
    make_cache_node, read_range, residency, seed_origin, kill_origin,
    _session, _read_frame,
)
from _test_a_robustness_helpers import (
    make_open_req, make_read_req, make_close_req,
)
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN

# Same doctrine as test_cache_partial_fill.py: every test stands up dedicated
# throwaway instances, and the slice-cache origin read path is serial-only.
def _phase_test_webdav_range_get_warms_successor_blocks_1(front):
    with pytest.raises(urllib.error.HTTPError) as ei:
        _get_range(front, "/f.bin", 7 * BLK, 8 * BLK - 1)


def _check_test_webdav_range_get_warms_successor_blocks_1(metrics):
    assert _metric(metrics, "brix_cache_prefetch_blocks_total") > 0


pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness]

BLK = 1024 * 1024               # 1 MiB slice granule (multiple-of-1m rule)
WINDOW = 4 * BLK                # brix_cache_prefetch_window under test


def _poll(predicate, timeout=10.0, interval=0.2):
    """Poll until predicate() is truthy; return its last value (falsy on
    timeout) so callers can assert with full context."""
    deadline = time.monotonic() + timeout
    value = predicate()
    while not value and time.monotonic() < deadline:
        time.sleep(interval)
        value = predicate()
    return value


def _present(store_dir, key):
    """The present-block list for a cached object, [] when absent."""
    r = residency(store_dir, key)
    return [] if r.get("absent") else r.get("present_blocks", [])


# ===========================================================================
# Config parse / validation
# ===========================================================================

class TestPrefetchConfig:
    def _nginx_t(self, lifecycle, tmp_path, prefetch_lines):
        cache = tmp_path / "cache"
        cache.mkdir(exist_ok=True)
        reg = lifecycle.register(NginxInstanceSpec(
            name="lc-vfs-prefetch-validate",
            template="nginx_vfs_prefetch_validate.conf",
            protocol="none",
            readiness="none",
            port=SHARED_PARSE_PLACEHOLDER_PORT,   # nginx -t only, never bound
            template_values={"HOST": HOST, "CACHE_DIR": str(cache),
                             "PREFETCH_LINES": prefetch_lines},
            reason="brix_cache_prefetch directive parse/validate (nginx -t).",
        ))
        endpoint = lifecycle.launcher.render_nginx(reg)
        return subprocess.run(
            [NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
            capture_output=True, text=True, timeout=30)

    def test_valid_directives_accepted(self, lifecycle, tmp_path):
        proc = self._nginx_t(lifecycle, tmp_path,
                             "        brix_cache_prefetch 4;\n"
                             "        brix_cache_prefetch_window 4m;\n")
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, f"valid prefetch config rejected:\n{out}"

    def test_jobs_above_cap_rejected(self, lifecycle, tmp_path):
        proc = self._nginx_t(lifecycle, tmp_path,
                             "        brix_cache_prefetch 65;\n")
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, "brix_cache_prefetch 65 must be rejected"
        assert "between 0 and 64" in out

    def test_window_below_floor_rejected(self, lifecycle, tmp_path):
        proc = self._nginx_t(lifecycle, tmp_path,
                             "        brix_cache_prefetch_window 4k;\n")
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, "4k prefetch window must be rejected"
        assert "at least 64k" in out


# ===========================================================================
# root:// plane — the kXR_read sequential-window engine
# ===========================================================================

def _prefetch_node(tmp_path, lifecycle, **kw):
    kw.setdefault("slice_size", BLK)
    kw.setdefault("prefetch", 4)
    kw.setdefault("prefetch_window", WINDOW)
    return make_cache_node("xroot", tmp=tmp_path, lifecycle=lifecycle, **kw)


def test_prefetch_completes_file_serves_offline(lifecycle, tmp_path):
    """SUCCESS: one 1-block read of a 4-block file backgrounds-fills the other
    three (window covers the file), flipping it COMPLETE — which then serves
    with the origin GONE, the durability a foreground-only fill cannot give."""
    with _prefetch_node(tmp_path, lifecycle) as node:
        data = seed_origin(node, "/f.bin", 4 * BLK)
        got = read_range(node.cache_port, "/f.bin", 0, BLK)     # block 0 only
        assert got == data[:BLK]
        r = _poll(lambda: residency(node.store_dir, "f.bin").get("complete"))
        assert r, ("background prefetch did not complete the file: "
                   f"{residency(node.store_dir, 'f.bin')}")
        kill_origin(node)
        assert read_range(node.cache_port, "/f.bin", 2 * BLK, BLK) \
            == data[2 * BLK:3 * BLK]


def test_prefetch_window_caps_speculation(lifecycle, tmp_path):
    """The window bounds the speculation runway: a 1-block read of an 8-block
    file hints from the read cursor (1m), so a 4m window fills blocks 1..4 in
    the background and MUST leave 5..7 absent."""
    with _prefetch_node(tmp_path, lifecycle) as node:
        seed_origin(node, "/f.bin", 8 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        assert _poll(lambda: set(_present(node.store_dir, "f.bin"))
                     >= {0, 1, 2, 3, 4}), \
            f"window fill missing: {_present(node.store_dir, 'f.bin')}"
        time.sleep(1.0)                       # grace: nothing beyond the window
        assert _present(node.store_dir, "f.bin") == [0, 1, 2, 3, 4]
        assert residency(node.store_dir, "f.bin")["complete"] is False


def test_random_access_disables_prefetch(lifecycle, tmp_path):
    """XrdPfc disable-on-random parity: on ONE handle, a sequential first read
    hints its window, but a following random jump must hint NOTHING — only the
    foreground-read block appears."""
    with _prefetch_node(tmp_path, lifecycle) as node:
        seed_origin(node, "/f.bin", 12 * BLK)
        s = _session(node.cache_port)
        try:
            s.sendall(make_open_req(b"/f.bin"))
            status, body = _read_frame(s)
            assert status == 0, f"open failed status={status}"
            fh = body[:4]
            for off in (0, 8 * BLK):          # sequential first, then random
                s.sendall(make_read_req(fh, off, BLK))
                while True:
                    status, _ = _read_frame(s)
                    if status != 4000:
                        break
                assert status == 0, f"read@{off} failed status={status}"
            s.sendall(make_close_req(fh))
            _read_frame(s)
        finally:
            s.close()
        assert _poll(lambda: set(_present(node.store_dir, "f.bin"))
                     >= {0, 1, 2, 3, 4}), \
            f"sequential window missing: {_present(node.store_dir, 'f.bin')}"
        time.sleep(1.0)                       # grace: random jump stays bare
        present = set(_present(node.store_dir, "f.bin"))
        def _assert_test_random_access_disables_prefetch_1():
            assert present & {9, 10, 11} == set(), \
                f"random access must not speculate: {sorted(present)}"
            assert 8 in present                   # the foreground-read block itself

        _assert_test_random_access_disables_prefetch_1()


def test_default_off_no_speculative_origin_reads(lifecycle, tmp_path):
    """SECURITY NEGATIVE: with the directives absent (default), a read fills
    exactly its own block — no background origin traffic, no extra residency."""
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path,
                         lifecycle=lifecycle) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        time.sleep(1.5)                       # grace: nothing may appear
        assert _present(node.store_dir, "f.bin") == [0]
        assert residency(node.store_dir, "f.bin")["complete"] is False


def _read_all(s, fh, off, length):
    """kXR_read over an open session, draining oksofar frames; returns
    (final_status, concatenated payload)."""
    s.sendall(make_read_req(fh, off, length))
    payload = b""
    while True:
        status, body = _read_frame(s)
        payload += body
        if status != 4000:
            return status, payload


def test_background_failure_leaves_server_healthy(lifecycle, tmp_path):
    """ERROR: a background job whose cache object was made unwritable fails in
    the executor (its own O_RDWR open), while the event loop keeps serving —
    the foreground handle (opened before the chmod) and reads of cached blocks
    are unaffected. One session throughout: a FRESH open would itself hit the
    read-only object, which is not the failure mode under test."""
    with _prefetch_node(tmp_path, lifecycle, prefetch_window=2 * BLK) as node:
        data = seed_origin(node, "/f.bin", 8 * BLK)
        obj_path = os.path.join(node.store_dir, "f.bin")
        s = _session(node.cache_port)
        try:
            s.sendall(make_open_req(b"/f.bin"))
            status, body = _read_frame(s)
            assert status == 0, f"open failed status={status}"
            fh = body[:4]
            # Read block 0: the 2m window off the 1m cursor queues blocks 1..2.
            status, got = _read_all(s, fh, 0, BLK)
            assert status == 0 and got == data[:BLK]
            assert _poll(lambda: set(_present(node.store_dir, "f.bin"))
                         >= {0, 1, 2})
            os.chmod(obj_path, 0o444)
            # Sequential read of block 1 hints block 3: the job posts — and
            # dies in its OWN partial open (O_RDWR on the read-only object).
            # The foreground serves block 1 from the fd it opened pre-chmod.
            status, got = _read_all(s, fh, BLK, BLK)
            assert status == 0 and got == data[BLK:2 * BLK]
            time.sleep(1.0)                               # let the job fail
            assert set(_present(node.store_dir, "f.bin")) == {0, 1, 2}
            # The server survived: the same handle still serves cached bytes.
            status, got = _read_all(s, fh, 2 * BLK, BLK)
            assert status == 0 and got == data[2 * BLK:3 * BLK]
            s.sendall(make_close_req(fh))
            _read_frame(s)
        finally:
            os.chmod(obj_path, 0o644)
            s.close()


# ===========================================================================
# WebDAV plane — the HTTP memory-backed serve loop engine
# ===========================================================================

FRONT_NAME = "lc-vfs-prefetch-webdav"
HTTP_ORIGIN_NAME = "lc-cache-partial-origin"     # reuse the static-origin spec

PREFETCH_ON = ("            brix_cache_prefetch 4;\n"
               "            brix_cache_prefetch_window 4m;\n")


def _webdav_front(tmp_path, lifecycle, prefetch_lines):
    """A WebDAV slice-cache front (fixed ledger ports) over a throwaway http
    static origin; returns (front_port, metrics_port, cache_dir, doc_root)."""
    doc_root = os.path.join(str(tmp_path), "http-origin")
    cache_dir = os.path.join(str(tmp_path), "cache")
    export = os.path.join(str(tmp_path), "export")
    for d in (doc_root, cache_dir, export):
        os.makedirs(d, exist_ok=True)
    origin_ep = lifecycle.start(NginxInstanceSpec(
        name=HTTP_ORIGIN_NAME,
        template="nginx_lc_cache_partial_http_origin.conf",
        protocol="http",
        data_root=doc_root,
        template_values={"BIND_HOST": BIND_HOST},
        reason="vfs-prefetch http static origin"))
    front_ep = lifecycle.start(NginxInstanceSpec(
        name=FRONT_NAME,
        template="nginx_lc_vfs_prefetch_webdav.conf",
        protocol="http",
        data_root=cache_dir,
        template_values={
            "BIND_HOST": BIND_HOST,
            "ORIGIN_URL": f"http://{HOST}:{origin_ep.port}",
            "EXPORT_ROOT": export,
            "CACHE_STORE": cache_dir,
            "SLICE_SIZE": BLK,
            "PREFETCH_LINES": prefetch_lines,
        },
        reason="vfs-prefetch WebDAV slice-cache front"))
    return front_ep.port, front_ep.extra_ports["METRICS_PORT"], \
        cache_dir, doc_root


def _seed_http(doc_root, name, size):
    data = bytes((i * 131 + 7) & 0xFF for i in range(size))
    with open(os.path.join(doc_root, name), "wb") as f:
        f.write(data)
    return data


def _get_range(port, path, start, end_incl):
    req = urllib.request.Request(
        f"http://{HOST}:{port}{path}",
        headers={"Range": f"bytes={start}-{end_incl}"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, resp.read()


def _metric(port, name):
    with urllib.request.urlopen(f"http://{HOST}:{port}/metrics",
                                timeout=10) as resp:
        for line in resp.read().decode().splitlines():
            if line.startswith(name + " "):
                return float(line.split()[-1])
    return None


def test_webdav_range_get_warms_successor_blocks(lifecycle, tmp_path):
    """SUCCESS: a 2 MiB range GET through the memory-backed serve loop hints
    BEYOND the request — the rolling 4m window off the per-chunk read cursor
    background-fills successor blocks through 5 (cursor tops out at 2m), MUST
    leave 6..7 absent, and the prefetch counters move on /metrics."""
    front, metrics, cache_dir, doc_root = _webdav_front(
        tmp_path, lifecycle, PREFETCH_ON)
    data = _seed_http(doc_root, "f.bin", 8 * BLK)
    jobs0 = _metric(metrics, "brix_cache_prefetch_jobs_total") or 0
    status, body = _get_range(front, "/f.bin", 0, 2 * BLK - 1)
    def _assert_test_webdav_range_get_warms_successor_blocks_2():
        assert status == 206 and body == data[:2 * BLK]
        assert _poll(lambda: set(_present(cache_dir, "f.bin"))
                     >= {0, 1, 2, 3, 4, 5}), \
            f"successor blocks not warmed: {_present(cache_dir, 'f.bin')}"

    _assert_test_webdav_range_get_warms_successor_blocks_2()
    time.sleep(1.0)                           # grace: window bound holds
    def _assert_test_webdav_range_get_warms_successor_blocks_3():
        assert set(_present(cache_dir, "f.bin")) & {6, 7} == set()
        assert _metric(metrics, "brix_cache_prefetch_jobs_total") > jobs0

    _assert_test_webdav_range_get_warms_successor_blocks_3()
    _check_test_webdav_range_get_warms_successor_blocks_1(metrics)
    # ERROR leg: an absent block with the origin gone fails cleanly (5xx, not
    # a hang or crash) and the front keeps answering /metrics.
    lifecycle.stop(HTTP_ORIGIN_NAME)
    _phase_test_webdav_range_get_warms_successor_blocks_1(front)
    def _assert_test_webdav_range_get_warms_successor_blocks_4():
        assert ei.value.code >= 500
        assert _metric(metrics, "brix_cache_prefetch_jobs_total") is not None

    _assert_test_webdav_range_get_warms_successor_blocks_4()


def test_webdav_default_off_no_speculation(lifecycle, tmp_path):
    """SECURITY NEGATIVE: without the directives, the same range GET fills
    exactly the requested blocks — the serve-loop hint is discarded by the
    driver, and the counters stay 0."""
    front, metrics, cache_dir, doc_root = _webdav_front(tmp_path, lifecycle, "")
    data = _seed_http(doc_root, "f.bin", 8 * BLK)
    status, body = _get_range(front, "/f.bin", 0, 2 * BLK - 1)
    assert status == 206 and body == data[:2 * BLK]
    time.sleep(1.5)                           # grace: nothing may appear
    assert set(_present(cache_dir, "f.bin")) <= {0, 1}
    assert _metric(metrics, "brix_cache_prefetch_jobs_total") == 0

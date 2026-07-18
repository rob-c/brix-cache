# tests/test_cvmfs_cold_tier.py — Phase-85 F7: VFS-backed hot/cold tiered cache.
#
# brix_cache_cold_store adds an optional cold store tier under the hot cache:
# a miss first attempts a verified PROMOTE from the cold copy (zero origin data
# traffic, cold copy consumed — move semantics), any cold failure silently
# falls back to the origin fill, and the eviction engine DEMOTES space-pressure
# victims into the cold store before removing the hot copy. A corrupt cold
# copy must never publish (the promote runs the same cvmfs-cas verify gate as
# an origin fill) and must never raise signal=cvmfs_tamper — the actor is
# local disk, not the origin, and a false signal would feed the maxretry=1
# fail2ban tamper jail.
#
# Port block: srv_verify (shared sequentially — module fixtures close before
# the other file's run in a sweep; suites never run concurrently in-session).
import hashlib
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from server_registry import NginxInstanceSpec

REPO = "test.cern.ch"

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

BLOCK = PortBlock("srv_verify")


# ---- fixtures --------------------------------------------------------------

@pytest.fixture(scope="module")
def tier():
    """Webroot origin + hot posix cache + cold posix store, with the hot-cache
    key layout learned from a probe fill (so cold planting matches whatever
    relative layout the cache store uses)."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_cold_webroot."))
    (root / "cvmfs" / REPO / "data").mkdir(parents=True)
    cold = Path(tempfile.mkdtemp(prefix="cvmfs_cold_store."))
    with srv_instance(BLOCK, webroot=root,
                      extra_directives=f"brix_cache_cold_store posix:{cold};") as s:
        s.webroot = root
        s.cold = cold
        # Layout probe: fill one object through the origin, find where the hot
        # cache stored it, and keep the (hash, relpath) pair as a template.
        probe = b"cold-tier layout probe\n" * 64
        hx = hashlib.sha1(probe).hexdigest()
        path = put_obj(s, probe)
        status, _, got = GET(s, path)
        assert status == 200 and got == probe, "layout probe fill failed"
        found = [p for p in s.cache.rglob("*")
                 if p.is_file() and hx[2:] in p.name]
        assert len(found) == 1, f"probe object not found uniquely in hot cache: {found}"
        s.probe_hex = hx
        s.rel_template = str(found[0].relative_to(s.cache))
        yield s
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(cold, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path, method="GET"):
    return request("127.0.0.1", s.nginx_port, method, path)


def body_for(tag, n=6000):
    seed = hashlib.sha256(f"cold_tier:{tag}".encode()).digest()
    return (seed * (n // len(seed) + 1))[:n]


def put_obj(w, body, hexname=None):
    """Drop a CAS object into the origin webroot; returns its URL path."""
    hx = hexname or hashlib.sha1(body).hexdigest()
    d = w.webroot / "cvmfs" / REPO / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / hx[2:]).write_bytes(body)
    return f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"


def cold_path_for(s, hx):
    """Map a CAS hash to its cold-store file path via the learned layout."""
    rel = s.rel_template.replace(
        f"{s.probe_hex[:2]}/{s.probe_hex[2:]}", f"{hx[:2]}/{hx[2:]}")
    assert rel != s.rel_template, "hash substitution failed on the layout template"
    return s.cold / rel


def plant_cold(s, hx, body):
    """Plant `body` in the cold store under the CAS name `hx`."""
    p = cold_path_for(s, hx)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)
    return p


def hot_path_for(s, hx):
    rel = s.rel_template.replace(
        f"{s.probe_hex[:2]}/{s.probe_hex[2:]}", f"{hx[:2]}/{hx[2:]}")
    return s.cache / rel


# ============================================================================
# 1. promote: a cold copy serves byte-identical with zero origin data traffic
# ============================================================================

def test_promote_from_cold_zero_origin_data(tier):
    body = body_for("promote")
    hx = hashlib.sha1(body).hexdigest()
    path = put_obj(tier, body)              # origin has it too (probe safety)
    cold_file = plant_cold(tier, hx, body)
    tier.reset_log()

    status, _, got = GET(tier, path)
    assert status == 200 and got == body
    assert tier.count_log(path) == 0, "promote still pulled origin data"
    # move semantics: the promoted object left the cold tier and landed hot
    assert not cold_file.exists(), "cold copy survived a successful promote"
    assert hot_path_for(tier, hx).exists(), "promoted object not in the hot cache"
    # and it is a normal cache hit afterwards
    assert GET(tier, path)[2] == body
    assert tier.count_log(path) == 0


# ============================================================================
# 2. cold outage/miss: silent fallback to the origin fill — never a 5xx
# ============================================================================

def test_cold_miss_falls_back_to_origin(tier):
    body = body_for("fallback")
    path = put_obj(tier, body)              # cold tier does NOT have it
    tier.reset_log()

    status, _, got = GET(tier, path)
    assert status == 200 and got == body, "empty cold tier broke the origin fill"
    assert tier.count_log(path) == 1
    # subsequent GET is a plain hot hit
    assert GET(tier, path)[2] == body
    assert tier.count_log(path) == 1


# ============================================================================
# 3. security-neg: a tampered cold copy is never served, never a tamper signal
# ============================================================================

def test_tampered_cold_copy_never_served_no_tamper_signal(tier):
    body = body_for("tamper")
    hx = hashlib.sha1(body).hexdigest()
    path = put_obj(tier, body)              # origin holds the GOOD bytes
    evil = b"EVIL" + body[4:]               # same length, wrong hash
    cold_file = plant_cold(tier, hx, evil)
    tier.reset_log()

    status, _, got = GET(tier, path)
    assert status == 200 and got == body, "tampered cold bytes leaked to the client"
    assert tier.count_log(path) == 1, "expected exactly one origin refill"
    assert not cold_file.exists(), "corrupt cold copy was not removed"

    log = tier.error_log.read_text(encoding="utf-8", errors="replace")
    assert "signal=cvmfs_tamper" not in log, \
        "local cold corruption raised the ORIGIN tamper signal (fail2ban poison)"
    assert "cold-tier object failed verification" in log


# ============================================================================
# 4. config gate: cold store without the hot tier is refused at nginx -t
# ============================================================================

def test_cold_store_without_hot_store_refused(lifecycle, tmp_path):
    # Registry-driven negative gate: the config lives in
    # tests/configs/nginx_cvmfs_cold_no_hot.conf and nginx -t is run through the
    # lifecycle harness.  expect_config_failure renders non-strict and supplies
    # only these template_values, so the test provides every placeholder.
    r = lifecycle.expect_config_failure(NginxInstanceSpec(
        name="lc-cvmfs-cold-no-hot",
        template="nginx_cvmfs_cold_no_hot.conf",
        template_values={
            "LOG_DIR": str(tmp_path),
            "PORT": 1,
            "BIND_HOST": "127.0.0.1",
            "COLD_DIR": str(tmp_path / "cold"),
        },
        reason="CVMFS F7 cold-store-without-hot config gate",
    ))
    assert r.returncode != 0, "cold store without hot cache_store passed nginx -t"
    assert "requires brix_cache_store" in (r.stderr + r.stdout)


# ============================================================================
# 5. demote-on-evict: watermark victims land byte-identical in the cold store
# ============================================================================

def _fs_usage_percent(path: Path) -> int:
    u = shutil.disk_usage(path)
    return int((u.used * 100) / u.total)


def test_demote_on_evict_stream(lifecycle, tmp_path):
    used = _fs_usage_percent(tmp_path)
    if used < 10 or used > 96:
        pytest.skip(f"filesystem usage {used}% outside testable 10-96% band")

    cache = tmp_path / "cache"
    cold = tmp_path / "cold"
    for d in (cache, cold):
        d.mkdir()

    planted = {}
    for idx in range(1, 5):
        name = f"plain_{idx}.bin"
        body = bytes((idx * 11 + i) % 251 for i in range(65_536))
        (cache / name).write_bytes(body)
        stamp = time.time() - (10 - idx) * 3600     # backdated: LRU victims
        os.utime(cache / name, (stamp, stamp))
        planted[name] = body

    # Launch through the registry lifecycle harness: the config lives in
    # tests/configs/nginx_cvmfs_cold_demote.conf and the cache/cold dirs live in
    # this test's tmp_path (it plants LRU victims and asserts on the cold store),
    # so they are passed as template values rather than the auto-injected export.
    lifecycle.start(NginxInstanceSpec(
        name="lc-cvmfs-cold-demote",
        template="nginx_cvmfs_cold_demote.conf",
        template_values={
            "BIND_HOST": "127.0.0.1",
            "CACHE_DIR": str(cache),
            "COLD_DIR": str(cold),
            "HIGH_WM": used - 2,
            "LOW_WM": max(1, used - 5),
        },
        reason="CVMFS F7 demote-on-evict",
    ))

    deadline = time.time() + 25
    while time.time() < deadline and list(cache.glob("plain_*.bin")):
        time.sleep(1)

    assert not list(cache.glob("plain_*.bin")), \
        "watermark reaper did not purge the planted files"
    for name, body in planted.items():
        demoted = cold / name
        assert demoted.exists(), f"evicted {name} was not demoted to cold"
        assert demoted.read_bytes() == body, f"demoted {name} bytes differ"

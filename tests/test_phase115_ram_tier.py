"""Phase-115 W4.2 — the RAM cache store (``brix_cache_store ram:<size>``).

The store is a per-worker heap object table reached through the ``ram`` storage
driver (``src/fs/backend/ram/``).  Two halves are pinned here:

  * config-parse (``nginx -t``): the size grammar, and the DURABILITY refusals
    that keep a memory store out of every role but the hot cache;
  * live HTTP against the dedicated ``ram-cache`` instance (port 18459): fill,
    hit, LRU eviction under the cap, and the degrade-instead-of-fail path when
    an object cannot fit at all.

Observing a RAM hit needs a trick, because there is no file to look at: fill the
entry, then rewrite the ORIGIN bytes in place preserving both size and mtime,
and read again.  Stale bytes mean the read was served from the store; fresh
bytes mean it went to the source.  Every live assertion below is built on that.

Three-per-change (success + error + security-negative) is satisfied per
behaviour, not per test function; the mapping is in the phase doc's W4.2 box.
"""

import os
import subprocess
import uuid

import pytest
import requests

from cmdscripts.live_common import inject_nginx_load_modules
from settings import (
    BIND_HOST,
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    NGINX_BIN,
    NGINX_RAM_CACHE_PORT,
    SERVER_HOST,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The live half shares ONE instance whose whole cache is 1 MiB, and the eviction
# case deliberately overruns it.  Two of these running concurrently would evict
# each other's entries and read as a cache that never held anything, so the
# module takes a group of its own; the parse cases are cheap enough to ride
# along rather than split the file.
pytestmark = pytest.mark.xdist_group("ram-cache")

# The dedicated instance's origin, from _ded("ram-cache", ...): $TEST_ROOT/
# data-ram-cache/origin, pre-created by the launcher.  The cache has no path.
RAM_CACHE_DATA = os.path.join(os.path.dirname(DATA_ROOT), "data-ram-cache")
RAM_CACHE_ORIGIN = os.path.join(RAM_CACHE_DATA, "origin")

# nginx_ram_cache.conf: brix_cache_store ram:1m.
RAM_CACHE_CAP = 1024 * 1024


# --------------------------------------------------------------------------
# config parse
# --------------------------------------------------------------------------

REMOTE = f"brix_storage_backend root://{HOST}:{NGINX_ANON_PORT};"


def _nginx_t(root, body):
    """`nginx -t` a one-server stream config whose body the caller owns."""
    for d in ("logs", "cache"):
        (root / d).mkdir(exist_ok=True)
    conf = root / "ram.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13298;
    brix_root on;
    brix_auth none;
    {body}
}} }}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


@pytest.mark.parametrize("size", ["64m", "1g", "512k", "1048576"])
def test_ram_cache_store_size_accepted(tmp_path, size):
    """The success case: a bare byte cap is the whole location."""
    rc, out = _nginx_t(tmp_path, f"{REMOTE}\n    brix_cache_store ram:{size};")
    assert rc == 0, f"expected ram:{size} accepted:\n{out}"


RAM_SIZE_REJECT = [
    ("ram:0", 'ram store size "0" is not a valid size'),
    ("ram:banana", 'ram store size "banana" is not a valid size'),
    ("ram:", 'ram store size "" is not a valid size'),
    ("ram:-1", 'ram store size "-1" is not a valid size'),
]


@pytest.mark.parametrize("store,needle", RAM_SIZE_REJECT)
def test_ram_cache_store_bad_size_rejected(tmp_path, store, needle):
    """An unbounded or unparseable RAM store is an OOM, not a configuration.

    Zero is rejected with the rest: a store that can hold nothing would accept
    every fill's reservation and refuse it at the bytes, so the operator would
    read "cache configured" and get no cache at all.
    """
    rc, out = _nginx_t(tmp_path, f"{REMOTE}\n    brix_cache_store {store};")
    assert rc != 0, f"expected {store!r} rejected"
    assert needle in out, f"expected {needle!r}, got:\n{out}"


def test_bare_ram_without_size_rejected(tmp_path):
    """`ram` with no colon is not a store URL at all — the generic diagnostic."""
    rc, out = _nginx_t(tmp_path, f"{REMOTE}\n    brix_cache_store ram;")
    assert rc != 0
    assert 'store url "ram" has no scheme' in out, out


# --- the durability refusals (security negatives) --------------------------

def test_ram_stage_store_refused(tmp_path):
    """SECURITY/DURABILITY: a RAM write stage would ACK a PUT into memory.

    The client gets a success status on the wire for bytes that no worker
    restart survives — silent data loss the writer can never detect.
    """
    rc, out = _nginx_t(
        tmp_path,
        f"{REMOTE}\n    brix_stage on;\n    brix_stage_store ram:64m;")
    assert rc != 0
    assert "only valid as the cache store" in out, out
    assert "brix_stage_store" in out, out


def test_ram_storage_backend_refused(tmp_path):
    """SECURITY/DURABILITY: as the backend it would be the only copy.

    The backend parser owns its own scheme table (vfs_backend_config.c), so the
    refusal comes from there with its own wording — which is exactly the point:
    `ram` is never registered as an authoritative source anywhere.
    """
    rc, out = _nginx_t(tmp_path, "brix_storage_backend ram:64m;")
    assert rc != 0
    assert "unrecognized backend scheme" in out, out


def test_ram_cold_store_refused(tmp_path):
    """The cold tier is the DEMOTION target — it cannot be the volatile one.

    Both cache stores parse as BRIX_TIER_CACHE, so the tier parse lets this
    through; the refusal lives in runtime_server_backend_cache.c, the only
    layer that knows hot from cold.  Without it, `nginx -t` accepted a cold
    tier costlier and more volatile than the disk tier demoting into it.
    """
    rc, out = _nginx_t(
        tmp_path,
        f"{REMOTE}\n    brix_cache_store posix:{tmp_path}/cache;"
        f"\n    brix_cache_cold_store ram:64m;")
    assert rc != 0
    assert "brix_cache_cold_store" in out, out
    assert "only valid as the hot cache store" in out, out


# --------------------------------------------------------------------------
# the phase-31 transfer budget must not see the store
# --------------------------------------------------------------------------

def test_ram_store_is_outside_the_transfer_budget():
    """A DESIGN CHOICE that has to stay a design choice.

    `xfer_heap_in_use` (phase-31, src/protocols/root/connection/budget.h) bounds
    TRANSFER scratch: brix_budget_admit defers a read with kXR_wait once the sum
    crosses the cap.  Folding cache-resident bytes into it would make a FULL
    CACHE defer reads — the server would wedge itself precisely when the cache
    was doing its job best.  The RAM store therefore carries its own hard cap
    and reports through the `space` slot instead.

    This is a source assertion because the failure mode is a wedge under load,
    which no functional test reproduces cheaply; the invariant is that the
    driver never reaches for the budget at all.
    """
    ram_dir = os.path.join(REPO, "src", "fs", "backend", "ram")
    offenders = []
    for name in sorted(os.listdir(ram_dir)):
        if not name.endswith((".c", ".h")):
            continue
        text = open(os.path.join(ram_dir, name), encoding="utf-8").read()
        for needle in ("xfer_heap_in_use", "brix_budget_"):
            if needle in text:
                offenders.append(f"{name}: {needle}")
    assert not offenders, (
        "the ram store must not participate in the phase-31 transfer budget: "
        + ", ".join(offenders))


# --------------------------------------------------------------------------
# live: the dedicated ram-cache instance
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def base_url():
    return f"http://{SERVER_HOST}:{NGINX_RAM_CACHE_PORT}"


@pytest.fixture
def ram_cache_origin():
    os.makedirs(RAM_CACHE_ORIGIN, exist_ok=True)
    return RAM_CACHE_ORIGIN


def _seed(name, payload):
    """Write an origin object and return (path, mtime) for later restoration."""
    path = os.path.join(RAM_CACHE_ORIGIN, name)
    with open(path, "wb") as fh:
        fh.write(payload)
    st = os.stat(path)
    return path, (st.st_atime, st.st_mtime)


def _rewrite_in_place(path, times, payload):
    """Swap the bytes under a cached entry, leaving size and mtime untouched.

    This is the whole observation trick: a subsequent read that returns the OLD
    bytes was served from the store, and one that returns the new bytes went to
    the source.  Size and mtime are restored so no revalidation heuristic can
    tell the object changed.
    """
    with open(path, "r+b") as fh:
        fh.write(payload)
    os.utime(path, times)


@pytest.mark.registry_server("ram-cache")
def test_fill_then_hit_serves_from_ram(base_url, ram_cache_origin):
    """Success: a second read of a filled object comes out of memory."""
    name = f"hit-{uuid.uuid4().hex}.bin"
    old = b"A" * 4096
    path, times = _seed(name, old)
    try:
        first = requests.get(f"{base_url}/{name}", timeout=15)
        assert first.status_code == 200, first.text[:400]
        assert first.content == old

        _rewrite_in_place(path, times, b"B" * 4096)
        second = requests.get(f"{base_url}/{name}", timeout=15)
        assert second.status_code == 200, second.text[:400]
        assert second.content == old, "second read did not come from the store"
    finally:
        os.unlink(path)


@pytest.mark.registry_server("ram-cache")
def test_object_larger_than_the_cap_degrades_to_the_source(base_url,
                                                           ram_cache_origin):
    """Error path: a fill that cannot fit must not fail the READ.

    brix_sd_ram_make_room refuses immediately when the want exceeds the whole
    capacity, staged_open returns ENOSPC, and the cache decorator degrades to a
    plain source read (sd_cache.c cache_open_miss_serve, §16: a sick cache never
    fails a read).  The object must be served correctly and must NOT be cached.
    """
    name = f"huge-{uuid.uuid4().hex}.bin"
    old = b"C" * (RAM_CACHE_CAP * 2)
    path, times = _seed(name, old)
    try:
        first = requests.get(f"{base_url}/{name}", timeout=60)
        assert first.status_code == 200, first.text[:400]
        assert first.content == old

        new = b"D" * (RAM_CACHE_CAP * 2)
        _rewrite_in_place(path, times, new)
        second = requests.get(f"{base_url}/{name}", timeout=60)
        assert second.status_code == 200, second.text[:400]
        assert second.content == new, (
            "an object larger than the whole cap must not have been cached")
    finally:
        os.unlink(path)


@pytest.mark.registry_server("ram-cache")
@pytest.mark.parametrize("over", [1.05, 1.5, 1.99], ids=["just", "half", "near"])
def test_no_object_between_one_and_two_caps_is_admitted(base_url,
                                                        ram_cache_origin,
                                                        over):
    """Regression: the growth path charged only each doubling's DELTA.

    Found live on 2026-09-07 (peer audit).  ``brix_sd_ram_ent_grow`` compared the
    increment it was about to add against the store, but the entry's own bytes
    reached ``st->used`` only at commit — so with nothing else resident every
    individual doubling was smaller than the whole cap and passed, and an object
    of up to TWICE the cap was admitted into a store configured to hold one.  A
    fill whose origin declares no length (``declared_size`` 0) never hit the
    early ``capacity < declared_size`` refusal either, so nothing else caught it.

    The band 1x..2x the cap is exactly the band that used to slip through, so it
    is the band pinned here: no size in it may be served from the store.  The
    fix keeps the whole allocation covered by the fill's reservation and refuses
    a ``want`` past the cap outright (``sd_ram_table.c``).
    """
    size = int(RAM_CACHE_CAP * over)
    name = f"over-{uuid.uuid4().hex}.bin"
    path, times = _seed(name, b"C" * size)
    try:
        first = requests.get(f"{base_url}/{name}", timeout=60)
        assert first.status_code == 200, first.text[:400]
        assert len(first.content) == size

        new = b"D" * size
        _rewrite_in_place(path, times, new)
        second = requests.get(f"{base_url}/{name}", timeout=60)
        assert second.status_code == 200, second.text[:400]
        assert second.content == new, (
            f"{size} bytes ({over}x the {RAM_CACHE_CAP}-byte cap) was served "
            "from the store: the per-worker memory cap is not being enforced")
    finally:
        os.unlink(path)


@pytest.mark.registry_server("ram-cache")
def test_an_oversized_fill_does_not_poison_the_store(base_url,
                                                     ram_cache_origin):
    """Security negative: a refused fill must leave the store's budget intact.

    An admission refusal that leaked its reservation would shrink the usable cap
    on every attempt until nothing could be cached at all — a remote caller who
    can ask for one oversized object could then deny the cache to everyone else.
    So: drive a refusal, then prove a normal object still fills and hits.
    """
    big = f"poison-{uuid.uuid4().hex}.bin"
    big_path, _ = _seed(big, b"C" * (RAM_CACHE_CAP + 4096))
    small = f"after-{uuid.uuid4().hex}.bin"
    small_path, times = _seed(small, b"A" * 4096)
    try:
        for _ in range(3):
            assert requests.get(f"{base_url}/{big}",
                                timeout=60).status_code == 200

        assert requests.get(f"{base_url}/{small}",
                            timeout=30).status_code == 200
        _rewrite_in_place(small_path, times, b"B" * 4096)
        again = requests.get(f"{base_url}/{small}", timeout=30)
        assert again.status_code == 200, again.text[:400]
        assert again.content == b"A" * 4096, (
            "the store stopped caching after refusing an oversized fill: the "
            "refusal leaked its reservation")
    finally:
        os.unlink(big_path)
        os.unlink(small_path)


def _fill_sequence(base_url, tag, count, chunk):
    """Seed and read `count` distinct objects, oldest first.

    Returns the per-object records the eviction assertions need.  Split out of
    the test body so the loop's failure mode is one assertion, not a branch
    tangled with the teardown.
    """
    records = []
    for i in range(count):
        body = bytes([65 + i]) * chunk
        name = f"lru-{tag}-{i}.bin"
        path, times = _seed(name, body)
        records.append((name, path, times, body))
        r = requests.get(f"{base_url}/{name}", timeout=30)
        assert r.status_code == 200, f"{name}: {r.text[:300]}"
    return records


def _unlink_all(records):
    for _name, path, _times, _body in records:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


@pytest.mark.registry_server("ram-cache")
def test_lru_evicts_the_coldest_under_the_cap(base_url, ram_cache_origin):
    """The cap and the LRU are one mechanism, not two.

    A hard cap with no eviction is a store that fills once and refuses every
    fill forever.  Fill the store past `ram:1m` with quarter-cap objects, then
    prove the FIRST one is gone (a re-read reaches the source) while the LAST
    one is still resident (a re-read returns stale bytes).
    """
    chunk = RAM_CACHE_CAP // 4
    records = _fill_sequence(base_url, uuid.uuid4().hex[:8], 6, chunk)
    try:
        # Swap every origin body; only an evicted entry can show the new bytes.
        for _name, path, times, body in records:
            _rewrite_in_place(path, times, b"Z" * len(body))

        first = requests.get(f"{base_url}/{records[0][0]}", timeout=30)
        last = requests.get(f"{base_url}/{records[-1][0]}", timeout=30)
        assert first.status_code == 200, first.text[:300]
        assert last.status_code == 200, last.text[:300]
        assert first.content == b"Z" * chunk, (
            "the coldest entry survived a 1.5x-capacity fill sequence")
        assert last.content == records[-1][3], (
            "the most recent entry was evicted before the coldest one")
    finally:
        _unlink_all(records)


@pytest.mark.registry_server("ram-cache")
def test_path_traversal_refused(base_url):
    """Security negative: the store has no path, but the EXPORT still does.

    A RAM cache changes where bytes live, never who may name them; `..` must be
    refused before any store is consulted.
    """
    r = requests.get(f"{base_url}/../etc/passwd", timeout=15)
    assert r.status_code in (400, 403, 404), r.status_code


@pytest.mark.registry_server("ram-cache")
def test_missing_object_is_404_not_a_cache_error(base_url):
    """A miss on an object the source does not have is a plain 404.

    Worth pinning separately: an empty RAM store and a full one must answer a
    genuine absence identically, and neither may leak an ENOSPC as a 5xx.
    """
    r = requests.get(f"{base_url}/absent-{uuid.uuid4().hex}.bin", timeout=15)
    assert r.status_code == 404, f"{r.status_code}: {r.text[:200]}"

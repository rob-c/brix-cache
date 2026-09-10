"""2.0 readiness — a cache store that cannot hold an object never fails the read.

The HTTP read plane offloads a cache-miss fill to the thread pool
(``brix_http_cache_fill_if_needed``) and re-enters the handler when the object
is cached.  Before 2.0 the offloaded path knew only two endings: a hit to
re-enter on, or a failure to answer with a status.  A refusal by the STORE
(``sd_ram_staged_open`` ENOSPC: the object is larger than the whole cache) was
neither, so the retry classifier treated it as transient, the fill ran out its
deadline and every waiter got a 504 "origin temporarily unreachable" for an
origin that had answered fine.  The decorator's own inline open already
degraded to a source read (``sd_cache_open_common``, "a sick cache never fails a
read"); the offloaded path did not.

The fix (2026-09-07) makes the two paths agree:

  * ``brix_fill_store_refused`` (``src/fs/cache/fill_retry.h``) is the ONE
    definition of a store refusal, shared by the classifier (definitive, no
    retry ladder) and the fill worker;
  * the worker marks the request (``brix_io_monitor_t.fill_refused``) and
    re-enters the handler, which declines a second offload and opens with
    ``BRIX_SD_O_NOFILL`` — the decorator serves the source directly, after the
    cache-only and admission checks, and caches nothing.

``tests/test_phase115_ram_tier.py`` owns the store's own cap semantics; this
module pins the plane-level contract those tests only observe indirectly: the
outcome line, the single attempt, the coalesced waiters, the 404 branch that
must stay ahead of the degrade, and the two policy checks it must never bypass.
"""

import http.client
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from settings import (
    DATA_ROOT,
    NGINX_RAM_CACHE_PORT,
    REGISTRY_ROOT,
    SERVER_HOST,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src")

# Same instance and the same 1 MiB cap as the RAM-tier suite; the two must
# not run concurrently (a refusal in one would be a fill in the other).
pytestmark = pytest.mark.xdist_group("ram-cache")

RAM_CACHE_ORIGIN = os.path.join(os.path.dirname(DATA_ROOT), "data-ram-cache",
                                "origin")
RAM_CACHE_ERRLOG = os.path.join(REGISTRY_ROOT, "ram-cache", "logs", "error.log")
RAM_CACHE_CAP = 1024 * 1024            # nginx_ram_cache.conf: ram:1m

STORE_REFUSED = "event=store-refused"
EXHAUSTED = "event=exhausted"
NOT_FOUND = "event=not-found"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _seed(name, payload):
    os.makedirs(RAM_CACHE_ORIGIN, exist_ok=True)
    path = os.path.join(RAM_CACHE_ORIGIN, name)
    with open(path, "wb") as fh:
        fh.write(payload)
    st = os.stat(path)
    return path, (st.st_atime, st.st_mtime)


def _rewrite_in_place(path, times, payload):
    """Swap the bytes under the same size and mtime: fresh bytes on a re-read
    prove the read went to the source (the RAM-tier suite's observation)."""
    with open(path, "r+b") as fh:
        fh.write(payload)
    os.utime(path, times)


def _log_lines_for(key):
    """Every fill outcome line naming `key` (the log may hold other tests')."""
    if not os.path.exists(RAM_CACHE_ERRLOG):
        return []
    with open(RAM_CACHE_ERRLOG, encoding="utf-8", errors="replace") as fh:
        return [ln.rstrip("\n") for ln in fh if "xrootd-fill:" in ln and key in ln]


def _source_text(rel):
    with open(os.path.join(SRC, rel), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def base_url():
    return f"http://{SERVER_HOST}:{NGINX_RAM_CACHE_PORT}"


# --------------------------------------------------------------------------
# success: served from the source, logged once, one attempt, never cached
# --------------------------------------------------------------------------

def _outcome_lines(name, needle):
    return [ln for ln in _log_lines_for(name) if needle in ln]


def _assert_refused_once(name):
    """The key's outcome lines: exactly the store-refusal verdict, one attempt,
    'from the source', and NO exhausted line (the pre-2.0 504 path)."""
    refused = _outcome_lines(name, STORE_REFUSED)
    assert refused, f"no {STORE_REFUSED} line for {name}"
    assert re.search(r"\battempts=1\b", refused[0]), refused[0]
    assert "from the source" in refused[0], refused[0]
    assert not _outcome_lines(name, EXHAUSTED), (
        "the store refusal still ran the retry ladder out")


def _assert_rewrite_is_visible(base_url, name, path, times, size):
    """Not cached: a rewrite under the same size/mtime is visible at once."""
    new = b"D" * size
    _rewrite_in_place(path, times, new)
    again = requests.get(f"{base_url}/{name}", timeout=60)
    assert again.status_code == 200, again.text[:300]
    assert again.content == new, "an over-cap object was retained"


@pytest.mark.registry_server("ram-cache")
def test_over_cap_object_is_served_and_the_refusal_is_one_definitive_line(
        base_url):
    """SUCCESS: the offloaded fill's store refusal degrades to a source read.

    Three things in one request, because they are one mechanism: the body is
    correct (200, the origin's bytes), the outcome line is the store-refusal
    verdict with ``attempts=1`` (the classifier did not spend the retry ladder
    on a store that can never say yes), and no ``exhausted`` line exists for
    the key (the pre-2.0 504 path was never taken).
    """
    name = f"r20-over-{uuid.uuid4().hex}.bin"
    old = b"C" * int(RAM_CACHE_CAP * 1.5)
    path, times = _seed(name, old)
    try:
        r = requests.get(f"{base_url}/{name}", timeout=60)
        assert r.status_code == 200, f"{r.status_code}: {r.text[:300]}"
        assert r.content == old
        _assert_refused_once(name)
        _assert_rewrite_is_visible(base_url, name, path, times, len(old))
    finally:
        os.unlink(path)


@pytest.mark.registry_server("ram-cache")
def test_every_coalesced_waiter_is_re_entered(base_url):
    """SUCCESS (stampede): N concurrent readers park on ONE fill; when the store
    refuses it, all N are re-entered and served — none is left with the
    pre-2.0 504, none with a 502."""
    name = f"r20-stampede-{uuid.uuid4().hex}.bin"
    body = b"S" * int(RAM_CACHE_CAP * 1.25)
    path, _ = _seed(name, body)
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(
                lambda _i: requests.get(f"{base_url}/{name}", timeout=60),
                range(4)))
        statuses = [r.status_code for r in results]
        assert statuses == [200] * 4, statuses
        assert all(r.content == body for r in results)
        assert [ln for ln in _log_lines_for(name) if STORE_REFUSED in ln]
    finally:
        os.unlink(path)


@pytest.mark.registry_server("ram-cache")
def test_range_read_of_an_over_cap_object_is_a_true_206(base_url):
    """SUCCESS: the source serve behind the degrade is the full GET path —
    a Range request on the un-cacheable object is honoured, not widened to
    200 or refused."""
    name = f"r20-range-{uuid.uuid4().hex}.bin"
    body = bytes(range(256)) * (int(RAM_CACHE_CAP * 1.1) // 256 + 1)
    path, _ = _seed(name, body)
    try:
        r = requests.get(f"{base_url}/{name}", timeout=60,
                         headers={"Range": "bytes=1000-1999"})
        assert r.status_code == 206, f"{r.status_code}: {r.text[:300]}"
        assert r.content == body[1000:2000]
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------
# error: the origin's own answers stay ahead of the degrade
# --------------------------------------------------------------------------

@pytest.mark.registry_server("ram-cache")
def test_absent_object_is_still_the_origins_404(base_url):
    """ERROR: a miss the source cannot satisfy is 404 with the ``not-found``
    outcome — the store-refusal branch sits beside the ENOENT branch and must
    never claim a request the origin already answered."""
    name = f"r20-absent-{uuid.uuid4().hex}.bin"
    r = requests.get(f"{base_url}/{name}", timeout=30)
    assert r.status_code == 404, f"{r.status_code}: {r.text[:200]}"
    lines = _log_lines_for(name)
    assert not [ln for ln in lines if STORE_REFUSED in ln], "\n".join(lines)


# --------------------------------------------------------------------------
# security negatives
# --------------------------------------------------------------------------

@pytest.mark.registry_server("ram-cache")
def test_traversal_on_an_over_cap_name_never_reaches_the_store():
    """SECURITY: the degrade changes where bytes come from, never who may name
    them — a ``..`` climbing out of the export under an over-cap-looking name
    is refused at the edge, so no fill (and no outcome line of any kind) ever
    exists for it.  Sent on a raw socket: ``requests`` resolves dot segments
    client-side and would test a plain miss."""
    tag = f"r20-trav-{uuid.uuid4().hex}"
    conn = http.client.HTTPConnection(SERVER_HOST, NGINX_RAM_CACHE_PORT,
                                      timeout=30)
    try:
        conn.putrequest("GET", f"/../../{tag}-huge.bin")
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        assert resp.status in (400, 403, 404), resp.status
    finally:
        conn.close()
    assert not _log_lines_for(tag), "\n".join(_log_lines_for(tag))


def test_no_fill_hint_sits_below_the_cache_only_and_admission_checks():
    """SECURITY: ``BRIX_SD_O_NOFILL`` may only ever shortcut the FILL.

    A cache-only export (``only_if_cached``) answers a miss with ENOENT so the
    node never becomes an origin puller, and the path filter decides what the
    cache admits; a re-entered request that could jump past either would turn
    the store's capacity into a policy bypass.  Pinned as a source-order
    assertion: the hint's branch must come after both checks in
    ``sd_cache_open_common``.
    """
    text = _source_text("fs/backend/cache/sd_cache.c")
    start = text.index("sd_cache_open_common(brix_sd_instance_t *inst")
    body = text[start:]
    only_if = body.index("st->policy.only_if_cached")
    admit = body.index("!sd_cache_admit(&st->policy, path")
    nofill = body.index("rq->sd_flags & BRIX_SD_O_NOFILL")
    assert only_if < nofill and admit < nofill, (
        f"only_if_cached@{only_if} admit@{admit} nofill@{nofill}")


def test_store_refusal_has_one_definition_shared_by_classifier_and_worker():
    """SECURITY/CONSISTENCY: the classifier deciding "definitive" and the
    worker deciding "re-enter from the source" must read the same predicate,
    or an errno could be definitive for one and a 502 for the other."""
    header = _source_text("fs/cache/fill_retry.h")
    assert "brix_fill_store_refused(int err)" in header
    assert "return err == ENOSPC;" in header
    for rel in ("fs/cache/fill_retry.c",
                "protocols/shared/http_cache_fill_worker.c"):
        text = _source_text(rel)
        assert "brix_fill_store_refused(" in text, rel
        code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)   # prose may say it
        assert "ENOSPC" not in code, (
            f"{rel} spells ENOSPC itself instead of asking the predicate")


def test_re_entry_declines_a_second_offload_before_the_miss_test():
    """CONSISTENCY: the re-entered request is still a miss, so the guard that
    declines a second offload must precede ``fill_needs_offload`` — after it,
    the request would loop between a fill the store refuses and a handler that
    asks for one."""
    text = _source_text("protocols/shared/http_cache_fill.c")
    start = text.index("brix_http_cache_fill_if_needed(ngx_http_request_t *r,")
    body = text[start:]
    assert body.index("m->fill_refused") < body.index(
        "brix_sd_cache_fill_needs_offload(inst, key)")

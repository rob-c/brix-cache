"""Phase-84 conformance corpus: srv_manifest — signed-metadata TTL caching.

Theme
-----
``.cvmfspublished`` / ``.cvmfswhitelist`` / ``.cvmfsreflog`` are MANIFEST-class
(mutable, repository-signed) and cache with ``brix_cvmfs_manifest_ttl``
(gate.c T12, sd_cache_policy.c, docs/04-protocols/cvmfs.md §4.2):

* within the TTL every request serves from cache — origin-fetch count frozen;
* past the TTL the entry refills, so a revision bump propagates within one TTL;
* a FAILED refill (origin 500 / connection reset / object gone) serves the
  stale copy — but only inside a bounded ``10 x TTL`` window keyed on the
  fill time; each stale serve re-arms expiry one TTL forward;
* beyond the window (or on a cold cache) a dead origin is ordinary origin
  trouble: the never-drop hold answers ``504 + Retry-After: 2`` — stale bytes
  are never served past the bound, fabricated bytes never at all;
* HEAD/GET parity, If-Modified-Since/304, weak-ETag stability all apply to
  metadata exactly as to any tier-served object;
* metadata 404s (missing name, unknown repo) are definitive per request — the
  T13 negative memo absorbs only CAS-class 404s, so each metadata miss probes
  the origin again and a late-appearing file is served promptly.

Port block 13120-13139 (mocks 13120-13129, nginx 13130-13139): module-scoped
fixtures take 13120-13122/13130-13132, ephemeral per-test instances rotate
over 13124-13129/13134-13139.
"""

import itertools
import os
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from settings import HOST

REPO = "test.cern.ch"
NAMES = (".cvmfspublished", ".cvmfswhitelist", ".cvmfsreflog")
SYN_NAMES = NAMES[:2]          # the synthetic mock has no .cvmfsreflog
TTL = 2                        # short-TTL fixtures: expiry waits stay cheap
EXPIRE = TTL + 0.6             # sleep that guarantees the entry is expired

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found: {NGINX_BIN}")

# One shared allocator for the module-scoped fixtures (3 mock/nginx pairs).
_BLOCK = PortBlock("srv_manifest")


class _FixedBlock(PortBlock):
    """A PortBlock pinned to one mock/nginx pair — ephemeral instances rotate
    pairs so a just-torn-down server can never answer for its successor."""

    def __init__(self, mock_port: int, nginx_port: int):
        super().__init__("srv_manifest")
        self._mp, self._np = mock_port, nginx_port

    def mock(self) -> int:
        return self._mp

    def nginx(self) -> int:
        return self._np


_EPHEMERAL_PAIRS = itertools.cycle([(13124 + i, 13134 + i) for i in range(6)])


@contextmanager
def ephemeral(**kw):
    """A throwaway srv_instance for tests that mutate origin/cache state."""
    mock_port, nginx_port = next(_EPHEMERAL_PAIRS)
    with srv_instance(_FixedBlock(mock_port, nginx_port), **kw) as srv:
        yield srv


def _get(url, headers=None):
    """GET returning (status, email.Message headers, body) — 4xx/5xx included."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def _meta_url(srv, name, repo=REPO):
    return f"{srv.base_url}/cvmfs/{repo}/{name}"


def _head(srv, name, headers=None, repo=REPO):
    return request(HOST, srv.nginx_port, "HEAD",
                   f"/cvmfs/{repo}/{name}", headers)


def _heads_count(srv, needle):
    """Origin HEAD probes for `needle` (the mock logs data GETs and size-probe
    HEADs separately; a metadata miss costs one probe, no GET)."""
    return sum(1 for e in srv.get_heads() if needle in e["path"])


def _field(manifest_body, letter):
    """Value of a one-letter field in the signed-manifest head (before `--`)."""
    head = manifest_body.split(b"\n--\n", 1)[0]
    for line in head.splitlines():
        if line[:1] == letter.encode():
            return line[1:].decode()
    return None


def _write_meta(meta_dir, name, payload):
    (meta_dir / name).write_bytes(payload)


def _wait_until(pred, deadline=3 * TTL + 2, step=0.25):
    """Poll `pred` until true or `deadline` seconds elapse.  Expiry waits use
    this instead of one fixed sleep: the host clock (WSL2) can step, and
    expires_at is wall-clock — a bounded poll keeps the assertion honest
    (propagation within a small number of TTLs) without the flake."""
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


# ---- module fixtures -------------------------------------------------------

@pytest.fixture(scope="module")
def web_state(tmp_path_factory):
    """Webroot-backed instance carrying ALL THREE metadata names, plus the
    cold-pass observations captured before any test can disturb the cache:
    per name — first-GET status/body, origin fetches after the first and an
    immediate second GET, and the on-disk bytes at fill time."""
    web = tmp_path_factory.mktemp("manifest_web")
    meta = web / "cvmfs" / REPO
    meta.mkdir(parents=True)
    for i, name in enumerate(NAMES):
        _write_meta(meta, name, f"{name}-origin-v1-{'x' * (8 + i)}\n".encode())

    with srv_instance(_BLOCK, webroot=web, manifest_ttl=TTL) as srv:
        cold = {}
        for name in NAMES:
            disk = (meta / name).read_bytes()
            s1, _, b1 = _get(_meta_url(srv, name))
            n1 = srv.count_log(name)
            s2, _, b2 = _get(_meta_url(srv, name))
            cold[name] = dict(status=(s1, s2), body=(b1, b2), disk=disk,
                              fetches=(n1, srv.count_log(name)))
        yield srv, meta, cold


@pytest.fixture(scope="module")
def srv(request):
    """Synthetic-origin instance, TTL 2 s — expiry / negative / unknown-repo."""
    with srv_instance(_BLOCK, manifest_ttl=TTL) as s:
        yield s


@pytest.fixture(scope="module")
def srv_long(request):
    """Synthetic-origin instance, TTL 600 s: after the priming pass below the
    entries stay fresh for the whole module, so within-TTL guarantees are
    race-free.  Primes both names twice, records the fill counts, resets the
    origin log — subsequent tests assert a ZERO origin-GET delta."""
    with srv_instance(_BLOCK, manifest_ttl=600) as s:
        counts = {}
        for name in SYN_NAMES:
            assert _get(_meta_url(s, name))[0] == 200
            assert _get(_meta_url(s, name))[0] == 200
            counts[name] = s.count_log(name)
        s.reset_log()
        s.prime_counts = counts
        yield s


# ---- A. cold fill + within-TTL caching ------------------------------------

@pytest.mark.parametrize("name", NAMES)
def test_cold_get_serves_origin_bytes(web_state, name):
    _, _, cold = web_state
    assert cold[name]["status"][0] == 200
    assert cold[name]["body"][0] == cold[name]["disk"]


@pytest.mark.parametrize("name", NAMES)
def test_cold_get_fetches_origin_once(web_state, name):
    _, _, cold = web_state
    assert cold[name]["fetches"][0] == 1


@pytest.mark.parametrize("name", NAMES)
def test_second_get_within_ttl_is_cache_hit(web_state, name):
    _, _, cold = web_state
    assert cold[name]["status"][1] == 200
    assert cold[name]["body"][1] == cold[name]["body"][0]
    assert cold[name]["fetches"][1] == cold[name]["fetches"][0]  # no refetch


@pytest.mark.parametrize("name", SYN_NAMES)
def test_within_ttl_many_gets_single_fill(srv_long, name):
    # Two priming GETs cost exactly one origin fetch; five more cost zero.
    assert srv_long.prime_counts[name] == 1
    for _ in range(5):
        assert _get(_meta_url(srv_long, name))[0] == 200
    assert srv_long.count_log(name) == 0        # log was reset after priming


@pytest.mark.parametrize("name", SYN_NAMES)
def test_head_within_ttl_no_origin_traffic(srv_long, name):
    g0, h0 = srv_long.count_log(name), _heads_count(srv_long, name)
    st, _, _ = _head(srv_long, name)
    assert st == 200
    assert srv_long.count_log(name) == g0
    assert _heads_count(srv_long, name) == h0


@pytest.mark.parametrize("name", SYN_NAMES)
def test_head_get_parity_synthetic(srv_long, name):
    gs, gh, gb = _get(_meta_url(srv_long, name))
    hs, hh, hb = _head(srv_long, name)
    assert (gs, hs) == (200, 200)
    assert hh.get("content-length") == str(len(gb)) == gh.get("Content-Length")
    assert hb == b""


def test_metadata_keys_cached_independently(srv):
    # Expire both, refetch ONLY the whitelist: the published count must not move.
    for name in SYN_NAMES:
        assert _get(_meta_url(srv, name))[0] == 200
    time.sleep(EXPIRE)
    srv.reset_log()
    assert _wait_until(lambda: _get(_meta_url(srv, ".cvmfswhitelist"))[0] == 200
                       and srv.count_log(".cvmfswhitelist") == 1)
    assert srv.count_log(".cvmfspublished") == 0


def test_served_whitelist_matches_origin_bytes(srv_long):
    # The synthetic whitelist is static, so cached-vs-origin bytes must agree.
    _, _, via_cache = _get(_meta_url(srv_long, ".cvmfswhitelist"))
    _, _, via_origin = _get(f"{srv_long.mock_url}/cvmfs/{REPO}/.cvmfswhitelist")
    assert via_cache == via_origin == b"mock-whitelist\n"


# ---- B. TTL expiry -> refetch ---------------------------------------------

@pytest.mark.parametrize("name", SYN_NAMES)
@pytest.mark.timeout(45)
def test_expired_entry_refetches_origin(srv, name):
    assert _get(_meta_url(srv, name))[0] == 200     # prime (fills or refills)
    srv.reset_log()
    assert _get(_meta_url(srv, name))[0] == 200     # within TTL: cache hit
    assert srv.count_log(name) == 0
    time.sleep(TTL)
    # past TTL the next GET refetches; poll (clock-step safe) then hold at 1.
    assert _wait_until(lambda: _get(_meta_url(srv, name))[0] == 200
                       and srv.count_log(name) >= 1)
    assert srv.count_log(name) == 1                  # exactly one refetch


@pytest.mark.timeout(45)
def test_refetch_rearms_ttl(srv):
    name = ".cvmfspublished"
    assert _get(_meta_url(srv, name))[0] == 200
    srv.reset_log()
    time.sleep(TTL)
    assert _wait_until(lambda: _get(_meta_url(srv, name))[0] == 200
                       and srv.count_log(name) >= 1)
    for _ in range(3):                               # fresh again: no refetch
        assert _get(_meta_url(srv, name))[0] == 200
    assert srv.count_log(name) == 1


# ---- C. revision-bump / content-change propagation ------------------------

@pytest.mark.timeout(45)
def test_bump_within_ttl_serves_cached_revision(request):
    with ephemeral(manifest_ttl=TTL) as srv:
        _, _, before = _get(_meta_url(srv, ".cvmfspublished"))
        assert _field(before, "S") == "1"
        srv.bump()
        _, _, after = _get(_meta_url(srv, ".cvmfspublished"))
        assert after == before                       # TTL still shields origin
        assert srv.count_log(".cvmfspublished") == 1


@pytest.mark.timeout(45)
def test_bump_visible_after_ttl(request):
    with ephemeral(manifest_ttl=TTL) as srv:
        _, _, before = _get(_meta_url(srv, ".cvmfspublished"))
        srv.bump()
        time.sleep(TTL)
        assert _wait_until(lambda: _field(
            _get(_meta_url(srv, ".cvmfspublished"))[2], "S") == "2")
        _, _, after = _get(_meta_url(srv, ".cvmfspublished"))
        assert _field(after, "C") != _field(before, "C")   # root hash moved


@pytest.mark.timeout(45)
def test_double_bump_latest_revision_wins(request):
    with ephemeral(manifest_ttl=TTL) as srv:
        assert _get(_meta_url(srv, ".cvmfspublished"))[0] == 200
        srv.bump()
        srv.bump()
        time.sleep(TTL)
        assert _wait_until(lambda: _field(
            _get(_meta_url(srv, ".cvmfspublished"))[2], "S") == "3")


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.timeout(45)
def test_webroot_rewrite_propagates_after_ttl(web_state, name):
    srv, meta, _ = web_state
    payload = f"{name}-rewritten-{time.time_ns()}\n".encode()
    assert _get(_meta_url(srv, name))[0] == 200      # ensure an entry exists
    _write_meta(meta, name, payload)
    time.sleep(TTL)
    assert _wait_until(lambda: _get(_meta_url(srv, name))[2] == payload)


@pytest.mark.timeout(45)
def test_head_reflects_new_length_after_ttl(web_state):
    srv, meta, _ = web_state
    payload = b"whitelist-grown-" + b"y" * 64 + b"\n"
    _write_meta(meta, ".cvmfswhitelist", payload)
    time.sleep(TTL)
    assert _wait_until(
        lambda: _head(srv, ".cvmfswhitelist")[1].get("content-length")
        == str(len(payload)))
    assert _head(srv, ".cvmfswhitelist")[0] == 200


# ---- D. stale-if-error (bounded 10 x TTL window) --------------------------

@pytest.mark.timeout(45)
def test_stale_served_on_origin_500(request):
    with ephemeral(manifest_ttl=TTL, client_hold=2) as srv:
        _, _, fresh = _get(_meta_url(srv, ".cvmfspublished"))
        time.sleep(TTL)
        srv.set_fault("http500", 500, path_re="cvmfspublished")

        def _stale_seen():
            s, _, body = _get(_meta_url(srv, ".cvmfspublished"))
            assert (s, body) == (200, fresh)         # stale copy, not a 5xx
            return "serving stale copy" in srv.error_log.read_text()

        assert _wait_until(_stale_seen)


@pytest.mark.timeout(45)
def test_stale_served_on_origin_reset(request):
    with ephemeral(manifest_ttl=TTL, client_hold=2) as srv:
        _, _, fresh = _get(_meta_url(srv, ".cvmfspublished"))
        time.sleep(EXPIRE)
        srv.set_fault("reset", 500, path_re="cvmfspublished")
        s, _, body = _get(_meta_url(srv, ".cvmfspublished"))
        assert (s, body) == (200, fresh)


@pytest.mark.timeout(45)
def test_stale_served_reflog_webroot(request, tmp_path):
    web = tmp_path / "web"
    meta = web / "cvmfs" / REPO
    meta.mkdir(parents=True)
    for name in NAMES:
        _write_meta(meta, name, f"{name}-stale-lab\n".encode())
    with ephemeral(webroot=web, manifest_ttl=TTL, client_hold=2) as srv:
        _, _, fresh = _get(_meta_url(srv, ".cvmfsreflog"))
        time.sleep(EXPIRE)
        srv.set_fault("http500", 500, path_re="cvmfsreflog")
        s, _, body = _get(_meta_url(srv, ".cvmfsreflog"))
        assert (s, body) == (200, fresh)


@pytest.mark.timeout(45)
def test_stale_serve_rearms_next_retry_one_ttl_out(request):
    # A stale serve pushes expires_at one TTL forward: the NEXT request must
    # come from cache without a fresh origin attempt (sd_cache_policy.c).
    with ephemeral(manifest_ttl=TTL, client_hold=2) as srv:
        _, _, fresh = _get(_meta_url(srv, ".cvmfspublished"))
        time.sleep(EXPIRE)
        srv.set_fault("http500", 500, path_re="cvmfspublished")
        assert _get(_meta_url(srv, ".cvmfspublished"))[0] == 200   # stale serve
        n = srv.count_log(".cvmfspublished")
        s, _, body = _get(_meta_url(srv, ".cvmfspublished"))
        assert (s, body) == (200, fresh)
        assert srv.count_log(".cvmfspublished") == n   # no new origin attempt


@pytest.mark.timeout(45)
def test_recovered_origin_refetches_after_rearm_expiry(request):
    with ephemeral(manifest_ttl=TTL, client_hold=2) as srv:
        assert _get(_meta_url(srv, ".cvmfspublished"))[0] == 200
        time.sleep(TTL)
        srv.set_fault("http500", 1, path_re="cvmfspublished")      # one-shot
        # poll until the one-shot fault is consumed and absorbed as a stale serve
        assert _wait_until(
            lambda: _get(_meta_url(srv, ".cvmfspublished"))[0] == 200
            and "serving stale copy" in srv.error_log.read_text())
        n = srv.count_log(".cvmfspublished")
        time.sleep(TTL)                          # re-armed expiry passes
        assert _wait_until(                       # healthy origin: fresh fill
            lambda: _get(_meta_url(srv, ".cvmfspublished"))[0] == 200
            and srv.count_log(".cvmfspublished") == n + 1)


@pytest.mark.timeout(45)
def test_deleted_at_origin_serves_stale_inside_window(request, tmp_path):
    # Refill failure mode "object gone" (open -> ENOENT) also rides the
    # stale-if-error path inside the window — a Stratum-1 mid-publish blip
    # must not blank a site's manifest.
    web = tmp_path / "web"
    meta = web / "cvmfs" / REPO
    meta.mkdir(parents=True)
    for name in NAMES:
        _write_meta(meta, name, f"{name}-doomed\n".encode())
    with ephemeral(webroot=web, manifest_ttl=TTL, client_hold=2) as srv:
        _, _, fresh = _get(_meta_url(srv, ".cvmfspublished"))
        (meta / ".cvmfspublished").unlink()
        s, _, body = _get(_meta_url(srv, ".cvmfspublished"))
        assert (s, body) == (200, fresh)         # within TTL: cache, trivially
        time.sleep(EXPIRE)
        s, _, body = _get(_meta_url(srv, ".cvmfspublished"))
        assert (s, body) == (200, fresh)         # past TTL: stale-if-error


@pytest.mark.timeout(45)
def test_cold_cache_origin_500_holds_then_504(request):
    # No prior fill => nothing stale to serve: the never-drop hold answers
    # 504 + Retry-After (docs §6) — never a fabricated body, never a drop.
    with ephemeral(manifest_ttl=TTL, client_hold=2) as srv:
        srv.set_fault("http500", 500, path_re="cvmfspublished")
        s, hdrs, _ = _get(_meta_url(srv, ".cvmfspublished"))
        assert s == 504
        assert hdrs.get("Retry-After") == "2"


@pytest.mark.timeout(45)
def test_cold_cache_origin_reset_holds_then_504(request):
    with ephemeral(manifest_ttl=TTL, client_hold=2) as srv:
        srv.set_fault("reset", 500, path_re="cvmfspublished")
        s, hdrs, _ = _get(_meta_url(srv, ".cvmfspublished"))
        assert s == 504
        assert hdrs.get("Retry-After") == "2"


@pytest.mark.timeout(60)
def test_beyond_stale_window_504_not_stale(request):
    # ttl=1: the 10 x TTL window (keyed on filled_at) closes after 10 s.
    # A faulted refill past it must NOT serve the stale copy — hard 504.
    with ephemeral(manifest_ttl=1, client_hold=2) as srv:
        s, _, stale = _get(_meta_url(srv, ".cvmfspublished"))
        assert s == 200
        time.sleep(10.5)
        srv.set_fault("http500", 500, path_re="cvmfspublished")

        def _hard_failure():
            s, hdrs, body = _get(_meta_url(srv, ".cvmfspublished"))
            if s != 504:
                assert (s, body) == (200, stale)     # still inside the window
                return False
            assert hdrs.get("Retry-After") == "2"
            assert body != stale                     # stale bytes never leak
            return True

        assert _wait_until(_hard_failure, deadline=20, step=0.5)


@pytest.mark.timeout(45)
def test_fault_on_published_leaves_whitelist_healthy(request):
    with ephemeral(manifest_ttl=TTL, client_hold=2) as srv:
        srv.set_fault("http500", 500, path_re="cvmfspublished")
        assert _get(_meta_url(srv, ".cvmfspublished"))[0] == 504
        s, _, body = _get(_meta_url(srv, ".cvmfswhitelist"))
        assert (s, body) == (200, b"mock-whitelist\n")


# ---- E. HEAD vs GET parity ------------------------------------------------

@pytest.mark.parametrize("name", NAMES)
def test_head_get_parity_webroot(web_state, name):
    srv, _, _ = web_state
    gs, _, gb = _get(_meta_url(srv, name))
    hs, hh, hb = _head(srv, name)
    assert (gs, hs) == (200, 200)
    assert hh.get("content-length") == str(len(gb))
    assert hb == b""


def test_head_missing_metadata_404(srv):
    st, _, body = _head(srv, ".cvmfsreflog")     # synthetic origin has none
    assert st == 404
    assert body == b""


def test_missing_metadata_head_and_get_agree(srv):
    gs, _, _ = _get(_meta_url(srv, ".cvmfsreflog"))
    hs, _, _ = _head(srv, ".cvmfsreflog")
    assert gs == hs == 404


# ---- F. If-Modified-Since / 304 / ETag ------------------------------------

@pytest.mark.parametrize("name", SYN_NAMES)
def test_ims_equal_last_modified_304(srv_long, name):
    _, hdrs, _ = _get(_meta_url(srv_long, name))
    lm = hdrs.get("Last-Modified")
    assert lm is not None
    s, _, body = _get(_meta_url(srv_long, name), {"If-Modified-Since": lm})
    assert (s, body) == (304, b"")


@pytest.mark.parametrize("name", SYN_NAMES)
def test_ims_older_date_full_200(srv_long, name):
    s, _, body = _get(_meta_url(srv_long, name),
                      {"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
    assert s == 200
    assert len(body) > 0


def test_ims_future_date_304(srv_long):
    s, _, body = _get(_meta_url(srv_long, ".cvmfspublished"),
                      {"If-Modified-Since": "Fri, 01 Jan 2038 00:00:00 GMT"})
    assert (s, body) == (304, b"")


def test_ims_malformed_date_ignored_200(srv_long):
    s, _, body = _get(_meta_url(srv_long, ".cvmfspublished"),
                      {"If-Modified-Since": "not-a-http-date"})
    assert s == 200
    assert len(body) > 0


def test_head_with_ims_304(srv_long):
    _, hdrs, _ = _get(_meta_url(srv_long, ".cvmfswhitelist"))
    st, _, body = _head(srv_long, ".cvmfswhitelist",
                        {"If-Modified-Since": hdrs.get("Last-Modified")})
    assert st == 304
    assert body == b""


def test_304_advertises_zero_length(srv_long):
    _, hdrs, _ = _get(_meta_url(srv_long, ".cvmfspublished"))
    s, h304, _ = _get(_meta_url(srv_long, ".cvmfspublished"),
                      {"If-Modified-Since": hdrs.get("Last-Modified")})
    assert s == 304
    assert h304.get("Content-Length") == "0"


def test_etag_weak_and_stable_across_hits(srv_long):
    _, h1, _ = _get(_meta_url(srv_long, ".cvmfswhitelist"))
    _, h2, _ = _get(_meta_url(srv_long, ".cvmfswhitelist"))
    assert h1.get("ETag", "").startswith('W/"')
    assert h1.get("ETag") == h2.get("ETag")


def test_ims_on_reflog_webroot_304(web_state):
    srv, _, _ = web_state
    _, hdrs, _ = _get(_meta_url(srv, ".cvmfsreflog"))
    s, _, body = _get(_meta_url(srv, ".cvmfsreflog"),
                      {"If-Modified-Since": hdrs.get("Last-Modified")})
    assert (s, body) == (304, b"")


# ---- G. negative behavior + unknown repositories --------------------------

def test_missing_reflog_404(srv):
    s, _, _ = _get(_meta_url(srv, ".cvmfsreflog"))
    assert s == 404


def test_missing_metadata_not_absorbed_each_request_probes_origin(srv):
    # The T13 negative memo is consulted for CAS-class URLs only (gate.c):
    # a metadata miss is answered per-request off the origin's own 404 —
    # observable as one size-probe HEAD per request, and zero data GETs.
    g0, h0 = srv.count_log(".cvmfsreflog"), _heads_count(srv, ".cvmfsreflog")
    for _ in range(3):
        assert _get(_meta_url(srv, ".cvmfsreflog"))[0] == 404
    assert _heads_count(srv, ".cvmfsreflog") == h0 + 3
    assert srv.count_log(".cvmfsreflog") == g0


@pytest.mark.parametrize("name", NAMES)
def test_unknown_repo_metadata_404(srv, name):
    s, _, _ = _get(_meta_url(srv, name, repo="unknown.example.org"))
    assert s == 404


def test_unknown_repo_does_not_poison_known_repo(srv):
    assert _get(_meta_url(srv, ".cvmfspublished",
                          repo="unknown.example.org"))[0] == 404
    assert _get(_meta_url(srv, ".cvmfspublished"))[0] == 200


def test_unknown_repo_head_404(srv):
    st, _, _ = _head(srv, ".cvmfswhitelist", repo="unknown.example.org")
    assert st == 404


def test_missing_metadata_appears_at_origin_served_promptly(request, tmp_path):
    # No stale-404 for metadata: the miss is re-asked every request, so a
    # freshly published file is visible immediately (no negative window).
    web = tmp_path / "web"
    meta = web / "cvmfs" / REPO
    meta.mkdir(parents=True)
    _write_meta(meta, ".cvmfspublished", b"pub-only\n")
    with ephemeral(webroot=web, manifest_ttl=TTL) as srv:
        assert _get(_meta_url(srv, ".cvmfsreflog"))[0] == 404
        _write_meta(meta, ".cvmfsreflog", b"reflog-appears\n")
        s, _, body = _get(_meta_url(srv, ".cvmfsreflog"))
        assert (s, body) == (200, b"reflog-appears\n")

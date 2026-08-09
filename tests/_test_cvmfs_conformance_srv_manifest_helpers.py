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

Port block 13120-13139 canonical (mocks +0..+9, nginx +10..+19), shifted into
the session tile by PortBlock: module-scoped fixtures take +0..+2/+10..+12,
ephemeral per-test instances rotate over +4..+9/+14..+19. The canonical range
overlaps the fleet's upstream-stub ports (settings.py STUB_*_BACKEND_PORT
13120-13126), so nothing here may name an absolute port.
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
    pairs so a just-torn-down server can never answer for its successor.
    Slots are offsets INTO the session tile (never canonical port literals:
    the canonical 1312x range doubles as the fleet's upstream-stub ports, and
    only the tile shift keeps a live fleet and this suite disjoint)."""

    def __init__(self, slot: int):
        super().__init__("srv_manifest")
        self._mp, self._np = self.base + 4 + slot, self.base + 14 + slot

    def mock(self) -> int:
        return self._mp

    def nginx(self) -> int:
        return self._np


_EPHEMERAL_SLOTS = itertools.cycle(range(6))


@contextmanager
def ephemeral(**kw):
    """A throwaway srv_instance for tests that mutate origin/cache state."""
    with srv_instance(_FixedBlock(next(_EPHEMERAL_SLOTS)), **kw) as srv:
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

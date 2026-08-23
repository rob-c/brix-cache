"""
tests/test_cache_passthrough_planes.py — store-then-evict passthrough beyond WebDAV.

WHAT: `brix_cache_passthrough` on the S3 and CVMFS planes, each with its own
      passthrough-OFF control, plus the root:// stream plane that must NOT be
      able to passthrough at all.

WHY:  passthrough is the escape hatch that serves a caller an object the
      ADMISSION policy declined: the fill runs under a separate spool cap and
      the key is dropped from the store once the last waiter has its fd
      (sd_cache_fill.c::cache_fill_admit_src). The `allow_pt = 1` opt-in is set
      in exactly ONE place — the shared HTTP cache-fill worker
      (http_cache_fill_worker.c:51) — which webdav/get.c, s3/object.c AND
      cvmfs/handler.c all route through, so all three HTTP-family protocols
      inherit it. Only WebDAV was ever tested. The stream plane's own fill
      (sd_cache_maint.c:134) passes `allow_pt = 0`, and nothing pinned that
      either.
      docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md item 17.

HOW:  three objects sized against the two caps, which is the only geometry in
      which admission and passthrough disagree:

          small  <= brix_cache_max_object              → admitted, CACHED
          mid     > max_object, <= passthrough_max     → the passthrough window
          huge    > both caps                          → refused everywhere

      Measured, not assumed (scratch probe, 2026-08-05):

          plane            small          mid            huge
          s3on  / cvon     200 + stored   200, NOT stored  502
          s3off / cvoff    200 + stored   502              502
          root://          200 + stored   200              200   ← never gated

      The root:// row is the negative: `brix_cache_passthrough on` is present in
      that server block and has no effect. `huge` is the discriminator — it is
      over the passthrough spool cap, so any plane that actually ran the
      passthrough gate refuses it; the stream plane serves it read-through.

Trio per CLAUDE.md:
  * success   — the passthrough window is served byte-exact on S3 and CVMFS,
                and the store is left WITHOUT the key (store-then-evict).
  * error     — the same object is 502 on the passthrough-off control, and an
                object over the spool cap is 502 even with passthrough on.
  * security  — passthrough widens no boundary: a key outside the configured
                bucket, a non-CVMFS URL shape, and a traversal are all still
                refused, and the un-gated stream plane spools nothing.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_cache_passthrough_planes.py -v
"""

import shutil
import subprocess

import pytest
import requests

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST, XRDCP_BIN

def _expression_1():
    return (
        [p for p, _, _ in HTTP_PLANES] + ["rootpt"]
    )


def _check_planes_1(path, r):
    assert r.status_code in (200, 201, 204), (path, r.status_code)


pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cache-passthrough")]

SPEC = "lc-cache-passthrough"
BUCKET = "ptbucket"
REPO = "repo.test"

MAX_OBJECT = 4096                  # brix_cache_max_object
PT_MAX = 1024 * 1024               # brix_cache_passthrough_max

OBJECTS = {
    "small": b"s" * 1000,              # admissible
    "mid":   b"m" * 50000,             # the passthrough window
    "huge":  b"h" * (2 * 1024 * 1024),  # over the spool cap too
}

# (plane, port key, passthrough on?)
HTTP_PLANES = [
    ("s3on",  "S3_PORT",     True),
    ("s3off", "S3_OFF_PORT", False),
    ("cvon",  "CV_PORT",     True),
    ("cvoff", "CV_OFF_PORT", False),
]
PT_ON = [p for p, _, on in HTTP_PLANES if on]
PT_OFF = [p for p, _, on in HTTP_PLANES if not on]


def _cas(name):
    """CVMFS CAS path for an object.

    The cvmfs URL grammar only accepts `/cvmfs/<repo>/data/<2hex>/<hex...>`
    (shared/cvmfs/grammar/classify.c) — a plain filename is not client traffic
    and is rejected before any cache decision is reached. The digest here need
    not match the bytes; it only has to be a standard-length hex name.
    """
    import hashlib
    hx = hashlib.sha256(OBJECTS[name]).hexdigest()
    return f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}"


# --------------------------------------------------------------------------- #
# Server.                                                                      #
# --------------------------------------------------------------------------- #
class Planes:
    def __init__(self, endpoint, cache_root, export_root):
        self.ep = endpoint
        self.cache_root = cache_root
        self.origin = f"http://{HOST}:{endpoint.port}"

    def url(self, plane, name):
        port = self.ep.extra_ports[dict((p, k) for p, k, _ in HTTP_PLANES)[plane]]
        tail = (f"/{BUCKET}/{name}.bin" if plane.startswith("s3")
                else _cas(name))
        return f"http://{HOST}:{port}{tail}"

    def get(self, plane, name, **kw):
        return requests.get(self.url(plane, name), timeout=90, **kw)

    def stored(self, plane):
        """Basenames currently present in that plane's cache store."""
        root = self.cache_root / plane
        return sorted(f.name for f in root.rglob("*") if f.is_file())


@pytest.fixture(scope="module")
def planes(tmp_path_factory):
    base = tmp_path_factory.mktemp("cache-pt")
    cache_root, export_root = base / "cache", base / "export"
    for plane in _expression_1():
        (cache_root / plane).mkdir(parents=True)
        (export_root / plane).mkdir(parents=True)

    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_lc_cache_passthrough.conf",
            protocol="http",
            template_values={"BIND_HOST": BIND_HOST,
                             "CACHE_ROOT": str(cache_root),
                             "EXPORT_ROOT": str(export_root),
                             "MAX_OBJECT": str(MAX_OBJECT),
                             "PT_MAX": str(PT_MAX)},
            reason="cache passthrough on the S3/CVMFS planes + root:// negative"))
        p = Planes(ep, cache_root, export_root)

        # Seed the origin: the S3 planes address `/<bucket>/<key>`, the CVMFS
        # planes a CAS path, and the stream plane the bare name.
        for d in ("/cvmfs", f"/cvmfs/{REPO}", f"/cvmfs/{REPO}/data", f"/{BUCKET}"):
            requests.request("MKCOL", p.origin + d, timeout=30)
        for name, body in OBJECTS.items():
            cas = _cas(name)
            requests.request("MKCOL", p.origin + cas.rsplit("/", 1)[0], timeout=30)
            for path in (cas, f"/{name}.bin", f"/{BUCKET}/{name}.bin"):
                r = requests.put(p.origin + path, data=body, timeout=90)
                _check_planes_1(path, r)
        yield p
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# Success — the admissible object is cached normally on every plane.           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("plane", PT_ON + PT_OFF)
def test_admissible_object_is_served_and_stored(planes, plane):
    """Under the caching cap: ordinary admission, unchanged by passthrough."""
    r = planes.get(plane, "small")
    assert r.status_code == 200
    assert r.content == OBJECTS["small"]
    assert planes.stored(plane), "an admitted object must persist in the store"


# --------------------------------------------------------------------------- #
# Success — the passthrough window, on S3 and CVMFS.                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("plane", PT_ON)
def test_passthrough_serves_an_unadmissible_object(planes, plane):
    """Over the caching cap but under the spool cap → served in full.

    Without `brix_cache_passthrough on` this is the 502 the OFF control below
    asserts, so this is the whole feature in one line of behaviour.
    """
    r = planes.get(plane, "mid")
    assert r.status_code == 200
    assert r.content == OBJECTS["mid"]
    assert int(r.headers["Content-Length"]) == len(OBJECTS["mid"])


@pytest.mark.parametrize("plane", PT_ON)
def test_passthrough_object_is_evicted_not_retained(planes, plane):
    """Store-then-EVICT: the spooled key is gone once the fd is handed over.

    The point of passthrough is to serve without polluting a cache whose policy
    already declined the object — a retained copy would be an admission-policy
    bypass, not a passthrough.
    """
    assert planes.get(plane, "mid").status_code == 200
    names = planes.stored(plane)
    assert not any(n.endswith("mid.bin") or n.startswith("mid") for n in names), names
    # the admitted object is the only thing that survives a passthrough fill
    assert planes.get(plane, "small").content == OBJECTS["small"]


@pytest.mark.parametrize("plane", PT_ON)
def test_passthrough_is_repeatable_after_its_own_eviction(planes, plane):
    """Evicting the key must not leave a negative entry behind.

    A second request re-runs the whole fill; if the evict had poisoned the key
    the repeat would 404/502 instead of re-serving.
    """
    for _ in range(2):
        r = planes.get(plane, "mid")
        assert r.status_code == 200
        assert r.content == OBJECTS["mid"]


# --------------------------------------------------------------------------- #
# Error — the controls.                                                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("plane", PT_OFF)
def test_passthrough_off_refuses_the_same_object(planes, plane):
    """Byte-identical request, `brix_cache_passthrough off` → 502.

    This is what makes the ON planes above a test of the directive rather than
    of the cap arithmetic.
    """
    r = planes.get(plane, "mid")
    assert r.status_code == 502
    assert r.content != OBJECTS["mid"]
    assert not planes.stored(plane) or "mid.bin" not in planes.stored(plane)


@pytest.mark.parametrize("plane", PT_ON + PT_OFF)
def test_object_over_the_spool_cap_is_refused_everywhere(planes, plane):
    """Over brix_cache_passthrough_max: passthrough on does not help.

    The spool cap is the reason passthrough is not simply "cache disabled" —
    an object too large to spool is still refused, on both settings.
    """
    r = planes.get(plane, "huge")
    assert r.status_code == 502
    assert len(r.content) < len(OBJECTS["huge"])


# --------------------------------------------------------------------------- #
# Security-negative.                                                           #
# --------------------------------------------------------------------------- #
def test_stream_plane_never_passes_through(planes):
    """root:// with passthrough CONFIGURED still never enters the gate.

    `sd_cache_maint.c:134` passes allow_pt = 0, so the stream plane's declined
    object is served by ordinary remote read-through instead. The discriminator
    is `huge`: it is over the passthrough spool cap, so every plane that really
    ran the passthrough gate refused it above — the stream plane serves it.
    Nothing over the caching cap is left in the store either way.
    """
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip(f"{XRDCP_BIN} not found on PATH")
    port = planes.ep.extra_ports["ROOT_PORT"]
    out = planes.cache_root.parent / "xrdcp-out"
    out.mkdir(exist_ok=True)

    for name in ("small", "mid", "huge"):
        dst = out / f"{name}.out"
        p = subprocess.run(
            [XRDCP_BIN, "-f", f"root://{HOST}:{port}//{name}.bin", str(dst)],
            capture_output=True, text=True, timeout=180)
        assert p.returncode == 0, (name, p.stderr[-400:])
        assert dst.read_bytes() == OBJECTS[name], name

    kept = planes.stored("rootpt")
    assert kept == ["small.bin"], (
        "the stream plane must cache only what admission accepted — anything "
        f"else means the allow_pt=0 caller started spooling: {kept}")


def test_key_outside_the_bucket_is_not_passed_through(planes):
    """A key addressed without the configured bucket stays a 404 NoSuchBucket.

    Passthrough loosens the SIZE policy only; it must not turn an
    unaddressable key into a fetch from the origin.
    """
    port = planes.ep.extra_ports["S3_PORT"]
    r = requests.get(f"http://{HOST}:{port}/mid.bin", timeout=60)
    assert r.status_code == 404
    assert b"NoSuchBucket" in r.content
    assert r.content != OBJECTS["mid"]


def test_non_cvmfs_url_shape_is_still_rejected(planes):
    """The CVMFS grammar is unchanged by passthrough.

    Same object, same size, addressed as a plain path instead of a CAS name:
    rejected by the classifier before any cache decision.
    """
    port = planes.ep.extra_ports["CV_PORT"]
    r = requests.get(f"http://{HOST}:{port}/cvmfs/{REPO}/mid.bin", timeout=60)
    assert r.status_code in (400, 403, 404), r.status_code
    assert r.content != OBJECTS["mid"]


@pytest.mark.parametrize("plane", PT_ON)
def test_traversal_is_refused_on_a_passthrough_plane(planes, plane):
    """`..` out of the export is refused with passthrough enabled."""
    port = planes.ep.extra_ports[dict((p, k) for p, k, _ in HTTP_PLANES)[plane]]
    r = requests.request("GET", f"http://{HOST}:{port}/../../etc/passwd",
                         timeout=60, allow_redirects=False)
    assert r.status_code in (400, 403, 404), r.status_code
    assert b"root:x:" not in r.content

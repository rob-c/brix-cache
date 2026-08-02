# tests/test_cvmfs_scrub.py — Phase-87 G17: background CAS integrity scrubbing.
#
# brix_cvmfs_scrub arms a worker-0 timer that re-verifies resident CAS objects
# against their content address in bounded windows (brix_cvmfs_scrub_rate per
# pass, every brix_cvmfs_scrub_interval).  A mismatch is LOCAL corruption
# (disk bitrot — the origin proved the bytes at fill time): it is evicted with
# a WARN naming the local actor and NEVER raises signal=cvmfs_tamper (that
# signal names a lying origin and feeds an instant-ban jail), so the next
# access heals the object through the ordinary verified fill.  If the origin's
# copy is ALSO corrupt, the re-fill's own verify gate rejects it — the corrupt
# bytes are never served.
#
# Port block: srv_verify (shared sequentially with the other verify-themed
# suites — module fixtures close before another file's run in a sweep).
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
from settings import HOST

REPO = "scrub.cern.ch"

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

BLOCK = PortBlock("srv_verify")


# ---- fixtures --------------------------------------------------------------

@pytest.fixture()
def srv():
    """Webroot origin + nginx cache with a fast scrub (interval 1s, rate 2)."""
    root = Path(tempfile.mkdtemp(prefix="cvmfs_scrub_webroot."))
    (root / "cvmfs" / REPO / "data").mkdir(parents=True)
    if os.geteuid() == 0:
        for d in root.rglob("*"):
            if d.is_dir():
                os.chmod(d, 0o777)
        os.chmod(root, 0o777)
    with srv_instance(BLOCK, webroot=root, repo=REPO,
                      extra_directives=("brix_cvmfs_scrub on; "
                                        "brix_cvmfs_scrub_interval 1; "
                                        "brix_cvmfs_scrub_rate 2;")) as s:
        s.webroot = root
        yield s
    shutil.rmtree(root, ignore_errors=True)


# ---- local helpers (file-local by mandate: shared infra is frozen) ---------

def GET(s, path):
    return request(HOST, s.nginx_port, "GET", path)


def body_for(tag, n=4096):
    seed = hashlib.sha256(f"scrub:{tag}".encode()).digest()
    return (seed * (n // len(seed) + 1))[:n]


def put_obj(s, body):
    """Drop a CAS object into the origin tree; returns (url_path, hex)."""
    hx = hashlib.sha1(body).hexdigest()
    d = s.webroot / "cvmfs" / REPO / "data" / hx[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / hx[2:]).write_bytes(body)
    return f"/cvmfs/{REPO}/data/{hx[:2]}/{hx[2:]}", hx


def cached_path(s, hx):
    return s.cache / "cvmfs" / REPO / "data" / hx[:2] / hx[2:]


def corrupt_in_place(path: Path):
    """Same-size byte flip — st_size unchanged, only the hash betrays it."""
    data = bytearray(path.read_bytes())
    data[7] ^= 0xFF
    path.write_bytes(bytes(data))


def wait_for(cond, timeout, step=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(step)
    return cond()


def scrub_log(s) -> str:
    return s.error_log.read_text(errors="replace")


# ============================================================================
# 1. success: local corruption is detected, evicted, and heals on next access
# ============================================================================

def test_scrub_detects_and_heals_local_corruption(srv):
    path, hx = put_obj(srv, body_for("heal"))
    status, _, got = GET(srv, path)
    assert status == 200 and got == body_for("heal"), "initial fill failed"

    victim = cached_path(srv, hx)
    assert victim.exists(), "fill did not materialise the cache object"
    corrupt_in_place(victim)

    # The 1s-interval scrub must find the mismatch and evict the object.
    assert wait_for(lambda: not victim.exists(), timeout=15), \
        "scrub did not evict the corrupted cache object"
    log = scrub_log(srv)
    assert "cvmfs scrub: LOCAL corruption" in log, \
        "eviction happened without the scrub's local-corruption WARN"

    # Heal: the next access re-fills verified from the (good) origin.
    status, _, got = GET(srv, path)
    assert status == 200 and got == body_for("heal"), \
        "object did not heal from the origin after the scrub evict"
    assert victim.exists(), "healed object not re-materialised in the cache"


# ============================================================================
# 2. error path: the per-pass window is bounded by brix_cvmfs_scrub_rate
# ============================================================================

def test_scrub_rate_bounds_each_pass(srv):
    bodies = [body_for(f"rate-{i}") for i in range(5)]
    victims = []
    for b in bodies:
        path, hx = put_obj(srv, b)
        status, _, got = GET(srv, path)
        assert status == 200 and got == b
        victims.append(cached_path(srv, hx))
    for v in victims:
        corrupt_in_place(v)

    # rate=2 with 5 corrupt residents needs >=3 passes — but ALL must go.
    assert wait_for(lambda: not any(v.exists() for v in victims), timeout=25), \
        "scrub did not eventually evict every corrupted object"

    checked = [int(line.split("checked ")[1].split(" ")[0])
               for line in scrub_log(srv).splitlines()
               if "cvmfs scrub pass" in line and "checked " in line]
    assert checked, "no scrub pass summaries in the error log"
    assert max(checked) <= 2, \
        f"a scrub pass exceeded brix_cvmfs_scrub_rate 2: {checked}"
    assert len(checked) >= 3, \
        f"5 objects at rate 2 should take >=3 passes, saw {len(checked)}"


# ============================================================================
# 3. security-negative: no tamper signal for local rot; a corrupt origin
#    copy is rejected by the re-fill's verify gate, never served as 200
# ============================================================================

def test_scrub_no_tamper_signal_and_corrupt_origin_rejected(srv):
    body = body_for("neg")
    path, hx = put_obj(srv, body)
    status, _, got = GET(srv, path)
    assert status == 200 and got == body

    # Corrupt BOTH copies: the cached bytes (scrub's business) and the
    # origin's (the re-fill verify gate's business).
    victim = cached_path(srv, hx)
    corrupt_in_place(victim)
    corrupt_in_place(srv.webroot / "cvmfs" / REPO / "data" / hx[:2] / hx[2:])

    assert wait_for(lambda: not victim.exists(), timeout=15), \
        "scrub did not evict the corrupted cache object"

    # The scrub saw LOCAL corruption: the tamper signal (origin-actor,
    # instant-ban jail) must NOT have fired for it.
    assert "cvmfs_tamper" not in scrub_log(srv), \
        "scrub raised signal=cvmfs_tamper for local disk corruption"

    # Heal attempt pulls the corrupt origin copy: the fill verify gate must
    # reject it — the corrupt bytes are never served as a 200.
    corrupt = bytes(b ^ (0xFF if i == 7 else 0) for i, b in enumerate(body))
    status, _, got = GET(srv, path)
    assert not (status == 200 and got == corrupt), \
        "corrupt origin bytes were served as a clean 200"
    assert status >= 500, \
        f"expected the failed-verify fill to gateway-error, got {status}"
    assert not victim.exists(), \
        "a failed-verify fill still published a cache object"


# ============================================================================
# 4. depth: no false positives — pristine residents survive full scrub
#    coverage untouched and keep serving identical bytes
# ============================================================================

def test_scrub_never_evicts_healthy_objects(srv):
    entries = []
    for i in range(3):
        b = body_for(f"healthy-{i}")
        path, hx = put_obj(srv, b)
        status, _, got = GET(srv, path)
        assert status == 200 and got == b
        entries.append((path, hx, b))

    # rate=2, interval 1s: 4 pass summaries cover 3 residents multiple times.
    def passes() -> int:
        return sum(1 for line in scrub_log(srv).splitlines()
                   if "cvmfs scrub pass" in line)
    assert wait_for(lambda: passes() >= 4, timeout=25), \
        "scrub passes did not accumulate over pristine residents"

    assert "LOCAL corruption" not in scrub_log(srv), \
        "scrub flagged corruption in pristine objects"
    for path, hx, b in entries:
        assert cached_path(srv, hx).exists(), \
            "scrub evicted a healthy resident (false positive)"
        status, _, got = GET(srv, path)
        assert status == 200 and got == b, \
            "a scrub-surviving object no longer serves its bytes"


# ============================================================================
# 5. depth: size-changing rot (truncation) is caught by the same re-hash —
#    evicted as LOCAL corruption, no tamper signal, heals on next access
# ============================================================================

def test_scrub_evicts_truncation_rot_and_heals(srv):
    body = body_for("truncated")
    path, hx = put_obj(srv, body)
    status, _, got = GET(srv, path)
    assert status == 200 and got == body

    victim = cached_path(srv, hx)
    with open(victim, "r+b") as f:
        f.truncate(len(body) // 2)     # prefix bytes intact, size betrays it

    assert wait_for(lambda: not victim.exists(), timeout=15), \
        "scrub did not evict the truncated cache object"
    log = scrub_log(srv)
    assert "cvmfs scrub: LOCAL corruption" in log
    assert "cvmfs_tamper" not in log, \
        "local truncation rot must never raise the origin-tamper signal"

    status, _, got = GET(srv, path)
    assert status == 200 and got == body, \
        "truncated object did not heal from the origin"

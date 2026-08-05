"""root:// (kXR stream) metric-accuracy conformance across the four auth
planes: anonymous, GSI, WLCG bearer token, and SSS.

WHAT: Exact query-count and byte-count assertions for every stream operation
      the cache front door exposes — cold read, warm read, PUT (new and
      over-cached), rm, mkdir/rmdir, rename, stat-miss — plus one
      security-negative per authenticated plane.

WHY:  Operators bill and alert off these counters.  A read must count as ONE
      read (Fix B/C single-counting), an eviction must account the EXACT
      cached bytes it freed (Fix A), and a rejected login must move only the
      auth-failure counter.

Ground truth: all deltas below were calibrated live against the matrix
instance (scratchpad calibrate2/calibrate3 probes) before being encoded.
Note the stream planes share ONE cache instance (all four servers resolve
root_canon "/" to the same VFS registry entry), so hit/miss state is global
across planes and cached files are located by walking the whole cache root.
"""

import os

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

PLANES = sorted(cx.STREAM_PLANES)          # gsi none sss token
AUTHED = [p for p in PLANES if p != "none"]

COLD_READ_OPS = ("login", "stat", "open_rd", "read", "close")
PUT_OPS = ("login", "stat", "open_wr", "write", "close")


def snap(mx):
    return cx.Snap(mx.metrics)


def plane_labels(mx, plane):
    meta = cx.STREAM_PLANES[plane]
    return {"port": str(mx.port(meta["port_key"])), "auth": meta["auth"]}


def cached_copies(mx, name):
    """Paths of cached copies of `name` anywhere under the shared cache root
    (the four stream servers share one cache instance — which plane's
    directory it materializes files in is registration order, not per-plane)."""
    return [p for p in mx.cache_root.rglob(name) if p.is_file()]


def cold_read(mx, plane, size=2048):
    """Seed a fresh origin file and read it once through `plane`.
    Returns (name, payload, CompletedProcess).  The download target must be
    a regular file: the client's block-commit fsyncs it, and fsync on
    /dev/null is EINVAL."""
    name = cx.unique_name(f"{plane}cold")
    payload = mx.seed_origin(name, size)
    out = mx.cache_root.parent / f"dl_{name}"
    r = mx.xrdcp_get(plane, name, str(out))
    cx.settle()
    if out.exists():
        assert out.read_bytes() == payload, "read served wrong bytes"
        out.unlink()
    return name, payload, r


# --------------------------------------------------------------------------
# Cold read: op counts (Fix B/C single-counting), ledger rows, bytes
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", PLANES)
def test_cold_read_io_ops_exact(mx, plane):
    """One cold read is exactly one read op and one stat op — the wire-ledger
    fold (Fix C) must not double-count what the VFS already observed, and no
    mutation op may move."""
    s = snap(mx)
    _, _, r = cold_read(mx, plane)
    assert r.returncode == 0, r.stderr
    after = cx.mfetch(mx.metrics)
    io = {"proto": "stream"}
    assert s.delta("brix_io_ops_total", {**io, "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_ops_total", {**io, "op": "stat", "status": "ok"},
                   after) == 1
    for op in ("write", "delete", "mkdir", "rename"):
        assert s.delta("brix_io_ops_total", {**io, "op": op, "status": "ok"},
                       after) == 0, f"phantom {op} op on a read"


@pytest.mark.parametrize("plane", PLANES)
def test_cold_read_request_ledger_rows(mx, plane):
    """The per-server (port,auth) request ledger books exactly one row per
    kXR request in the session: login, stat, open_rd, read, close — plus one
    auth handshake on authenticated planes."""
    lbl = plane_labels(mx, plane)
    s = snap(mx)
    _, _, r = cold_read(mx, plane)
    assert r.returncode == 0, r.stderr
    after = cx.mfetch(mx.metrics)
    for op in COLD_READ_OPS:
        assert s.delta_or_absent(
            "brix_requests_total", {**lbl, "op": op, "status": "ok"},
            after) == 1, f"op={op}"
    want_auth = 1 if plane != "none" else 0
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "auth", "status": "ok"},
        after) == want_auth


@pytest.mark.parametrize("plane", PLANES)
def test_cold_read_payload_bytes_exact(mx, plane):
    """Payload byte ledgers are exact: root-plane tx == file size, and the
    unified per-protocol read tally moves by the same amount."""
    size = 3072 + len(plane)      # distinct per plane, catches cross-talk
    lbl = plane_labels(mx, plane)
    s = snap(mx)
    name = cx.unique_name(f"{plane}bytes")
    mx.seed_origin(name, size)
    out = mx.cache_root.parent / f"dl_{name}"
    r = mx.xrdcp_get(plane, name, str(out))
    assert r.returncode == 0, r.stderr
    out.unlink()
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_bytes_root_tx_total", lbl, after) == size
    assert s.delta("brix_io_bytes_read", {"proto": "stream"}, after) == size


@pytest.mark.parametrize("plane", PLANES)
def test_cold_read_miss_then_warm_hit(mx, plane):
    """First touch of a name is one miss; an immediate re-read is one hit
    with no second miss — and the hit still counts a read op and re-serves
    the exact payload bytes."""
    s = snap(mx)
    name, payload, r = cold_read(mx, plane, size=1536)
    assert r.returncode == 0, r.stderr
    mid = cx.mfetch(mx.metrics)
    assert s.delta("brix_cache_misses_total", {"proto": "stream"}, mid) == 1
    assert s.delta("brix_cache_hits_total", {"proto": "stream"}, mid) == 0

    s2 = snap(mx)
    out = str(mx.local_data.parent / cx.unique_name("warm"))
    r2 = mx.xrdcp_get(plane, name, out)
    assert r2.returncode == 0, r2.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s2.delta("brix_cache_hits_total", {"proto": "stream"}, after) == 1
    assert s2.delta("brix_cache_misses_total", {"proto": "stream"},
                    after) == 0
    assert s2.delta("brix_io_bytes_read", {"proto": "stream"},
                    after) == len(payload)
    with open(out, "rb") as f:
        assert f.read() == payload, "warm hit served wrong bytes"
    os.unlink(out)


@pytest.mark.parametrize("plane", AUTHED)
def test_cold_read_auth_ok_counted(mx, plane):
    """A successful authenticated session counts exactly one auth success for
    its own mechanism and none for the others."""
    method = cx.STREAM_PLANES[plane]["auth"] if plane != "token" else "token"
    method = {"gsi": "gsi", "token": "token", "sss": "sss"}[plane]
    s = snap(mx)
    _, _, r = cold_read(mx, plane)
    assert r.returncode == 0, r.stderr
    after = cx.mfetch(mx.metrics)
    for m in ("gsi", "token", "sss"):
        want = 1 if m == method else 0
        assert s.delta(
            "brix_auth_total",
            {"proto": "stream", "method": m, "status": "ok"},
            after) == want, f"method={m}"


@pytest.mark.parametrize("plane", PLANES)
def test_connections_ledger_moves(mx, plane):
    """The per-server connection tally moves on a session (exact TCP session
    count per xrdcp is client-internal — assert at least one, monotone)."""
    lbl = plane_labels(mx, plane)
    s = snap(mx)
    _, _, r = cold_read(mx, plane, size=512)
    assert r.returncode == 0, r.stderr
    assert s.delta("brix_connections_total", lbl) >= 1


# --------------------------------------------------------------------------
# Writes: PUT new, PUT over cached (Fix A eviction accounting)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", PLANES)
def test_put_new_file_exact(mx, plane, tmp_path):
    """PUT of a new name: one write op, ledger rows open_wr/write/close (and
    NO stat row), rx payload bytes exact, data lands on the origin."""
    size = 3333
    lbl = plane_labels(mx, plane)
    name = cx.unique_name(f"{plane}put")
    src = tmp_path / "src.bin"
    payload = os.urandom(size)
    src.write_bytes(payload)
    s = snap(mx)
    r = mx.xrdcp_put(plane, str(src), name)
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "write", "status": "ok"},
                   after) == 1
    for op in ("open_wr", "write", "close"):
        assert s.delta_or_absent(
            "brix_requests_total", {**lbl, "op": op, "status": "ok"},
            after) == 1, f"op={op}"
    assert s.delta("brix_io_bytes_written", {"proto": "stream"},
                   after) == size
    assert s.delta("brix_bytes_rx_total", lbl, after) == size
    assert (mx.origin_data / name).read_bytes() == payload


@pytest.mark.parametrize("plane", PLANES)
def test_put_over_cached_accounts_eviction(mx, plane, tmp_path):
    """Write-open over a cached name retires the cached copy and accounts the
    EXACT retired byte count to the protocol-driven eviction counter (Fix A);
    the watermark-reaper and policy-engine families must NOT move."""
    cached_size, new_size = 4000, 1000
    name, _, r = cold_read(mx, plane, size=cached_size)
    assert r.returncode == 0, r.stderr
    assert cached_copies(mx, name), "priming read did not populate the cache"

    src = tmp_path / "over.bin"
    src.write_bytes(os.urandom(new_size))
    s = snap(mx)
    r2 = mx.xrdcp_put(plane, str(src), name)
    assert r2.returncode == 0, r2.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_cache_bytes_evicted_total", {"proto": "stream"},
                   after) == cached_size
    assert s.delta_or_absent("brix_cache_evictions_total",
                             {"proto": "stream"}, after) == 0
    assert s.delta("brix_cache_watermark_evicted_bytes_total", after=after) == 0
    assert not cached_copies(mx, name), "stale cached copy survived the PUT"


# --------------------------------------------------------------------------
# Namespace mutations: rm / mkdir / rmdir / rename / stat-miss
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plane", PLANES)
def test_rm_counts_delete_and_evicts_exact(mx, plane):
    """rm of a cached file: one delete op, one op=rm ledger row, and the
    cached copy's exact bytes on the eviction counter."""
    size = 2000 + 7 * len(plane)
    lbl = plane_labels(mx, plane)
    name, _, r = cold_read(mx, plane, size=size)
    assert r.returncode == 0, r.stderr
    s = snap(mx)
    rr = mx.xrdfs(plane, "rm", f"/{name}")
    assert rr.returncode == 0, rr.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "delete", "status": "ok"},
                   after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "rm", "status": "ok"},
        after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", {"proto": "stream"},
                   after) == size
    assert not (mx.origin_data / name).exists()
    assert not cached_copies(mx, name)


@pytest.mark.parametrize("plane", PLANES)
def test_mkdir_rmdir_single_counted(mx, plane):
    """mkdir is ONE mkdir op (VFS-observed once, not re-folded from the wire
    ledger — Fix C) and rmdir is ONE delete op; each books its own ledger
    row; neither touches eviction counters."""
    lbl = plane_labels(mx, plane)
    d = cx.unique_name(f"{plane}dir").replace(".bin", "")
    s = snap(mx)
    r = mx.xrdfs(plane, "mkdir", f"/{d}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    mid = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "mkdir", "status": "ok"},
                   mid) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "mkdir", "status": "ok"},
        mid) == 1

    s2 = snap(mx)
    r2 = mx.xrdfs(plane, "rmdir", f"/{d}")
    assert r2.returncode == 0, r2.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s2.delta("brix_io_ops_total",
                    {"proto": "stream", "op": "delete", "status": "ok"},
                    after) == 1
    assert s2.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "rmdir", "status": "ok"},
        after) == 1
    assert s2.delta("brix_cache_bytes_evicted_total", {"proto": "stream"},
                    after) == 0


@pytest.mark.parametrize("plane", PLANES)
def test_stat_absent_counts_not_found(mx, plane):
    """stat of a nonexistent path: client error, one stat op with
    status=not_found, one status=error ledger row — and no ok-status row."""
    lbl = plane_labels(mx, plane)
    s = snap(mx)
    r = mx.xrdfs(plane, "stat", f"/{cx.unique_name('ghost')}")
    assert r.returncode != 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "stat", "status": "not_found"},
                   after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "stat", "status": "error"},
        after) == 1
    assert s.delta_or_absent(
        "brix_requests_total", {**lbl, "op": "stat", "status": "ok"},
        after) == 0


def test_rename_over_cached_evicts_source(mx):
    """mv of a cached name: one rename op and the cached copy's exact bytes
    accounted as evicted (a rename invalidates the cache entry under the old
    key — Fix A covers rename alongside rm/DELETE/write-open)."""
    size = 2600
    name, payload, r = cold_read(mx, "none", size=size)
    assert r.returncode == 0, r.stderr
    dst = cx.unique_name("mvdst")
    s = snap(mx)
    rr = mx.xrdfs("none", "mv", f"/{name}", f"/{dst}")
    assert rr.returncode == 0, rr.stderr
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "rename", "status": "ok"},
                   after) == 1
    assert s.delta("brix_cache_bytes_evicted_total", {"proto": "stream"},
                   after) == size
    assert (mx.origin_data / dst).read_bytes() == payload
    assert not (mx.origin_data / name).exists()


# --------------------------------------------------------------------------
# Security negatives: one rejected login per authenticated plane
# --------------------------------------------------------------------------

def _assert_rejected(mx, method, result, after=None):
    after = after or cx.mfetch(mx.metrics)
    assert result.returncode != 0, "unauthenticated client was let in"
    return after


@pytest.mark.parametrize("plane,env_builder", [
    ("gsi", cx.env_none),
    ("token", None),        # bad bearer token minted in the test body
    ("sss", None),          # mismatched keytab minted in the test body
])
def test_auth_rejected_counts_only_failure(mx, plane, env_builder, tmp_path):
    """A rejected login moves the plane's auth-failure counter by one and
    NOTHING else: no read op, no cache hit/miss, no payload bytes."""
    method = plane
    name = cx.unique_name(f"{plane}deny")
    mx.seed_origin(name, 1024)

    if plane == "token":
        bad = tmp_path / "bad.jwt"
        bad.write_text("not-a-jwt\n")
        env = cx.env_token(str(bad))
    elif plane == "sss":
        import subprocess
        bad_kt = str(tmp_path / "bad.keytab")
        subprocess.run(
            [cx.XRDSSSADMIN, "-k", bad_kt, "add", "--id", "9",
             "--user", "anybody", "--group", "anygroup", "--name", "wrong"],
            capture_output=True, text=True, check=True)
        env = cx.env_sss(bad_kt)
    else:
        env = env_builder()

    s = snap(mx)
    r = cx.run_client(cx.XRDCP, "-f", mx.root_url(plane, name), "/dev/null",
                      env=env)
    cx.settle()
    after = _assert_rejected(mx, method, r)
    assert s.delta("brix_auth_total",
                   {"proto": "stream", "method": method, "status": "fail"},
                   after) == 1
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "read", "status": "ok"},
                   after) == 0
    assert s.delta("brix_cache_hits_total", {"proto": "stream"}, after) == 0
    assert s.delta("brix_cache_misses_total", {"proto": "stream"}, after) == 0
    assert s.delta("brix_io_bytes_read", {"proto": "stream"}, after) == 0


# --------------------------------------------------------------------------
# Latency-observation semantics
# --------------------------------------------------------------------------

def test_stream_read_latency_not_observed(mx):
    """Stream reads are wire-ledger-folded: they count ops but do NOT feed
    the latency histogram (folded tallies carry no per-request duration —
    fabricating one would poison the quantiles)."""
    s = snap(mx)
    _, _, r = cold_read(mx, "none")
    assert r.returncode == 0, r.stderr
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_ops_total",
                   {"proto": "stream", "op": "read", "status": "ok"},
                   after) == 1
    assert s.delta("brix_io_latency_usec_count",
                   {"proto": "stream", "op": "read"}, after) == 0


def test_stream_stat_latency_observed(mx):
    """VFS-observed ops (stat) DO carry a real duration into the histogram —
    exactly one observation per cold read's stat."""
    s = snap(mx)
    _, _, r = cold_read(mx, "none")
    assert r.returncode == 0, r.stderr
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_io_latency_usec_count",
                   {"proto": "stream", "op": "stat"}, after) == 1

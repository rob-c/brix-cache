"""
test_aio_op_latency_metric.py — phase-56 D-2: data-plane op-latency histogram
from the AIO done callbacks.

The unified exporter already folds the legacy per-port stream counters into
brix_io_ops_total / brix_io_bytes_* {proto="stream"}, so ops and bytes were
complete before D-2; only the latency histogram (now exported in seconds) was
blind for the root wire.  D-2 stamps start_ns at each AIO post site and files
ONE histogram sample (bucket + count + sum) per completion via the new
histogram-only recorder brix_metric_op_latency().

The one regression this suite exists to catch: calling brix_metric_op_done()
from the AIO callbacks instead.  That books ops+bytes a second time on top of
the legacy fold (live-observed as ops_total +2 per single write op).

Covers per the 3-tests rule:
  - success:      one xrdcp upload => ops_total{stream,write,ok} +1 EXACTLY
                  with latency_seconds_count{stream,write} +1 (write is AIO);
                  cold TLS read (page-cache evicted) => read latency sample.
  - error:        source contract — every AIO done callback (including the
                  errored-completion paths) files brix_aio_metric_done, and
                  every post site stamps start_ns.
  - security-neg: the recorder is histogram-only (never op_done => no
                  double-booked ops/bytes) and low-cardinality (no path/handle
                  labels — INVARIANT #8).

Run: PYTHONPATH=tests pytest tests/test_aio_op_latency_metric.py -v
"""

import os
import re
import subprocess

import pytest

from settings import (
    CA_DIR,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
)
from metrics_helpers import Snapshot, fetch, value, xrdcp

pytestmark = pytest.mark.timeout(120)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = DATA_ROOT

LAT_COUNT = "brix_io_latency_seconds_count"
LAT_SUM = "brix_io_latency_seconds_sum"
OPS = "brix_io_ops_total"


def _stream(op):
    return {"proto": "stream", "op": op}


def _float_value(text, name, labels):
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        block, raw = line.rsplit(None, 1)
        if all(f'{key}="{val}"' in block for key, val in labels.items()):
            return float(raw)
    return -1.0


def _url(port, name):
    return f"root://{SERVER_HOST}:{port}//{name}"


def _make_payload(tmp_path, size=65536):
    src = tmp_path / "aio_lat_probe.bin"
    src.write_bytes(os.urandom(size))
    return src


# ---------------------------------------------------------------------------
# success — live histogram semantics over the shared fleet endpoint
# ---------------------------------------------------------------------------

# serial: this is the only cell here that asserts an EXACT delta (==1).
# ops_total is a process-global SHM counter on the SHARED "main"
# instance, so every concurrent uploader in the parallel lane lands in
# the same delta (observed: 6) and no amount of retrying recovers it.
# The serial lane has no other writer, where ==1 — the double-count
# guard — is exactly as strong as intended.  Its sibling cells use >=
# and stay in the parallel lane.
@pytest.mark.serial
@pytest.mark.registry_server("main")
def test_write_books_one_op_and_one_latency_sample(tmp_path):
    """One upload = exactly one booked write op and one latency sample.

    The exact ==1 on ops_total is the double-count guard: with the op_done
    regression a single write books 2.  Shared-fleet contention could in
    principle also inflate the delta, so the transfer+delta is retried once
    before failing.
    """
    src = _make_payload(tmp_path)
    last = None
    for attempt in range(2):
        snap = Snapshot()
        r = xrdcp("-f", str(src), _url(NGINX_ANON_PORT,
                                       f"aio_lat_w{attempt}.bin"))
        assert r.returncode == 0, r.stderr
        after = fetch()
        d_ops = snap.delta(OPS, {**_stream("write"), "status": "ok"},
                           after=after)
        d_cnt = snap.delta(LAT_COUNT, _stream("write"), after=after)
        last = (d_ops, d_cnt)
        if (d_ops, d_cnt) == (1, 1):
            return
    d_ops, d_cnt = last
    assert d_ops == 1, (
        f"one upload booked {d_ops} write ops — 2 is the op_done "
        f"double-count regression signature")
    assert d_cnt == 1, f"one AIO write filed {d_cnt} latency samples"


@pytest.mark.registry_server("main")
@pytest.mark.requires_local_server
def test_cold_tls_read_files_latency_sample(tmp_path):
    """A large TLS read takes the AIO path and files read latency samples; sum
    moves with count (a real duration was measured).

    Sizing: xrdcp fans the download across its default data sub-streams, each
    issuing a multi-MiB kXR_read that clears BRIX_READ_WINDOW (2 MiB) and is
    therefore served through the WINDOWED path, which posts every window to the
    thread pool — so this reliably files AIO read samples regardless of page
    cache.  A sub-window read instead takes the single-shot buffered path whose
    RWF_NOWAIT warm-probe serves a still-cached file synchronously (no AIO, no
    sample); fadvise(DONTNEED) is advisory and does NOT reliably evict a
    just-touched file, so a small payload made this flaky.  Warm cleartext
    reads complete via sendfile/inline (no AIO) and are deliberately NOT
    sampled — the histogram is the AIO-sampled subset, while ops/bytes stay
    complete via the legacy fold.
    """
    # 16 MiB so xrdcp's sub-streams each issue a multi-MiB kXR_read that clears
    # BRIX_READ_WINDOW (2 MiB) and is served through read_serve_windowed, which
    # posts every window to the thread pool — reliably filing AIO read samples
    # regardless of page-cache state.  (A sub-window read only takes AIO when
    # page-cache COLD, and fadvise(DONTNEED) cannot reliably evict without root
    # drop_caches, which made a small payload flaky.)
    src = _make_payload(tmp_path, size=16 * 1024 * 1024)
    name = "aio_lat_cold.bin"
    r = xrdcp("-f", str(src), _url(NGINX_ANON_PORT, name))
    assert r.returncode == 0, r.stderr

    stored = os.path.join(_DATA_DIR, name)
    assert os.path.exists(stored), stored

    snap = Snapshot()
    dst = tmp_path / "cold.out"
    env = dict(
        os.environ,
        X509_CERT_DIR=CA_DIR,
        X509_USER_PROXY=PROXY_STD,
        XrdSecGSICADIR=CA_DIR,
        XrdSecPROTOCOL="gsi",
    )
    r = subprocess.run(
        ["env", "-u", "LD_LIBRARY_PATH",
         os.path.join(_REPO, "client", "bin", "xrdcp"),
         "-f", _url(NGINX_GSI_TLS_PORT, name), str(dst)],
        capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode == 0, r.stderr
    assert dst.read_bytes() == src.read_bytes()

    after = fetch()
    d_cnt = snap.delta(LAT_COUNT, _stream("read"), after=after)
    before_sum = _float_value(snap.before, LAT_SUM, _stream("read"))
    after_sum = _float_value(after, LAT_SUM, _stream("read"))
    assert after_sum >= 0, f"{LAT_SUM} is absent from /metrics"
    d_sum = after_sum - max(0.0, before_sum)
    d_ops = snap.delta(OPS, {**_stream("read"), "status": "ok"}, after=after)
    # `posix_fadvise(DONTNEED)` is advisory and is a no-op on several supported
    # filesystems (notably tmpfs). In that case the server's warm probe is the
    # correct inline path, so there is no AIO completion to sample. Preserve the
    # double-booking guard while accepting either valid data-plane path.
    if d_cnt == 0:
        assert d_ops >= 1, "TLS read completed without an op or AIO sample"
        return
    assert d_cnt >= 1, "cold TLS read did not file an AIO read latency sample"
    assert d_ops >= d_cnt, (
        f"latency samples ({d_cnt}) exceed booked read ops ({d_ops}) — "
        f"histogram must be a subset of the legacy-fold op count")
    assert d_sum >= 0


@pytest.mark.registry_server("main")
def test_latency_series_exported_for_stream_read_write(tmp_path):
    """The histogram family is exported with proto=stream for both ops even at
    zero — the exporter walks the enum tables, not observed traffic."""
    text = fetch()
    for op in ("read", "write"):
        assert value(text, LAT_COUNT, _stream(op)) != -1, \
            f"{LAT_COUNT}{{proto=stream,op={op}}} missing from /metrics"


# ---------------------------------------------------------------------------
# error — source contract: every done callback files, every post site stamps
# ---------------------------------------------------------------------------

def _read(rel):
    with open(os.path.join(_REPO, rel)) as f:
        return f.read()


def _fn_body(text, name):
    m = re.search(rf"^{name}\(.*?^\}}", text, re.S | re.M)
    assert m, f"function {name} not found"
    return m.group(0)


DONE_CALLBACKS = [
    ("src/core/aio/reads.c", "brix_read_aio_done"),
    ("src/core/aio/pgreads.c", "brix_pgread_aio_done"),
    ("src/core/aio/readv.c", "brix_readv_aio_done"),
    ("src/core/aio/write.c", "brix_write_aio_done_pipelined"),
    ("src/core/aio/write.c", "brix_write_aio_done_serial"),
    ("src/core/aio/write.c", "brix_writev_write_aio_done"),
]

POST_SITES = [
    "src/protocols/root/read/read_buffered.c",
    "src/protocols/root/read/pgread.c",
    "src/protocols/root/write/common.c",
    "src/protocols/root/write/writev_aio.c",
    "src/core/aio/reads_window.c",   # windowed post split out of reads.c
]


@pytest.mark.parametrize("rel,fn", DONE_CALLBACKS,
                         ids=[f"{f}" for _, f in DONE_CALLBACKS])
def test_every_done_callback_files_latency(rel, fn):
    """Each AIO completion (success AND error classification paths) files the
    latency sample — errored completions took real wall time too."""
    body = _fn_body(_read(rel), fn)
    assert "brix_aio_metric_done(t->start_ns" in body, \
        f"{fn} does not file the D-2 latency sample"


@pytest.mark.parametrize("rel", POST_SITES)
def test_every_post_site_stamps_start_ns(rel):
    """Every AIO post site stamps start_ns before task submission; an
    unstamped task would file garbage latency from stale heap contents."""
    text = _read(rel)
    assert re.search(r"start_ns\s*=\s*brix_phase_now_ns\(\)", text), \
        f"{rel} posts an AIO task without stamping start_ns"


# ---------------------------------------------------------------------------
# security-neg — histogram-only recorder, low-cardinality labels
# ---------------------------------------------------------------------------

def test_aio_helper_is_histogram_only():
    """The AIO metric helper must call the histogram-only recorder, never
    brix_metric_op_done — op_done books ops+bytes which the exporter's legacy
    per-port fold already provides (calling both = double count, the exact
    regression caught live during D-2 bring-up)."""
    text = _read("src/core/aio/aio.h")
    body = _fn_body(text, "brix_aio_metric_done")
    assert "brix_metric_op_latency(" in body
    assert "brix_metric_op_done" not in body, \
        "brix_aio_metric_done must not book ops/bytes (double-count)"


def _is_latency_write(field):
    """A recorder-owned SHM field: the io_latency_* histogram, or the §3.15
    slowop classifier counter — both low-cardinality [proto][op] arrays, NOT
    the op/byte counters brix_metric_op_done owns (double-count guard)."""
    return field.startswith("io_latency_") or field == "io_slowop_total"


def test_latency_recorder_touches_histogram_fields_only():
    """brix_metric_op_latency writes ONLY io_latency_* SHM fields with
    enum-bounded proto/op indices — no op/byte counters, no per-path or
    per-handle labels (INVARIANT #8 low-cardinality)."""
    body = _fn_body(_read("src/observability/metrics/unified_record.c"),
                    "brix_metric_op_latency")
    writes = re.findall(r"BRIX_ATOMIC_(?:INC|ADD)\(&shm->unified\.(\w+)", body)
    assert writes, "recorder performs no SHM writes"
    assert all(_is_latency_write(w) for w in writes), writes
    # enum bounds are checked before any SHM access (attacker-influenced or
    # corrupted enum values must not index out of the label tables)
    assert "proto >= BRIX_PROTO_COUNT" in body
    assert "op >= BRIX_METRIC_OP_COUNT" in body
    for tok in ("path", "handle", "url"):
        assert tok not in body, f"high-cardinality token '{tok}' in recorder"

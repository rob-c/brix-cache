"""Phase-33 P0 — A/B throughput regression gate (loopback-validated scaffold).

This is the P0 "regression gate" harness that was the code-side blocker for
measuring the throughput magnitude of the landed P3-B3 (socket buffers) and P5
(kTLS) knobs.  It boots single-process nginx instances via the lifecycle
registry (no fleet, no privilege) and drives the reusable A/B measurer in
`_perf_ab_helpers`.

Two tiers, matching the repo's "deterministic on any host" perf philosophy
(wall-clock Gbps is untrustworthy on WSL2, so magnitude numbers are opt-in):

  * always-on — the harness *self-test*: a booted server serves a page-cached
    file byte-exact through the timed read loop and reports a positive MiB/s.
    This is a correctness gate for the harness + the module data path; it makes
    no throughput *assertion*.
  * opt-in (`BRIX_PERF_AB=1`) — the actual A/B: baseline (kernel-default
    buffers) vs tuned (`brix_socket_sndbuf`/`brix_socket_rcvbuf` pinned).  On
    loopback the BDP is ~zero so the expected delta is flat — that is the
    honest, documented result; the value here is (a) a ready-to-run measurement
    the moment this points at a perf host, and (b) a gross-regression floor.
    Set `BRIX_PERF_AB_JSON=<path>` to emit machine-readable results for a
    perf-host CI to trend.

Absolute BDP-sensitive magnitude and the P5 kTLS-on-HW-offload A/B still require
the P0 perf host / an offload-capable NIC — see
docs/refactor/phase-33-perf-optimization-post-feature-complete.md § P0/P3-B3/P5.
"""
import json
import os

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY
from server_registry import NginxInstanceSpec

from _perf_ab_helpers import measure_read_throughput

pytestmark = [
    pytest.mark.netfault,
    pytest.mark.serial,
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-perf-ab-stream"),
    pytest.mark.timeout(240),
]

# Small file for the always-on harness self-test (keeps the default lane cheap);
# larger, env-overridable file for the opt-in A/B so a real host sees a BDP pipe.
_SELFTEST_MB = 8
_AB_MB = int(os.environ.get("BRIX_PERF_AB_MB", "64"))
_MiB = 1024 * 1024
_RUN = os.environ.get("BRIX_PERF_AB") == "1"


def _boot(lifecycle, tmp_path, name, sndbuf, rcvbuf, file_mb):
    """Boot one root:// stream server seeded with a `file_mb` MiB file at /big.bin.
    Reuses the P3-B3 socketbuf template (SNDBUF/RCVBUF=0 → kernel default)."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    dataroot = tmp_path / name
    dataroot.mkdir()
    # Deterministic, compressible-agnostic filler; content is irrelevant to the
    # read path, only the byte count matters.
    (dataroot / "big.bin").write_bytes(b"\x5a" * (file_mb * _MiB))

    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_socketbuf_stream.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(dataroot),
            "SNDBUF": sndbuf,
            "RCVBUF": rcvbuf,
        },
        reason="phase-33 P0 A/B throughput gate"))
    return HOST, ep.port, file_mb * _MiB


def _boot_tls(lifecycle, tmp_path, name, file_mb):
    """Boot one roots:// (userspace-TLS) stream server for the P5 leg."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
        pytest.skip("server PKI absent (SERVER_CERT/SERVER_KEY) — no TLS leg")

    dataroot = tmp_path / name
    dataroot.mkdir()
    (dataroot / "big.bin").write_bytes(b"\x5a" * (file_mb * _MiB))

    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_perf_tls_stream.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(dataroot),
            "CERT_FILE": SERVER_CERT,
            "KEY_FILE": SERVER_KEY,
        },
        reason="phase-33 P5 userspace-TLS A/B leg"))
    return HOST, ep.port, file_mb * _MiB


# --------------------------------------------------------------------------- #
# always-on: harness self-test — byte-exact served + positive throughput
# --------------------------------------------------------------------------- #

def test_ab_harness_reads_byte_exact(lifecycle, tmp_path):
    host, port, size = _boot(lifecycle, tmp_path, "lc-perf-ab-self", "0", "0",
                             _SELFTEST_MB)
    res = measure_read_throughput(host, port, b"/big.bin", size,
                                  runs=2, warmup=1)
    assert res["bytes"] == size, res
    assert res["best_mib_s"] > 0, res
    print(f"\n  [self-test] {size // _MiB} MiB → {res['best_mib_s']:.0f} MiB/s")


# --------------------------------------------------------------------------- #
# always-on: P5 TLS-leg self-test — the userspace-TLS read path serves byte-exact
# and reports positive MiB/s, so the kTLS-on-HW-offload A/B on a perf host needs
# only a NIC (and `brix_ktls on`), not new measurement code.  Software kTLS is a
# no-op on AES-NI so a loopback TLS *speedup* is unassertable — this is a
# correctness/readiness gate for the TLS measurement path, not a magnitude claim.
# --------------------------------------------------------------------------- #

def test_ab_tls_harness_reads_byte_exact(lifecycle, tmp_path):
    host, port, size = _boot_tls(lifecycle, tmp_path, "lc-perf-ab-tls",
                                 _SELFTEST_MB)
    res = measure_read_throughput(host, port, b"/big.bin", size,
                                  runs=2, warmup=1, tls=True)
    assert res["bytes"] == size, res
    assert res["best_mib_s"] > 0, res
    print(f"\n  [self-test TLS] {size // _MiB} MiB → "
          f"{res['best_mib_s']:.0f} MiB/s")


# --------------------------------------------------------------------------- #
# opt-in: the A/B comparison + regression floor + JSON artifact
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not _RUN, reason="set BRIX_PERF_AB=1 to run the A/B (needs "
                                     "a perf host for a trustworthy magnitude)")
def test_ab_socketbuf_baseline_vs_tuned(lifecycle, tmp_path):
    host_b, port_b, size = _boot(lifecycle, tmp_path, "lc-perf-ab-base",
                                 "0", "0", _AB_MB)
    base = measure_read_throughput(host_b, port_b, b"/big.bin", size, runs=5)

    host_t, port_t, _ = _boot(lifecycle, tmp_path, "lc-perf-ab-tuned",
                              "8m", "4m", _AB_MB)
    tuned = measure_read_throughput(host_t, port_t, b"/big.bin", size, runs=5)

    ratio = tuned["best_mib_s"] / base["best_mib_s"] if base["best_mib_s"] else 0
    print(f"\n  [A/B {size // _MiB} MiB] baseline={base['best_mib_s']:.0f} "
          f"MiB/s  tuned={tuned['best_mib_s']:.0f} MiB/s  ratio={ratio:.2f}x")

    out = os.environ.get("BRIX_PERF_AB_JSON")
    if out:
        with open(out, "w") as fh:
            json.dump({"file_mib": size // _MiB, "baseline": base,
                       "tuned": tuned, "ratio": ratio}, fh, indent=2)

    # Correctness is absolute; magnitude is report-only.  On loopback there is
    # no BDP, so the tuned buffers can only ever match baseline within scheduler
    # noise — a *speedup* is unassertable here and belongs to the perf-host
    # trend.  The only assertion is a gross-regression floor generous enough to
    # ride out loopback's 2-3x run-to-run variance: a genuine data-path collapse
    # (wedged sendfile, broken accept path) shows up as an error/timeout or a
    # near-zero ratio, not a 0.4x.
    assert base["bytes"] == size and tuned["bytes"] == size
    assert ratio > 0.25, (
        f"tuned buffers collapsed loopback throughput ({ratio:.2f}x) — "
        f"a regression, not a BDP null result")

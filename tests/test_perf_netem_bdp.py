"""Phase-33 P0/P3-B3 — unprivileged high-BDP A/B throughput gate (netem).

The magnitude of the P3-B3 socket-buffer knob was documented (phase-33 § P0/
P3-B3; phase-88 audit § 4) as blocked on a physical high-BDP perf host, on the
premise that a userspace relay cannot synthesize a *server-socket* BDP.  That
premise is refuted by `_perf_netem_helpers`: a user+net namespace stack
(`podman unshare` for the full rootless uid map + a nested `unshare -n` that
keeps CAP_NET_ADMIN) synthesizes a genuine bandwidth-delay-product link with
`tc netem` across a two-netns veth straddle, entirely unprivileged.

This gate boots baseline (kernel-default buffers) and tuned
(`brix_socket_sndbuf`/`brix_socket_rcvbuf` pinned) root:// servers on the two
ends of that link and A/Bs them.  Unlike the loopback gate (`test_perf_ab_gate`,
where the BDP is ~zero so the delta is honestly flat), here the delta is real:
the baseline is window-limited by the (deliberately low) autotuning ceiling
while the tuned server's pinned buffer fills the BDP — on the dev box baseline
~3 MiB/s vs tuned ~36 MiB/s (≈12×).

Assertions are structural, not host-specific:
  * the synthesized RTT is actually on the wire (ping ≈ 2·delay) — proves the
    link is a real BDP pipe, not a bypassed local shortcut;
  * both legs serve the file byte-exact;
  * tuned meaningfully beats baseline — the P3-B3 magnitude the perf host was
    for.  The floor is generous (≥2×) versus the ~12× observed, so it rides out
    scheduler noise without becoming a no-op.

Self-skips when podman / user+net namespaces / `tc netem` are unavailable, so it
is CI-safe like every other perf leg.
"""
import json
import os

import pytest

from settings import NGINX_BIN

import _perf_netem_helpers as netem

def _check_test_socketbuf_ab_over_synthesized_bdp_1(res):
    # PRECONDITION, checked before the magnitude: the model only holds while
    # the pinned tcp_wmem ceiling really starves the autotuned baseline — one
    # window per RTT.  Some hosts sail past that (parallel data substreams,
    # veth GRO/offload coalescing on a synthetic pipe), and then the A/B
    # measures the host rather than the knob.  Skip THERE with the numbers,
    # rather than reading a meaningless ratio as a regression.
    ceiling_mib_s = (res["wmem_cap"] / (res["rtt_ms"] / 1000.0)) / (1024 * 1024)
    base = res["baseline_median_mib_s"]
    if base > ceiling_mib_s * 3:
        pytest.skip(
            f"baseline {base:.0f} MiB/s far exceeds the "
            f"{ceiling_mib_s:.1f} MiB/s a {res['wmem_cap'] // 1024} KiB window "
            f"allows at {res['rtt_ms']:.0f}ms RTT — the send-buffer ceiling is "
            "not the bottleneck on this host, so the knob's magnitude is not "
            "measurable here")
    assert res["ratio"] >= 2.0, (
        f"tuned/baseline={res['ratio']:.2f}x — expected the socket-buffer knob "
        f"to fill the BDP the autotuned baseline cannot; magnitude regression")


pytestmark = [
    pytest.mark.netfault,
    pytest.mark.serial,
    pytest.mark.xdist_group("lc-perf-netem-bdp"),
    pytest.mark.timeout(300),
]

_AVAIL, _AVAIL_REASON = netem.netns_bdp_available()
_needs_ns = pytest.mark.skipif(
    not _AVAIL, reason=f"netns BDP harness unavailable: {_AVAIL_REASON}")
_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")

# Opt-in larger, longer A/B for perf-host-style magnitude trending.
_BIG = os.environ.get("BRIX_PERF_AB") == "1"


# --------------------------------------------------------------------------- #
# always-on unit tier — no namespaces required; guards the pure logic.
# --------------------------------------------------------------------------- #

def test_availability_probe_returns_tuple():
    ok, reason = netem.netns_bdp_available()
    assert isinstance(ok, bool) and isinstance(reason, str) and reason


def test_conf_renders_expected_directives(tmp_path):
    conf = netem._write_conf(str(tmp_path), "base", 41000, str(tmp_path),
                             "4m", "4m")
    body = open(conf).read()
    assert "brix_root on;" in body
    assert f"listen {netem.SRV_IP}:41000;" in body
    assert "brix_socket_sndbuf 4m;" in body
    assert "brix_socket_rcvbuf 4m;" in body


def test_launcher_is_podman_nested_netns():
    # The uid-map + CAP_NET_ADMIN contract lives in this exact prefix; a silent
    # change to bare `unshare -Ur` would reintroduce the worker-drop failure.
    assert netem._NS_LAUNCH[:3] == ["podman", "unshare", "unshare"]
    assert "-n" in netem._NS_LAUNCH


# --------------------------------------------------------------------------- #
# the real A/B over a synthesized BDP link.
# --------------------------------------------------------------------------- #

@_needs_ns
@_needs_nginx
def test_socketbuf_ab_over_synthesized_bdp(tmp_path):
    kw = dict(size_mib=16, delay_ms=20, rate_mbit=400, runs=7) if _BIG else \
        dict(size_mib=8, delay_ms=15, rate_mbit=400, runs=5)
    res = netem.run_ab_over_bdp(NGINX_BIN, str(tmp_path), **kw)

    if not res.get("available"):
        pytest.skip(f"harness self-skipped: {res.get('reason')}")

    # Median, not best-of-N: netem's rate limiter can drain one baseline run as a
    # near-line-rate burst, and best-of-N would latch onto that transient and
    # collapse the A/B contrast (see _perf_netem_helpers._inside).
    base = res["baseline_median_mib_s"]
    tuned = res["tuned_median_mib_s"]
    print(f"\n  [netem BDP {res['size'] // (1024 * 1024)} MiB  "
          f"RTT={res['rtt_ms']:.0f}ms  BDP={res['bdp_bytes'] // 1024} KiB] "
          f"baseline(med)={base:.0f} MiB/s  tuned(med)={tuned:.0f} MiB/s  "
          f"ratio={res['ratio']:.1f}x  tcp_wmem={res['wmem_effective']!r}")

    out = os.environ.get("BRIX_PERF_AB_JSON")
    if out:
        with open(out, "w") as fh:
            json.dump(res, fh, indent=2)

    # (1) the link is a genuine BDP pipe — netem is on the wire, not bypassed.
    expected_rtt = 2 * kw["delay_ms"]
    def _assert_test_socketbuf_ab_over_synthesized_bdp_1():
        assert res["rtt_ms"] >= expected_rtt * 0.6, (
            f"RTT {res['rtt_ms']:.1f}ms << {expected_rtt}ms — netem not applied "
            f"(local-delivery shortcut?), the BDP is not real")
        # (2) both legs serve the whole file byte-exact.
        assert res["baseline"]["bytes"] == res["size"]

    _assert_test_socketbuf_ab_over_synthesized_bdp_1()
    def _assert_test_socketbuf_ab_over_synthesized_bdp_2():
        assert res["tuned"]["bytes"] == res["size"]
        # (3) the P3-B3 magnitude: the pinned buffer fills the BDP the window-capped
        # baseline cannot.  Floor is generous vs the ~12x observed.
        assert base > 0 and tuned > 0

    _assert_test_socketbuf_ab_over_synthesized_bdp_2()
    _check_test_socketbuf_ab_over_synthesized_bdp_1(res)

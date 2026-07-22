"""
tests/test_phase51_resilience.py — phase-51 cross-protocol resilience wiring.

Self-contained smoke tests for the phase-51 hardening
(docs/refactor/phase-51-cross-protocol-resilience.md).  They do NOT touch the
shared test fleet:

  * the directive-parse tests run ``nginx -t`` on a throwaway config (no port
    binding, no PKI, no fleet) to prove the new directives are accepted and merge
    cleanly — covering A3 (per-IP CMS cap), E4 (GSI in-flight cap), A4 (manager
    reaper arming) and B1 (proxy write-stall);
  * the metrics test asserts the new ``brix_*`` resilience counters are exported
    on /metrics, and SKIPS cleanly when the metrics endpoint is not running.

Run:
    PYTHONPATH=tests pytest tests/test_phase51_resilience.py -v
"""

import os

import pytest

from settings import HOST, NGINX_BIN, NGINX_METRICS_PORT
from server_registry import NginxInstanceSpec


pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    # Fixed exclusive-band ledger ports (lc-phase51-*) → serialise the family so a
    # fixed port never has two concurrent drivers.
    pytest.mark.xdist_group("lc-phase51"),
    pytest.mark.skipif(
        not os.path.exists(NGINX_BIN),
        reason=f"nginx binary not found at {NGINX_BIN}"),
]


def _assert_parse_ok(lifecycle, name, template):
    """Register a parse-only spec, render it, and run `nginx -t`.

    A clean return from nginx_test() (no RegistryCommandFailure) is the
    equivalent of the original rc==0; we additionally assert the -t banner
    strings on the returned CompletedProcess to preserve assertion strength.
    """
    spec = lifecycle.register(NginxInstanceSpec(
        name=name,
        template=template,
        protocol="root",
        reason="phase-51 resilience directive parse-only check"))
    lifecycle.reconfigure(spec.name)
    result = lifecycle.nginx_test(spec.name)
    out = result.stdout + result.stderr
    assert "syntax is ok" in out and "test is successful" in out, out


def test_new_stream_directives_parse(lifecycle):
    """All new stream-side resilience directives are accepted by nginx -t."""
    _assert_parse_ok(
        lifecycle, "lc-phase51-directives", "nginx_lc_phase51_directives.conf")


def test_directive_disable_values_parse(lifecycle):
    """The 0/off disable escapes parse too (back-compat)."""
    _assert_parse_ok(
        lifecycle, "lc-phase51-disable", "nginx_lc_phase51_disable.conf")


# Counters that brix_export_resilience_metrics() must emit (E6/A1).
_EXPECTED_COUNTERS = [
    "brix_cms_read_timeouts_total",
    "brix_cms_login_timeouts_total",
    "brix_cms_idle_closes_total",
    "brix_cms_cap_rejections_total",
    "brix_cms_frame_yields_total",
    "brix_ocsp_timeouts_total",
    "brix_auth_l1_hits_total",
    "brix_auth_l1_misses_total",
    "brix_acc_nss_breaker_open_total",
    "brix_acc_dns_breaker_open_total",
]


def test_resilience_metrics_exported():
    """The new resilience counters appear on /metrics (skips if not running)."""
    import urllib.request
    import urllib.error

    url = f"http://{HOST}:{NGINX_METRICS_PORT}/metrics"
    try:
        body = urllib.request.urlopen(url, timeout=5).read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        pytest.skip(f"metrics endpoint {url} not reachable: {exc}")

    missing = [c for c in _EXPECTED_COUNTERS if c not in body]
    assert not missing, f"phase-51 counters missing from /metrics: {missing}"

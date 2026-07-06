"""PX-* — proxy certificate handling.

Two surfaces enforce different rules:

  * davs:// (WebDAV x509 auth) does NOT accept GSI proxy certificate chains at
    all — every proxy is refused regardless of type.  These tests confirm that
    on the wire (no proxy sneaks through the HTTP surface).

  * root:// GSI accepts RFC 3820 proxies and enforces limited-proxy
    monotonicity (a full proxy may not be issued beneath a limited one,
    RFC 3820 §3.8).  That decision logic lives in the ngx-free
    brix_proxy_chain_ok()/brix_px_classify() and is proven directly, against
    real forge proxy chains, by tests/c/x509_conformance_test.c
    (PX-C01..PX-C05).  It is exercised there rather than here because driving a
    live GSI proxy handshake requires the full stream client; the C tests cover
    the same certificates the wire path would see.
"""
import pytest

import x509forge
from wlcg_fleet import WlcgInstance

pytestmark = [pytest.mark.x509conf, pytest.mark.slow]


@pytest.mark.parametrize("scenario,cred", [
    ("px_rfc3820_ok", "proxy_full"),
    ("sp_proxy_cn_exempt", "proxy_in_ns"),
])
def test_davs_refuses_proxy_chains(tmp_path, scenario, cred):
    """A valid RFC 3820 proxy is refused by the WebDAV x509 surface."""
    sc = x509forge.forge_scenario(tmp_path / scenario, scenario)
    inst = WlcgInstance(tmp_path / f"{scenario}-inst", ca_dir=sc.ca_dir,
                        signing_policy="off")
    inst.start()
    try:
        accepted, code = inst.attempt_davs(sc.credentials[cred])
        assert accepted is False, (
            f"WebDAV must refuse proxy chains, got HTTP {code}")
    finally:
        inst.stop()

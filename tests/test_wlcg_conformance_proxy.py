"""PX-* — WebDAV accepts valid RFC 3820 proxies and rejects malformed or
escalated chains through the same verifier as native GSI.
"""
import pytest

import x509forge
from wlcg_fleet import WlcgInstance

# Both cases drive the SAME fixed exclusive-band WlcgInstance ("lc-wlcg", port
# 31020), and a 2-way parametrize is two ITEMS: without this group xdist can
# hand them to two workers, which then launch one instance on one port twice.
pytestmark = [pytest.mark.x509conf, pytest.mark.slow,
              pytest.mark.xdist_group("lc-wlcg")]


@pytest.mark.parametrize("scenario,cred,expected", [
    ("px_rfc3820_ok", "proxy_full", True),
    ("sp_proxy_cn_exempt", "proxy_in_ns", True),
    ("px_noncritical_pci", "proxy_noncrit", False),
    ("px_limited_to_full", "escalated", False),
])
def test_davs_validates_proxy_chains(tmp_path, scenario, cred, expected):
    """Acceptance requires a valid proxy profile and no privilege escalation."""
    sc = x509forge.forge_scenario(tmp_path / scenario, scenario)
    inst = WlcgInstance(tmp_path / f"{scenario}-inst", ca_dir=sc.ca_dir,
                        signing_policy="off")
    inst.start()
    try:
        accepted, code = inst.attempt_davs(sc.credentials[cred])
        assert accepted is expected, (
            f"WebDAV proxy verdict for {scenario}: HTTP {code}, expected {expected}")
    finally:
        inst.stop()

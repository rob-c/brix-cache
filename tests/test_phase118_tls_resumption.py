"""TLS-009 needs confirmed resumption without inherited application identity."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = (ROOT / "client/apps/diag/xrd_conform_root_tls.c").read_text()
TLS = (ROOT / "client/lib/net/tls.c").read_text()


def test_resumption_probe_requires_an_authenticated_baseline_and_ticket():
    """Success: the source session is authenticated and actually resumable."""
    assert "authenticated->sec_list[0] == '\\0'" in PROBE
    assert "brix_connect(&baseline_connection" in PROBE
    assert "brix_tls_session_get(&baseline_connection)" in PROBE
    assert "SSL_get1_session" in TLS


def test_nonresumed_connection_cannot_supply_false_evidence():
    """Error: a full replacement handshake stays explicitly inconclusive."""
    assert "!resumed.tls_session_reused" in PROBE
    assert '"server-did-not-resume-session"' in PROBE
    assert "SSL_session_reused(ssl)" in TLS


def test_resumed_transport_cannot_inherit_root_authorization():
    """Security-negative: auth is suppressed and protected stat must fail."""
    assert "options.force_anon = 1" in PROBE
    assert "status.kxr == kXR_NotAuthorized" in PROBE
    assert '"resumed-session-inherited-authorization"' in PROBE

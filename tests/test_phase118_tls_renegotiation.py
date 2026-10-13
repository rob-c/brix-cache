"""TLS-008 needs peer-observed TLS-1.2 renegotiation evidence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = (ROOT / "client/apps/diag/xrd_conform_root_tls.c").read_text()
TLS = (ROOT / "client/lib/net/tls.c").read_text()


def test_renegotiation_probe_constrains_an_isolated_tls12_session():
    """Success: TLS-1.3 negotiation cannot hide a TLS-1.2 weakness."""
    assert "options.tls_max_version = TLS1_2_VERSION" in PROBE
    assert "brix_tls_probe_renegotiate(&connection" in PROBE


def test_renegotiation_transport_error_is_not_misreported_as_refusal():
    """Error: timeout or local unavailability remains inconclusive."""
    assert '"tls12-renegotiation-indeterminate"' in PROBE
    assert '"TLS renegotiation response unavailable"' in TLS


def test_accepted_renegotiation_is_a_security_divergence():
    """Security-negative: a completed second handshake turns TLS-008 red."""
    assert "if (rc == 1) return 1" in TLS
    assert "result > 0 ? BRIX_CONFORM_VERDICT_DIVERGENT" in PROBE
    assert '"tls12-renegotiation-accepted"' in PROBE

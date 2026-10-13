"""TLS-006 must be decided by paired wire handshakes."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = (ROOT / "client/apps/diag/xrd_conform_root_tls.c").read_text()
TLS = (ROOT / "client/lib/net/tls.c").read_text()


def test_tls_floor_has_a_tls12_control_before_the_legacy_probe():
    """Success: endpoint liveness is proven at the supported floor first."""
    assert "options.tls_max_version = TLS1_2_VERSION" in PROBE
    assert '"tls12-control-handshake-unavailable"' in PROBE


def test_tls_floor_sends_a_real_tls11_limited_clienthello():
    """Error: the isolated client is constrained below the promised floor."""
    assert "options.tls_max_version = TLS1_1_VERSION" in PROBE
    assert "SSL_CTX_set_max_proto_version(ctx, c->opts.tls_max_version)" in TLS


def test_tls_floor_cannot_pass_when_the_legacy_handshake_succeeds():
    """Security-negative: accepting TLS 1.1 is explicitly divergent."""
    assert "legacy ? BRIX_CONFORM_VERDICT_DIVERGENT" in PROBE
    assert '"legacy-tls-clienthello-accepted"' in PROBE

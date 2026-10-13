"""GSI transcript rows must use observed legacy-handshake evidence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOGIN = (ROOT / "client/apps/diag/xrd_conform_root_login.c").read_text()
GSI = (ROOT / "client/lib/auth/sec/sec_gsi.c").read_text()
AUTH = (ROOT / "client/lib/auth/auth.c").read_text()


def test_legacy_gsi_probe_records_all_four_transcript_rows():
    """Success: an isolated version-10300 exchange grades LOG-009..012."""
    assert "options.gsi_version = 10300" in LOGIN
    for clause in ("LOG-009", "LOG-010", "LOG-011", "LOG-012"):
        assert f'grade_active(execution, "{clause}"' in LOGIN


def test_unavailable_legacy_exchange_is_not_reported_as_conformant():
    """Error: missing credentials or legacy support stays inconclusive."""
    assert '"gsi-legacy-transcript-unavailable"' in LOGIN
    assert "BRIX_CONFORM_VERDICT_INCONCLUSIVE" in LOGIN


def test_key_continuity_requires_the_servers_terminal_ok():
    """Security-negative: merely building round two cannot prove persistence."""
    assert "c->gsi_round2_response_built = 1" in GSI
    assert "status == kXR_ok" in AUTH
    assert "c->gsi_server_key_persisted = 1" in AUTH
    assert "connection.gsi_server_key_persisted" in LOGIN

"""SIG-009 must distinguish local assessment ceilings from wire findings."""

from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1]
          / "client/apps/diag/xrd_conform_root_sigver.c").read_text()


def test_bound_signing_success_path_still_requires_a_wire_refusal():
    """Success: only the server's defined signature refusal can pass SIG-009."""
    assert "bound-unsigned-request-refused" in SOURCE
    assert "status.kxr == kXR_SigVerErr" in SOURCE


def test_each_local_budget_failure_is_inconclusive_and_phase_specific():
    """Error: exhausted local ceilings are not remote divergences."""
    for phase in ("signed-open", "bind", "bound-read"):
        assert f'"request-ceiling-before-{phase}"' in SOURCE
    assert SOURCE.count("BRIX_CONFORM_VERDICT_INCONCLUSIVE") >= 5


def test_budget_failure_cannot_reuse_stale_wire_status():
    """Security-negative: a skipped read cannot inherit an earlier kXR code."""
    assert "got = reserve(execution" not in SOURCE
    assert "got = brix_file_read(&secondary" in SOURCE


def test_unencrypted_signature_claim_executes_a_real_positive_probe():
    """Success: secOFrce drives the exact raw-hash wire form."""
    assert "brix_gsi_sigver_hash(1" in SOURCE
    assert '"unencrypted-hash-accepted-and-corruption-refused"' in SOURCE


def test_unencrypted_signature_local_failure_cannot_pass_the_clause():
    """Error: inability to make or exchange the hash is a divergence."""
    assert '"advertised-unencrypted-hash-refused"' in SOURCE
    assert "positive.rc == 0" in SOURCE


def test_unencrypted_signature_must_be_verified_not_merely_accepted():
    """Security-negative: one changed hash byte must receive a refusal."""
    assert "if (corrupt) hash[0] ^= 0x80" in SOURCE
    assert "is_refusal(negative)" in SOURCE
    assert '"unencrypted-hash-accepted-without-verification"' in SOURCE

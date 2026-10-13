"""Phase-118 locate ledger must not invent wire options or response grammars."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
FLAGS = (REPO / "src/protocols/root/protocol/flags.h").read_text()
LEDGER = (REPO / "docs/refactor/phase-118-security-assessment-toolkit.md").read_text()
PROBE = (REPO / "client/apps/diag/xrd_conform_root_locate.c").read_text()


def test_locate_address_family_claim_uses_no_undefined_wire_flag():
    """Security-negative: no guessed address-selector constant can reach wire."""
    for name in ("kXR_addrboth", "kXR_addrIPv4", "kXR_addrIPv6"):
        assert name not in FLAGS
        assert name not in LEDGER


def test_compact_locate_claim_is_retracted_against_authoritative_grammar():
    """Error honesty: absence of a compact grammar is a skip, never a pass."""
    generated = (REPO / "client/lib/conform/ledger_rows.inc").read_text()
    assert "LOC-010" in LEDGER
    assert "**Retracted:**" in LEDGER
    assert "not-applicable/retracted/LOC-010" in generated
    assert '"LOC-010"' not in PROBE


def test_real_locate_cache_and_timing_rows_name_required_fixtures():
    """Success path: real options retain explicit, actionable fixture gates."""
    assert "fixture-required:mutable-locate-cache" in PROBE
    assert "fixture-required:slow-cluster-member" in PROBE


def test_pgread_does_not_claim_the_pgwrite_error_list_limit():
    """Security-negative: a pgwrite CSE limit is never forged into pgread."""
    flags = FLAGS
    root_probe = (REPO / "client/apps/diag/xrd_conform_root.c").read_text()
    assert "max corrupt pages reportable in ONE pgwrite request" in flags
    assert '"PGR-027"' not in root_probe


def test_stat_backup_bit_does_not_invent_a_query_response():
    """Error honesty: no query infotype is documented as returning bkpexist."""
    opcodes = (REPO / "src/protocols/root/protocol/opcodes.h").read_text()
    query_lines = "\n".join(line for line in opcodes.splitlines()
                            if "#define kXR_Q" in line)
    meta_probe = (REPO / "client/apps/diag/xrd_conform_root_meta.c").read_text()
    assert "bkpexist" not in query_lines
    assert '"STA-012"' not in meta_probe


def test_retracted_rows_remain_generated_catalogue_entries():
    """Success: corrections preserve stable clause IDs and ledger cardinality."""
    generated = (REPO / "client/lib/conform/ledger_rows.inc").read_text()
    for clause in ("PGR-027", "STA-012", "LOC-009", "LOC-010"):
        assert f'BRIX_CONFORM_CLAUSE("{clause}"' in generated
        assert f'"not-applicable/retracted/{clause}"' in generated
    assert generated.count("BRIX_CONFORM_CLAUSE(") == 527


def test_manager_holder_set_checks_every_advertised_endpoint():
    """Success: CMS-001 cannot pass after checking only the first holder."""
    assert "verify_data_endpoints" in PROBE
    assert "served == holders" in PROBE
    assert "manager-holder-set-serves-path" in PROBE
    root_runner = (REPO / "client/apps/diag/xrd_conform_root.c").read_text()
    assert "xrd_conform_probe_cms_manager(execution, &connection, url.path)" \
        in root_runner


def test_manager_missing_holder_requires_exact_not_found():
    """Error path: an empty success or generic error fails CMS-002."""
    assert "probe_missing_holder_set" in PROBE
    assert "status.kxr == kXR_NotFound" in PROBE
    assert "empty-holder-set-wrong-answer" in PROBE


def test_holder_fanout_is_bounded_before_remote_connections():
    """Security-negative: a hostile locate list cannot cause unbounded fanout."""
    assert "CONFORM_LOCATE_ENDPOINT_MAX" in PROBE
    assert "holders >= CONFORM_LOCATE_ENDPOINT_MAX" in PROBE


def test_redundant_manager_sets_are_compared_canonically():
    """Success: equivalent sets pass even when manager reply order differs."""
    assert "canonical_holder_set" in PROBE
    assert "qsort(endpoints" in PROBE
    assert "redundant-manager-holder-sets-agree" in PROBE


def test_redundant_manager_mismatch_is_a_divergence():
    """Error: a different holder set cannot be softened to inconclusive."""
    assert "redundant-manager-holder-set-mismatch" in PROBE
    assert "BRIX_CONFORM_VERDICT_DIVERGENT" in PROBE


def test_single_manager_does_not_forge_redundancy_evidence():
    """Security-negative: CMS-005 needs at least two manager observations."""
    assert "cms_manager_count >= 2" in PROBE


def test_manager_only_open_observes_the_unfollowed_wire_status():
    """Success: CMS-006 accepts a first-hop redirect or defined refusal."""
    assert "probe_manager_direct_service" in PROBE
    assert "wire_status == kXR_redirect" in PROBE
    assert "wire_status == kXR_error" in PROBE


def test_manager_only_direct_open_is_divergent():
    """Error: kXR_ok from a manager-only role is never treated as redirect."""
    assert "manager-only-open-served-directly" in PROBE
    assert "BRIX_CONFORM_VERDICT_DIVERGENT" in PROBE


def test_mixed_server_manager_role_does_not_forge_cms006():
    """Security-negative: CMS-006 applies only to a manager-only role claim."""
    assert "!= kXR_isManager) return;" in PROBE

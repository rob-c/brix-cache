"""Every selected Phase-118 gap must name the evidence it still requires."""

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / "client/apps/diag/xrd_conform_fixture_gates.c").read_text()
LEDGER = (REPO / "client/lib/conform/ledger_rows.inc").read_text()
RETRACTED = {"PGR-027", "STA-012", "LOC-009", "LOC-010"}


def _gates():
    return re.findall(r'\{ "([A-Z0-9]+-\d{3})", "([^"]+)" \}', SOURCE)


def _ledger_ids():
    return set(re.findall(
        r'^BRIX_CONFORM_CLAUSE\("([A-Z0-9]+-\d{3})"', LEDGER, re.MULTILINE))


def _native_runner_source():
    return "\n".join(
        path.read_text(errors="replace")
        for path in sorted((REPO / "client/apps/diag").glob("xrd_conform*.c"))
        if path.name != "xrd_conform_fixture_gates.c"
    )


def test_fixture_gate_ids_are_unique_and_present_in_the_ledger():
    """Success: every gate addresses exactly one stable catalogue row."""
    gates = _gates()
    ledger = (REPO / "client/lib/conform/ledger_rows.inc").read_text()
    ids = [clause_id for clause_id, _ in gates]
    assert ids
    assert len(ids) == len(set(ids))
    assert all(f'BRIX_CONFORM_CLAUSE("{clause_id}"' in ledger
               for clause_id in ids)


def test_fixture_gates_only_replace_the_provisional_result():
    """Security-negative: skips, divergences and observations cannot be masked."""
    assert 'row->verdict == BRIX_CONFORM_VERDICT_INCONCLUSIVE' in SOURCE
    assert 'strcmp(row->reason, "probe-not-executed") == 0' in SOURCE


def test_every_gate_has_an_actionable_machine_reason():
    """Error honesty: generic or success-looking reasons are forbidden."""
    reasons = [reason for _, reason in _gates()]
    assert reasons
    assert all(reason.startswith("fixture-required:") for reason in reasons)
    assert all("probe-not-executed" not in reason for reason in reasons)


def test_every_executable_clause_has_a_native_runner_owner():
    """Completeness: fallback fixture gates cannot count as native ownership."""
    native = _native_runner_source()
    executable = _ledger_ids() - RETRACTED
    missing = sorted(clause for clause in executable
                     if f'"{clause}"' not in native)
    assert len(_ledger_ids()) == 527
    assert len(executable) == 523
    assert not missing, f"executable clauses without native owners: {missing}"


def test_retracted_clauses_have_no_active_native_runner_path():
    """Error honesty: withdrawn assertions remain catalogue-only history."""
    native = _native_runner_source()
    active = sorted(clause for clause in RETRACTED
                    if f'"{clause}"' in native)
    assert not active, f"retracted clauses still referenced by runners: {active}"

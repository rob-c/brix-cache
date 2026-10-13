"""Phase-118 PGR status-frame success, error, and security negatives."""
import json
import subprocess
from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import PgOrigin
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 31 + 7) & 0xFF for index in range(40 * 1024))
LARGE_PAYLOAD = bytes(range(256)) * 65536 + b"x"
READV_LIMIT_PAYLOAD = bytes(range(256)) * 12289
MUTATING_FAMILIES = {
    "CHM", "CKP", "DIR", "FAT", "MKD", "MV", "PGW", "PRP", "RM", "SYN",
    "TRN", "WRT", "WVC",
}
MUTATING_ROWS = {
    "QRY-011", "STA-005", "STA-006", "STA-011", "PGR-029", "RD-017",
    "RD-009", "RD-011", "PGR-028", "PGR-025", "PGR-026", "CHU-001",
    "CHU-002", "CHU-003", "CHU-004", "OPN-008", "OPN-009", "OPN-010",
    "OPN-011", "OPN-014", "OPN-015", "OPN-016", "OPN-017", "OPN-021",
    "OPN-022", "OPN-023", "OPN-024", "OPN-025", "OPN-026",
}


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _needs_mutation(clause):
    if clause is None:
        return False
    return clause in MUTATING_ROWS or clause.split("-")[0] in MUTATING_FAMILIES


def _needs_disruption(behaviour, families, clause):
    return (behaviour == "corrupt" or families == "BND"
            or clause in {"FRM-012", "FRM-021", "PGR-021", "OPN-032",
                          "OPN-033", "PRP-006"})


def _extend_run_authority(command, target, behaviour, families, clause):
    if _needs_disruption(behaviour, families, clause):
        command.extend(["--allow-disrupt", "--confirm-target", target])
    if _needs_mutation(clause):
        command.extend(["--allow-mutate", "--scratch", "/"])


def _extend_row_options(command, target, clause):
    if clause == "DIR-007":
        request_index = command.index("--request-limit") + 1
        command[request_index] = "700"
    if clause == "OPN-033":
        command.extend(["--open-fixture", f"idle={target}"])
    if clause is not None:
        command.extend(["--only", clause])


def _extend_verification(command, verify_negative):
    rows = ((verify_negative,) if isinstance(verify_negative, str)
            else verify_negative or ())
    for clause in rows:
        command.extend(["--verify-negative", clause])


def _run_timeout(payload, wall_seconds, clause):
    if len(payload) > 1024 * 1024 or wall_seconds > 10:
        return max(20, wall_seconds + 30)
    return 30 if clause == "QRY-010" else 20


def _run(tmp_path, behaviour="ok", families="PGR", only=None,
         verify_negative=None, payload=PAYLOAD, byte_limit=4194304,
         request_limit=256, wall_seconds=10):
    _require_xrd()
    output = tmp_path / behaviour
    with PgOrigin(payload, behaviour=behaviour,
                  advertise=behaviour not in (
                      "no_pgwrite", "pgwrite_unclaimed_ack",
                  )) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        command = [str(XRD), "conform", "accept",
                   target,
                   "--families", families, "--budget", "boundary",
                   "--fail-on", "divergent", "--wall-seconds",
                   str(wall_seconds),
                   "--request-limit", str(request_limit),
                   "--byte-limit", str(byte_limit),
                   "--out", str(output)]
        if families == "BND":
            command.extend(["--profile", "full"])
        _extend_run_authority(command, target, behaviour, families, only)
        _extend_row_options(command, target, only)
        _extend_verification(command, verify_negative)
        result = subprocess.run(
            command,
            text=True, capture_output=True,
            timeout=_run_timeout(payload, wall_seconds, only),
            check=False,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def test_valid_status_structure_is_proven(tmp_path):
    result, rows = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    for clause in ("PGR-001", "PGR-002", "PGR-003", "PGR-004", "PGR-005",
                   "PGR-007", "PGR-019", "PGR-020", "PGR-022", "PGR-023",
                   "PGR-024", "PGR-031", "PGR-032"):
        assert rows[clause]["verdict"] == "conformant"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("bad_body_sid", "PGR-004"),
    ("bad_requestid", "PGR-003"),
    ("bad_status_crc", "PGR-005"),
    ("bad_reserved", "PGR-031"),
    ("bad_resptype", "PGR-032"),
    ("bad_offset", "PGR-007"),
])
def test_hostile_status_structure_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, verify_negative=owner)
    assert result.returncode == 1
    assert rows[owner]["verdict"] == "divergent"
    assert rows[owner]["reason"] == "hostile-status-field-rejected"
    assert rows["PGR-020"]["verdict"] == "divergent"


def test_out_of_domain_page_result_type_owns_sequence_clause(tmp_path):
    result, rows = _run(tmp_path, "bad_resptype", "PGR", "PGR-006",
                        "PGR-006")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["PGR-006"]["verdict"] == "divergent"
    assert rows["PGR-006"]["reason"] == \
        "hostile-result-sequence-rejected"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("pg_plain_ok", "PGR-001"),
    ("pg_short_status", "PGR-002"),
    ("pg_bad_008", "PGR-008"),
    ("pg_bad_009", "PGR-009"),
    ("pg_bad_010", "PGR-010"),
    ("pg_bad_011", "PGR-011"),
    ("pg_bad_012", "PGR-012"),
    ("pg_bad_013", "PGR-013"),
    ("pg_bad_grid", "PGR-014"),
    ("pg_bad_015", "PGR-015"),
    ("pg_reject_zero", "PGR-018"),
    ("pg_bad_grid", "PGR-019"),
    ("pg_valid_crc_corrupt", "PGR-021"),
    ("pg_bad_retry", "PGR-022"),
    ("pg_bad_args", "PGR-023"),
    ("pg_bad_any", "PGR-024"),
    ("pg_accept_negative", "PGR-030"),
])
def test_hostile_pgread_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "PGR", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_hostile_fractional_only_object_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "pg_bad_016", "PGR", "PGR-016",
                        "PGR-016", payload=PAYLOAD[:4095])
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["PGR-016"]["verdict"] == "divergent"


def test_hostile_empty_object_answer_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "pg_reject_zero", "PGR", "PGR-017",
                        "PGR-017", payload=b"")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["PGR-017"]["verdict"] == "divergent"


def test_write_only_handle_cannot_be_page_read(tmp_path):
    result, rows = _run(tmp_path, "ok", "PGR", "PGR-029", "PGR-029")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["PGR-029"]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("rd_bad_after_baseline", "RD-001"),
    ("rd_reject_zero", "RD-002"),
    ("rd_invent_eof", "RD-003"),
    ("rd_invent_eof", "RD-004"),
    ("rd_straddle_extra", "RD-005"),
    ("rd_bad_006", "RD-006"),
    ("rd_bad_007", "RD-007"),
    ("rd_bad_008", "RD-008"),
    ("rd_invent_eof", "RD-012"),
    ("rd_error_maxlen", "RD-013"),
    ("rd_bad_partition", "RD-014"),
    ("rd_mutate_repeat", "RD-015"),
    ("ok", "RD-018"),
    ("ok", "RD-019"),
    ("rd_bad_primary_args", "RD-020"),
    ("rd_accept_unbound", "RD-021"),
    ("rd_bad_readahead", "RD-022"),
    ("ok", "RD-023"),
    ("ok", "RD-030"),
    ("ok", "RD-031"),
    ("ok", "RD-032"),
    ("ok", "RD-033"),
])
def test_hostile_read_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "RD", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_write_only_handle_read_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "ok", "RD", "RD-017", "RD-017")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["RD-017"]["verdict"] == "divergent"


def test_hostile_empty_object_read_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "rd_invent_eof", "RD", "RD-010",
                        "RD-010", payload=b"")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["RD-010"]["verdict"] == "divergent"


def test_bound_read_control_is_conformant(tmp_path):
    result, rows = _run(tmp_path, "ok", "BND")
    assert result.returncode == 0, result.stderr + result.stdout
    for owner in ("BND-001", "BND-002", "BND-003", "BND-004", "BND-005"):
        assert rows[owner]["verdict"] == "conformant"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("bind_zero_pathid", "BND-001"),
    ("bind_wrong_stream", "BND-002"),
    ("bind_corrupt", "BND-003"),
    ("bind_limit_ignored", "BND-004"),
    ("bind_stale_accept", "BND-005"),
])
def test_hostile_bound_stream_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "BND", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_hostile_bound_stream_overlap_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "bind_corrupt", "RD", "RD-016", "RD-016")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["RD-016"]["verdict"] == "divergent"


def test_hostile_control_envelope_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "bind_ping_corrupt", "ENV", "ENV-002",
                        "ENV-002")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["ENV-002"]["verdict"] == "divergent"


@pytest.mark.parametrize(("family", "owner"), [
    ("RD", "RD-009"),
    ("PGR", "PGR-025"),
    ("PGR", "PGR-026"),
    ("CHU", "CHU-001"),
    ("CHU", "CHU-002"),
    ("CHU", "CHU-003"),
    ("CHU", "CHU-004"),
])
@pytest.mark.timeout(120)
def test_unsplit_large_response_is_rejected(tmp_path, family, owner):
    result, rows = _run(tmp_path, "ok", family, owner, owner,
                        payload=LARGE_PAYLOAD, byte_limit=536870912,
                        request_limit=2048, wall_seconds=45)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


_MUTATION_NEGATIVE_ROWS = (
    *(f"CHM-{index:03d}" for index in range(1, 4)),
    "DIR-001", "DIR-004", "DIR-005", "DIR-008", "DIR-010",
    *(f"MKD-{index:03d}" for index in range(1, 6)),
    "MV-001", "MV-002", "MV-004", "MV-006", "MV-007",
    "PGW-013",
    "PRP-001", "PRP-007",
    "RM-002", "RM-003", "RM-006", "RM-007",
    *(f"TRN-{index:03d}" for index in range(1, 8)),
    "WRT-006",
)


@pytest.mark.parametrize("owner", _MUTATION_NEGATIVE_ROWS)
def test_hostile_mutation_contract_is_rejected(tmp_path, owner):
    family = owner.split("-", 1)[0]
    behaviour = "dir_control_inconsistent" if owner == "DIR-004" else "ok"
    result, rows = _run(tmp_path, behaviour, family, owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize("owner", [
    "WRT-001", "WRT-002", "WRT-003", "WRT-004", "WRT-005", "WRT-009",
    "WRT-008", "WRT-010", "WRT-011",
])
def test_hostile_write_observation_is_rejected(tmp_path, owner):
    """A peer that acknowledges writes without applying them must go red."""
    family = owner.split("-", 1)[0]
    result, rows = _run(
        tmp_path,
        "write_oversized_accept" if owner == "WRT-008"
        else "concurrent_write_ack" if owner == "WRT-011" else "ok",
        family, owner, owner,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("writev_ack", "WVC-001"),
    ("writev_ack", "WVC-002"),
    ("writev_ack", "WVC-003"),
    ("writev_ack", "WVC-004"),
    ("writev_server_error", "WVC-005"),
    ("ok", "SYN-001"),
    ("sync_server_error", "SYN-002"),
])
def test_hostile_writev_and_sync_contract_is_rejected(
        tmp_path, behaviour, owner):
    family = owner.split("-", 1)[0]
    result, rows = _run(
        tmp_path, behaviour, family, owner, owner, request_limit=4096,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("checkpoint_server_error", "CKP-001"),
    ("checkpoint_bad_capacity", "CKP-002"),
    ("checkpoint_no_rollback", "CKP-003"),
    ("checkpoint_accept", "CKP-004"),
])
def test_hostile_checkpoint_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(
        tmp_path, behaviour, "CKP", owner, owner, request_limit=512,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("ok", "PGW-001"),
    ("ok", "PGW-002"),
    ("ok", "PGW-003"),
    ("pgwrite_ack", "PGW-004"),
    ("ok", "PGW-005"),
    ("ok", "PGW-006"),
    ("ok", "PGW-007"),
    ("ok", "PGW-008"),
    ("ok", "PGW-009"),
    ("ok", "PGW-010"),
    ("ok", "PGW-011"),
    ("ok", "PGW-012"),
    ("pgwrite_unclaimed_ack", "PGW-014"),
])
def test_hostile_pgwrite_contract_is_rejected(tmp_path, behaviour, owner):
    """Advertised/refused and unadvertised/accepted pgwrite lies go red."""
    result, rows = _run(tmp_path, behaviour, "PGW", owner, owner,
                        request_limit=1024)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_unadvertised_pgwrite_refusal_is_conformant(tmp_path):
    """A peer with kXR_suppgrw clear may refuse a direct pgwrite probe."""
    result, rows = _run(tmp_path, "no_pgwrite", "PGW", "PGW-014")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["PGW-014"]["verdict"] == "conformant"
    assert rows["PGW-014"]["reason"] == "unadvertised-pgwrite-refused"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("rdv_bad_001", "RDV-001"),
    ("rdv_bad_002", "RDV-002"),
    ("rdv_bad_003", "RDV-003"),
    ("rdv_bad_004", "RDV-004"),
    ("rdv_bad_005", "RDV-005"),
    ("rdv_bad_006", "RDV-006"),
    ("rdv_bad_007", "RDV-007"),
    ("rdv_bad_008", "RDV-008"),
    ("rdv_bad_009", "RDV-009"),
    ("rdv_bad_010", "RDV-010"),
    ("rdv_bad_016", "RDV-016"),
    ("rdv_bad_017", "RDV-017"),
])
def test_hostile_readv_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "RDV", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_controlled_readv_zero_element_is_conformant(tmp_path):
    result, rows = _run(tmp_path, "rdv_ok", "RDV", "RDV-008")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["RDV-008"]["verdict"] == "conformant"


def test_truncated_readv_response_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "rdv_truncated", "RDV", "RDV-001",
                        "RDV-001")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["RDV-001"]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("rdv_bad_011", "RDV-011"),
    ("rdv_bad_014", "RDV-014"),
    ("rdv_bad_015", "RDV-015"),
    ("rdv_bad_020", "RDV-020"),
])
def test_hostile_readv_extended_contract_is_rejected(
        tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "RDV", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("rdv_bad_012", "RDV-012"),
    ("rdv_bad_013", "RDV-013"),
    ("rdv_bad_019", "RDV-019"),
])
def test_hostile_readv_limit_claim_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(
        tmp_path, behaviour, "RDV", owner, owner,
        payload=READV_LIMIT_PAYLOAD, byte_limit=67108864, wall_seconds=30,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_hostile_large_readv_framing_is_rejected(tmp_path):
    result, rows = _run(
        tmp_path, "rdv_bad_018", "RDV", "RDV-018", "RDV-018",
        payload=LARGE_PAYLOAD, byte_limit=536870912, request_limit=2048,
        wall_seconds=45,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["RDV-018"]["verdict"] == "divergent"


def test_bad_status_crc_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "corrupt", verify_negative="PGR-020")
    assert result.returncode == 1
    assert rows["PGR-020"]["verdict"] == "divergent"
    assert rows["PGR-021"]["verdict"] == "conformant"


def test_controlled_origin_protocol_contract_is_conformant(tmp_path):
    result, rows = _run(tmp_path, families="PROT")
    assert result.returncode == 0, result.stderr + result.stdout
    for clause in ("PROT-001", "PROT-002", "PROT-003", "PROT-004",
                   "PROT-005", "PROT-006", "PROT-007", "PROT-008",
                   "PROT-009", "PROT-010", "PROT-011", "PROT-012",
                   "PROT-013", "PROT-014"):
        assert rows[clause]["verdict"] == "conformant"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("protocol_aux_missing", "PROT-001"),
    ("protocol_aux_short", "PROT-002"),
])
def test_malformed_initial_protocol_response_is_retained(tmp_path, behaviour,
                                                         owner):
    result, rows = _run(tmp_path, behaviour, "PROT",
                        verify_negative=owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_out_of_domain_security_level_is_detected(tmp_path):
    result, rows = _run(tmp_path, "protocol_bad_seclvl", "PROT",
                        verify_negative="PROT-006")
    assert result.returncode == 1
    assert rows["PROT-006"]["verdict"] == "divergent"
    capture = tmp_path / "protocol_bad_seclvl" / "PROT-006.xrdcap"
    assert capture.read_bytes().startswith(b"XRDCAP1\n")


def test_truncated_security_vector_is_detected(tmp_path):
    result, rows = _run(tmp_path, "protocol_bad_secvec", "PROT",
                        verify_negative="PROT-008")
    assert result.returncode == 1
    assert rows["PROT-008"]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owners"), [
    ("protocol_bad_role", ("PROT-003",)),
    ("protocol_missing_sec", ("PROT-004",)),
    ("protocol_bad_bif", ("PROT-005",)),
    ("protocol_bad_secreq", ("PROT-007",)),
    ("protocol_changes", ("PROT-009", "PROT-010")),
    ("protocol_refuse_legacy", ("PROT-011",)),
    ("protocol_tpc_changes", ("PROT-012",)),
    ("protocol_unknown_reject", ("PROT-013",)),
    ("protocol_tls_without_capability", ("PROT-014",)),
])
def test_hostile_protocol_claim_is_rejected(tmp_path, behaviour, owners):
    result, rows = _run(tmp_path, behaviour, "PROT",
                        verify_negative=owners)
    assert result.returncode == 1, result.stderr + result.stdout
    for owner in owners:
        assert rows[owner]["verdict"] == "divergent"


def test_wrong_post_login_streamid_is_detected(tmp_path):
    result, rows = _run(tmp_path, "frame_bad_echo", "FRM", "FRM-003",
                        "FRM-003")
    assert result.returncode == 1
    assert rows["FRM-003"]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("frame_protocol_error", "FRM-001"),
    ("frame_protocol_close", "FRM-002"),
    ("frame_bad_echo", "FRM-004"),
    ("frame_bad_echo", "FRM-005"),
    ("frame_drop_second_protocol", "FRM-006"),
    ("frame_drop_second_protocol", "FRM-007"),
    ("frame_reject_nul", "FRM-008"),
    ("ok", "FRM-009"),
    ("ok", "FRM-010"),
    ("ok", "FRM-011"),
    ("frame_poison_recovery", "FRM-012"),
    ("frame_drop_surplus_ping", "FRM-013"),
    ("frame_accept_extreme", "FRM-014"),
    ("frame_accept_extreme", "FRM-015"),
    ("frame_reject_padding", "FRM-016"),
    ("ok", "FRM-017"),
    ("ok", "FRM-018"),
    ("frame_server_error_valid", "FRM-019"),
    ("frame_bytewise_reject", "FRM-020"),
    ("frame_slow_drop", "FRM-021"),
    ("frame_drop_second_protocol", "FRM-022"),
    ("frame_drop_second_protocol", "FRM-023"),
])
def test_hostile_framing_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "FRM", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("ok", "ENV-001"),
    ("ok", "ENV-003"),
    ("ok", "ENV-004"),
    ("env_gpfile_server_error", "ENV-005"),
])
def test_hostile_session_control_contract_is_rejected(tmp_path, behaviour,
                                                       owner):
    result, rows = _run(tmp_path, behaviour, "ENV", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize("owner", [
    "QRY-001", "QRY-002", "QRY-003", "QRY-007",
    "QRY-009", "QRY-012", "QRY-013", "QRY-014",
])
def test_hostile_query_contract_is_rejected(tmp_path, owner):
    result, rows = _run(tmp_path, "ok", "QRY", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("query_wrong_sha", "QRY-004"),
    ("query_same_crc", "QRY-005"),
    ("query_unknown_success", "QRY-006"),
    ("query_bad_space", "QRY-008"),
    ("query_optional_server_error", "QRY-010"),
    ("query_bad_qprep", "QRY-011"),
])
def test_malicious_query_answer_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "QRY", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("ok", "FAT-001"),
    ("ok", "FAT-002"),
    ("ok", "FAT-003"),
    ("ok", "FAT-004"),
    ("ok", "FAT-005"),
    ("ok", "FAT-006"),
    ("ok", "FAT-007"),
    ("fattr_server_error", "FAT-008"),
    ("ok", "FAT-009"),
])
def test_hostile_fattr_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "FAT", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("stat_malformed", "STA-001"),
    ("stat_wrong_size", "STA-002"),
    ("stat_bad_flags", "STA-003"),
    ("ok", "STA-004"),
    ("stat_writable", "STA-005"),
    ("ok", "STA-006"),
    ("ok", "STA-007"),
    ("stat_handle_mismatch", "STA-008"),
    ("ok", "STA-009"),
    ("stat_offline", "STA-010"),
    ("ok", "STA-011"),
    ("ok", "STA-013"),
    ("ok", "STA-014"),
    ("ok", "STA-015"),
    ("ok", "STA-016"),
    ("ok", "STA-017"),
    ("ok", "STA-018"),
])
def test_hostile_stat_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "STA", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrd_conform_pg_status_extended")

"""Live Phase-118 success, error, and security-negative ROOT probes."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from official_interop_lib import chown_brix
from settings import (DATA_ROOT, NGINX_ANON_PORT, NGINX_HTTP_WEBDAV_PORT,
                      READONLY_DATA_ROOT, READONLY_PORT, SERVER_HOST, TEST_ROOT)
from xrd_conform_live_fixtures import (
    basic_results, bound_stream_results, query_claim_results,
)


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"

# Every fixture below mutates the protocol-defined brix-conform-* corpus under
# the same anonymous export. Keep both live modules on one worker: concurrent
# accept/full runs otherwise remove one another's scratch objects and turn
# deterministic protocol checks into NotFound/leftover cascades.
pytestmark = pytest.mark.xdist_group("xrd-conform-live")


@pytest.fixture(scope="module")
def open_disrupt_results(tmp_path_factory):
    """Run bounded handle-exhaustion probes with explicit target authority."""
    output = tmp_path_factory.mktemp("xrd-conform-open-disrupt")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "accept", target, "--families", "OPN",
         "--open-fixture", f"idle={target}",
         "--allow-disrupt", "--confirm-target", target,
         "--fail-on", "divergent", "--wall-seconds", "30",
         "--request-limit", "128", "--byte-limit", "1048576",
         "--out", str(output)],
        text=True, capture_output=True, timeout=45, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def readv_results(tmp_path_factory):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path_factory.mktemp("xrd-conform-readv")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//random.bin"
    result = subprocess.run(
        [str(XRD), "conform", "accept", target,
         "--families", "RDV", "--budget", "boundary",
         "--fail-on", "divergent", "--wall-seconds", "60",
         "--request-limit", "128", "--byte-limit", "33554432",
         "--out", str(output)],
        text=True, capture_output=True, timeout=75, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def readv_chunked_results(tmp_path_factory):
    output = tmp_path_factory.mktemp("xrd-conform-readv-chunked")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "accept", target,
         "--families", "RDV,CHU", "--budget", "boundary",
         "--allow-mutate", "--scratch", "/",
         "--fail-on", "divergent", "--wall-seconds", "120",
         "--request-limit", "1400", "--byte-limit", "268435456",
         "--out", str(output)],
        text=True, capture_output=True, timeout=135, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    leftovers = list((Path(TEST_ROOT) / "data").glob("brix-conform-*"))
    assert leftovers == []
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def namespace_results(tmp_path_factory):
    output = tmp_path_factory.mktemp("xrd-conform-namespace")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "full", target,
         "--families", "DIR,MKD,MV,RM,CHM", "--allow-mutate", "--scratch", "/",
         "--fail-on", "divergent", "--wall-seconds", "60",
         "--request-limit", "1024", "--byte-limit", "16777216",
         "--out", str(output)],
        text=True, capture_output=True, timeout=75, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    leftovers = list((Path(TEST_ROOT) / "data").glob("brix-conform-ns*"))
    leftovers += list((Path(TEST_ROOT) / "data").glob("brix-conform-dir*"))
    assert leftovers == []
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def write_results(tmp_path_factory):
    output = tmp_path_factory.mktemp("xrd-conform-write")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "full", target,
         "--families", "WRT,WVC,SYN,TRN,PGW,FAT",
         "--allow-mutate", "--scratch", "/", "--fail-on", "divergent",
         "--wall-seconds", "60", "--request-limit", "512",
         "--byte-limit", "33554432", "--out", str(output)],
        text=True, capture_output=True, timeout=75, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    leftovers = list((Path(TEST_ROOT) / "data").glob("brix-conform-write*"))
    assert leftovers == []
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def open_mutation_results(tmp_path_factory):
    """Run the scratch-confined open-option matrix once for its row tests."""
    output = tmp_path_factory.mktemp("xrd-conform-open-mutate")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "full", target, "--families", "OPN,STA",
         "--allow-mutate", "--scratch", "/", "--fail-on", "divergent",
         "--wall-seconds", "60", "--request-limit", "256",
         "--byte-limit", "16777216", "--out", str(output)],
        text=True, capture_output=True, timeout=75, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    leftovers = list((Path(TEST_ROOT) / "data").glob("brix-conform-open*"))
    assert leftovers == []
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


def test_open_posc_clean_close_publishes_bytes(open_mutation_results):
    """Success: a clean POSC close leaves the exact completed object."""
    assert open_mutation_results["OPN-016"]["verdict"] == "conformant"


def test_open_posc_stat_flag_transitions(open_mutation_results):
    """Success: POSC pending is set before close and clear after commit."""
    assert open_mutation_results["STA-011"]["verdict"] == "conformant"


def test_open_posc_abort_leaves_no_object(open_mutation_results):
    """Security-negative: dropping a POSC handle removes partial state."""
    assert open_mutation_results["OPN-015"]["verdict"] == "conformant"


def test_open_new_only_refuses_existing_object(open_mutation_results):
    """Error: exclusive create preserves an existing object with ItExists."""
    assert open_mutation_results["OPN-008"]["verdict"] == "conformant"


def test_open_append_places_write_at_eof(open_mutation_results):
    """Success: append mode preserves the prefix despite an explicit offset."""
    assert open_mutation_results["OPN-014"]["verdict"] == "conformant"


def test_open_all_option_bits_fail_closed(open_mutation_results):
    """Security-negative: contradictory all-bits open is ArgInvalid."""
    assert open_mutation_results["OPN-025"]["verdict"] == "conformant"


def test_open_replica_refusal_and_write_only_capability(open_mutation_results):
    """Error/security-negative: replica refuses; wrto cannot be read through."""
    assert open_mutation_results["OPN-022"]["verdict"] == "conformant"


def test_open_refresh_observes_an_independent_session_change(
        open_mutation_results):
    """Success: refresh+retstat reports the independently replaced size."""
    row = open_mutation_results["OPN-021"]
    assert row["verdict"] == "conformant"
    assert row["reason"] == \
        "refresh-open-observed-independent-metadata-change"


def test_close_reserved_bytes_do_not_invent_size_contract(basic_results):
    """Security-negative: close reserved bytes cannot alter durable content."""
    assert basic_results["OPN-031"]["verdict"] == "conformant"


@pytest.fixture(scope="module")
def prepare_results(tmp_path_factory):
    """Run live prepare/QPrep agreement and refusal probes once."""
    output = tmp_path_factory.mktemp("xrd-conform-prepare")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "full", target, "--families", "PRP,QRY",
         "--allow-mutate", "--scratch", "/",
         "--allow-disrupt", "--confirm-target", target,
         "--fail-on", "divergent",
         "--wall-seconds", "30", "--request-limit", "128",
         "--byte-limit", "16777216", "--out", str(output)],
        text=True, capture_output=True, timeout=45, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


def test_prepare_returns_request_id(prepare_results):
    """Success: staging an existing target returns a pollable id."""
    assert prepare_results["PRP-001"]["verdict"] == "conformant"


def test_prepare_cancel_is_idempotent_and_non_enumerating(prepare_results):
    """Success/error/security-negative: repeat and foreign/absent cancel agree."""
    assert prepare_results["PRP-002"]["verdict"] == "conformant"


def test_qprep_agrees_and_is_session_scoped(prepare_results):
    """Security-negative: QPrep agrees locally without cross-session leakage."""
    assert prepare_results["QRY-011"]["verdict"] == "conformant"


def test_prepare_missing_path_is_not_silent(prepare_results):
    """Error: a missing strict stage target is refused synchronously."""
    assert prepare_results["PRP-005"]["verdict"] == "conformant"


def test_prepare_unreachable_notify_completes(prepare_results):
    """Success: an unreachable notification callback cannot hold prepare."""
    row = prepare_results["PRP-006"]
    assert row["verdict"] == "conformant"
    assert row["reason"] == "unreachable-notify-completed-and-session-reusable"


def test_prepare_unreachable_notify_keeps_session_usable(prepare_results):
    """Error path: callback failure leaves the request stream synchronized."""
    assert "session-reusable" in prepare_results["PRP-006"]["reason"]


def test_prepare_unreachable_notify_is_not_skipped(prepare_results):
    """Security-negative: reserved TCP port one is exercised, not skipped."""
    assert prepare_results["PRP-006"]["verdict"] != "skipped"


@pytest.fixture(scope="module")
def checkpoint_results(tmp_path_factory):
    """Run the complete scratch-confined checkpoint family once."""
    output = tmp_path_factory.mktemp("xrd-conform-checkpoint")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "full", target, "--families", "CKP",
         "--allow-mutate", "--scratch", "/", "--fail-on", "divergent",
         "--wall-seconds", "60", "--request-limit", "96",
         "--byte-limit", "1048576", "--out", str(output)],
        text=True, capture_output=True, timeout=75, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    leftovers = list((Path(TEST_ROOT) / "data").glob("brix-conform-checkpoint*"))
    assert leftovers == []
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


def test_checkpoint_query_has_consistent_capacity(checkpoint_results):
    """Success: checkpoint query reports a usable consistent capacity."""
    assert checkpoint_results["CKP-002"]["verdict"] == "conformant"


def test_checkpoint_rollback_restores_bytes(checkpoint_results):
    """Error recovery: rollback restores the exact pre-write bytes."""
    assert checkpoint_results["CKP-003"]["verdict"] == "conformant"


def test_checkpoint_overlimit_fails_before_data_loss(checkpoint_results):
    """Security-negative: an oversized snapshot is refused without truncation."""
    assert checkpoint_results["CKP-004"]["verdict"] == "conformant"


READONLY_POLICY_CLAUSES = (
    "WRT-006", "OPN-011", "PGW-013", "TRN-006", "MKD-005", "MV-006",
    "RM-007", "CHM-003", "PRP-007", "STA-005", "STA-006", "LOC-004",
    "CAC-010", "FAT-009",
)


def _run_readonly_clause(tmp_path, port, clause, tag="present", verify=False):
    output = tmp_path / f"readonly-{clause}-{port}-{tag}"
    target = f"root://{SERVER_HOST}:{port}//test.txt"
    command = [str(XRD), "conform", "full", target, "--only", clause,
         "--profile", "cache" if clause == "CAC-010" else "data",
         "--allow-mutate", "--scratch", "/", "--fail-on", "divergent",
         "--wall-seconds", "20", "--request-limit", "32",
         "--byte-limit", "1048576", "--out", str(output)]
    if verify:
        command.extend(["--verify-negative", clause])
    result = subprocess.run(
        command,
        text=True, capture_output=True, timeout=30, check=False,
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in report["results"]}
    return result, rows[clause]


@pytest.fixture
def fattr_readonly_fixtures():
    readonly_fixture = Path(READONLY_DATA_ROOT) / "brix-conform-fattr-readonly"
    writable_fixture = Path(DATA_ROOT) / "brix-conform-fattr-readonly"
    roots = (Path(READONLY_DATA_ROOT), Path(DATA_ROOT))
    for root in roots:
        (root / "brix-conform-readonly-file").write_bytes(b"R" * 8192)
        (root / "brix-conform-readonly-source").write_bytes(b"source\n")
        chown_brix(root / "brix-conform-readonly-file",
                   root / "brix-conform-readonly-source")
        (root / "brix-conform-readonly-target").unlink(missing_ok=True)
        try:
            (root / "brix-conform-readonly-newdir").rmdir()
        except FileNotFoundError:
            pass
    readonly_fixture.write_bytes(b"readonly\n")
    writable_fixture.write_bytes(b"writable\n")
    chown_brix(readonly_fixture, writable_fixture)
    try:
        yield readonly_fixture, writable_fixture
    finally:
        readonly_fixture.unlink(missing_ok=True)
        writable_fixture.unlink(missing_ok=True)
        for root in roots:
            for leaf in ("brix-conform-readonly-file",
                         "brix-conform-readonly-source",
                         "brix-conform-readonly-target"):
                (root / leaf).unlink(missing_ok=True)
            try:
                (root / "brix-conform-readonly-newdir").rmdir()
            except FileNotFoundError:
                pass


@pytest.mark.registry_server("readonly")
def test_fattr_readonly_returns_fsreadonly(tmp_path, fattr_readonly_fixtures):
    """FAT-009 accepts only the typed read-only policy response."""
    result, row = _run_readonly_clause(tmp_path, READONLY_PORT, "FAT-009")
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"
    assert row["reason"] == "readonly-fattr-set-refused"


def test_fattr_readonly_probe_rejects_writable_export(
        tmp_path, fattr_readonly_fixtures):
    """FAT-009 goes red on a writable export and removes probe residue."""
    _, writable_fixture = fattr_readonly_fixtures
    result, row = _run_readonly_clause(tmp_path, NGINX_ANON_PORT, "FAT-009")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert row["reason"] == "readonly-fattr-wrong-answer"
    assert not any(name.endswith("phase118-readonly")
                   for name in os.listxattr(writable_fixture))


def test_fattr_readonly_probe_does_not_confuse_missing_object(
        tmp_path, fattr_readonly_fixtures):
    """FAT-009 does not treat a missing fixture as read-only evidence."""
    _, writable_fixture = fattr_readonly_fixtures
    writable_fixture.unlink()
    result, row = _run_readonly_clause(tmp_path, NGINX_ANON_PORT, "FAT-009",
                                       "missing")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert row["reason"] == "readonly-fattr-wrong-answer"


@pytest.mark.registry_server("readonly")
@pytest.mark.parametrize("clause", READONLY_POLICY_CLAUSES[:-1])
def test_readonly_policy_clause_is_conformant(
        tmp_path, fattr_readonly_fixtures, clause):
    """Each exact read-only row observes its required policy behavior."""
    result, row = _run_readonly_clause(tmp_path, READONLY_PORT, clause)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant", row


@pytest.mark.parametrize("clause", READONLY_POLICY_CLAUSES[:-1])
def test_readonly_policy_clause_rejects_writable_control(
        tmp_path, fattr_readonly_fixtures, clause):
    """Each exact read-only row goes red against its writable control."""
    result, row = _run_readonly_clause(
        tmp_path, NGINX_ANON_PORT, clause, verify=True,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent", row


def test_readonly_write_probe_does_not_confuse_missing_object(
        tmp_path, fattr_readonly_fixtures):
    """The write-policy probe preserves NotFound as a divergent outcome."""
    missing = Path(DATA_ROOT) / "brix-conform-readonly-file"
    missing.unlink()
    result, row = _run_readonly_clause(tmp_path, NGINX_ANON_PORT, "WRT-006",
                                       "missing")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert "kxr=3011" in row["received"]


def test_readonly_prepare_probe_does_not_confuse_missing_object(
        tmp_path, fattr_readonly_fixtures):
    """PRP-007 preserves NotFound instead of treating it as policy evidence."""
    missing = Path(DATA_ROOT) / "brix-conform-readonly-file"
    missing.unlink()
    result, row = _run_readonly_clause(tmp_path, NGINX_ANON_PORT, "PRP-007",
                                       "missing")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert "kxr=3011" in row["received"]


@pytest.fixture(scope="module")
def disruptive_framing_results(tmp_path_factory):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path_factory.mktemp("xrd-conform-disrupt-framing")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "accept", target,
         "--families", "FRM", "--budget", "boundary",
         "--allow-disrupt", "--confirm-target", target,
         "--fail-on", "divergent", "--wall-seconds", "30",
         "--request-limit", "256", "--byte-limit", "1048576",
         "--out", str(output)],
        text=True, capture_output=True, timeout=45, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def http_error_results(tmp_path_factory):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path_factory.mktemp("xrd-conform-http-errors")
    target = f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}/test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "accept", target,
         "--families", "HTE", "--budget", "boundary",
         "--fail-on", "divergent", "--wall-seconds", "20",
         "--request-limit", "32", "--byte-limit", "1048576",
         "--out", str(output)],
        text=True, capture_output=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def mutating_results(tmp_path_factory):
    output = tmp_path_factory.mktemp("xrd-conform-mutate")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "accept", target,
         "--families", "RD,PGR", "--budget", "boundary",
         "--allow-mutate", "--scratch", "/",
         "--fail-on", "divergent", "--wall-seconds", "90",
         "--request-limit", "1400", "--byte-limit", "134217728",
         "--out", str(output)],
        text=True, capture_output=True, timeout=105, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    leftovers = list((Path(TEST_ROOT) / "data").glob("brix-conform-*"))
    assert leftovers == []
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


def test_open_success_and_distinct_handles(basic_results):
    assert basic_results["PROT-003"]["verdict"] == "conformant"
    assert basic_results["PROT-014"]["verdict"] == "conformant"
    assert basic_results["OPN-001"]["verdict"] == "conformant"
    assert basic_results["OPN-002"]["verdict"] == "conformant"
    assert basic_results["OPN-013"]["verdict"] == "conformant"
    assert basic_results["ERR-008"]["verdict"] == "conformant"


def test_open_response_metadata_modes_and_lifecycle(basic_results):
    for clause in ("OPN-003", "OPN-005", "OPN-006", "OPN-007",
                   "OPN-018", "OPN-019", "OPN-027", "OPN-028",
                   "OPN-029", "OPN-030"):
        assert basic_results[clause]["verdict"] == "conformant"


def test_handshake_and_protocol_shapes_are_exact(basic_results):
    for clause in ("HSK-001", "HSK-002", "HSK-003", "HSK-004", "HSK-005",
                   "HSK-006", "HSK-007", "PROT-001",
                   "PROT-002", "PROT-004", "PROT-005", "PROT-006",
                   "PROT-007", "PROT-008", "PROT-012", "PROT-013"):
        assert basic_results[clause]["verdict"] == "conformant"


def test_protocol_repeats_and_version_floor_are_stable(basic_results):
    for clause in ("PROT-009", "PROT-010", "PROT-011"):
        assert basic_results[clause]["verdict"] == "conformant"


def test_anonymous_login_and_session_lifecycle(basic_results):
    for clause in ("LOG-001", "LOG-002", "LOG-003", "LOG-007", "LOG-013",
                   "LOG-014", "LOG-018", "LOG-019", "LOG-020"):
        assert basic_results[clause]["verdict"] == "conformant"
    assert basic_results["LOG-004"]["reason"] == \
        "claim-absent:security-mechanism"
    assert basic_results["SIG-001"]["reason"] == \
        "claim-absent:request-signing"


def test_disruptive_frame_rows_fail_closed_by_default(basic_results):
    for clause in ("FRM-012", "FRM-021"):
        assert basic_results[clause]["verdict"] == "skipped"
        assert basic_results[clause]["reason"] == \
            "probe-class-disabled:disrupt"


def test_complete_frame_family_is_conformant(disruptive_framing_results):
    for clause in ("FRM-001", "FRM-002", "FRM-003", "FRM-004", "FRM-005",
                   "FRM-006", "FRM-007", "FRM-008", "FRM-009", "FRM-010",
                   "FRM-011", "FRM-012", "FRM-013", "FRM-014", "FRM-015",
                   "FRM-016", "FRM-017", "FRM-018", "FRM-019", "FRM-020",
                   "FRM-021", "FRM-022", "FRM-023"):
        assert disruptive_framing_results[clause]["verdict"] == "conformant"


def test_cross_session_handle_theft_is_rejected(basic_results):
    row = basic_results["OPN-004"]
    assert row["verdict"] == "conformant"
    assert row["reason"] == "cross-session-handle-refused"
    assert basic_results["ERR-016"]["verdict"] == "conformant"


def test_unknown_and_malformed_read_authority_is_refused(basic_results):
    for clause in ("RD-019", "RD-023", "RD-031", "RD-033"):
        assert basic_results[clause]["verdict"] == "conformant"


def test_read_path_ids_are_confined(basic_results):
    assert basic_results["RD-020"]["verdict"] == "conformant"
    assert basic_results["RD-021"]["verdict"] == "conformant"


def test_read_extreme_boundaries_and_readahead_are_bounded(basic_results):
    assert basic_results["RD-012"]["verdict"] == "conformant"
    assert basic_results["RD-013"]["verdict"] == "conformant"
    assert basic_results["RD-022"]["verdict"] == "conformant"
    assert basic_results["RD-014"]["verdict"] == "conformant"


def test_pgread_structure_arguments_and_negative_bounds(basic_results):
    # /test.txt is deliberately tiny. Full page geometry is exercised against
    # the 40 KiB controlled origin; here prove the live server's structural,
    # argument, terminal-byte, zero-length, and negative-bound contracts.
    for clause in ("PGR-001", "PGR-002", "PGR-003", "PGR-004", "PGR-005",
                   "PGR-007", "PGR-015", "PGR-018", "PGR-022", "PGR-023",
                   "PGR-024", "PGR-030", "PGR-031", "PGR-032"):
        assert basic_results[clause]["verdict"] == "conformant"


def test_mutating_standard_corpus_exact_sizes(mutating_results):
    for clause in ("RD-010", "PGR-016", "PGR-017"):
        assert mutating_results[clause]["verdict"] == "conformant"


def test_mutating_large_response_and_offset_boundaries(mutating_results):
    for clause in ("RD-009", "RD-011", "PGR-006", "PGR-025", "PGR-026",
                   "PGR-028"):
        assert mutating_results[clause]["verdict"] == "conformant"


def test_mutating_substream_and_write_only_security(mutating_results):
    for clause in ("RD-016", "RD-017", "PGR-029"):
        assert mutating_results[clause]["verdict"] == "conformant"


def test_file_dirlist_and_missing_locate_errors(basic_results):
    assert basic_results["DIR-006"]["verdict"] == "conformant"
    assert basic_results["LOC-003"]["verdict"] == "conformant"
    assert basic_results["LOC-007"]["verdict"] == "conformant"
    assert basic_results["LOC-008"]["verdict"] == "conformant"
    assert basic_results["STA-004"]["verdict"] == "conformant"
    assert basic_results["QRY-002"]["verdict"] == "conformant"
    assert basic_results["QRY-004"]["verdict"] == "conformant"
    assert basic_results["QRY-006"]["verdict"] == "conformant"
    assert basic_results["QRY-008"]["verdict"] == "conformant"
    assert basic_results["ERR-039"]["verdict"] == "conformant"
    assert basic_results["ERR-041"]["verdict"] == "conformant"
    assert basic_results["ERR-002"]["verdict"] == "conformant"


def test_stat_forms_boundaries_and_batch_agreement(basic_results):
    for clause in ("STA-001", "STA-002", "STA-003", "STA-004", "STA-007",
                   "STA-008", "STA-009", "STA-010", "STA-013", "STA-014", "STA-015",
                   "STA-016", "STA-017", "STA-018"):
        assert basic_results[clause]["verdict"] == "conformant"


def test_directory_dstat_shape_and_confinement(basic_results):
    for clause in ("DIR-002", "DIR-003", "DIR-006", "DIR-009"):
        assert basic_results[clause]["verdict"] == "conformant"


def test_fattr_support_has_defined_wire_result(basic_results):
    assert basic_results["FAT-008"]["verdict"] == "conformant"


def test_unknown_http_method_is_rejected_with_allow(http_error_results):
    row = http_error_results["HTE-003"]
    assert row["verdict"] == "conformant"
    assert row["reason"] == "unknown-method-rejected-with-allow"


def test_qconfig_multikey_order_and_unknown_continuity(basic_results):
    assert basic_results["QRY-001"]["verdict"] == "conformant"
    assert basic_results["QRY-014"]["verdict"] == "conformant"


def test_qconfig_claims_match_observed_checksums_and_readv_limit(
        query_claim_results):
    row = query_claim_results["QRY-003"]
    assert row["verdict"] == "conformant"
    assert "advertised-checksums-served=" in row["received"]
    assert "readv-bound-observed=" in row["received"]


def test_bound_path_routes_bytes_and_expires(bound_stream_results):
    for clause in ("BND-001", "BND-002", "BND-003"):
        assert bound_stream_results[clause]["verdict"] == "conformant"


def test_bound_stream_limit_has_defined_refusal(bound_stream_results):
    """Error: bind_max live streams are accepted and the next is refused."""
    assert bound_stream_results["BND-004"]["verdict"] == "conformant"


def test_closed_bound_pathid_loses_authority(bound_stream_results):
    """Security-negative: a disconnected secondary's pathid cannot be reused."""
    assert bound_stream_results["BND-005"]["verdict"] == "conformant"


def test_handle_exhaustion_is_bounded_and_recovers(open_disrupt_results):
    """Error/security-negative: exhaustion preserves live handles and recovers."""
    assert open_disrupt_results["OPN-032"]["verdict"] == "conformant"


def test_idle_handle_survives_asserted_keepalive_boundary(open_disrupt_results):
    """Success: a two-second idle interval does not silently lose the handle."""
    assert open_disrupt_results["OPN-033"]["verdict"] == "conformant"

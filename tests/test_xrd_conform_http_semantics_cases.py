"""Phase-118 HTTP, S3, WebDAV, and cross-plane semantic cases."""
import pytest

from test_xrd_conform_http_semantics import (
    _run,
    _run_cross_plane,
)
from xrd_conform_http_case_helpers import (
    _run_cross_plane_mutation,
    _run_dav_directory,
)


@pytest.mark.parametrize(("scheme", "row", "credentials"), [
    ("http", "HTR-001", False),
    ("s3", "S3-001", True),
])
def test_planted_web_baseline_is_prf_exact(
        tmp_path, scheme, row, credentials):
    result, rows = _run(
        tmp_path, scheme=scheme, with_s3_credentials=credentials, only=row,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows[row]["verdict"] == "conformant"


@pytest.mark.parametrize(("scheme", "row", "credentials"), [
    ("http", "HTR-001", False),
    ("s3", "S3-001", True),
])
def test_planted_web_baseline_corruption_is_detected(
        tmp_path, scheme, row, credentials):
    result, rows = _run(
        tmp_path, "prf_baseline_corrupt", scheme=scheme,
        with_s3_credentials=credentials, verify_negative=row, only=row,
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[row]["verdict"] == "divergent"


def test_cross_plane_size_mismatch_is_detected(tmp_path):
    result, rows = _run_cross_plane(
        tmp_path, "s3_size_mismatch", verify_negative="XPR-001",
    )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["XPR-001"]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("htr_bad_002", "HTR-002"),
    ("htr_bad_003", "HTR-003"),
    ("htr_bad_004", "HTR-004"),
    ("htr_bad_005", "HTR-005"),
    ("htr_bad_006", "HTR-006"),
    ("htr_bad_007", "HTR-007"),
    ("htr_bad_008", "HTR-008"),
    ("htr_bad_009", "HTR-009"),
    ("htr_bad_013", "HTR-013"),
    ("htr_bad_014", "HTR-014"),
])
def test_hostile_http_range_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, verify_negative=owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_truncated_content_length_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "htr_bad_015",
                        verify_negative="HTR-015", only="HTR-015")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["HTR-015"]["verdict"] == "divergent"
    assert rows["HTR-015"]["reason"] == "GET-content-length-truncated"


def test_multipart_ranges_reassemble_exactly(tmp_path):
    """Valid ordinary and overlapping MIME ranges are accepted."""
    result, rows = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTR-010"]["verdict"] == "conformant"
    assert rows["HTR-011"]["verdict"] == "conformant"


def test_multipart_corruption_is_detected(tmp_path):
    """A part whose bytes disagree with Content-Range turns both rows red."""
    result, rows = _run(tmp_path, "multipart_bad",
                        verify_negative=("HTR-010", "HTR-011"))
    assert result.returncode == 1
    assert rows["HTR-010"]["verdict"] == "divergent"
    assert rows["HTR-011"]["verdict"] == "divergent"


def test_chunked_body_requires_valid_zero_termination(tmp_path):
    """A complete chunk sequence is reassembled and graded conformant."""
    result, rows = _run(tmp_path, "chunked_ok")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTR-016"]["verdict"] == "conformant"


def test_missing_zero_chunk_is_detected(tmp_path):
    """EOF without the mandatory zero chunk is not accepted as a body."""
    result, rows = _run(tmp_path, "chunked_bad", verify_negative="HTR-016",
                        only="HTR-016")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["HTR-016"]["verdict"] == "divergent"


def test_oversized_chunk_claim_is_detected(tmp_path):
    """A chunk length larger than its available data cannot be truncated."""
    result, rows = _run(tmp_path, "chunked_oversize",
                        verify_negative="HTR-016", only="HTR-016")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["HTR-016"]["verdict"] == "divergent"


def test_want_digest_matches_local_recompute(tmp_path):
    """Canonical sha256 integrity metadata matches the adopted bytes."""
    result, rows = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTR-021"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour", ["digest_bad", "digest_name_bad"])
def test_want_digest_rejects_wrong_value_or_name(tmp_path, behaviour):
    """A false value or non-ROOT algorithm spelling turns HTR-021 red."""
    result, rows = _run(tmp_path, behaviour, verify_negative="HTR-021")
    assert result.returncode == 1
    assert rows["HTR-021"]["verdict"] == "divergent"


def test_etag_is_stable_then_changes_after_put(tmp_path):
    """Two reads agree and a scratch-confined content mutation changes ETag."""
    result, rows = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTR-017"]["verdict"] == "conformant"


def test_static_etag_after_mutation_is_detected(tmp_path):
    """Reusing one validator across changed content turns HTR-017 red."""
    result, rows = _run(tmp_path, "etag_static", verify_negative="HTR-017")
    assert result.returncode == 1
    assert rows["HTR-017"]["verdict"] == "divergent"


def test_s3_range_grid_agrees_with_http_semantics(tmp_path):
    result, rows = _run(tmp_path, scheme="s3")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-002"]["verdict"] == "conformant"


def test_s3_range_corruption_propagates_to_agreement_row(tmp_path):
    result, rows = _run(tmp_path, "multipart_bad", scheme="s3",
                        verify_negative="S3-002")
    assert result.returncode == 1
    assert rows["S3-002"]["verdict"] == "divergent"


def test_s3_range_transport_error_propagates_to_agreement_row(tmp_path):
    result, rows = _run(tmp_path, "range_error", scheme="s3",
                        verify_negative="S3-002")
    assert result.returncode == 1
    assert rows["S3-002"]["verdict"] == "divergent"


def test_s3_missing_key_and_bucket_codes_are_distinguished(tmp_path):
    result, rows = _run(tmp_path, scheme="s3")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-010"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour", ["s3_key_code_bad", "s3_bucket_code_bad"])
def test_s3_generic_missing_error_is_rejected(tmp_path, behaviour):
    result, rows = _run(tmp_path, behaviour, scheme="s3",
                        verify_negative="S3-010")
    assert result.returncode == 1
    assert rows["S3-010"]["verdict"] == "divergent"


def test_s3_listing_and_one_key_pagination_agree(tmp_path):
    result, rows = _run(tmp_path, scheme="s3")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-003"]["verdict"] == "conformant"
    assert rows["S3-004"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour,row", [
    ("s3_list_extra", "S3-003"),
    ("s3_list_unbounded", "S3-003"),
    ("s3_list_replay_bad", "S3-004"),
])
def test_s3_listing_fault_is_detected(tmp_path, behaviour, row):
    result, rows = _run(tmp_path, behaviour, scheme="s3",
                        verify_negative=row)
    assert result.returncode == 1
    assert rows[row]["verdict"] == "divergent"


def test_s3_special_keys_round_trip_without_normalization(tmp_path):
    result, rows = _run(tmp_path, scheme="s3")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-014"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour", [
    "s3_special_get_bad", "s3_special_list_bad",
])
def test_s3_special_key_fault_is_detected(tmp_path, behaviour):
    result, rows = _run(tmp_path, behaviour, scheme="s3",
                        verify_negative="S3-014")
    assert result.returncode == 1
    assert rows["S3-014"]["verdict"] == "divergent"


def test_s3_multipart_semantics_are_complete(tmp_path):
    result, rows = _run(tmp_path, scheme="s3")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-011"]["verdict"] == "conformant"
    assert rows["S3-012"]["verdict"] == "conformant"
    assert rows["S3-013"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour,row", [
    ("s3_multipart_order_bad", "S3-011"),
    ("s3_multipart_missing_accepted", "S3-011"),
    ("s3_multipart_small_accepted", "S3-012"),
    ("s3_multipart_etag_bad", "S3-013"),
])
def test_s3_multipart_fault_is_detected(tmp_path, behaviour, row):
    result, rows = _run(tmp_path, behaviour, scheme="s3",
                        verify_negative=row)
    assert result.returncode == 1
    assert rows[row]["verdict"] == "divergent"


def test_cross_plane_missing_object_agrees(tmp_path):
    result, rows = _run_cross_plane(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-007"]["verdict"] == "conformant"


def test_cross_plane_server_checksums_agree(tmp_path):
    """HTTP Digest and S3 ChecksumSHA256 prove the same adopted bytes."""
    result, rows = _run_cross_plane(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-003"]["verdict"] == "conformant"


def test_cross_plane_namespace_sets_agree(tmp_path):
    """WebDAV and S3 expose the same bounded direct-child name set."""
    result, rows = _run_cross_plane(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-004"]["verdict"] == "conformant"


def test_webdav_depth_one_matches_root_directory(tmp_path):
    """Success: DAV Depth:1 and ROOT dirlist expose the same direct child."""
    result, rows = _run_dav_directory(tmp_path, ["fixture"])
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["DAV-002"]["verdict"] == "conformant"


def test_webdav_root_directory_failure_stays_inconclusive(tmp_path):
    """Error: one unavailable namespace plane cannot become agreement."""
    result, rows = _run_dav_directory(tmp_path, None)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["DAV-002"]["verdict"] == "inconclusive"
    assert rows["DAV-002"]["reason"] == \
        "fixture-required:paired-root-directory"


def test_webdav_root_directory_mismatch_is_detected(tmp_path):
    """Security-negative: an extra ROOT-visible child turns DAV-002 red."""
    result, rows = _run_dav_directory(
        tmp_path, ["fixture", "root-only-child"],
        verify_negative="DAV-002",
    )
    assert result.returncode == 1
    assert rows["DAV-002"]["verdict"] == "divergent"


@pytest.mark.parametrize("behaviour", [
    "http_namespace_extra", "s3_namespace_extra",
])
def test_cross_plane_namespace_mismatch_is_detected(tmp_path, behaviour):
    """Security-negative: a name visible on only one plane is divergent."""
    result, rows = _run_cross_plane(tmp_path, behaviour,
                                    verify_negative="XPR-004")
    assert result.returncode == 1
    assert rows["XPR-004"]["verdict"] == "divergent"


def test_cross_plane_truncated_namespace_is_not_accepted(tmp_path):
    """A truncated S3 page cannot be treated as a complete namespace set."""
    result, rows = _run_cross_plane(tmp_path, "s3_namespace_truncated")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-004"]["verdict"] == "inconclusive"
    assert rows["XPR-004"]["reason"] == \
        "fixture-required:cross-plane-directory"


def test_cross_plane_filename_classes_can_be_refused(tmp_path):
    """All three non-ASCII classes may be explicitly refused on both planes."""
    result, rows = _run_cross_plane(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-011"]["verdict"] == "conformant"


def test_cross_plane_filename_classes_can_resolve_same_bytes(tmp_path):
    """All three filename classes may resolve to the adopted bytes."""
    result, rows = _run_cross_plane(tmp_path, "filename_visible")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-011"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour", [
    "http_filename_visible", "s3_filename_wrong",
])
def test_cross_plane_filename_mismatch_is_detected(tmp_path, behaviour):
    """Security-negative: asymmetric policy or wrong bytes are divergent."""
    result, rows = _run_cross_plane(tmp_path, behaviour,
                                    verify_negative="XPR-011")
    assert result.returncode == 1
    assert rows["XPR-011"]["verdict"] == "divergent"


def test_cross_plane_mutation_reaches_root_and_s3_then_cleans_up(tmp_path):
    """A scratch PUT reaches ROOT stat and S3 list/GET, then disappears."""
    result, rows = _run_cross_plane_mutation(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-009"]["verdict"] == "conformant"
    assert rows["XPR-009"]["received"] == \
        "put=1 root-size=1 s3-list=1 s3-bytes=1 cleanup=1"


def test_cross_plane_mutation_hidden_from_s3_listing_is_detected(tmp_path):
    """Security-negative: successful GET cannot excuse a hidden list entry."""
    result, rows = _run_cross_plane_mutation(
        tmp_path, "mutation_s3_hidden", verify_negative="XPR-009")
    assert result.returncode == 1
    assert rows["XPR-009"]["verdict"] == "divergent"
    assert "s3-list=0" in rows["XPR-009"]["received"]


def test_cross_plane_mutation_cleanup_failure_is_detected(tmp_path):
    """Error path: an acknowledged DELETE that leaves data behind is red."""
    result, rows = _run_cross_plane_mutation(
        tmp_path, "mutation_delete_bad", verify_negative="XPR-009")
    assert result.returncode == 1
    assert rows["XPR-009"]["verdict"] == "divergent"
    assert "cleanup=0" in rows["XPR-009"]["received"]


def test_http_create_reads_back_through_http_and_root(tmp_path):
    """Success: a two-plane fixture completes HTC-001 byte-exactly."""
    result, rows = _run_cross_plane_mutation(
        tmp_path, clause="HTC-001",
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTC-001"]["verdict"] == "conformant"
    assert rows["HTC-001"]["received"] == \
        "put=1 http-bytes=1 root-size=1 cleanup=1"


def test_http_create_rejects_wrong_http_readback(tmp_path):
    """Security-negative: substituted HTTP bytes make HTC-001 divergent."""
    result, rows = _run_cross_plane_mutation(
        tmp_path, "mutation_http_bytes_bad", "HTC-001",
        verify_negative="HTC-001",
    )
    assert result.returncode == 1
    assert rows["HTC-001"]["verdict"] == "divergent"
    assert "http-bytes=0" in rows["HTC-001"]["received"]


def test_http_create_requires_verified_cleanup(tmp_path):
    """Error: an acknowledged ineffective DELETE cannot pass HTC-001."""
    result, rows = _run_cross_plane_mutation(
        tmp_path, "mutation_delete_bad", "HTC-001",
        verify_negative="HTC-001",
    )
    assert result.returncode == 1
    assert rows["HTC-001"]["verdict"] == "divergent"
    assert "cleanup=0" in rows["HTC-001"]["received"]


def test_cross_plane_false_s3_checksum_is_detected(tmp_path):
    """Security-negative: false S3 integrity metadata cannot satisfy XPR-003."""
    result, rows = _run_cross_plane(tmp_path, "s3_checksum_bad",
                                    verify_negative="XPR-003")
    assert result.returncode == 1
    assert rows["XPR-003"]["verdict"] == "divergent"


def test_cross_plane_checksum_needs_two_server_claims(tmp_path):
    """Optional metadata absence remains honest instead of passing local hashes."""
    result, rows = _run_cross_plane(tmp_path, "s3_checksum_absent")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-003"]["verdict"] == "inconclusive"
    assert rows["XPR-003"]["reason"] == \
        "fixture-required:cross-plane-checksum"


def test_cross_plane_traversal_is_refused(tmp_path):
    """The same parent-segment payload is refused on HTTP and S3."""
    result, rows = _run_cross_plane(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-008"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour", [
    "http_traversal_visible", "s3_traversal_visible",
])
def test_cross_plane_traversal_exposure_is_detected(tmp_path, behaviour):
    """Security-negative: acceptance by either plane is a divergence."""
    result, rows = _run_cross_plane(tmp_path, behaviour,
                                    verify_negative="XPR-008")
    assert result.returncode == 1
    assert rows["XPR-008"]["verdict"] == "divergent"


def test_cross_plane_case_policy_agrees(tmp_path):
    """The deterministic case variant is absent on both HTTP and S3."""
    result, rows = _run_cross_plane(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-010"]["verdict"] == "conformant"


@pytest.mark.parametrize("behaviour", ["http_case_visible", "s3_case_visible"])
def test_cross_plane_case_mismatch_is_detected(tmp_path, behaviour):
    """Security-negative: one plane exposing the alias is a divergence."""
    result, rows = _run_cross_plane(tmp_path, behaviour,
                                    verify_negative="XPR-010")
    assert result.returncode == 1
    assert rows["XPR-010"]["verdict"] == "divergent"


@pytest.mark.parametrize("behaviour", [
    "http_missing_visible", "s3_missing_visible",
])
def test_cross_plane_missing_object_exposure_is_detected(tmp_path, behaviour):
    result, rows = _run_cross_plane(tmp_path, behaviour,
                                    verify_negative="XPR-007")
    assert result.returncode == 1
    assert rows["XPR-007"]["verdict"] == "divergent"

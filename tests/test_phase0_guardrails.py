"""
Phase 0 source-reduction guardrail inventory.

Phase 0 of docs/09-developer-guide/source-reduction-plan.md is a safety gate:
before code is deleted or delegated to nginx/external libraries, the project
must already have behavioral coverage for the compatibility surfaces that can
regress during the reduction work.

These tests are intentionally lightweight and do not start nginx.  They make
the Phase 0 inventory explicit so future cleanup cannot silently remove or
rename the regression suites without updating the roadmap and this contract.
The behavioral suites named here still provide the real protocol checks.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath):
    path = ROOT / relpath
    assert path.exists(), f"Phase 0 guardrail file is missing: {relpath}"
    return path.read_text(encoding="utf-8").lower()


def _assert_markers(relpath, markers):
    text = _read(relpath)
    missing = [marker for marker in markers if marker.lower() not in text]
    assert not missing, (
        f"{relpath} is missing Phase 0 guardrail markers: {missing}"
    )


def test_webdav_method_parity_guardrails_present():
    """WebDAV method parity is covered by direct and XrdHttp-style suites."""
    # The webdav status-code suite was split: HEAD/DELETE/MKCOL + the OPTIONS
    # check stay in the base file; PROPFIND/MOVE/COPY moved to the _b file.
    _assert_markers(
        "tests/test_http_webdav_status_codes.py",
        [
            "class testhead",
            "class testdelete",
            "class testmkcol",
            "test_options_allow_header_has_webdav_methods",
        ],
    )
    _assert_markers(
        "tests/test_http_webdav_status_codes_b.py",
        [
            "class testpropfind",
            "class testmove",
            "class testcopy",
        ],
    )
    _assert_markers(
        "tests/test_webdav.py",
        [
            "test_head_existing_file",
            "test_delete_existing_file",
            "test_mkcol_creates_directory",
            "test_propfind_depth1_lists_children",
        ],
    )
    _assert_markers(
        "tests/test_xrdhttp_webdav.py",
        [
            "test_head_existing_file",
            "test_get_with_range_header",
            "test_propfind_depth_zero",
        ],
    )


def test_token_auth_negative_guardrails_present():
    """Token success and negative cases exist for stream and WebDAV paths."""
    _assert_markers(
        "tests/test_token_auth.py",
        [
            "test_valid_token_auth",
            "test_bad_signature_rejected",
            "test_wrong_issuer_rejected",
            "test_wrong_audience_rejected",
            "test_expired_token_rejected",
            "test_put_denied_without_write_scope",
        ],
    )
    _assert_markers(
        "tests/test_token_security.py",
        [
            "test_alg_none_rejected",
            "test_scope_data_does_not_match_database",
            "test_read_scope_blocks_write",
            "test_wrong_issuer_rejected",
            "test_wrong_audience_rejected",
        ],
    )
    _assert_markers(
        "tests/test_token_jwks_refresh.py",
        [
            "test_jwks_hot_refresh_new_key",
            "test_jwks_keeps_old_keys_on_parse_error",
            "test_jwks_old_key_rejected_after_rotation",
        ],
    )


def test_lock_child_lock_negative_guardrails_present():
    """DELETE, MOVE, and COPY must fail when target collections contain locks."""
    _assert_markers(
        "tests/test_http_webdav_lock_recursive.py",
        [
            "test_copy_overwrites_locked_file_fails",
            "test_copy_collection_overwrites_locked_member_fails",
            "test_move_collection_overwrites_locked_member_fails",
            "test_delete_collection_with_locked_member_fails",
        ],
    )


def test_xrdhttp_checksum_and_metadata_guardrails_present():
    """XrdHttp checksum, status, range, stats, and metadata coverage exists."""
    _assert_markers(
        "tests/test_xrdhttp.py",
        [
            "test_status_header_on_not_found",
            "test_status_zero_on_success",
            "test_crc32_digest_header",
            "test_crc32c_digest_header",
            "test_stats_returns_xml",
            "test_cksum_security_unknown_algorithm",
        ],
    )
    _assert_markers(
        "tests/test_xrdhttp_conformance.py",
        [
            "class testheaderconformance",
            "test_head_content_length_matches_file",
            "test_propfind_nonexistent_collection",
        ],
    )
    _assert_markers(
        "tests/test_query_extended.py",
        [
            "test_qcksum_crc32c_known_file",
            "test_qckscan_directory_tree",
            "test_qckscan_nonexistent_path_errors",
        ],
    )


def test_cache_and_tpc_guardrails_present():
    """Cache fill/write-through and TPC success/auth-negative suites exist."""
    _assert_markers(
        "tests/test_cache_write_through.py",
        [
            "test_server_accepts_brix_session",
            "test_read_seeded_file",
            "test_write_and_read_back",
            "test_sync_checksum_matches",
            "test_async_checksum_matches",
        ],
    )
    _assert_markers(
        "tests/test_webdav_tpc.py",
        [
            "test_required_source_to_required_destination",
            "test_tpc_disabled_destination_rejects_copy",
            "test_readonly_destination_rejects_copy_before_pull",
            "test_missing_service_credential_cannot_pull_required_source",
            "test_both_source_and_destination_headers_rejected_400",
        ],
    )
    _assert_markers(
        "tests/test_webdav_tpc_cred.py",
        [
            "test_credential_none_default",
            "test_credential_invalid_mode_returns_400",
            "test_credential_token_exchange_accepted",
            "test_push_invalid_credential_mode",
        ],
    )
    _assert_markers(
        "tests/test_tpc_ssrf_policy.py",
        [
            "test_loopback_ipv4_rejected",
            "test_rfc1918_10_rejected",
            "test_public_ip_not_ssrf_blocked",
        ],
    )


def test_phase0_dependency_matrix_hooks_present():
    """Minimal and external-dependency build hooks are present and tested."""
    _assert_markers(
        "config",
        [
            "pkg-config --exists libxml-2.0",
            "-dbrix_have_libxml2=1",
            "src/core/compat/xml.c",
            "src/core/compat/crc32c.c",
        ],
    )
    _assert_markers(
        "tests/cmdscripts/unit_tests.py",
        [
            "pkg-config",
            "libxml-2.0",
            "test_xml_compat.c",
            "test_crc32c.c",
        ],
    )
    _assert_markers(
        "tests/unit/test_xml_compat.c",
        [
            "brix_xml_escape",
            "brix_xml_parse_lockinfo",
        ],
    )
    _assert_markers(
        "tests/unit/test_crc32c.c",
        [
            "brix_crc32c_value",
            "brix_crc32c_copy_value",
        ],
    )


def test_phase0_roadmap_documents_the_guardrail_contract():
    """The roadmap must point maintainers to the enforced Phase 0 contract."""
    _assert_markers(
        "docs/09-developer-guide/source-reduction-plan.md",
        [
            "Status: implemented",
            "tests/test_phase0_guardrails.py",
            "tests/test_http_webdav_status_codes.py",
            "tests/test_token_auth.py",
            "tests/test_http_webdav_lock_recursive.py",
            "tests/test_xrdhttp.py",
            "tests/test_cache_write_through.py",
            "tests/test_webdav_tpc.py",
            "tests/cmdscripts/unit_tests.py",
        ],
    )

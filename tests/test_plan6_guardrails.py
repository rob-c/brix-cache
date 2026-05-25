"""
Plan 6 source-layer guardrail inventory.

shared-code-plan-6.md (docs/09-developer-guide/) defines seven cross-protocol
service-layer refactors.  Before any production code is moved, behavioral
coverage must already exist for the surfaces that are being extracted.

These tests are intentionally lightweight and do not start nginx.  They make
the Plan 6 inventory explicit so future refactors cannot silently remove or
rename the regression suites without updating the roadmap and this contract.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath):
    path = ROOT / relpath
    assert path.exists(), f"Plan 6 guardrail file is missing: {relpath}"
    return path.read_text(encoding="utf-8").lower()


def _assert_markers(relpath, markers):
    text = _read(relpath)
    missing = [marker for marker in markers if marker.lower() not in text]
    assert not missing, (
        f"{relpath} is missing Plan 6 guardrail markers: {missing}"
    )


def test_namespace_mutation_guardrails_present():
    """Namespace mutation (delete/mkdir/copy/rename) is covered across all three protocols."""
    # Native stream: kXR_rm, kXR_mkdir, kXR_mv
    _assert_markers(
        "tests/test_interop_namespace.py",
        [
            "test_mkdir_visible_on_both_servers",
            "test_rmdir_removes_directory_on_both",
            "test_rm_removes_file_on_both",
            "test_mv_renames_file_visible_on_both",
        ],
    )
    # WebDAV: DELETE, MKCOL, MOVE, COPY
    _assert_markers(
        "tests/test_webdav.py",
        [
            "test_delete_existing_file",
            "test_delete_missing_returns_404",
            "test_mkcol_creates_directory",
            "test_mkcol_nested_missing_parent_returns_409",
        ],
    )
    _assert_markers(
        "tests/test_http_webdav_status_codes.py",
        [
            "class testdelete",
            "class testmkcol",
            "class testmove",
            "class testcopy",
        ],
    )
    # S3: DELETE, PUT (mkdir sentinel), CopyObject, DeleteObjects
    _assert_markers(
        "tests/test_s3.py",
        [
            "test_delete_object",
            "test_delete_idempotent",
            "test_copy_object",
            "test_delete_objects_success",
            "test_delete_objects_nonexistent_is_ok",
        ],
    )


def test_namespace_security_negative_guardrails_present():
    """Traversal/escape attacks on namespace mutations are covered."""
    _assert_markers(
        "tests/test_s3.py",
        [
            "test_copy_object_path_traversal",
            "test_delete_objects_path_traversal",
        ],
    )
    _assert_markers(
        "tests/test_webdav.py",
        [
            "test_delete_dot_dot_escape",
            "test_mkcol_rejects_double_encoded_traversal_segments",
        ],
    )
    _assert_markers(
        "tests/test_security_hardening.py",
        [
            "path",
            "traversal",
        ],
    )


def test_multi_range_guardrails_present():
    """XrdHttp multi-range and native readv coalescing are covered."""
    _assert_markers(
        "tests/test_xrdhttp.py",
        [
            "test_multipart_response_two_ranges",
            "test_multipart_contains_correct_data",
            "test_single_range_not_multipart",
        ],
    )
    _assert_markers(
        "tests/test_readv.py",
        [
            "test_single_segment",
            "test_three_non_overlapping",
            "test_matches_scalar_read",
            "test_unordered_segments",
        ],
    )


def test_external_target_ssrf_guardrails_present():
    """SSRF guard coverage exists for native TPC and WebDAV TPC."""
    _assert_markers(
        "tests/test_tpc_ssrf_policy.py",
        [
            "test_loopback_ipv4_rejected",
            "test_rfc1918_10_rejected",
            "test_public_ip_not_ssrf_blocked",
            "test_loopback_not_ssrf_blocked_when_allow_local",
        ],
    )
    _assert_markers(
        "tests/test_webdav_tpc.py",
        [
            "test_required_source_to_required_destination",
            "test_tpc_disabled_destination_rejects_copy",
            "test_readonly_destination_rejects_copy_before_pull",
        ],
    )


def test_checksum_cache_guardrails_present():
    """Checksum query, XrdHttp Digest, and cache-invalidation tests exist."""
    _assert_markers(
        "tests/test_query_extended.py",
        [
            "test_qcksum_crc32c_known_file",
            "test_checksum_changes_after_overwrite",
        ],
    )
    _assert_markers(
        "tests/test_xrdhttp.py",
        [
            "test_crc32_digest_header",
            "test_crc32c_digest_header",
            "test_cksum_security_unknown_algorithm",
        ],
    )


def test_capability_allow_header_guardrails_present():
    """WebDAV Allow header and CORS method list coverage exists."""
    _assert_markers(
        "tests/test_http_webdav_status_codes.py",
        [
            "test_options_allow_header_has_get_put",
            "test_options_allow_header_has_webdav_methods",
            "test_options_cors_preflight_200",
            "test_options_cors_allows_put",
        ],
    )
    _assert_markers(
        "tests/test_webdav.py",
        [
            "test_delete_existing_file",
            "test_mkcol_creates_directory",
        ],
    )


def test_plan6_roadmap_exists():
    """The Plan 6 design document is present in the developer guide."""
    _assert_markers(
        "docs/09-developer-guide/shared-code-plan-6.md",
        [
            "opportunity 1: shared namespace mutation service",
            "opportunity 2: shared byte-range vector planner",
            "opportunity 3: shared external transfer target policy",
            "opportunity 4: shared integrity metadata service",
            "opportunity 5: protocol capability",
            "opportunity 6: shared export-root preparation",
            "opportunity 7: async job lifecycle",
            "phase 0: guardrail tests",
        ],
    )
    _assert_markers(
        "docs/09-developer-guide/shared-code-plan-6.md",
        [
            "src/config/root_prepare",
            "src/compat/protocol_caps",
            "src/compat/net_target",
            "src/compat/range_vector",
        ],
    )


def test_export_root_helper_present():
    """Opportunity 6 export-root helper is wired into all three protocol surfaces."""
    _assert_markers(
        "src/config/root_prepare.h",
        [
            "xrootd_prepare_export_root",
            "xrootd_export_root_opts_t",
            "allow_write",
            "required",
        ],
    )
    _assert_markers(
        "src/config/root_prepare.c",
        [
            "xrootd_prepare_export_root",
            "realpath",
            "xrootd_validate_path",
        ],
    )
    # S3 merge uses the helper
    _assert_markers(
        "src/s3/module.c",
        [
            "xrootd_prepare_export_root",
        ],
    )
    # WebDAV merge uses the helper
    _assert_markers(
        "src/webdav/config.c",
        [
            "xrootd_prepare_export_root",
        ],
    )
    # Native stream postconfiguration uses the helper
    _assert_markers(
        "src/config/runtime_server.c",
        [
            "xrootd_prepare_export_root",
        ],
    )


def test_capability_registry_present():
    """Opportunity 5 capability registry is wired into WebDAV and S3."""
    _assert_markers(
        "src/compat/protocol_caps.h",
        [
            "xrootd_http_operation_t",
            "xrootd_proto_op_read",
            "xrootd_proto_op_write",
            "xrootd_http_operation_allow_header",
            "xrootd_http_operation_find",
        ],
    )
    _assert_markers(
        "src/webdav/operation_table.c",
        [
            "xrootd_webdav_operations",
            "xrootd_proto_op_read",
            "xrootd_proto_op_write",
        ],
    )
    _assert_markers(
        "src/s3/operation_table.c",
        [
            "xrootd_s3_operations",
            "xrootd_proto_op_read",
            "xrootd_proto_op_write",
        ],
    )
    # WebDAV Allow header driven by the table
    _assert_markers(
        "src/webdav/methods_basic.c",
        [
            "xrootd_http_operation_allow_header",
        ],
    )
    # WebDAV CORS methods driven by the table
    _assert_markers(
        "src/webdav/cors.c",
        [
            "xrootd_http_operation_allow_header",
        ],
    )

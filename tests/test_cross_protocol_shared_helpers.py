"""
Cross-protocol shared-helper inventory.

These tests keep the source-sharing work honest without starting nginx.  The
behavioral coverage lives in the WebDAV, S3, TPC, query, and metrics suites;
this file verifies that the protocol handlers remain wired through the shared
helpers instead of silently growing private copies again.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath):
    path = ROOT / relpath
    assert path.exists(), f"missing expected file: {relpath}"
    return path.read_text(encoding="utf-8")


def _assert_markers(relpath, markers):
    text = _read(relpath)
    missing = [marker for marker in markers if marker not in text]
    assert not missing, f"{relpath} is missing markers: {missing}"


def _assert_absent(relpath, markers):
    text = _read(relpath)
    present = [marker for marker in markers if marker in text]
    assert not present, f"{relpath} still has private helper markers: {present}"


def test_copy_and_http_file_response_helpers_are_shared():
    _assert_markers(
        "src/s3/copy.c",
        ['#include "s3.h"', "xrootd_ns_local_copy("],
    )
    _assert_absent("src/s3/copy.c", ["static int\ns3_copy_file"])
    _assert_markers(
        "src/webdav/fs/copy_engine.c",
        ["../../compat/copy_range.h", "xrootd_copy_range("],
    )
    _assert_markers(
        "src/webdav/get.c",
        ["../compat/http_file_response.h", "xrootd_http_send_file_range("],
    )
    _assert_markers(
        "src/s3/object.c",
        ["../compat/http_file_response.h", "xrootd_http_send_file_range("],
    )


def test_query_xml_and_base64url_helpers_are_shared():
    for relpath in (
        "src/s3/list_objects_v2.c",
        "src/s3/multipart_helpers.c",
        "src/webdav/xrdhttp.c",
    ):
        _assert_markers(relpath, ["xrootd_http_query_"])

    _assert_markers(
        "src/webdav/propfind.c",
        ["../compat/http_xml.h", "xrootd_http_chain_appendf("],
    )
    _assert_markers(
        "src/webdav/lock.c",
        ["../compat/http_xml.h", "xrootd_http_chain_appendf("],
    )
    _assert_absent("src/webdav/lock.c", ["webdav_propfind_append("])
    _assert_markers(
        "src/s3/util.c",
        ["../compat/http_xml.h", "xrootd_http_send_xml_error("],
    )
    _assert_markers(
        "src/s3/list_objects_v2.c",
        ["../token/b64url.h", "b64url_encode(", "b64url_decode("],
    )
    _assert_absent(
        "src/s3/list_objects_v2.c",
        ["static const signed char inv", "s3_b64url_"],
    )


def test_iso8601_and_hex_helpers_are_shared():
    _assert_markers(
        "src/compat/time.c",
        ["xrootd_format_iso8601(", ".000Z"],
    )
    for relpath in (
        "src/s3/copy.c",
        "src/s3/list_objects_v2.c",
        "src/s3/multipart_complete_list_parts.c",
        "src/s3/multipart_complete_list_uploads.c",
        "src/s3/multipart_complete_upload_part_copy.c",
        "src/webdav/propfind.c",
    ):
        _assert_markers(relpath, ["xrootd_format_iso8601("])
    _assert_markers("src/webdav/propfind.c", ["../compat/time.h"])
    _assert_absent("src/s3/util.c", ["s3_iso8601("])
    _assert_absent("src/s3/s3.h", ["s3_iso8601("])

    _assert_markers(
        "src/compat/hex.h",
        ["xrootd_hex_nibble(", "xrootd_hex_from_char(", "xrootd_hex_encode("],
    )
    _assert_markers(
        "src/path/helpers.c",
        ["../compat/hex.h", "xrootd_hex_nibble("],
    )
    _assert_markers(
        "src/compat/xml.c",
        ['#include "hex.h"', "xrootd_hex_nibble("],
    )
    _assert_markers(
        "src/token/macaroon.c",
        ["../compat/hex.h", "xrootd_hex_from_char("],
    )
    _assert_markers(
        "src/compat/uri.c",
        ['#include "hex.h"', "xrootd_hex_from_char("],
    )
    _assert_markers(
        "src/compat/checksum.c",
        ['#include "hex.h"', "xrootd_hex_encode("],
    )
    _assert_markers(
        "src/s3/auth_sigv4_verify.c",
        ["../compat/hex.h", "xrootd_hex_encode("],
    )
    _assert_absent("src/path/helpers.c", ["xrootd_hex_digit("])
    _assert_absent("src/compat/xml.c", ["xrootd_xml_hex_digit("])
    _assert_absent("src/token/macaroon.c", ["hex_to_int("])
    _assert_absent("src/compat/uri.c", ["hex_val("])
    _assert_absent("src/s3/auth_sigv4_canonical.c", ["hex_encode("])
    _assert_absent("src/s3/s3_auth_internal.h", ["hex_encode("])


def test_token_fs_usage_and_shm_slot_helpers_are_shared():
    for relpath in (
        "src/upstream/auth.c",
        "src/tpc/gsi_outbound_common.c",
        "src/tpc/tpc_token.c",
    ):
        _assert_markers(relpath, ["xrootd_token_read_file("])

    for relpath in ("src/tpc/tpc_token.c", "src/webdav/tpc_cred_parse.c"):
        _assert_markers(relpath, ["xrootd_oauth2_parse_access_token("])

    for relpath in (
        "src/query/space.c",
        "src/metrics/stream_cache.c",
        "src/webdav/propfind.c",
    ):
        _assert_markers(relpath, ["xrootd_fs_usage_"])

    for relpath in (
        "src/manager/pending.c",
        "src/tpc/key_registry.c",
        "src/webdav/lock.c",
    ):
        _assert_markers(relpath, ["../compat/shm_slots.h", "xrootd_shm_"])


def test_phase5_tpc_common_layer_is_shared():
    for relpath in (
        "src/tpc/common/credential.h",
        "src/tpc/common/credential.c",
        "src/tpc/common/auth.c",
        "src/tpc/common/registry.h",
        "src/tpc/common/registry.c",
        "src/tpc/common/transfer.h",
        "src/tpc/common/progress.c",
        "src/tpc/common/metrics.c",
        "src/tpc/common/metrics.h",
    ):
        _read(relpath)

    _assert_markers(
        "config",
        [
            "src/tpc/common/credential.c",
            "src/tpc/common/auth.c",
            "src/tpc/common/registry.c",
            "src/tpc/common/progress.c",
            "src/tpc/common/metrics.c",
        ],
    )
    _assert_markers(
        "src/read/open_request.c",
        ["xrootd_tpc_check_authz("],
    )
    _assert_markers(
        "src/webdav/tpc.c",
        ["../tpc/common/auth.h", "xrootd_tpc_check_authz("],
    )
    for relpath in ("src/tpc/launch.c", "src/webdav/tpc_thread.c", "src/webdav/tpc.c"):
        _assert_markers(relpath, ["xrootd_tpc_registry_add("])
    for relpath in ("src/tpc/source.c", "src/webdav/tpc_curl.c", "src/webdav/tpc_marker.c"):
        _assert_markers(relpath, ["xrootd_tpc_progress_emit("])
    for relpath in ("src/tpc/tpc_token.c", "src/webdav/tpc_cred.c"):
        _assert_markers(relpath, ["xrootd_tpc_credential_parse("])
    _assert_markers(
        "src/dashboard/api.c",
        ["../tpc/common/registry.h", "xrootd_tpc_registry_snapshot("],
    )


def test_http_header_body_and_condition_helpers_are_shared():
    _assert_markers(
        "src/webdav/webdav.h",
        ["../compat/http_headers.h", "xrootd_http_find_header("],
    )
    _assert_markers(
        "src/s3/auth_sigv4_parse.c",
        ["../compat/http_headers.h", "xrootd_http_get_header("],
    )
    _assert_markers(
        "src/s3/copy.c",
        ["../compat/http_headers.h", "xrootd_http_find_header("],
    )
    _assert_markers(
        "src/compat/http_headers.h",
        ["xrootd_http_extract_bearer("],
    )
    _assert_markers(
        "src/webdav/auth_token.c",
        ["../compat/http_headers.h", "xrootd_http_extract_bearer("],
    )
    _assert_absent(
        "src/webdav/auth_token.c",
        ['ngx_strncmp(auth_hdr.data, "Bearer ", 7)'],
    )
    _assert_markers(
        "src/webdav/tpc.c",
        ["../compat/http_headers.h", "xrootd_http_extract_bearer("],
    )
    _assert_absent(
        "src/webdav/tpc.c",
        ['bearer_prefix = "Bearer "', "ngx_strncasecmp(auth_hdr->value.data"],
    )

    for relpath in ("src/webdav/put.c", "src/s3/put.c"):
        _assert_markers(
            relpath,
            ["../compat/http_body.h", "xrootd_http_body_write_to_fd("],
        )

    for relpath in ("src/webdav/propfind.c", "src/s3/delete_objects.c"):
        _assert_markers(relpath, ["../compat/http_body.h", "xrootd_http_body_read_all("])

    _assert_markers(
        "src/webdav/put.c",
        ["../compat/http_conditionals.h", "xrootd_http_check_etag_preconditions("],
    )
    _assert_markers(
        "src/webdav/methods/copy_conditionals.c",
        ["../../compat/http_conditionals.h", "xrootd_http_check_etag_preconditions("],
    )
    _assert_markers(
        "src/webdav/get.c",
        ["../compat/http_conditionals.h", "xrootd_http_check_if_modified_since("],
    )
    for relpath in ("src/webdav/copy.c", "src/webdav/move.c"):
        _assert_markers(relpath, ["xrootd_http_overwrite_forbidden("])


def test_phase1_http_status_header_and_query_helpers_are_shared():
    _assert_markers(
        "src/compat/http_headers.h",
        [
            "xrootd_http_effective_status(",
            "xrootd_http_set_header_num(",
            "xrootd_http_request_header_add(",
        ],
    )
    for relpath in ("src/webdav/metrics.c", "src/s3/metrics.c"):
        _assert_markers(
            relpath,
            ["../compat/http_headers.h", "xrootd_http_effective_status("],
        )

    _assert_markers(
        "src/webdav/xrdhttp.c",
        [
            "../compat/http_headers.h",
            "xrootd_http_set_header(",
            "xrootd_http_set_header_num(",
            "xrootd_http_request_header_add(",
        ],
    )
    _assert_absent(
        "src/webdav/xrdhttp.c",
        ["static ngx_int_t\nadd_header_str", "static ngx_int_t\nadd_header_num"],
    )

    _assert_markers(
        "src/s3/handler.c",
        [
            "../compat/http_query.h",
            "xrootd_http_query_get(",
            "xrootd_http_find_header(",
        ],
    )
    _assert_absent("src/s3/handler.c", ['needle[] = "list-type=2"'])
    _assert_markers(
        "src/s3/multipart_complete_upload_part_copy.c",
        ["../compat/http_headers.h", "xrootd_http_find_header("],
    )


def test_checksum_fs_walk_staging_and_cms_frame_helpers_are_shared():
    for relpath in (
        "src/query/checksum_qcksum.c",
        "src/query/checksum_qcksum_async.c",
        "src/query/checksum_ckscan_common.c",
        "src/query/checksum_ckscan_dispatch.c",
        "src/query/checksum_ckscan_async.c",
        "src/dirlist/dcksm.c",
        "src/webdav/xrdhttp.c",
    ):
        _assert_markers(relpath, ["../compat/checksum.h", "xrootd_checksum_"])

    for relpath in ("src/webdav/namespace.c", "src/s3/multipart_helpers.c"):
        _assert_markers(
            relpath,
            ["../compat/fs_walk.h", "xrootd_fs_remove_tree_confined("],
        )

    for relpath in ("src/webdav/propfind.c", "src/query/checksum_ckscan_common.c"):
        _assert_markers(relpath, ["xrootd_fs_is_dot_entry("])

    for relpath in (
        "src/s3/put.c",
        "src/webdav/tpc.c",
    ):
        _assert_markers(relpath, ["../compat/staged_file.h", "xrootd_staged_open("])

    for relpath in (
        "src/s3/copy.c",
        "src/webdav/copy.c",
    ):
        _assert_markers(relpath, ['#include "s3.h"' if "s3" in relpath else "webdav.h", "xrootd_ns_local_copy("])

    for relpath in ("src/cms/send.c", "src/cms/server_send.c"):
        _assert_markers(relpath, ["frame_io.h", "xrootd_cms_send_frame("])


def test_webdav_config_path_validation_is_shared():
    _assert_markers(
        "src/webdav/config.c",
        ["../config/config.h", "#define webdav_validate_path          xrootd_validate_path"],
    )
    _assert_absent(
        "src/webdav/config.c",
        ["typedef enum", "static char *\nwebdav_validate_path"],
    )


def test_unified_path_resolver_is_registered():
    _assert_markers(
        "config",
        [
            "src/path/unified.h",
            "src/path/unified.c",
        ],
    )
    _assert_markers(
        "src/path/unified.h",
        [
            "xrootd_path_resolve_cstr(",
            "allow_missing_tail",
            "allow_missing_parents",
            "require_directory",
        ],
    )


def test_stream_path_resolver_uses_unified_adapter():
    _assert_markers(
        "src/path/resolve_path_variants.c",
        [
            '#include "unified.h"',
            "xrootd_path_resolve_cstr(",
            "allow_missing_tail",
            "allow_missing_parents",
        ],
    )
    _assert_absent(
        "src/path/resolve_path_variants.c",
        [
            "realpath(",
            "lstat(",
            "xrootd_path_component_forbidden(",
        ],
    )


def test_http_path_resolver_uses_unified_adapter():
    _assert_markers(
        "src/compat/path.c",
        [
            "../path/unified.h",
            "xrootd_path_resolve_cstr(",
            "XROOTD_PATH_STATUS_INVALID",
            "XROOTD_PATH_STATUS_TOO_LONG",
        ],
    )
    _assert_absent(
        "src/compat/path.c",
        [
            "has_forbidden_components",
            "realpath(",
            "strrchr(",
        ],
    )


def test_phase2_identity_type_is_registered():
    _assert_markers(
        "config",
        [
            "src/types/identity.h",
            "src/types/identity.c",
        ],
    )
    _assert_markers(
        "src/types/identity.h",
        [
            "typedef struct {",
            "XROOTD_AUTHN_GSI",
            "XROOTD_AUTHN_TOKEN",
            "XROOTD_AUTHN_SSS",
            "XROOTD_AUTHN_S3KEY",
            "xrootd_identity_t",
        ],
    )
    _assert_markers(
        "src/types/context.h",
        ["xrootd_identity_t *identity"],
    )
    _assert_markers(
        "src/webdav/webdav.h",
        ["../types/identity.h", "xrootd_identity_t *identity"],
    )
    _assert_markers(
        "src/s3/s3.h",
        ["../types/identity.h", "xrootd_identity_t *identity"],
    )


def test_phase2_auth_paths_populate_identity():
    _assert_markers(
        "src/gsi/auth.c",
        ["xrootd_identity_set_dn(", "XROOTD_AUTHN_GSI"],
    )
    _assert_markers(
        "src/gsi/token.c",
        ["xrootd_identity_set_token_claims("],
    )
    _assert_markers(
        "src/sss/auth_request.c",
        ["xrootd_identity_set_dn(", "XROOTD_AUTHN_SSS"],
    )
    _assert_markers(
        "src/webdav/auth_cert.c",
        ["xrootd_identity_alloc(", "xrootd_identity_set_dn("],
    )
    _assert_markers(
        "src/webdav/auth_token.c",
        ["xrootd_identity_set_token_claims("],
    )
    _assert_markers(
        "src/s3/auth_sigv4_verify.c",
        ["xrootd_identity_t *identity", "XROOTD_AUTHN_S3KEY"],
    )


def test_phase2_policy_consumes_identity():
    _assert_markers(
        "src/path/authdb.c",
        [
            "xrootd_find_authdb_rule_identity(",
            "xrootd_check_authdb_identity(",
            "xrootd_identity_dn_cstr(",
            "xrootd_identity_vo_csv_cstr(",
        ],
    )
    _assert_markers(
        "src/path/acl.c",
        ["xrootd_check_vo_acl_identity(", "xrootd_identity_vo_csv_cstr("],
    )
    _assert_markers(
        "src/handshake/policy.c",
        ["xrootd_identity_check_token_scope("],
    )
    for relpath in (
        "src/read/open_request.c",
        "src/write/common.c",
        "src/query/prepare.c",
        "src/dirlist/handler.c",
    ):
        _assert_markers(relpath, ["xrootd_check_vo_acl_identity("])
        _assert_absent(relpath, ["ctx->vo_list) != NGX_OK"])


def test_phase2_voms_identity_rejects_injected_vo_tokens():
    _assert_markers(
        "src/voms/collect.c",
        [
            "xrootd_vo_token_safe(",
            "ch <= ' '",
            "ch >= 0x7f",
            "ch == ','",
            "ch == '/'",
            "xrootd_fqan_to_vo(",
        ],
    )


def test_phase3_vfs_layer_is_registered():
    _assert_markers(
        "config",
        [
            "src/fs/vfs.h",
            "src/fs/vfs_internal.h",
            "src/fs/vfs_open.c",
            "src/fs/vfs_read.c",
            "src/fs/vfs_write.c",
            "src/fs/vfs_stat.c",
            "src/fs/vfs_dir.c",
            "src/fs/vfs_unlink.c",
            "src/fs/vfs_rename.c",
            "src/fs/vfs_mkdir.c",
            "src/fs/vfs_sync.c",
            "src/fs/fd_cache.c",
        ],
    )
    _assert_markers(
        "src/fs/vfs.h",
        [
            "XROOTD_VFS_O_READ",
            "XROOTD_VFS_O_WRITE",
            "xrootd_vfs_ctx_t",
            "xrootd_vfs_open(",
            "xrootd_vfs_read(",
            "xrootd_vfs_write(",
            "xrootd_vfs_stat(",
        ],
    )


def test_phase3_vfs_preserves_io_invariants():
    _assert_markers(
        "src/fs/vfs_read.c",
        [
            "b->memory = 1",
            "b->in_file = 1",
            "dup(fh->fd)",
            "xrootd_crc32c_value(",
        ],
    )
    _assert_markers(
        "src/fs/vfs_write.c",
        [
            "xrootd_vfs_pwrite_full(",
            "xrootd_crc32c_extend(",
            "b->in_file",
            "ngx_buf_in_memory(",
        ],
    )
    _assert_markers("src/fs/vfs_unlink.c", ["xrootd_ns_delete("])
    _assert_markers("src/fs/vfs_mkdir.c", ["xrootd_ns_mkdir("])
    _assert_markers("src/fs/vfs_rename.c", ["xrootd_ns_rename("])


def test_phase3_http_read_metadata_uses_vfs():
    _assert_markers(
        "src/s3/object.c",
        [
            "../fs/vfs.h",
            "xrootd_vfs_open(",
            "xrootd_vfs_file_stat(",
            "xrootd_vfs_stat(",
        ],
    )
    _assert_markers(
        "src/webdav/resource.c",
        ["../fs/vfs.h", "xrootd_vfs_stat("],
    )


def test_phase4_cache_layer_is_registered():
    _assert_markers(
        "config",
        [
            "src/cache/open.h",
            "src/cache/meta.h",
            "src/cache/writethrough.h",
            "src/cache/open.c",
            "src/cache/meta.c",
        ],
    )
    _assert_markers(
        "src/cache/open.h",
        [
            "xrootd_cache_open(",
            "xrootd_cache_record_access(",
            "xrootd_cache_path_for_resolved(",
        ],
    )
    _assert_markers(
        "src/cache/meta.h",
        [
            "xrootd_cache_meta_t",
            "XROOTD_CACHE_META_ETAG_MAX",
            "xrootd_cache_meta_read(",
            "xrootd_cache_meta_write(",
        ],
    )


def test_phase4_vfs_cache_hooks_are_present():
    _assert_markers(
        "src/fs/vfs.h",
        [
            "cache_root_canon",
            "cache_enabled",
            "cache_writethrough_cfg",
            "xrootd_vfs_file_from_cache(",
        ],
    )
    _assert_markers(
        "src/fs/vfs_open.c",
        [
            "../cache/open.h",
            "xrootd_cache_open(ctx, flags, &fh)",
            "xrootd_vfs_adopt_fd(",
            "from_cache",
        ],
    )
    _assert_markers(
        "src/fs/vfs_read.c",
        ["../cache/open.h", "xrootd_cache_record_access("],
    )
    _assert_markers(
        "src/fs/vfs_write.c",
        ["../cache/writethrough.h", "xrootd_cache_should_writethrough("],
    )


def test_phase4_http_protocols_use_vfs_cache_path():
    _assert_markers(
        "src/webdav/get.c",
        [
            "../cache/open.h",
            "../fs/vfs.h",
            "xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ",
            "vctx.cache_root_canon = conf->cache_root_canon",
            "xrootd_cache_record_access(",
        ],
    )
    _assert_absent(
        "src/webdav/get.c",
        ["cache_path = cache_root_canon + (path - root_canon)"],
    )
    _assert_markers(
        "src/s3/object.c",
        [
            "../cache/open.h",
            "vctx->cache_root_canon = cf->cache_root_canon",
            "xrootd_vfs_file_from_cache(",
            "xrootd_cache_record_access(",
        ],
    )
    _assert_markers(
        "src/s3/module.c",
        ["xrootd_s3_cache_root", "cache_root_canon"],
    )


def test_phase4_cache_metadata_and_eviction_guardrails():
    _assert_markers(
        "src/cache/fetch.c",
        [
            "xrootd_cache_meta_from_stat(",
            "xrootd_cache_meta_write(",
        ],
    )
    _assert_markers(
        "src/cache/open.c",
        [
            "xrootd_cache_validate_meta(",
            "O_NOFOLLOW",
            "xrootd_vfs_adopt_fd(",
        ],
    )
    _assert_markers(
        "src/cache/evict_candidates.c",
        ['strcmp(name + name_len - suffix_len, ".meta")'],
    )
    _assert_markers(
        "src/cache/evict_policy.c",
        ["xrootd_cache_meta_path(", "unlink(meta_path)"],
    )


def test_security_level_enforcement_is_linked():
    _assert_markers(
        "src/handshake/dispatch.c",
        ["xrootd_verify_pending_sigver(", "xrootd_signing_enforce_level("],
    )
    _assert_markers(
        "src/handshake/sigver.c",
        [
            "xrootd_signing_enforce_level(",
            "xrootd_sigver_opcode_requires(",
            "kXR_InvalidRequest",
        ],
    )


def test_new_shared_helpers_are_wired_into_module_config():
    for marker in (
        "src/compat/checksum.c",
        "src/compat/fs_walk.c",
        "src/compat/http_body.c",
        "src/compat/http_conditionals.c",
        "src/compat/http_headers.c",
        "src/compat/hex.c",
        "src/compat/staged_file.c",
        "src/compat/time.c",
        "src/cms/frame_io.c",
    ):
        _assert_markers("config", [marker])


def test_phase6_unified_metrics_observability_is_wired():
    for relpath in (
        "src/metrics/unified.h",
        "src/metrics/unified.c",
        "src/metrics/access_log.h",
        "src/metrics/access_log.c",
    ):
        _read(relpath)

    _assert_markers(
        "config",
        [
            "src/metrics/unified.h",
            "src/metrics/access_log.h",
            "src/metrics/unified.c",
            "src/metrics/access_log.c",
        ],
    )
    _assert_markers(
        "src/metrics/metrics.h",
        ["ngx_xrootd_unified_metrics_t", "ngx_xrootd_unified_metrics_t unified"],
    )
    _assert_markers(
        "src/metrics/stream.c",
        ["xrootd_export_unified_metrics(mw, shm)", "DEPRECATED"],
    )
    _assert_markers(
        "src/metrics/unified.c",
        [
            "xrootd_metric_op_done(",
            "xrootd_metric_cache_result(",
            "xrootd_metric_auth(",
            "xrootd_metric_tpc(",
            "xrootd_io_ops_total",
            "xrootd_auth_total",
            "xrootd_tpc_transfers_total",
        ],
    )
    _assert_markers(
        "src/fs/vfs_internal.h",
        ["xrootd_metric_op_done(", "xrootd_access_log_emit("],
    )
    for relpath in (
        "src/fs/vfs_read.c",
        "src/fs/vfs_write.c",
        "src/fs/vfs_stat.c",
        "src/fs/vfs_unlink.c",
        "src/fs/vfs_mkdir.c",
        "src/fs/vfs_rename.c",
        "src/fs/vfs_dir.c",
    ):
        _assert_markers(relpath, ["xrootd_vfs_observe_"])
    _assert_markers(
        "src/fs/vfs_open.c",
        ["xrootd_metric_cache_result("],
    )
    _assert_markers(
        "src/webdav/metrics.c",
        ["../metrics/unified.h", "xrootd_metric_op_done("],
    )
    _assert_markers(
        "src/s3/metrics.c",
        ["../metrics/unified.h", "xrootd_metric_op_done("],
    )
    _assert_markers(
        "src/tpc/common/metrics.c",
        ["../../metrics/unified.h", "xrootd_metric_tpc("],
    )


def test_implementation_plan_feature_gaps_are_closed():
    _assert_markers(
        "src/handshake/dispatch_read.c",
        [
            "case kXR_stat:",
            "xrootd_handle_stat",
            "case kXR_statx:",
            "xrootd_handle_statx",
            "case kXR_locate:",
            "xrootd_handle_locate",
            "case kXR_clone:",
            "xrootd_handle_clone",
        ],
    )
    _assert_markers(
        "src/handshake/dispatch_write.c",
        [
            "case kXR_pgwrite:",
            "xrootd_handle_pgwrite",
            "case kXR_chkpoint:",
            "xrootd_handle_chkpoint",
        ],
    )
    _assert_markers(
        "src/read/pgread.c",
        [
            "xrootd_pgread_encode_pages(",
            "xrootd_crc32c_copy(",
            "xrootd_build_pgread_status(",
        ],
    )
    _assert_markers(
        "src/write/pgwrite.c",
        [
            "xrootd_pgwrite_decode_payload(",
            "xrootd_crc32c_copy(",
            "xrootd_send_pgwrite_status(",
        ],
    )
    _assert_markers(
        "src/write/chkpoint.c",
        [
            "xrootd_handle_chkpoint(",
            "xrootd_chkpoint_recover_root(",
        ],
    )

    _assert_markers(
        "src/webdav/access.c",
        [
            "webdav_add_cors_headers(r)",
            "webdav_verify_proxy_cert(r, conf)",
            "webdav_verify_bearer_token(r, conf)",
            "webdav_check_token_write_scope(r, scope_method)",
            "webdav_metrics_return(r,",
        ],
    )
    _assert_markers(
        "src/webdav/auth_token.c",
        [
            "webdav_verify_bearer_token(",
            "webdav_check_token_write_scope(",
            "xrootd_identity_check_token_scope(",
            "xrootd_token_check_write(",
        ],
    )
    _assert_markers(
        "src/webdav/dispatch.c",
        [
            "webdav_metrics_return(r, webdav_proxy_handler(r))",
            "webdav_metrics_return(r, webdav_handle_get(r))",
            "webdav_metrics_return(r, webdav_handle_delete(r))",
            "webdav_metrics_return(r, webdav_handle_mkcol(r))",
            "webdav_metrics_return(r, webdav_handle_copy(r))",
            "webdav_metrics_return(r, webdav_handle_move(r))",
            "webdav_metrics_return(r, webdav_handle_propfind(r))",
        ],
    )

    _assert_markers(
        "src/s3/handler.c",
        [
            "s3_verify_sigv4(r, cf, s3ctx->identity)",
            "s3_handle_list_multipart_uploads(r, cf)",
            "s3_handle_list_parts(r, fs_path, cf",
            "s3_handle_upload_part_copy(r, fs_path, cf",
            "s3_handle_multipart_abort(r, fs_path, cf, upload_id)",
            "s3_handle_multipart_initiate(r, fs_path, cf",
            "xrootd_http_read_body(r, s3_multipart_complete_body_handler)",
        ],
    )
    _assert_markers(
        "src/s3/auth_sigv4_verify.c",
        [
            "s3_verify_sigv4(",
            "s3_record_auth_result(",
            "XROOTD_AUTHN_S3KEY",
        ],
    )
    _assert_markers(
        "src/s3/multipart_complete.c",
        [
            '#include "multipart_complete_list_parts.c"',
            '#include "multipart_complete_list_uploads.c"',
            '#include "multipart_complete_upload_part_copy.c"',
        ],
    )
    _assert_absent(
        "src/s3/auth_sigv4_verify.c",
        ["webdav_verify_bearer_token"],
    )
    _assert_absent(
        "src/s3/handler.c",
        ["webdav_verify_bearer_token"],
    )


def test_stream_missing_auth_plugins_are_wired():
    _assert_markers(
        "config",
        [
            "pkg-config --exists krb5",
            "-DXROOTD_HAVE_KRB5=1",
            "src/unix/auth.c",
            "src/krb5/config.c",
            "src/krb5/auth.c",
        ],
    )
    _assert_markers(
        "src/stream/module.c",
        [
            'ngx_string("unix")',
            "XROOTD_AUTH_UNIX",
            'ngx_string("krb5")',
            "XROOTD_AUTH_KRB5",
            "xrootd_krb5_principal",
            "xrootd_krb5_keytab",
            "xrootd_krb5_ip_check",
            "xrootd_unix_trust_remote",
        ],
    )
    _assert_markers(
        "src/session/protocol.c",
        [
            "want_unix",
            "want_krb5",
            "pe[0] = 'u'; pe[1] = 'n'; pe[2] = 'i'; pe[3] = 'x'",
            "pe[0] = 'k'; pe[1] = 'r'; pe[2] = 'b'; pe[3] = '5'",
        ],
    )
    _assert_markers(
        "src/session/login.c",
        [
            '"&P=unix"',
            '"&P=krb5,%s"',
            "auth parameter block too long",
        ],
    )
    _assert_markers(
        "src/gsi/auth.c",
        [
            "xrootd_handle_unix_auth(ctx, c, conf)",
            "xrootd_handle_krb5_auth(ctx, c, conf)",
        ],
    )
    _assert_markers(
        "src/unix/auth.c",
        [
            "xrootd_unix_peer_is_loopback(",
            "unix_trust_remote",
            "XROOTD_AUTHN_UNIX",
            "xrootd_session_register(",
        ],
    )
    _assert_markers(
        "src/krb5/config.c",
        [
            "krb5_parse_name(",
            "krb5_kt_start_seq_get(",
            "xrootd_auth krb5 requested",
        ],
    )
    _assert_markers(
        "src/krb5/auth.c",
        [
            "krb5_rd_req(",
            "krb5_aname_to_localname(",
            "XROOTD_AUTHN_KRB5",
            "xrootd_session_register(",
        ],
    )
    _assert_markers(
        "src/metrics/unified.c",
        ['"unix"', '"krb5"', "XROOTD_METRIC_AUTH_UNIX", "XROOTD_METRIC_AUTH_KRB5"],
    )

from _test_cross_protocol_shared_helpers_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_copy_and_http_file_response_helpers_are_shared():
    # Phase 55: local-object copy moved behind the shared VFS copy entry point
    # (xrootd_vfs_copy → xrootd_ns_local_copy in src/fs/vfs_copy.c).  The S3
    # CopyObject handler must route through that shared seam, not a private copy.
    _assert_markers(
        "src/s3/copy.c",
        ['#include "s3.h"', "xrootd_vfs_copy("],
    )
    _assert_absent("src/s3/copy.c", ["static int\ns3_copy_file"])
    # Phase 62: WebDAV COPY's local copy moved behind the shared VFS copy seam
    # (xrootd_vfs_copyfile / xrootd_vfs_copytree, src/fs/vfs_walk.c), which owns
    # the underlying copy_file_range path.  The handler must route through that
    # seam, and the shared VFS layer keeps the single xrootd_copy_range() impl.
    _assert_markers(
        "src/webdav/fs/copy_engine.c",
        ["../../fs/vfs.h", "xrootd_vfs_copyfile("],
    )
    _assert_markers(
        "src/fs/vfs_walk.c",
        ["xrootd_copy_range("],
    )
    # Phase 12: the range-parse → headers → send pipeline (including the
    # xrootd_http_send_file_range call) moved into the shared file-serve
    # handler.  Both WebDAV GET and S3 GetObject now delegate to it via
    # xrootd_http_serve_file_ranged() instead of each invoking the
    # http_file_response helpers directly.
    _assert_markers(
        "src/shared/file_serve.c",
        ["../compat/http_file_response.h", "xrootd_http_send_file_range("],
    )
    _assert_markers(
        "src/webdav/get.c",
        ["../shared/file_serve.h", "xrootd_http_serve_file_ranged("],
    )
    _assert_markers(
        "src/s3/object.c",
        ["../shared/file_serve.h", "xrootd_http_serve_file_ranged("],
    )


def test_query_xml_and_base64url_helpers_are_shared():
    for relpath in (
        "src/s3/list_objects_v2.c",
        "src/s3/multipart_helpers.c",
        "src/webdav/xrdhttp.c",
    ):
        _assert_markers(relpath, ["xrootd_http_query_"])

    # propfind was split into propfind_props.c / propfind_walk.c with a shared
    # propfind_internal.h; the http_xml include lives in the header, the chain
    # builder is used by the props unit.
    _assert_markers("src/webdav/propfind_internal.h", ["../compat/http_xml.h"])
    _assert_markers("src/webdav/propfind_props.c", ["xrootd_http_chain_appendf("])
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
        "src/core/compat/time.c",
        ["xrootd_format_iso8601(", ".000Z"],
    )
    for relpath in (
        "src/s3/copy.c",
        "src/s3/list_common.c",
        "src/s3/multipart_complete_list_parts.c",
        "src/s3/multipart_complete_list_uploads.c",
        "src/s3/multipart_complete_upload_part_copy.c",
        "src/webdav/propfind_props.c",
    ):
        _assert_markers(relpath, ["xrootd_format_iso8601("])
    _assert_markers("src/webdav/propfind_internal.h", ["../compat/time.h"])
    _assert_absent("src/s3/util.c", ["s3_iso8601("])
    _assert_absent("src/s3/s3.h", ["s3_iso8601("])

    _assert_markers(
        "src/core/compat/hex.h",
        ["xrootd_hex_nibble(", "xrootd_hex_from_char(", "xrootd_hex_encode("],
    )
    _assert_markers(
        "src/fs/path/helpers.c",
        ["../compat/hex.h", "xrootd_hex_nibble("],
    )
    _assert_markers(
        "src/core/compat/xml.c",
        ['#include "hex.h"', "xrootd_hex_nibble("],
    )
    _assert_markers(
        "src/auth/token/macaroon.c",
        ["../compat/hex.h", "xrootd_hex_from_char("],
    )
    _assert_markers(
        "src/core/compat/uri.c",
        ['#include "hex.h"', "xrootd_hex_from_char("],
    )
    _assert_markers(
        "src/core/compat/checksum.c",
        ['#include "hex.h"', "xrootd_hex_encode("],
    )
    _assert_markers(
        "src/s3/auth_sigv4_verify.c",
        ["../compat/hex.h", "xrootd_hex_encode("],
    )
    _assert_absent("src/fs/path/helpers.c", ["xrootd_hex_digit("])
    _assert_absent("src/core/compat/xml.c", ["xrootd_xml_hex_digit("])
    _assert_absent("src/auth/token/macaroon.c", ["hex_to_int("])
    _assert_absent("src/core/compat/uri.c", ["hex_val("])
    _assert_absent("src/s3/auth_sigv4_canonical.c", ["hex_encode("])
    _assert_absent("src/s3/s3_auth_internal.h", ["hex_encode("])


def test_token_fs_usage_and_shm_slot_helpers_are_shared():
    for relpath in (
        "src/net/upstream/auth.c",
        "src/tpc/gsi_outbound_common.c",
        "src/tpc/tpc_token.c",
    ):
        _assert_markers(relpath, ["xrootd_token_read_file("])

    for relpath in ("src/tpc/tpc_token.c", "src/webdav/tpc_cred_parse.c"):
        _assert_markers(relpath, ["xrootd_oauth2_parse_access_token("])

    for relpath in (
        "src/query/space.c",
        "src/observability/metrics/stream_cache.c",
        "src/webdav/propfind_props.c",
    ):
        _assert_markers(relpath, ["xrootd_fs_usage_"])

    for relpath in (
        "src/net/manager/pending.c",
        "src/tpc/key_registry.c",
    ):
        _assert_markers(relpath, ["../compat/shm_slots.h", "xrootd_shm_"])

    # Phase 16: WebDAV lock state migrated off the SHM slot table onto xattrs
    # (the unified prop store).  lock.c must no longer reference shm_slots and
    # must use the webdav_lock_xattr_* persistence helpers instead.
    _assert_absent("src/webdav/lock.c", ["../compat/shm_slots.h", "xrootd_shm_"])
    _assert_markers("src/webdav/lock.c", ["webdav_lock_xattr_read("])


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
    for relpath in ("src/tpc/source.c", "src/webdav/tpc_curl_pmark.c", "src/webdav/tpc_marker.c"):
        _assert_markers(relpath, ["xrootd_tpc_progress_emit("])
    for relpath in ("src/tpc/tpc_token.c", "src/webdav/tpc_cred.c"):
        _assert_markers(relpath, ["xrootd_tpc_credential_parse("])
    # dashboard api was split: registry include in dashboard_api_internal.h, the
    # snapshot call in api_transfers.c.
    _assert_markers("src/observability/dashboard/dashboard_api_internal.h",
                    ["../tpc/common/registry.h"])
    _assert_markers("src/observability/dashboard/api_transfers.c",
                    ["xrootd_tpc_registry_snapshot("])


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
        "src/core/compat/http_headers.h",
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

    # s3/put was split: the http_body include lives in s3_put_internal.h while the
    # writer call stays in put.c; webdav/put.c still carries both directly.
    _assert_markers("src/webdav/put.c",
                    ["../compat/http_body.h", "xrootd_http_body_write_to_fd("])
    _assert_markers("src/s3/s3_put_internal.h", ["../compat/http_body.h"])
    _assert_markers("src/s3/put.c", ["xrootd_http_body_write_to_fd("])

    # propfind was split: the include is in propfind_internal.h, the reader in
    # propfind.c; delete_objects.c still carries both directly.
    _assert_markers("src/webdav/propfind_internal.h", ["../compat/http_body.h"])
    _assert_markers("src/webdav/propfind.c", ["xrootd_http_body_read_all("])
    _assert_markers("src/s3/delete_objects.c",
                    ["../compat/http_body.h", "xrootd_http_body_read_all("])

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
        "src/core/compat/http_headers.h",
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

    # Phase 62: directory enumeration moved behind the VFS seam — propfind walks
    # via xrootd_vfs_readdir and ckscan via xrootd_vfs_walk, both of which skip
    # "."/".." centrally in src/fs/vfs_walk.c (the single xrootd_fs_is_dot_entry
    # caller) instead of each handler filtering dotted entries itself.
    _assert_markers("src/webdav/propfind_walk.c", ["xrootd_vfs_readdir("])
    _assert_markers("src/query/checksum_ckscan_common.c", ["xrootd_vfs_walk("])
    _assert_markers("src/fs/vfs_walk.c", ["xrootd_fs_is_dot_entry("])

    # s3/put was split: the staged_file include is in s3_put_internal.h, the open
    # call stays in put.c — now routed through the VFS seam
    # (xrootd_vfs_staged_open, phase-62 VFS closure) rather than the raw
    # xrootd_staged_open; webdav/tpc.c still carries the raw open directly.
    _assert_markers("src/s3/s3_put_internal.h", ["../compat/staged_file.h"])
    _assert_markers("src/s3/put.c", ["xrootd_vfs_staged_open("])
    _assert_markers("src/webdav/tpc.c",
                    ["../compat/staged_file.h", "xrootd_staged_open("])

    # Phase 55: both the S3 CopyObject and WebDAV COPY handlers delegate the
    # local-object copy to the shared VFS copy seam (xrootd_vfs_copy), which is
    # the single place that reaches xrootd_ns_local_copy (src/fs/vfs_copy.c).
    for relpath in (
        "src/s3/copy.c",
        "src/webdav/copy.c",
    ):
        _assert_markers(relpath, ['#include "s3.h"' if "s3" in relpath else "webdav.h", "xrootd_vfs_copy("])

    for relpath in ("src/net/cms/send.c", "src/net/cms/server_send.c"):
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
            "src/fs/path/unified.h",
            "src/fs/path/unified.c",
        ],
    )
    _assert_markers(
        "src/fs/path/unified.h",
        [
            "xrootd_path_resolve_cstr(",
            "allow_missing_tail",
            "allow_missing_parents",
            "require_directory",
        ],
    )


def test_stream_path_resolver_uses_unified_adapter():
    # Phase 8 retired the realpath-based EXISTING/WRITE resolvers; only the
    # config-time _noexist variant remains, and it resolves through the shared
    # unified.h adapter (allow_missing_parents).  ("realpath(" survives only in
    # the explanatory comment, so it is no longer in the absent set.)
    _assert_markers(
        "src/fs/path/resolve_path_variants.c",
        [
            '#include "unified.h"',
            "xrootd_path_resolve_cstr(",
            "allow_missing_parents",
        ],
    )
    _assert_absent(
        "src/fs/path/resolve_path_variants.c",
        [
            "lstat(",
            "xrootd_path_component_forbidden(",
        ],
    )


def test_http_path_resolver_uses_unified_adapter():
    # Phase 8: the HTTP/S3 adapter (compat/path.c) no longer canonicalises with
    # realpath() + the unified.h string resolver.  It joins the request lexically
    # under the export root via the shared beneath API (xrootd_beneath_full_path)
    # and lets openat2(RESOLVE_BENEATH) enforce confinement at the operation.
    # Verify it uses that shared resolver rather than reimplementing path munging.
    _assert_markers(
        "src/core/compat/path.c",
        [
            "../path/beneath.h",
            "xrootd_beneath_full_path(",
        ],
    )
    _assert_absent(
        "src/core/compat/path.c",
        [
            "has_forbidden_components",
            "strrchr(",
        ],
    )


def test_phase2_identity_type_is_registered():
    _assert_markers(
        "config",
        [
            "src/core/types/identity.h",
            "src/core/types/identity.c",
        ],
    )
    _assert_markers(
        "src/core/types/identity.h",
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
        "src/core/types/context.h",
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
        "src/auth/gsi/auth.c",
        ["xrootd_identity_set_dn(", "XROOTD_AUTHN_GSI"],
    )
    _assert_markers(
        "src/auth/gsi/token.c",
        ["xrootd_identity_set_token_claims("],
    )
    _assert_markers(
        "src/auth/sss/auth_request.c",
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

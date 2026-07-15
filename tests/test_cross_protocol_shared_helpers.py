from _test_cross_protocol_shared_helpers_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_copy_and_http_file_response_helpers_are_shared():
    # Phase 55: local-object copy moved behind the shared VFS copy entry point
    # (brix_vfs_copy → brix_ns_local_copy in src/fs/vfs/vfs_copy.c).  The S3
    # CopyObject handler must route through that shared seam, not a private copy.
    _assert_markers(
        "src/protocols/s3/copy.c",
        ['#include "s3.h"', "brix_vfs_copy("],
    )
    _assert_absent("src/protocols/s3/copy.c", ["static int\ns3_copy_file"])
    # Phase 62: WebDAV COPY's local copy moved behind the shared VFS copy seam
    # (brix_vfs_copyfile / brix_vfs_copytree, src/fs/vfs/vfs_walk.c), which owns
    # the underlying copy_file_range path.  The handler must route through that
    # seam, and the shared VFS layer keeps the single brix_copy_range() impl.
    _assert_markers(
        "src/protocols/webdav/fs/copy_engine.c",
        ["fs/vfs.h", "brix_vfs_copyfile("],
    )
    _assert_markers(
        "src/fs/vfs/vfs_walk.c",
        ["brix_copy_range("],
    )
    # Phase 12: the range-parse → headers → send pipeline (including the
    # brix_http_send_file_range call) moved into the shared file-serve
    # handler.  Both WebDAV GET and S3 GetObject now delegate to it via
    # brix_http_serve_file_ranged() instead of each invoking the
    # http_file_response helpers directly.
    _assert_markers(
        "src/protocols/shared/file_serve.c",
        ["core/http/http_file_response.h", "brix_http_send_file_range("],
    )
    _assert_markers(
        "src/protocols/webdav/get.c",
        ["protocols/shared/file_serve.h", "brix_http_serve_file_ranged("],
    )
    _assert_markers(
        "src/protocols/s3/object.c",
        ["protocols/shared/file_serve.h", "brix_http_serve_file_ranged("],
    )


def test_query_xml_and_base64url_helpers_are_shared():
    for relpath in (
        "src/protocols/s3/list_objects_v2.c",
        "src/protocols/s3/multipart_helpers.c",
        "src/protocols/webdav/xrdhttp.c",
    ):
        _assert_markers(relpath, ["brix_http_query_"])

    # propfind was split into propfind_props.c / propfind_walk.c with a shared
    # propfind_internal.h; the http_xml include lives in the header, the chain
    # builder is used by the props unit.
    _assert_markers("src/protocols/webdav/propfind_internal.h", ["core/http/http_xml.h"])
    _assert_markers("src/protocols/webdav/propfind_props.c", ["brix_http_chain_appendf("])
    _assert_markers(
        "src/protocols/webdav/lock.c",
        ["core/http/http_xml.h", "brix_http_chain_appendf("],
    )
    _assert_absent("src/protocols/webdav/lock.c", ["webdav_propfind_append("])
    _assert_markers(
        "src/protocols/s3/util.c",
        ["core/http/http_xml.h", "brix_http_send_xml_error("],
    )
    _assert_markers(
        "src/protocols/s3/list_objects_v2.c",
        ["auth/token/b64url.h", "b64url_encode(", "b64url_decode("],
    )
    _assert_absent(
        "src/protocols/s3/list_objects_v2.c",
        ["static const signed char inv", "s3_b64url_"],
    )


def test_iso8601_and_hex_helpers_are_shared():
    _assert_markers(
        "src/core/compat/time.c",
        ["brix_format_iso8601(", ".000Z"],
    )
    for relpath in (
        "src/protocols/s3/copy.c",
        "src/protocols/s3/list_common.c",
        "src/protocols/s3/multipart_complete_list_parts.c",
        "src/protocols/s3/multipart_complete_list_uploads.c",
        "src/protocols/s3/multipart_complete_upload_part_copy.c",
        "src/protocols/webdav/propfind_props.c",
    ):
        _assert_markers(relpath, ["brix_format_iso8601("])
    _assert_markers("src/protocols/webdav/propfind_internal.h", ["core/compat/time.h"])
    _assert_absent("src/protocols/s3/util.c", ["s3_iso8601("])
    _assert_absent("src/protocols/s3/s3.h", ["s3_iso8601("])

    _assert_markers(
        "src/core/compat/hex.h",
        ["brix_hex_nibble(", "brix_hex_from_char(", "brix_hex_encode("],
    )
    _assert_markers(
        "src/fs/path/helpers.c",
        ["core/compat/hex.h", "brix_hex_nibble("],
    )
    _assert_markers(
        "src/core/compat/xml.c",
        ['#include "hex.h"', "brix_hex_nibble("],
    )
    _assert_markers(
        "src/auth/token/macaroon.c",
        ["core/compat/hex.h", "brix_hex_from_char("],
    )
    _assert_markers(
        "src/core/compat/uri.c",
        ['#include "hex.h"', "brix_hex_from_char("],
    )
    _assert_markers(
        "src/core/compat/checksum.c",
        ['#include "hex.h"', "brix_hex_encode("],
    )
    # phase-79 file-size split: the SigV4 crypto core (which hex-encodes the
    # digest/signature) moved from auth_sigv4_verify.c into
    # auth_sigv4_verify_crypto.c.
    _assert_markers(
        "src/protocols/s3/auth_sigv4_verify_crypto.c",
        ["core/compat/hex.h", "brix_hex_encode("],
    )
    _assert_absent("src/fs/path/helpers.c", ["brix_hex_digit("])
    _assert_absent("src/core/compat/xml.c", ["brix_xml_hex_digit("])
    _assert_absent("src/auth/token/macaroon.c", ["hex_to_int("])
    _assert_absent("src/core/compat/uri.c", ["hex_val("])
    _assert_absent("src/protocols/s3/auth_sigv4_canonical.c", ["hex_encode("])
    _assert_absent("src/protocols/s3/s3_auth_internal.h", ["hex_encode("])


def test_token_fs_usage_and_shm_slot_helpers_are_shared():
    # phase-79 file-size split: tpc_token.c's token-file/exchange machinery
    # (the brix_token_read_file caller) moved into tpc_token_exchange.c.
    for relpath in (
        "src/net/upstream/auth.c",
        "src/tpc/gsi/gsi_outbound_common.c",
        "src/tpc/outbound/tpc_token_exchange.c",
    ):
        _assert_markers(relpath, ["brix_token_read_file("])

    for relpath in ("src/tpc/outbound/tpc_token.c", "src/protocols/webdav/tpc_cred_parse.c"):
        _assert_markers(relpath, ["brix_oauth2_parse_access_token("])

    for relpath in (
        "src/protocols/root/query/space.c",
        "src/observability/metrics/stream_cache.c",
        "src/protocols/webdav/propfind_props.c",
    ):
        _assert_markers(relpath, ["brix_fs_usage_"])

    for relpath in (
        "src/net/manager/pending.c",
        "src/tpc/engine/key_registry.c",
    ):
        _assert_markers(relpath, ["core/compat/shm_slots.h", "brix_shm_"])

    # Phase 16: WebDAV lock state migrated off the SHM slot table onto xattrs
    # (the unified prop store).  lock.c must no longer reference shm_slots and
    # must use the webdav_lock_xattr_* persistence helpers instead.
    _assert_absent("src/protocols/webdav/lock.c", ["core/compat/shm_slots.h", "brix_shm_"])
    _assert_markers("src/protocols/webdav/lock.c", ["webdav_lock_xattr_read("])


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
    # The root:// open TPC-context handling was split into open_tpc.c.
    _assert_markers(
        "src/protocols/root/read/open_tpc.c",
        ["brix_tpc_check_authz("],
    )
    _assert_markers(
        "src/protocols/webdav/tpc.c",
        ["tpc/common/auth.h", "brix_tpc_check_authz("],
    )
    for relpath in ("src/tpc/engine/launch.c", "src/protocols/webdav/tpc_thread.c", "src/protocols/webdav/tpc.c"):
        _assert_markers(relpath, ["brix_tpc_registry_add("])
    # phase-79 file-size split: source.c's Phase-2/3 stream loop (which emits the
    # progress samples) moved into source_stream.c.
    for relpath in ("src/tpc/outbound/source_stream.c", "src/protocols/webdav/tpc_curl_pmark.c", "src/protocols/webdav/tpc_marker.c"):
        _assert_markers(relpath, ["brix_tpc_progress_emit("])
    for relpath in ("src/tpc/outbound/tpc_token.c", "src/protocols/webdav/tpc_cred.c"):
        _assert_markers(relpath, ["brix_tpc_credential_parse("])
    # dashboard api was split: registry include in dashboard_api_internal.h, the
    # snapshot call in api_transfers.c.
    _assert_markers("src/observability/dashboard/dashboard_api_internal.h",
                    ["tpc/common/registry.h"])
    _assert_markers("src/observability/dashboard/api_transfers.c",
                    ["brix_tpc_registry_snapshot("])


def test_http_header_body_and_condition_helpers_are_shared():
    _assert_markers(
        "src/protocols/webdav/webdav.h",
        ["core/http/http_headers.h", "brix_http_find_header("],
    )
    _assert_markers(
        "src/protocols/s3/auth_sigv4_parse.c",
        ["core/http/http_headers.h", "brix_http_get_header("],
    )
    _assert_markers(
        "src/protocols/s3/copy.c",
        ["core/http/http_headers.h", "brix_http_find_header("],
    )
    _assert_markers(
        "src/core/http/http_headers.h",
        ["brix_http_extract_bearer("],
    )
    _assert_markers(
        "src/protocols/webdav/auth_token.c",
        ["core/http/http_headers.h", "brix_http_extract_bearer("],
    )
    _assert_absent(
        "src/protocols/webdav/auth_token.c",
        ['ngx_strncmp(auth_hdr.data, "Bearer ", 7)'],
    )
    _assert_markers(
        "src/protocols/webdav/tpc.c",
        ["core/http/http_headers.h", "brix_http_extract_bearer("],
    )
    _assert_absent(
        "src/protocols/webdav/tpc.c",
        ['bearer_prefix = "Bearer "', "ngx_strncasecmp(auth_hdr->value.data"],
    )

    # s3/put was split: the http_body include lives in s3_put_internal.h while the
    # writer call stays in put.c.  phase-79 file-size split: webdav/put.c's body
    # streaming (the brix_http_body_write_to_fd callers) moved into put_body.c;
    # the include remains in put.c.
    _assert_markers("src/protocols/webdav/put.c", ["core/http/http_body.h"])
    _assert_markers("src/protocols/webdav/put_body.c",
                    ["core/http/http_body.h", "brix_http_body_write_to_fd("])
    _assert_markers("src/protocols/s3/s3_put_internal.h", ["core/http/http_body.h"])
    # phase-79 split: the buffered/streaming writer call sites moved from
    # put.c into put_stream.c (and put_aio.c for the aio path).
    _assert_markers("src/protocols/s3/put_stream.c", ["brix_http_body_write_to_fd("])

    # propfind was split: the include is in propfind_internal.h, the reader in
    # propfind.c; delete_objects.c still carries both directly.
    _assert_markers("src/protocols/webdav/propfind_internal.h", ["core/http/http_body.h"])
    _assert_markers("src/protocols/webdav/propfind.c", ["brix_http_body_read_all("])
    _assert_markers("src/protocols/s3/delete_objects.c",
                    ["core/http/http_body.h", "brix_http_body_read_all("])

    # phase-79 split: put.c's precondition/setup phase moved into put_setup.c
    # (put.c keeps the http_conditionals include).
    _assert_markers(
        "src/protocols/webdav/put.c",
        ["core/http/http_conditionals.h"],
    )
    _assert_markers(
        "src/protocols/webdav/put_setup.c",
        ["brix_http_check_etag_preconditions("],
    )
    _assert_markers(
        "src/protocols/webdav/methods/copy_conditionals.c",
        ["core/http/http_conditionals.h", "brix_http_check_etag_preconditions("],
    )
    _assert_markers(
        "src/protocols/webdav/get.c",
        ["core/http/http_conditionals.h", "brix_http_check_if_modified_since("],
    )
    for relpath in ("src/protocols/webdav/copy.c", "src/protocols/webdav/move.c"):
        _assert_markers(relpath, ["brix_http_overwrite_forbidden("])


def test_phase1_http_status_header_and_query_helpers_are_shared():
    _assert_markers(
        "src/core/http/http_headers.h",
        [
            "brix_http_effective_status(",
            "brix_http_set_header_num(",
            "brix_http_request_header_add(",
        ],
    )
    for relpath in ("src/protocols/webdav/metrics.c", "src/protocols/s3/metrics.c"):
        _assert_markers(
            relpath,
            ["core/http/http_headers.h", "brix_http_effective_status("],
        )

    # phase-79 file-size split: xrdhttp.c's response/header emission (the
    # brix_http_set_header* / request_header_add callers) moved into
    # xrdhttp_response.c; xrdhttp.c keeps the http_headers include.
    _assert_markers(
        "src/protocols/webdav/xrdhttp.c",
        ["core/http/http_headers.h"],
    )
    _assert_markers(
        "src/protocols/webdav/xrdhttp_response.c",
        [
            "brix_http_set_header(",
            "brix_http_set_header_num(",
        ],
    )
    # ... while the outbound-request header add lives in the TPC half.
    _assert_markers(
        "src/protocols/webdav/xrdhttp_tpc.c",
        ["brix_http_request_header_add("],
    )
    _assert_absent(
        "src/protocols/webdav/xrdhttp.c",
        ["static ngx_int_t\nadd_header_str", "static ngx_int_t\nadd_header_num"],
    )

    _assert_markers(
        "src/protocols/s3/handler.c",
        [
            "core/http/http_query.h",
            "brix_http_query_get(",
            "brix_http_find_header(",
        ],
    )
    _assert_absent("src/protocols/s3/handler.c", ['needle[] = "list-type=2"'])
    _assert_markers(
        "src/protocols/s3/multipart_complete_upload_part_copy.c",
        ["core/http/http_headers.h", "brix_http_find_header("],
    )


def test_checksum_fs_walk_staging_and_cms_frame_helpers_are_shared():
    for relpath in (
        "src/protocols/root/query/checksum_qcksum.c",
        "src/protocols/root/query/checksum_qcksum_async.c",
        "src/protocols/root/query/checksum_ckscan_common.c",
        "src/protocols/root/query/checksum_ckscan_dispatch.c",
        "src/protocols/root/query/checksum_ckscan_async.c",
        "src/protocols/root/dirlist/dcksm.c",
        "src/protocols/webdav/xrdhttp.c",
    ):
        _assert_markers(relpath, ["core/compat/checksum.h", "brix_checksum_"])

    for relpath in ("src/protocols/webdav/namespace.c", "src/protocols/s3/multipart_helpers.c"):
        _assert_markers(
            relpath,
            ["core/compat/fs_walk.h", "brix_fs_remove_tree_confined("],
        )

    # Phase 62: directory enumeration moved behind the VFS seam — propfind walks
    # via brix_vfs_readdir and ckscan via brix_vfs_walk, both of which skip
    # "."/".." centrally in src/fs/vfs/vfs_walk.c (the single brix_fs_is_dot_entry
    # caller) instead of each handler filtering dotted entries itself.
    _assert_markers("src/protocols/webdav/propfind_walk.c", ["brix_vfs_readdir("])
    _assert_markers("src/protocols/root/query/checksum_ckscan_common.c", ["brix_vfs_walk("])
    _assert_markers("src/fs/vfs/vfs_walk.c", ["brix_fs_is_dot_entry("])

    # s3/put was split: the staged_file include is in s3_put_internal.h, the open
    # call stays in put.c — now routed through the VFS seam
    # (brix_vfs_staged_open, phase-62 VFS closure) rather than the raw
    # brix_staged_open; webdav/tpc.c still carries the raw open directly.
    _assert_markers("src/protocols/s3/s3_put_internal.h", ["core/compat/staged_file.h"])
    # phase-79 file-size split: put.c's PUT precondition/open phase (which routes
    # the staged-write open through the VFS seam) moved into put_inner.c.
    _assert_markers("src/protocols/s3/put_inner.c", ["brix_vfs_staged_open("])
    # phase-79 file-size split: tpc.c's pull-side staged-write open moved into
    # tpc_pull.c; tpc.c keeps the staged_file include.
    _assert_markers("src/protocols/webdav/tpc.c", ["core/compat/staged_file.h"])
    _assert_markers("src/protocols/webdav/tpc_pull.c", ["brix_staged_open("])

    # Phase 55: both the S3 CopyObject and WebDAV COPY handlers delegate the
    # local-object copy to the shared VFS copy seam (brix_vfs_copy), which is
    # the single place that reaches brix_ns_local_copy (src/fs/vfs/vfs_copy.c).
    for relpath in (
        "src/protocols/s3/copy.c",
        "src/protocols/webdav/copy.c",
    ):
        _assert_markers(relpath, ['#include "s3.h"' if "s3" in relpath else "webdav.h", "brix_vfs_copy("])

    for relpath in ("src/net/cms/send.c", "src/net/cms/server_send.c"):
        _assert_markers(relpath, ["frame_io.h", "brix_cms_send_frame("])


def test_webdav_config_path_validation_is_shared():
    _assert_markers(
        "src/protocols/webdav/config.c",
        ["core/config/config.h", "#define webdav_validate_path          brix_validate_path"],
    )
    _assert_absent(
        "src/protocols/webdav/config.c",
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
            "brix_path_resolve_cstr(",
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
            "brix_path_resolve_cstr(",
            "allow_missing_parents",
        ],
    )
    _assert_absent(
        "src/fs/path/resolve_path_variants.c",
        [
            "lstat(",
            "brix_path_component_forbidden(",
        ],
    )


def test_http_path_resolver_uses_unified_adapter():
    # Phase 8: the HTTP/S3 adapter (compat/path.c) no longer canonicalises with
    # realpath() + the unified.h string resolver.  It joins the request lexically
    # under the export root via the shared beneath API (brix_beneath_full_path)
    # and lets openat2(RESOLVE_BENEATH) enforce confinement at the operation.
    # Verify it uses that shared resolver rather than reimplementing path munging.
    _assert_markers(
        "src/core/compat/path.c",
        [
            "fs/path/beneath.h",
            "brix_beneath_full_path(",
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
            "BRIX_AUTHN_GSI",
            "BRIX_AUTHN_TOKEN",
            "BRIX_AUTHN_SSS",
            "BRIX_AUTHN_S3KEY",
            "brix_identity_t",
        ],
    )
    _assert_markers(
        "src/core/types/context.h",
        ["brix_identity_t *identity"],
    )
    _assert_markers(
        "src/protocols/webdav/webdav.h",
        ["core/types/identity.h", "brix_identity_t *identity"],
    )
    _assert_markers(
        "src/protocols/s3/s3.h",
        ["core/types/identity.h", "brix_identity_t *identity"],
    )


def test_phase2_auth_paths_populate_identity():
    _assert_markers(
        "src/auth/gsi/auth.c",
        ["brix_identity_set_dn(", "BRIX_AUTHN_GSI"],
    )
    _assert_markers(
        "src/auth/gsi/token.c",
        ["brix_identity_set_token_claims("],
    )
    _assert_markers(
        "src/auth/sss/auth_request.c",
        ["brix_identity_set_dn(", "BRIX_AUTHN_SSS"],
    )
    _assert_markers(
        "src/protocols/webdav/auth_cert.c",
        ["brix_identity_alloc(", "brix_identity_set_dn("],
    )
    _assert_markers(
        "src/protocols/webdav/auth_token.c",
        ["brix_identity_set_token_claims("],
    )
    _assert_markers(
        "src/protocols/s3/auth_sigv4_verify.c",
        ["brix_identity_t *identity", "BRIX_AUTHN_S3KEY"],
    )


def test_http_precondition_evaluation_is_shared():
    # S3 GET/HEAD and conditional-PUT preconditions route through the shared
    # RFC 9110 evaluator (core/http/http_conditionals.c); the former private
    # evaluator/matcher (s3_eval_preconditions / s3_etag_header_matches) must
    # not grow back.
    _assert_markers(
        "src/protocols/s3/conditional.c",
        [
            "core/http/http_conditionals.h",
            "brix_http_eval_preconditions(",
            "BRIX_HTTP_COND_READ",
        ],
    )
    _assert_absent(
        "src/protocols/s3/conditional.c",
        ["s3_eval_preconditions", "s3_etag_header_matches", "s3_str_contains"],
    )
    # WebDAV COPY/PUT keep using the shared ETag-precondition subset.
    _assert_markers(
        "src/protocols/webdav/methods/copy_conditionals.c",
        ["brix_http_check_etag_preconditions("],
    )
    # The shared engine owns both outcome modes.
    _assert_markers(
        "src/core/http/http_conditionals.c",
        ["brix_http_eval_preconditions(", "BRIX_HTTP_COND_READ"],
    )

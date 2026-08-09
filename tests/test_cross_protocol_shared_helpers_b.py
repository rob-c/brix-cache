from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cross_protocol_shared_helpers_helpers")

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
    # phase-79 file-size split: put.c's PUT precondition/open phase moved into
    # put_inner.c, and the staged-write open now routes through the unified writer
    # seam (brix_vfs_writer_open with BRIX_VFS_O_ATOMIC — which itself performs the
    # brix_vfs_staged_open temp+publish) rather than opening the staged file directly.
    _assert_markers("src/protocols/s3/put_inner.c", ["brix_vfs_writer_open("])
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

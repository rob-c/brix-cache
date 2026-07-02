from _test_cross_protocol_shared_helpers_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_phase2_policy_consumes_identity():
    _assert_markers(
        "src/auth/authz/authdb.c",
        [
            "xrootd_find_authdb_rule_identity(",
            "xrootd_check_authdb_identity(",
            "xrootd_identity_dn_cstr(",
            "xrootd_identity_vo_csv_cstr(",
        ],
    )
    _assert_markers(
        "src/auth/authz/acl.c",
        ["xrootd_check_vo_acl_identity(", "xrootd_identity_vo_csv_cstr("],
    )
    _assert_markers(
        "src/handshake/policy.c",
        ["xrootd_identity_check_token_scope("],
    )
    # auth_gate.c is the canonical consumer of all three tiers; handlers that
    # have been converted call xrootd_auth_gate() instead of the three functions
    # directly.  Verify auth_gate.c implements the full triad.
    _assert_markers(
        "src/auth/authz/auth_gate.c",
        ["xrootd_check_authdb(", "xrootd_check_vo_acl_identity(",
         "xrootd_check_token_scope("],
    )
    # Files with unconverted call-sites still call the VO ACL helper directly.
    # (write/common.c was since converted — its write ops now authorise through
    # the op-descriptor table / xrootd_auth_gate(), so it no longer calls the VO
    # ACL helper directly and is no longer listed here.)
    for relpath in (
        "src/read/open_request.c",
        "src/query/prepare.c",
    ):
        _assert_markers(relpath, ["xrootd_check_vo_acl_identity("])
        _assert_absent(relpath, ["ctx->vo_list) != NGX_OK"])
    # dirlist was fully converted to auth_gate; confirm it no longer duplicates
    # the triad and instead delegates to the gate.
    _assert_markers("src/dirlist/handler.c", ["xrootd_auth_gate("])
    _assert_absent("src/dirlist/handler.c",
                   ["ctx->vo_list) != NGX_OK", "xrootd_check_vo_acl_identity("])


def test_phase2_voms_identity_rejects_injected_vo_tokens():
    _assert_markers(
        "src/auth/voms/collect.c",
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
    # The data-plane read/write entry points are no longer public API on vfs.h —
    # byte I/O routes through xrootd_vfs_io_execute() (vfs_io_core.c); vfs.h
    # exposes open/stat plus the sendfile/readdir surface.
    _assert_markers(
        "src/fs/vfs.h",
        [
            "XROOTD_VFS_O_READ",
            "XROOTD_VFS_O_WRITE",
            "xrootd_vfs_ctx_t",
            "xrootd_vfs_open(",
            "xrootd_vfs_stat(",
        ],
    )


def test_phase3_vfs_preserves_io_invariants():
    # The read path's I/O invariants now live in focused units after the split:
    #  - file-backed sendfile buffer (b->in_file=1) -> compat/http_file_response.c
    #  - zero-copy fd ownership: the backend LENDS its fd (sd_posix returns obj->fd)
    #    and the serve consumer dups it before closing the handle, so the response
    #    owns the sendfile fd's lifetime (no double-close) -> shared/file_serve.c
    #  - read-side CRC -> fs/vfs_io_core.c
    #  - the write byte primitive -> fs/vfs_write.c
    _assert_markers("src/core/compat/http_file_response.c", ["b->in_file = 1"])
    _assert_markers("src/shared/file_serve.c",
                    ["send_fd = dup(fd)", "xrootd_vfs_close(fh"])
    _assert_markers("src/fs/vfs_io_core.c", ["xrootd_crc32c_value("])
    _assert_markers("src/fs/vfs_write.c", ["xrootd_vfs_pwrite_full("])
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
            "src/fs/cache/open.h",
            "src/fs/cache/meta.h",
            "src/fs/cache/writethrough.h",
            "src/fs/cache/open.c",
            "src/fs/cache/meta.c",
        ],
    )
    _assert_markers(
        "src/fs/cache/open.h",
        [
            "xrootd_cache_open(",
            "xrootd_cache_record_access(",
            "xrootd_cache_path_for_resolved(",
        ],
    )
    _assert_markers(
        "src/fs/cache/meta.h",
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
    # Read-side cache-hit recording moved out of vfs_read.c into the shared HTTP
    # serve pipeline; the write-through decision moved into its own cache unit.
    _assert_markers(
        "src/shared/file_serve.c",
        ["../cache/open.h", "xrootd_cache_record_access("],
    )
    _assert_markers(
        "src/fs/cache/writethrough_decision.c",
        ["writethrough.h", "xrootd_cache_should_writethrough("],
    )


def test_phase4_http_protocols_use_vfs_cache_path():
    # The per-request VFS-ctx setup (incl. cache_root_canon wiring) was factored
    # into the shared xrootd_vfs_ctx_init() helper (fs/vfs_open.c); WebDAV and S3
    # GET now pass cache_root_canon into that one helper rather than assigning the
    # field inline. Assert each GET handler routes through the helper + still opens
    # read-only through the VFS and records cache access.
    _assert_markers(
        "src/webdav/get.c",
        [
            "../cache/open.h",
            "../fs/vfs.h",
            "xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ",
            "xrootd_vfs_ctx_init(",
            "conf->cache_root_canon",
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
            "xrootd_vfs_ctx_init(",
            "cf->cache_root_canon",
        ],
    )
    # The single wiring point: xrootd_vfs_ctx_init() sets cache_root_canon (and
    # derives cache_enabled) for every HTTP caller.
    _assert_markers(
        "src/fs/vfs_open.c",
        ["vctx->cache_root_canon = cache_root_canon"],
    )
    # Phase 12: the cache-hit detection and access-record calls moved out of the
    # per-protocol GET handlers into the shared file-serve pipeline. Both WebDAV
    # and S3 GET now record cache access via xrootd_http_serve_file_ranged().
    _assert_markers(
        "src/shared/file_serve.c",
        [
            "../cache/open.h",
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
        "src/fs/cache/fetch.c",
        [
            "xrootd_cache_meta_from_stat(",
            "xrootd_cache_meta_write(",
        ],
    )
    _assert_markers(
        "src/fs/cache/open.c",
        [
            "xrootd_cache_validate_meta(",
            "O_NOFOLLOW",
            "xrootd_vfs_adopt_fd(",
        ],
    )
    _assert_markers(
        "src/fs/cache/evict_candidates.c",
        ['strcmp(name + name_len - suffix_len, ".meta")'],
    )
    _assert_markers(
        "src/fs/cache/evict_policy.c",
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
        "src/core/compat/checksum.c",
        "src/core/compat/fs_walk.c",
        "src/core/compat/http_body.c",
        "src/core/compat/http_conditionals.c",
        "src/core/compat/http_headers.c",
        "src/core/compat/hex.c",
        "src/core/compat/staged_file.c",
        "src/core/compat/time.c",
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
    # The metadata ops carry the observe hook directly; data-plane read/write are
    # observed through the I/O core (vfs_io_core.c), not vfs_read.c/vfs_write.c.
    for relpath in (
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
            # pgread uses the in-place 3-way CRC (zero-copy) rather than the
            # copy-while-summing variant the write path uses.
            "xrootd_crc32c_value(",
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
    # The multipart-complete sub-handlers are now separate compilation units
    # listed in config (no longer #included into one amalgamation .c).
    _assert_markers(
        "config",
        [
            "src/s3/multipart_complete_list_parts.c",
            "src/s3/multipart_complete_list_uploads.c",
            "src/s3/multipart_complete_upload_part_copy.c",
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
            "src/auth/unix/auth.c",
            "src/auth/krb5/config.c",
            "src/auth/krb5/auth.c",
        ],
    )
    # The auth-method name->enum table moved into module_enums.c; the krb5/unix
    # config directives stay in module.c (split out of the old monolith).
    _assert_markers(
        "src/stream/module_enums.c",
        [
            'ngx_string("unix")',
            "XROOTD_AUTH_UNIX",
            'ngx_string("krb5")',
            "XROOTD_AUTH_KRB5",
        ],
    )
    _assert_markers(
        "src/stream/module.c",
        [
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
        "src/auth/gsi/auth.c",
        [
            "xrootd_handle_unix_auth(ctx, c, conf)",
            "xrootd_handle_krb5_auth(ctx, c, conf)",
        ],
    )
    _assert_markers(
        "src/auth/unix/auth.c",
        [
            "xrootd_unix_peer_is_loopback(",
            "unix_trust_remote",
            "XROOTD_AUTHN_UNIX",
            "xrootd_session_register(",
        ],
    )
    _assert_markers(
        "src/auth/krb5/config.c",
        [
            "krb5_parse_name(",
            "krb5_kt_start_seq_get(",
            "xrootd_auth krb5 requested",
        ],
    )
    _assert_markers(
        "src/auth/krb5/auth.c",
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

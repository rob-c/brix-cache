from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cross_protocol_shared_helpers_helpers")

def test_phase6_unified_metrics_observability_is_wired():
    for relpath in (
        "src/observability/metrics/unified.h",
        "src/observability/metrics/unified.c",
        "src/observability/metrics/access_log.h",
        "src/observability/metrics/access_log.c",
    ):
        _read(relpath)

    _assert_markers(
        "config",
        [
            "src/observability/metrics/unified.h",
            "src/observability/metrics/access_log.h",
            "src/observability/metrics/unified.c",
            "src/observability/metrics/access_log.c",
        ],
    )
    _assert_markers(
        "src/observability/metrics/metrics.h",
        ["ngx_brix_unified_metrics_t", "ngx_brix_unified_metrics_t unified"],
    )
    # phase-79 file-size split: stream.c's per-server-slot family emitters (which
    # carry the DEPRECATED-family markers) moved into stream_family.c; the
    # exposition driver (brix_export_unified_metrics) stayed in stream.c.
    _assert_markers(
        "src/observability/metrics/stream.c",
        ["brix_export_unified_metrics(mw, shm)"],
    )
    _assert_markers(
        "src/observability/metrics/stream_family.c",
        ["DEPRECATED"],
    )
    # phase-79 file-size split: unified.c (was 1076 lines) was split into
    # unified_record.c (record-side mutators), unified_export_io.c (io exporters),
    # and unified_export.c (cred/cache/auth/tpc exporters). The wiring is unchanged;
    # the markers now live in their respective split files.
    _assert_markers(
        "src/observability/metrics/unified_record.c",
        [
            "brix_metric_op_done(",
            "brix_metric_cache_result(",
            "brix_metric_auth(",
            "brix_metric_tpc(",
        ],
    )
    _assert_markers(
        "src/observability/metrics/unified_export_io.c",
        ["brix_io_ops_total"],
    )
    _assert_markers(
        "src/observability/metrics/unified_export.c",
        ["brix_auth_total", "brix_tpc_transfers_total"],
    )
    _assert_markers(
        "src/fs/vfs/vfs_internal.h",
        ["brix_metric_op_done(", "brix_access_log_emit("],
    )
    # The metadata ops carry the observe hook directly; data-plane read/write are
    # observed through the I/O core (vfs_io_core.c), not vfs_read.c/vfs_write.c.
    for relpath in (
        "src/fs/vfs/vfs_stat.c",
        "src/fs/vfs/vfs_unlink.c",
        "src/fs/vfs/vfs_mkdir.c",
        "src/fs/vfs/vfs_rename.c",
        "src/fs/vfs/vfs_dir.c",
    ):
        _assert_markers(relpath, ["brix_vfs_observe_"])
    _assert_markers(
        "src/fs/vfs/vfs_open.c",
        ["brix_metric_cache_result("],
    )
    _assert_markers(
        "src/protocols/webdav/metrics.c",
        ["observability/metrics/unified.h", "brix_metric_op_done("],
    )
    _assert_markers(
        "src/protocols/s3/metrics.c",
        ["observability/metrics/unified.h", "brix_metric_op_done("],
    )
    _assert_markers(
        "src/tpc/common/metrics.c",
        ["observability/metrics/unified.h", "brix_metric_tpc("],
    )


def test_implementation_plan_feature_gaps_are_closed():
    _assert_markers(
        "src/protocols/root/handshake/dispatch_read.c",
        [
            "case kXR_stat:",
            "brix_handle_stat",
            "case kXR_statx:",
            "brix_handle_statx",
            "case kXR_locate:",
            "brix_handle_locate",
            "case kXR_clone:",
            "brix_handle_clone",
        ],
    )
    # phase-79: dispatch_write.c replaced its switch ladder with the
    # table-driven brix_wr_routes[] descriptor array; the opcodes appear as
    # table rows rather than case labels.
    _assert_markers(
        "src/protocols/root/handshake/dispatch_write.c",
        [
            "{ kXR_pgwrite,",
            "brix_handle_pgwrite",
            "{ kXR_chkpoint,",
            "brix_handle_chkpoint",
        ],
    )
    # pgread.c was split; the page-encode + in-place CRC moved to pgread_encode.c,
    # while the status-frame builder stayed in pgread.c.
    _assert_markers(
        "src/protocols/root/read/pgread_encode.c",
        [
            "brix_pgread_encode_pages(",
            # pgread uses the in-place 3-way CRC (zero-copy) rather than the
            # copy-while-summing variant the write path uses.
            "brix_crc32c_value(",
        ],
    )
    _assert_markers(
        "src/protocols/root/read/pgread.c",
        [
            "brix_build_pgread_status(",
        ],
    )
    _assert_markers(
        "src/protocols/root/write/pgwrite.c",
        [
            "brix_pgwrite_decode_payload(",
            "brix_crc32c_copy(",
            "brix_send_pgwrite_status(",
        ],
    )
    # phase-79 split: the journal-recovery half of chkpoint.c moved into
    # chkpoint_recover.c.
    _assert_markers(
        "src/protocols/root/write/chkpoint.c",
        ["brix_handle_chkpoint("],
    )
    _assert_markers(
        "src/protocols/root/write/chkpoint_recover.c",
        ["brix_chkpoint_recover_root("],
    )

    _assert_markers(
        "src/protocols/webdav/access.c",
        [
            "webdav_add_cors_headers(r)",
            # 7de0b6d renamed webdav_check_token_write_scope → _scope
            # (now enforces READ and WRITE scope, not write-only).
            "webdav_check_token_scope(r, mname)",
            "webdav_metrics_return(r,",
        ],
    )
    # access.c was split; the cert/bearer verification calls moved to access_auth.c.
    _assert_markers(
        "src/protocols/webdav/access_auth.c",
        [
            "webdav_verify_proxy_cert(r, conf)",
            "webdav_verify_bearer_token(r, conf)",
        ],
    )
    _assert_markers(
        "src/protocols/webdav/auth_token.c",
        [
            "webdav_verify_bearer_token(",
            # renamed from webdav_check_token_write_scope (7de0b6d: read+write)
            "webdav_check_token_scope(",
            "brix_identity_check_token_scope(",
            "brix_token_check_write(",
        ],
    )
    _assert_markers(
        "src/protocols/webdav/dispatch.c",
        [
            # webdav_proxy_handler retired with the reverse-proxy transport
            # (A-2 surface retirement); dispatch goes straight to the handlers.
            "webdav_metrics_return(r, webdav_handle_get(r))",
            "webdav_metrics_return(r, webdav_handle_delete(r))",
            "webdav_metrics_return(r, webdav_handle_mkcol(r))",
            "webdav_metrics_return(r, webdav_handle_copy(r))",
            "webdav_metrics_return(r, webdav_handle_move(r))",
            "webdav_metrics_return(r, webdav_handle_propfind(r))",
        ],
    )

    # phase-79 split: handler.c kept the auth gate; the bucket-level routing
    # (ListMultipartUploads) moved into handler_dispatch.c and the per-object
    # multipart routing into handler_object_route.c (where the body read is
    # wired through the s3_read_body_metric wrapper).
    _assert_markers(
        "src/protocols/s3/handler.c",
        ["s3_verify_sigv4(r, cf, s3ctx->identity)"],
    )
    _assert_markers(
        "src/protocols/s3/handler_dispatch.c",
        ["s3_handle_list_multipart_uploads(r, cf)"],
    )
    _assert_markers(
        "src/protocols/s3/handler_object_route.c",
        [
            "s3_handle_list_parts(r, fs_path, cf",
            "s3_handle_upload_part_copy(r, fs_path, cf",
            "s3_handle_multipart_abort(r, fs_path, cf, upload_id)",
            "s3_handle_multipart_initiate(r, fs_path, cf",
            "s3_multipart_complete_body_handler",
        ],
    )
    _assert_markers(
        "src/protocols/s3/auth_sigv4_verify.c",
        [
            "s3_verify_sigv4(",
            "s3_record_auth_result(",
            "BRIX_AUTHN_S3KEY",
        ],
    )
    # The multipart-complete sub-handlers are now separate compilation units
    # listed in config (no longer #included into one amalgamation .c).
    _assert_markers(
        "config",
        [
            "src/protocols/s3/multipart_complete_list_parts.c",
            "src/protocols/s3/multipart_complete_list_uploads.c",
            "src/protocols/s3/multipart_complete_upload_part_copy.c",
        ],
    )
    _assert_absent(
        "src/protocols/s3/auth_sigv4_verify.c",
        ["webdav_verify_bearer_token"],
    )
    _assert_absent(
        "src/protocols/s3/handler.c",
        ["webdav_verify_bearer_token"],
    )


def test_stream_missing_auth_plugins_are_wired():
    _assert_markers(
        "config",
        [
            "pkg-config --exists krb5",
            "-DBRIX_HAVE_KRB5=1",
            "src/auth/unix/auth.c",
            "src/auth/krb5/config.c",
            "src/auth/krb5/auth.c",
        ],
    )
    # The auth-method name->enum table moved into module_enums.c; the krb5/unix
    # config directives stay in module.c (split out of the old monolith).
    _assert_markers(
        "src/protocols/root/stream/module_enums.c",
        [
            'ngx_string("unix")',
            "BRIX_AUTH_UNIX",
            'ngx_string("krb5")',
            "BRIX_AUTH_KRB5",
        ],
    )
    _assert_markers(
        "src/protocols/root/stream/module.c",
        [
            "brix_krb5_principal",
            "brix_krb5_keytab",
            "brix_krb5_ip_check",
            "brix_unix_trust_remote",
        ],
    )
    # Authentication offers are emitted in the login response's standard
    # &P=<protocol> list. The protocol response carries only the security-level
    # trailer; putting auth entries there shifts that fixed wire structure.
    _assert_markers(
        "src/protocols/root/session/protocol.c",
        ["want->unx", "want->krb5", "protocol_write_sec_trailer"],
    )
    _assert_markers(
        "src/protocols/root/session/login.c",
        ['snprintf(out, cap, "&P=unix")',
         'snprintf(out, cap, "&P=krb5,%s"'],
    )
    _assert_markers(
        "src/protocols/root/session/login.c",
        [
            '"&P=unix"',
            '"&P=krb5,%s"',
            "auth parameter block too long",
        ],
    )
    # phase-79: the kXR_auth protocol dispatch in gsi/auth.c became a
    # descriptor table, so the handlers appear as table entries rather than
    # direct (ctx, c, conf) calls.
    _assert_markers(
        "src/auth/gsi/auth.c",
        [
            "brix_handle_unix_auth",
            "brix_handle_krb5_auth",
        ],
    )
    _assert_markers(
        "src/auth/unix/auth.c",
        [
            "brix_unix_peer_is_loopback(",
            "unix_trust_remote",
            "BRIX_AUTHN_UNIX",
            "brix_session_register(",
        ],
    )
    _assert_markers(
        "src/auth/krb5/config.c",
        [
            "krb5_parse_name(",
            "krb5_kt_start_seq_get(",
            "brix_auth krb5 requested",
        ],
    )
    _assert_markers(
        "src/auth/krb5/auth.c",
        [
            "krb5_rd_req(",
            "krb5_aname_to_localname(",
            "BRIX_AUTHN_KRB5",
            "brix_session_register(",
        ],
    )
    _assert_markers(
        "src/observability/metrics/unified.c",
        ['"unix"', '"krb5"', "BRIX_METRIC_AUTH_UNIX", "BRIX_METRIC_AUTH_KRB5"],
    )

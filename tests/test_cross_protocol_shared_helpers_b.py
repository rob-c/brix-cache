from _test_cross_protocol_shared_helpers_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_phase2_policy_consumes_identity():
    _assert_markers(
        "src/auth/authz/authdb.c",
        [
            "brix_find_authdb_rule_identity(",
            "brix_check_authdb_identity(",
            "brix_identity_dn_cstr(",
            "brix_identity_vo_csv_cstr(",
        ],
    )
    _assert_markers(
        "src/auth/authz/acl.c",
        ["brix_check_vo_acl_identity(", "brix_identity_vo_csv_cstr("],
    )
    _assert_markers(
        "src/protocols/root/handshake/policy.c",
        ["brix_identity_check_token_scope("],
    )
    # auth_gate.c is the canonical consumer of all three tiers; handlers that
    # have been converted call brix_auth_gate() instead of the three functions
    # directly.  Verify auth_gate.c implements the full triad.
    _assert_markers(
        "src/auth/authz/auth_gate.c",
        ["brix_check_authdb(", "brix_check_vo_acl_identity(",
         "brix_check_token_scope("],
    )
    # Files with unconverted call-sites still call the VO ACL helper directly.
    # (write/common.c was since converted — its write ops now authorise through
    # the op-descriptor table / brix_auth_gate(), so it no longer calls the VO
    # ACL helper directly and is no longer listed here.  open_request.c was
    # converted in phase-79: its open path now authorises through
    # brix_auth_gate()/brix_auth_gate_op() instead of calling the helper.)
    for relpath in (
        "src/protocols/root/query/prepare.c",
    ):
        _assert_markers(relpath, ["brix_check_vo_acl_identity("])
        _assert_absent(relpath, ["ctx->vo_list) != NGX_OK"])
    _assert_markers("src/protocols/root/read/open_request.c",
                    ["brix_auth_gate("])
    _assert_absent("src/protocols/root/read/open_request.c",
                   ["ctx->vo_list) != NGX_OK", "brix_check_vo_acl_identity("])
    # dirlist was fully converted to auth_gate; confirm it no longer duplicates
    # the triad and instead delegates to the gate.
    _assert_markers("src/protocols/root/dirlist/handler.c", ["brix_auth_gate("])
    _assert_absent("src/protocols/root/dirlist/handler.c",
                   ["ctx->vo_list) != NGX_OK", "brix_check_vo_acl_identity("])


def test_phase2_voms_identity_rejects_injected_vo_tokens():
    # The per-character injection guard was refactored out of collect.c into a
    # shared static-inline brix_vo_token_is_safe() in vo_token.h; the property is
    # unchanged, only its location. collect.c still calls the guard + fqan→vo.
    _assert_markers(
        "src/auth/voms/vo_token.h",
        [
            "ch <= ' '",
            "ch >= 0x7f",
            "ch == ','",
            "ch == '/'",
        ],
    )
    _assert_markers(
        "src/auth/voms/collect.c",
        [
            "brix_vo_token_safe(",
            "brix_fqan_to_vo(",
        ],
    )


def test_phase3_vfs_layer_is_registered():
    _assert_markers(
        "config",
        [
            "src/fs/vfs/vfs.h",
            "src/fs/vfs/vfs_internal.h",
            "src/fs/vfs/vfs_open.c",
            "src/fs/vfs/vfs_read.c",
            "src/fs/vfs/vfs_write.c",
            "src/fs/vfs/vfs_stat.c",
            "src/fs/vfs/vfs_dir.c",
            "src/fs/vfs/vfs_unlink.c",
            "src/fs/vfs/vfs_rename.c",
            "src/fs/vfs/vfs_mkdir.c",
            "src/fs/vfs/vfs_sync.c",
            "src/fs/vfs/fd_cache.c",
        ],
    )
    # The data-plane read/write entry points are no longer public API on vfs.h —
    # byte I/O routes through brix_vfs_io_execute() (vfs_io_core.c); vfs.h
    # exposes open/stat plus the sendfile/readdir surface.
    _assert_markers(
        "src/fs/vfs/vfs.h",
        [
            "BRIX_VFS_O_READ",
            "BRIX_VFS_O_WRITE",
            "brix_vfs_ctx_t",
            "brix_vfs_open(",
            "brix_vfs_stat(",
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
    _assert_markers("src/core/http/http_file_response.c", ["b->in_file = 1"])
    _assert_markers("src/protocols/shared/file_serve.c",
                    ["send_fd = dup(fd)", "brix_vfs_close(fh"])
    _assert_markers("src/fs/vfs/vfs_io_core.c", ["brix_crc32c_value("])
    _assert_markers("src/fs/vfs/vfs_write.c", ["brix_vfs_pwrite_full("])
    _assert_markers("src/fs/vfs/vfs_unlink.c", ["brix_ns_delete("])
    _assert_markers("src/fs/vfs/vfs_mkdir.c", ["brix_ns_mkdir("])
    _assert_markers("src/fs/vfs/vfs_rename.c", ["brix_ns_rename("])


def test_phase3_http_read_metadata_uses_vfs():
    # phase-79 file-size split: object.c's HEAD/HeadBucket cluster (which does the
    # metadata brix_vfs_stat) moved to object_meta.c; the GET range-serve path
    # (brix_vfs_open / brix_vfs_file_stat) stayed in object.c.
    _assert_markers(
        "src/protocols/s3/object.c",
        [
            "fs/vfs.h",
            "brix_vfs_open(",
            "brix_vfs_file_stat(",
        ],
    )
    _assert_markers(
        "src/protocols/s3/object_meta.c",
        ["brix_vfs_stat("],
    )
    _assert_markers(
        "src/protocols/webdav/resource.c",
        ["fs/vfs.h", "brix_vfs_stat("],
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
            "brix_cache_open(",
            "brix_cache_record_access(",
            "brix_cache_path_for_resolved(",
        ],
    )
    _assert_markers(
        "src/fs/cache/meta.h",
        [
            "brix_cache_meta_t",
            "BRIX_CACHE_META_ETAG_MAX",
            "brix_cache_meta_read(",
            "brix_cache_meta_write(",
        ],
    )


def test_phase4_vfs_cache_hooks_are_present():
    _assert_markers(
        "src/fs/vfs/vfs.h",
        [
            "cache_root_canon",
            "cache_enabled",
            "cache_writethrough_cfg",
            "brix_vfs_file_from_cache(",
        ],
    )
    _assert_markers(
        "src/fs/vfs/vfs_open.c",
        [
            "fs/cache/open.h",
            # phase-79 split: the cache-probe helper takes the caller's fh
            # pointer directly (was a local &fh at the old inline call site).
            "brix_cache_open(ctx, flags, fh)",
            "brix_vfs_adopt_fd(",
            "from_cache",
        ],
    )
    # Read-side cache-hit recording moved out of vfs_read.c into the shared HTTP
    # serve pipeline; the write-through decision moved into its own cache unit.
    _assert_markers(
        "src/protocols/shared/file_serve.c",
        ["fs/cache/open.h", "brix_cache_record_access("],
    )
    _assert_markers(
        "src/fs/cache/writethrough_decision.c",
        ["writethrough.h", "brix_cache_should_writethrough("],
    )


def test_phase4_http_protocols_use_vfs_cache_path():
    # The per-request VFS-ctx setup (incl. cache_root_canon wiring) was factored
    # into the shared brix_vfs_ctx_init() helper (fs/vfs_open.c); WebDAV and S3
    # GET now pass cache_root_canon into that one helper rather than assigning the
    # field inline. Assert each GET handler routes through the helper + still opens
    # read-only through the VFS and records cache access.
    _assert_markers(
        "src/protocols/webdav/get.c",
        [
            "fs/cache/open.h",
            "fs/vfs.h",
            # phase-79 split: get.c now works with a vctx pointer (vfs ctx is
            # heap/ctx-held rather than a stack local, so no & at the call).
            "brix_vfs_open(vctx, BRIX_VFS_O_READ",
            "brix_vfs_ctx_init(",
            "conf->cache_root_canon",
            "brix_cache_record_access(",
        ],
    )
    _assert_absent(
        "src/protocols/webdav/get.c",
        ["cache_path = cache_root_canon + (path - root_canon)"],
    )
    _assert_markers(
        "src/protocols/s3/object.c",
        [
            "fs/cache/open.h",
            "brix_vfs_ctx_init(",
            "cf->cache_root_canon",
        ],
    )
    # The single wiring point: brix_vfs_ctx_init() sets cache_root_canon (and
    # derives cache_enabled) for every HTTP caller.  phase-79 file-size split:
    # brix_vfs_ctx_init/adopt moved from vfs_open.c into vfs_open_adopt.c.
    _assert_markers(
        "src/fs/vfs/vfs_open_adopt.c",
        ["vctx->cache_root_canon = cache_root_canon"],
    )
    # Phase 12: the cache-hit detection and access-record calls moved out of the
    # per-protocol GET handlers into the shared file-serve pipeline. Both WebDAV
    # and S3 GET now record cache access via brix_http_serve_file_ranged().
    _assert_markers(
        "src/protocols/shared/file_serve.c",
        [
            "fs/cache/open.h",
            "brix_vfs_file_from_cache(",
            "brix_cache_record_access(",
        ],
    )
    # phase-79 split: the merge half (which canonicalises cache_root into
    # cache_root_canon) moved from module.c into module_merge.c.
    _assert_markers(
        "src/protocols/s3/module.c",
        ["brix_s3_cache_root"],
    )
    _assert_markers(
        "src/protocols/s3/module_merge.c",
        ["cache_root_canon"],
    )


def test_phase4_cache_metadata_and_eviction_guardrails():
    _assert_markers(
        "src/fs/cache/fetch.c",
        [
            "brix_cache_meta_from_stat(",
            "brix_cache_meta_write(",
        ],
    )
    _assert_markers(
        "src/fs/cache/open.c",
        [
            "brix_cache_validate_meta(",
            "O_NOFOLLOW",
            "brix_vfs_adopt_fd(",
        ],
    )
    _assert_markers(
        "src/fs/cache/evict_candidates.c",
        ['strcmp(name + name_len - suffix_len, ".meta")'],
    )
    _assert_markers(
        "src/fs/cache/evict_policy.c",
        ["brix_cache_meta_path(", "unlink(meta_path)"],
    )


def test_security_level_enforcement_is_linked():
    _assert_markers(
        "src/protocols/root/handshake/dispatch.c",
        ["brix_verify_pending_sigver(", "brix_signing_enforce_level("],
    )
    _assert_markers(
        "src/protocols/root/handshake/sigver.c",
        [
            "brix_signing_enforce_level(",
            "brix_sigver_opcode_requires(",
            "kXR_InvalidRequest",
        ],
    )


def test_new_shared_helpers_are_wired_into_module_config():
    for marker in (
        "src/core/compat/checksum.c",
        "src/core/compat/fs_walk.c",
        "src/core/http/http_body.c",
        "src/core/http/http_conditionals.c",
        "src/core/http/http_headers.c",
        "src/core/compat/hex.c",
        "src/core/compat/staged_file.c",
        "src/core/compat/time.c",
        "src/net/cms/frame_io.c",
    ):
        _assert_markers("config", [marker])


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
    _assert_markers(
        "src/protocols/root/read/pgread.c",
        [
            "brix_pgread_encode_pages(",
            # pgread uses the in-place 3-way CRC (zero-copy) rather than the
            # copy-while-summing variant the write path uses.
            "brix_crc32c_value(",
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
            "webdav_verify_proxy_cert(r, conf)",
            "webdav_verify_bearer_token(r, conf)",
            # 7de0b6d renamed webdav_check_token_write_scope → _scope
            # (now enforces READ and WRITE scope, not write-only).
            "webdav_check_token_scope(r, mname)",
            "webdav_metrics_return(r,",
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
            "webdav_metrics_return(r, webdav_proxy_handler(r))",
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
    # phase-79: protocol.c's sec-entry emission was refactored — the want_*
    # locals became fields of a want struct and the byte-by-byte entry writes
    # became the protocol_sec_entry_write() helper.
    _assert_markers(
        "src/protocols/root/session/protocol.c",
        [
            "want->unx",
            "want->krb5",
            'protocol_sec_entry_write(pe, "unix")',
            'protocol_sec_entry_write(pe, "krb5")',
        ],
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

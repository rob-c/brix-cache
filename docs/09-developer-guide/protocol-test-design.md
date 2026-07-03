# Protocol Conformance Test Design — root:// / cms:// / root+https (XrdHttp)

Goal: a thorough, gap-driven test suite proving BriX-Cache is a verified **drop-in for an official XRootD instance** across the three protocol surfaces, including in complex mesh networks. Generated from a 7-area protocol-surface + coverage map (see workflow `protocol-test-design`).

All proposed files are **self-contained** (provision their own nginx and, where needed, a reference xrootd / Python protocol peer) so they are immune to the shared-fleet churn; run each with `TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest <file> -v`.

## Implementation status (June 2026)

**All 12 P0 files are implemented and pass as a group: 170 passed / 6 skipped / 1 xfailed / 0 failed**, even with the background load test saturating the host (~200 nginx procs). Run the whole P0 set in one invocation with the fleet up:

```
TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest \
  tests/test_handshake_protocol_wire.py tests/test_session_lifecycle_wire.py \
  tests/test_pgread_wire_conformance.py tests/test_large_offset_wire.py \
  tests/test_open_flags_lifecycle.py tests/test_dropin_byte_for_byte.py \
  tests/test_xrdhttp_wait_retry_digest_range.py tests/test_webdav_delete_lock_security.py \
  tests/test_proxy_protocol_edges.py tests/test_cms_wire_pup_conformance.py \
  tests/test_cms_state_have_select.py tests/test_sigver_wire_conformance.py -q
```

**Self-contained port map** (de-conflicted so the suite runs as a whole — they originally 5-way-collided on 12950). Keep any new self-contained file clear of these:

| File | Ports |
|---|---|
| `test_proxy_protocol_edges` | 12950–12972 (reserved block) |
| `test_open_flags_lifecycle` | 12980 |
| `test_xrdhttp_wait_retry_digest_range` | 12988 |
| `test_dropin_byte_for_byte` | 12990, 12991 |
| `test_cms_wire_pup_conformance` | 12993, 12994, 12995 |
| `test_cms_state_have_select` | 12996, 12997, 12998 |
| `test_webdav_delete_lock_security` | 13210 |
| handshake / session / pgread / large_offset / sigver | shared fleet 11094 (no own ports) |

**Drop-in divergences the suite caught and fixed:**
- **Real product bug — kXR_pgread page alignment.** The encoder split pages from the read start instead of the absolute file offset, so an unaligned read emitted one full first page + 1 CRC where official XRootD emits a short first page (aligned) + 2 CRCs (`pgread(off=100,rlen=4096)`: official 4104 page-stream bytes vs old nginx 4100). Broke the pgRetry/AsyncPageReader contract. Fixed in `src/protocols/root/read/pgread.c::xrootd_pgread_encode_pages()` (now takes the file offset and caps the first page to the next 4096 boundary; sizing widened by the in-page offset) + the AIO path in `src/core/aio/reads.c`. Verified by `test_pgread_wire_conformance::test_sub_page_unaligned_first_page_crc` and `test_dropin_byte_for_byte::test_pgread_at_offset_page_stream_matches`.
- **Not a bug — POSC abort.** A POSC open that is written to but never cleanly closed (client drops the socket) leaves **no** final file and **no** `.xrd-tmp.` staging orphan: the server unlinks the staging temp ~0.02 s after the disconnect EOF (`on_disconnect → close_all_files → free_fhandle → unlink(file->path)`). The original `test_open_flags_lifecycle::test_posc_abort_leaves_no_final_file` failure was a test race (single check, no poll) — fixed by polling for the async teardown.

## Proposed test files (gap-driven)

### P0

#### `tests/test_session_lifecycle_wire.py` — root/root-session-auth

_Closes none/partial coverage on kXR_set (no dedicated test), kXR_endsess edge cases (wrong/missing sessid, post-endsess reuse, idempotency), and the pre-login opcode gate enforcement. All are drop-in fidelity gaps: a real xrootd client/redirector relies on exact gate semantics and login-required errors._

- test_kxr_set_before_login_rejected (login-gated per dispatch_session.c:140 — raw socket, expect kXR_error/NotAuthorized, NOT kXR_ok)
- test_kxr_set_unknown_option_returns_ok_or_error (whitelist behavior)
- test_kxr_set_after_login_ok
- test_endsess_wrong_sessid_rejected
- test_endsess_without_login_rejected
- test_endsess_then_request_on_same_conn_rejected (logged_in/auth_done cleared)
- test_endsess_idempotent_second_call
- test_kxr_bind_before_primary_login_behavior (special pre-login case)
- test_kxr_bind_random_sessid_rejected
- test_kxr_bind_pathid_zero_reserved
- test_pre_login_gate_each_mutating_opcode (open/read/write/stat/chmod/mkdir/rm/dirlist/sync/truncate/writev each → reject before login)
- test_pre_login_ping_then_invalid_opcode (ping ok, then unknown opcode rejected)
- test_legacy_opcode_below_3000_before_login


#### `tests/test_handshake_protocol_wire.py` — root/root-session-auth

_Handshake/kXR_protocol/kXR_login have full-marked coverage but the wire edge cases (bad magic, sub-5-byte body, secreqs trailer encoding, wantTLS-without-TLS error path, split framing, username NUL injection) are explicit gaps and are exactly what an official xrootd client probes during negotiation. Pure raw-wire; no client lib needed._

- test_handshake_bad_magic_fifth_not_2012_disconnect
- test_handshake_bad_fourth_not_4
- test_handshake_response_is_8byte_serverresponsebody_protocolversion_0x520_dataserver
- test_handshake_split_across_two_tcp_segments (slow-network framing)
- test_protocol_body_under_5_bytes_rejected
- test_protocol_secreqs_trailer_lists_advertised_methods
- test_protocol_wantTLS_on_nontls_port_returns_TLSRequired
- test_protocol_renegotiation_after_initial
- test_login_username_embedded_nul_rejected
- test_login_username_all_nul_padding
- test_login_pid_endianness_and_extremes_0_and_0xffffffff
- test_login_repeated_on_same_session


#### `tests/test_sigver_wire_conformance.py` — root/root-session-auth

_sigver replay/monotonicity is partial. Seqno boundary/wraparound, exact-replay, interleaving, and the token/anon no-op path are documented gaps. Request signing is a WLCG security-level requirement for drop-in parity; mis-handling UINT64_MAX or no-signing-key paths is a real crash/bypass risk._

- test_seqno_boundary_zero_and_one
- test_seqno_uint64_max_no_overflow_bypass
- test_exact_replay_identical_seqno_and_hmac_rejected
- test_large_seqno_jump_accepted
- test_interleaved_sigver_and_nonsigver_requests
- test_sigver_on_token_auth_no_signing_key_no_crash (signing_active=0 no-op)
- test_sigver_anonymous_accepted_but_not_verified
- test_expectrid_mismatch_rejected
- test_nodata_sig_flag_with_large_payload
- test_hmac_mismatch_specific_error


#### `tests/test_pgread_wire_conformance.py` — root/root-fileio

_pgread is marked full but the dedicated suite is thin (security-suite only). The kXR_status(4007) framing, per-page CRC32c, pgRetry flag, unaligned-first-page CRC, and EOF short-page are explicit drop-in gaps — xrdcp v5 integrity downloads depend on byte/CRC-exact parity with official xrootd. Pure raw-wire (client lib doesn't expose pgread framing)._

- test_pgread_status_4007_framing_32byte_overhead
- test_pgread_per_page_crc32c_matches_reference_crc
- test_pgread_subpage_unaligned_first_page_crc
- test_pgread_single_page_and_zero_length_rlen
- test_pgread_eof_short_final_page
- test_pgread_data_equals_plain_read_byte_exact
- test_pgread_pgRetry_flag_set_behavior
- test_pgread_rlen_capped_at_request_max
- test_pgread_slice_handle_rejected_kXR_Unsupported


#### `tests/test_open_flags_lifecycle.py` — root/root-fileio

_kXR_open flag matrix + POSC abort path + handle exhaustion + double-close are partial/gap items in both root-fileio and errors-edge-security. These are exact POSIX-semantics behaviors a real client expects; POSC abort and handle-table exhaustion are crash/leak risks. Self-contained nginx with low XROOTD_MAX_OPEN_FILES makes exhaustion deterministic._

- test_open_new_on_existing_returns_ItExists
- test_open_delete_truncates_to_zero
- test_open_apnd_appends
- test_open_mkpath_creates_parents
- test_open_retstat_returns_inline_stat (saves round-trip)
- test_open_refresh_cache_bypass
- test_invalid_flag_combo_apnd_plus_delete
- test_posc_graceful_close_persists
- test_posc_disconnect_abort_leaves_no_final_file
- test_handle_exhaustion_max_files_error_path
- test_close_double_close_rejected
- test_close_pending_aio_waits_or_cancels


#### `tests/test_large_offset_wire.py` — root/root-fileio

_64-bit offset handling is partial with many gaps (INT64_MAX, 4GB boundary, overflow, negative). 32-bit truncation at 4GB and offset+rlen overflow are classic regressions and drop-in correctness hazards on large HEP files. Raw-wire + sparse files keep this fast and self-contained (no multi-GB allocation)._

- test_write_then_read_at_4gb_boundary (sparse)
- test_offset_just_below_int64_max
- test_negative_offset_rejected_all_opcodes (read/readv/write/pgwrite/truncate)
- test_offset_plus_rlen_overflow_rejected
- test_stat_size_field_width_above_4gb
- test_truncate_to_large_sparse_offset
- test_readv_mixed_small_and_above_2gb_offsets


#### `tests/test_cms_wire_pup_conformance.py` — cms/cms-clustering

_The single most common CMS interop bug is Pup tagged-vs-bare confusion; login 4-string tail order, load bare-blob length, frame header, and streamid echo on avail are the exact wire seams that break against real cmsd. These are gaps in cms-clustering. Self-contained: a Python CMS peer (socket) drives nginx's CMS server listener / reads its client login — no real cmsd needed, robust to the churning fleet._

- test_login_4string_tail_order_SID_Paths_ifList_envCGI
- test_login_paths_reencoded_w_r_newline_format
- test_login_empty_string_encoded_00_00
- test_load_theLoad_is_bare_2byte_length_NOT_tagged_0x80
- test_load_dskFree_is_tagged_int
- test_pup_short_tag_0x80_int_tag_0xa0_roundtrip
- test_pup_mixed_scalars_and_strings_sequence
- test_frame_header_8byte_bigendian_streamid_code_modifier_dlen
- test_oversized_frame_over_4088_disconnects
- test_frame_fragmentation_across_recv_boundaries
- test_avail_echoes_streamid_from_space_query
- test_have_sets_CMS_MOD_RAW_and_HAVE_ONLINE


#### `tests/test_cms_state_have_select.py` — cms/cms-clustering

_On-demand selection (state/have) is the correctness core of real cmsd routing and is only partially covered; path-traversal/symlink-escape on state queries is a security gap (must NOT answer have for an escaping path). select/try malformed-payload parsing and streamid correlation are drop-in must-pass. Self-contained CMS peer._

- test_state_have_roundtrip_matching_streamid
- test_state_path_traversal_dotdot_rejected_before_stat
- test_state_symlink_escape_not_answered_with_have
- test_state_empty_or_missing_nul_terminator
- test_select_short_payload_missing_nul_handled
- test_select_port_is_bigendian_2byte
- test_select_unknown_streamid_silently_ignored
- test_try_multiple_entries_parsed_first_used
- test_try_malformed_entry_parser_stops_cleanly
- test_gone_empty_payload_behavior
- test_gone_before_login_ignored


#### `tests/test_xrdhttp_wait_retry_digest_range.py` — xrdhttp/xrdhttp-webdav

_X-Xrootd-Wait/Retry headers have NO tests, Digest-on-range/multipart and Want-Digest vs ?xrd.want.cksum conflict are gaps, and the PROPPATCH 207/200 client-compat behavior (rucio/Cyberduck) is a deliberate drop-in divergence that must be locked by a regression test. Self-contained nginx WebDAV (HTTP, no TLS needed) plus a rate-limit zone._

- test_x_xrootd_wait_header_emitted_under_ratelimit
- test_x_xrootd_retry_header_on_lock_contention
- test_digest_on_range_206_partial_body
- test_digest_on_multipart_byteranges
- test_want_digest_vs_xrd_want_cksum_conflict_resolution
- test_overlapping_multirange_merged_or_fullfile
- test_if_range_conditional (currently unimplemented — assert documented behavior)
- test_proppatch_returns_207_200_not_501 (client-compat stub)
- test_search_acl_stub_207


#### `tests/test_webdav_delete_lock_security.py` — xrdhttp/xrdhttp-webdav

_DELETE-on-collection (partial), UNLOCK owner/token validation, shared locks, lock-timeout cleanup, and CRLF injection (partial, no explicit test) are gaps. UNLOCK-by-different-owner and CRLF response-splitting are security-relevant; the 409-on-nonempty-DELETE is an intentional drop-in divergence to lock down. Self-contained HTTP WebDAV nginx._

- test_delete_nonempty_collection_returns_409 (documented non-RFC, lock behavior)
- test_unlock_by_different_owner_fails (RFC 4918 6.5)
- test_unlock_malformed_lock_token_400
- test_unlock_nonexistent_resource_409
- test_shared_lock_multiple_owners
- test_lock_timeout_expiry_lazy_cleanup
- test_crlf_injection_in_destination_header_rejected
- test_crlf_in_custom_x_header_sanitized
- test_cors_origin_reflection_no_crlf
- test_mkcol_with_body_rejected
- test_multilevel_mkcol_missing_intermediate_409


#### `tests/test_proxy_protocol_edges.py` — root/mesh-dropin

_Proxy handle-map saturation, kXR_wait retry exhaustion/large-payload, redirect hop-limit + handle invalidation, oksofar-interrupted-by-wait, and chmod-through-proxy (zero coverage) are partial/gap mesh items. These are the transparent-proxy seams that must behave like a real xrootd proxy. Self-contained: nginx proxy in front of a Python protocol stub (upstream_protocol_stubs.py pattern) that emits wait/redirect/oksofar deterministically — far more robust than the flaky shared fleet._

- test_handle_map_saturation_256_open_then_fail
- test_handle_reuse_after_close_distinct_upstream
- test_kxr_wait_retry_exhaustion_relayed_to_client_after_5
- test_kxr_wait_retry_large_payload_over_64k_not_saved
- test_kxr_redirect_hop_limit_3
- test_kxr_redirect_handle_invalid_on_new_upstream
- test_oksofar_streaming_dirlist_1000_entries_reassembled
- test_oksofar_interrupted_by_wait_midstream
- test_path_rewrite_dirlist_entry_names_returned_asis
- test_chmod_through_proxy (no coverage)
- test_endsess_midflight_pgwrite_cleanup


#### `tests/test_dropin_byte_for_byte.py` — root/mesh-dropin

_Drop-in/official-xrootd byte-for-byte parity is the headline goal and is the weakest area (no byte-for-byte test, v3-vs-v5 opcode subset untested). Cross-checks nginx vs an official xrootd on the same DATA_ROOT for stat/space/config/pgread/dirlist/error-family. Self-contained: provision both nginx and a reference xrootd (skip cleanly if xrootd binary absent), avoiding the shared fleet entirely._

- test_stat_ascii_format_field_order_matches_official (id size flags mtime)
- test_qspace_oss_fields_match_official
- test_qconfig_keys_match_official
- test_pgread_crc_pages_match_official_byte_exact
- test_dirlist_names_match_official
- test_error_family_matches_official_for_enoent_eacces_eisdir
- test_v3_client_sends_v5only_opcode_clone_returns_Unsupported
- test_v3_negotiation_response_format

### P1

#### `tests/test_sss_auth_wire.py` — root/root-session-auth

_SSS is partial with only incidental conformance coverage; the challenge/response round-trip, key rotation, and empty-secret rejection are untested. SSS is a primary cluster/intra-site auth mode for xrootd drop-in. Self-contained nginx with a fixed sss keytab makes this robust to the flaky shared fleet._

- test_sss_challenge_response_roundtrip (kXR_auth sss → kXR_authmore challenge → second kXR_auth HMAC → auth_done)
- test_sss_wrong_secret_rejected_NotAuthorized
- test_sss_empty_secret_rejected
- test_sss_partial_challenge_then_valid_request_survives
- test_sss_multiple_preconfigured_secrets_rotation
- test_sss_concurrent_auth_isolation


#### `tests/test_unix_krb5_auth_wire.py` — root/root-session-auth

_Unix auth is partial and krb5 auth has NONE coverage (zero tests). krb5/auth.c + krb5/config.c exist but are entirely untested — a drop-in replacement claiming krb5 support must at least prove advertisement + malformed-token safety. Self-contained server with a generated keytab (skip if krb5 libs/keytab absent)._

- test_unix_self_asserted_uid_gid_accepted_on_trusted_port
- test_unix_uid_for_missing_local_user_rejected
- test_unix_root_uid_zero_policy
- test_unix_negative_uid_handling
- test_krb5_advertised_when_keytab_configured (kXR_protocol secreqs lists krb5)
- test_krb5_malformed_token_rejected_not_crash
- test_krb5_missing_keytab_skips (config guard)


#### `tests/test_chkpoint_clone_wire.py` — root/root-fileio

_kXR_chkpoint is partial and kXR_clone is NONE in errors-edge-security. The ckp* opcode/subcode interpreter (begin/commit/query/rollback/xeq) and clone range copy have no rigorous wire tests; query response byte-format and the 100MiB limit are drop-in conformance points. Self-contained, sparse, fast._

- test_ckpQuery_response_format_maxsize_usesize_8bytes
- test_ckpBegin_then_write_then_commit_persists
- test_ckpRollback_restores_pre_checkpoint_state
- test_ckpRollback_without_active_checkpoint_errors
- test_ckpBegin_exceed_100MiB_limit_error
- test_ckpXeq_write_suboperation
- test_clone_range_copy_basic
- test_clone_range_beyond_eof_error
- test_clone_negative_offset_length_rejected


#### `tests/test_dirlist_wire_conformance.py` — root/root-namespace-meta

_dirlist is full but 64KB oksofar chunk-boundary, dcksm, and unsafe-filename skipping are explicit gaps. Frame-boundary correctness at exactly 65536 bytes is a known fragile seam (handler.c chunk_cap) and a drop-in conformance must-pass. Raw-wire to read oksofar/ok frames; self-contained with crafted dir tree._

- test_dirlist_chunk_boundary_exactly_65536 (oksofar frame split per handler.c:68)
- test_dirlist_just_over_and_under_64k
- test_dcksm_per_entry_checksum_present
- test_dcksm_with_disabled_algorithm_behavior
- test_unsafe_filename_control_char_skipped_silently
- test_unsafe_filename_embedded_DEL_0x7f
- test_dstat_inline_sizes_match_individual_stat
- test_dirlist_on_file_is_error
- test_dirlist_empty_dir_single_ok_frame


#### `tests/test_statx_qprep_wire.py` — root/root-namespace-meta

_statx coverage relies on the client lib which lacks statx (env constraint) — only raw-wire can exercise it; multi-path mixed success, delimiter handling and no-symlink-follow are gaps. QPrep is partial with only implicit coverage. Both are drop-in metadata behaviors. Self-contained._

- test_statx_multi_path_response_lines (raw wire — client lib lacks statx)
- test_statx_mixed_success_and_error_per_path
- test_statx_nul_vs_newline_delimiter
- test_statx_does_not_follow_symlink
- test_statx_per_path_auth_across_vo_boundaries
- test_qprep_status_A_available_M_missing_lines
- test_qprep_request_id_handling
- test_qprep_fallback_to_stored_prepare_paths


#### `tests/test_namespace_modebits_wire.py` — root/root-namespace-meta

_Mode-bit masking (mkdir/chmod), kXR_mv 0x20-separator/arg1len wire parsing, rm EISDIR retry, rmdir idempotency, and Qckscan cancel/symlink-loop are gaps across namespace items. The mv separator parse and chmod type-bit stripping are precise wire behaviors a drop-in must match. Self-contained raw-wire._

- test_mkdir_mode_0777_0755_0644_masking
- test_mkdir_default_0755_when_client_sends_zero
- test_chmod_default_0644_when_zero
- test_chmod_strips_file_type_bits_S_IFREG
- test_mv_separator_must_be_0x20_reject_0x00_0x09
- test_mv_arg1len_exceeds_payload_rejected
- test_mv_overwrite_existing_dst
- test_rm_eisdir_recursive_retry
- test_rmdir_enotempty_error_enoent_idempotent_success
- test_qckscan_cancel_flag
- test_qckscan_symlink_loop_no_hang


#### `tests/test_cms_status_xauth_backoff.py` — cms/cms-clustering

_kYR_status SUSPEND/RESUME reception is partial (server_recv is a no-op dispatcher), xauth SSS cluster-auth is partial (no keytab test), backoff and CIDR allowlist are partial. Suspend/resume drives whether nginx is selectable in a cluster — a drop-in correctness gap. Self-contained: drive status/xauth frames from a Python CMS peer and assert client-facing redirect behavior._

- test_status_RESUME_clears_cms_suspended_unblocks_clients
- test_status_SUSPEND_blocks_new_logins_redirects
- test_status_combined_RESUME_NOSTAGE_STAGE_bits
- test_xauth_sss_login_parms_challenge_verify_register_sequence
- test_xauth_invalid_credential_closes_connection
- test_xauth_out_of_order_before_login
- test_reconnect_backoff_doubles_6_12_24_capped
- test_backoff_reset_on_successful_reconnect
- test_cms_server_allow_cidr_in_range_allowed_out_rejected


#### `tests/test_xrdhttp_status_mapping_conformance.py` — xrdhttp/xrdhttp-webdav

_X-Xrootd-Status mapping table is the XrdHttp drop-in contract; edge HTTP codes, server-generated requuid, and 63-byte truncation are gaps. A WLCG client switching from official XrdHttp to nginx relies on identical kXR codes in headers. Self-contained; optional official-XrdHttp cross-check when libXrdHttp present (skip otherwise)._

- test_x_xrootd_status_kxr_code_for_each_http_status (200/404/403/409/412/416/423/500/501)
- test_x_xrootd_proto_echoed
- test_requuid_server_generated_when_absent
- test_requuid_truncated_to_63_bytes
- test_xrd_stats_xml_wellformed_and_unauthenticated
- test_status_mapping_against_official_xrdhttp_if_available (cross-check)


#### `tests/test_multihop_mesh_dropin.py` — root/mesh-dropin

_3+ hop chains, mixed proxy→cache→storage, asymmetric-auth chains, and credential-bridge propagation through a second hop are the systematically-untested mesh topology gaps and central to 'complex mesh' drop-in fidelity. Self-contained: stack 3 nginx instances + storage in a module fixture (reuses readonly_http provisioning pattern); skip if memory-constrained._

- test_3hop_proxy_chain_read_byte_exact
- test_3hop_handle_translation_cascades
- test_proxy_to_cache_to_storage_read
- test_asymmetric_auth_chain_anon_then_token
- test_credential_bridge_gsi_to_token_propagates_through_proxy2
- test_proxy_chain_plus_mirror_no_divergence
- test_redirect_across_chain_followed


#### `tests/test_errno_mapping_matrix.py` — root/errors-edge-security

_errno→kXR→HTTP mapping is full but lacks per-value and cross-protocol-consistency tests; EXDEV/ELOOP→403 and NS-status→HTTP are precise drop-in contracts. A single mapping table drives both protocols, so a matrix test guards regressions cheaply. Self-contained: craft files/paths that deterministically trigger each errno on a private nginx._

- test_each_errno_to_kxr_code (ENOENT/EACCES/EPERM/EXDEV/ELOOP/ENOTEMPTY/EEXIST/ENOTDIR/ENOMEM/ENOSPC/EINVAL)
- test_each_errno_to_http_status (404/403/507/409/414/500)
- test_cross_protocol_same_errno_same_http_status_webdav_vs_s3
- test_exdev_eloop_map_to_403_not_500 (kernel-confinement)
- test_ns_status_to_http_mkdir_rmdir_mv_rm
- test_enametoolong_414


#### `tests/test_tls_gototls_buffer.py` — root/errors-edge-security

_gotoTLS buffer ordering, handshake timeout recovery, streamid preservation across upgrade, and the ERR_clear_error regression are partial/gap security-critical items. Sending cleartext after gotoTLS but before ClientHello is a real buffer-corruption/security boundary. Self-contained nginx on a TLS-capable port with a generated host cert; skip if cert unavailable._

- test_data_sent_before_clienthello_after_gototls (cleartext-vs-tls buffer rule)
- test_tls_handshake_timeout_connection_recovery
- test_tls_handshake_failure_disconnects_cleanly
- test_streamid_preserved_across_tls_upgrade
- test_no_weak_ciphers_sslv3_rc4_des_negotiable
- test_err_clear_error_no_spurious_unknown_ca (Phase 33 fix regression)


## Coverage matrix

| Protocol | Area | Sub-surface | Current coverage | Proposed new file(s) | Resulting coverage |
|---|---|---|---|---|---|
| root | session-auth | kXR_set | none | test_session_lifecycle_wire.py | full |
| root | session-auth | kXR_endsess edge | partial | test_session_lifecycle_wire.py | full |
| root | session-auth | pre-login gate | partial | test_session_lifecycle_wire.py | full |
| root | session-auth | handshake/protocol/login wire edges | full (gaps) | test_handshake_protocol_wire.py | full+edges |
| root | session-auth | kXR_sigver replay/boundary | partial | test_sigver_wire_conformance.py | full |
| root | session-auth | SSS challenge/response | partial | test_sss_auth_wire.py | full |
| root | session-auth | Unix auth | partial | test_unix_krb5_auth_wire.py | full |
| root | session-auth | Kerberos 5 | **none** | test_unix_krb5_auth_wire.py | partial (advertise+safety) |
| root | session-auth | kXR_bind edges | partial | test_session_lifecycle_wire.py | partial→full |
| root | fileio | kXR_pgread framing/CRC/flags | full (thin) | test_pgread_wire_conformance.py | full |
| root | fileio | kXR_open flag matrix + POSC | full/partial | test_open_flags_lifecycle.py | full |
| root | fileio | handle exhaustion / double-close | partial | test_open_flags_lifecycle.py | full |
| root | fileio | 64-bit offsets / overflow | partial | test_large_offset_wire.py | full |
| root | fileio | kXR_chkpoint | partial | test_chkpoint_clone_wire.py | full |
| root | fileio | kXR_clone | **none** | test_chkpoint_clone_wire.py | partial→full |
| root | namespace-meta | dirlist 64k chunk / dcksm / unsafe names | full (gaps) | test_dirlist_wire_conformance.py | full |
| root | namespace-meta | statx (no client-lib support) | full (gaps) | test_statx_qprep_wire.py | full |
| root | namespace-meta | QPrep | partial | test_statx_qprep_wire.py | full |
| root | namespace-meta | mode bits / mv parse / Qckscan | full/partial | test_namespace_modebits_wire.py | full |
| cms | clustering | Pup encoding / frame / login tail | full (gaps) | test_cms_wire_pup_conformance.py | full |
| cms | clustering | state/have, select/try parsing | partial | test_cms_state_have_select.py | full |
| cms | clustering | status SUSPEND/RESUME, xauth, backoff, CIDR | partial | test_cms_status_xauth_backoff.py | full |
| xrdhttp | webdav | X-Xrootd-Wait/Retry, Digest-on-range | **none/partial** | test_xrdhttp_wait_retry_digest_range.py | full |
| xrdhttp | webdav | DELETE-coll / UNLOCK owner / CRLF / locks | partial | test_webdav_delete_lock_security.py | full |
| xrdhttp | webdav | X-Xrootd-Status mapping / requuid gen | full (gaps) | test_xrdhttp_status_mapping_conformance.py | full |
| root | mesh-dropin | handle-map / wait-retry / redirect / oksofar / proxy-chmod | partial/gap | test_proxy_protocol_edges.py | full |
| root | mesh-dropin | byte-for-byte vs official xrootd, v3/v5 subset | **none/partial** | test_dropin_byte_for_byte.py | full |
| root | mesh-dropin | 3+ hop / proxy→cache / asymmetric auth / bridge | partial | test_multihop_mesh_dropin.py | partial→full |
| root | errors-edge | errno→kXR→HTTP per-value + cross-protocol | full (gaps) | test_errno_mapping_matrix.py | full |
| root | errors-edge | gotoTLS buffer / handshake timeout / ciphers | partial | test_tls_gototls_buffer.py | full |

## P0 rationale (drop-in priority order)

Ordered P0 list (highest drop-in value first), with rationale:

1. test_dropin_byte_for_byte.py (mesh-dropin) — This is THE headline goal: verified drop-in for official XRootD. It is the single weakest area (no byte-for-byte parity test exists, v3-vs-v5 opcode subset untested). It cross-checks nginx vs a real xrootd on the same DATA_ROOT for stat ASCII format, Qspace/Qconfig fields, pgread CRC pages, dirlist names, and error families. Everything else is moot if the wire bytes diverge from the reference. Self-contained (provisions both daemons, skips if xrootd absent), so it sidesteps the flaky fleet.

2. test_cms_wire_pup_conformance.py (cms) — Pup tagged-vs-bare confusion is explicitly the most common CMS interop bug; login 4-string tail order and load bare-blob length are the historic desync vectors against real cmsd. Without correct CMS framing, nginx cannot act as a cluster manager/data-node drop-in at all. Self-contained Python CMS peer is robust to fleet churn.

3. test_cms_state_have_select.py (cms) — On-demand selection (state/have) is the correctness core of real cmsd routing; answering 'have' for a path-traversal/symlink-escaping path is a security defect, and select/try streamid correlation governs whether redirects reach the client. Drop-in routing fidelity depends on it.

4. test_pgread_wire_conformance.py (root fileio) — kXR_status(4007) framing + per-page CRC32c is the v5 integrity-download contract used by every modern xrdcp; CRC/byte parity with official xrootd is non-negotiable for drop-in. Dedicated suite is currently thin.

5. test_handshake_protocol_wire.py (root session) — The handshake/protocol/login negotiation is the first thing any official client does; bad-magic disconnect, sub-5-byte body, secreqs trailer, wantTLS-without-TLS error, and username NUL injection are the exact probes a real client/redirector performs.

6. test_session_lifecycle_wire.py (root session) — kXR_set has zero coverage and is login-gated in product code (dispatch_session.c:140); endsess edge cases and the pre-login gate are correctness/security seams a real client exercises on every connection.

7. test_sigver_wire_conformance.py (root session) — Request signing is a WLCG security-level requirement; UINT64_MAX seqno wraparound and the no-signing-key (token/anon) no-op path are real bypass/crash risks and drop-in parity points.

8. test_open_flags_lifecycle.py (root fileio) — The kXR_open flag matrix, POSC abort path, and handle-table exhaustion / double-close are POSIX-semantics + leak/crash hazards every client depends on; deterministic with a low max-files self-contained server.

9. test_large_offset_wire.py (root fileio) — 4GB/INT64_MAX boundaries and offset+rlen overflow are classic 32-bit-truncation regressions on the large HEP files this product exists to serve.

10. test_proxy_protocol_edges.py (mesh) — Handle-map saturation, kXR_wait retry exhaustion/large-payload, redirect hop-limit + stale-handle, oksofar-interrupted-by-wait, and proxy chmod (zero coverage) are the transparent-proxy seams that must match a real xrootd proxy; a Python protocol stub makes them deterministic and fleet-independent.

11. test_xrdhttp_wait_retry_digest_range.py (xrdhttp) — X-Xrootd-Wait/Retry have no tests; the PROPPATCH 207/200 client-compat stub is a deliberate drop-in divergence (rucio/Cyberduck) that must be regression-locked.

12. test_webdav_delete_lock_security.py (xrdhttp) — UNLOCK-by-different-owner, CRLF response-splitting, and the intentional 409-on-nonempty-DELETE divergence are security-relevant + drop-in contract points.

Why P0 over P1: every P0 either (a) directly proves wire parity with official XRootD/cmsd, (b) closes a zero-coverage opcode/header on the critical path, or (c) guards a crash/bypass/leak. P1 items (SSS/Unix/krb5, chkpoint/clone, dirlist-chunk, statx, mode-bits, status/xauth/backoff, status-mapping, multihop, errno-matrix, gotoTLS-buffer) are valuable conformance/security depth but are either less-used auth modes, secondary opcodes, or extensions of already-tested surfaces.

## Environment notes

ENV CONSTRAINTS HONORED:
- Self-contained preferred: 18 of the proposed files provision their own nginx (and, where needed, a reference xrootd or a Python protocol/CMS peer) via tempfile.mkdtemp + a generated nginx.conf + Popen, following the canonical pattern in tests/test_readonly_http_endpoint.py (fixture: _free_port, _wait_port, nginx -t validate-then-skip, module-scoped teardown). This makes them immune to the background load test that churns/OOMs the shared fleet (load_test.py / run_load_test.sh now uses ports 12790-12799 per memory load_test_perf_and_bottlenecks). Use _free_port() not fixed ports to avoid collisions with the running fleet/load test.
- TEST_SKIP_SERVER_SETUP=1: All self-contained files run cleanly under TEST_SKIP_SERVER_SETUP=1 because conftest.pytest_sessionstart returns early and they never touch manage_test_servers.sh. Recommend documenting `TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_<new>.py -v` in each file header (matches existing convention).
- Python XRootD client lacks statx: test_statx_qprep_wire.py and all framing-level tests (pgread, sigver, dirlist oksofar, CMS Pup) are RAW-WIRE over sockets using the struct.pack helpers established in test_wire_protocol_security.py (_handshake/_login/_read_response 8-byte '!2sHI' header). Do NOT route these through XRootD.client — confirmed XRootD client is importable (miniconda site-packages) but exposes no statx and sanitizes offsets before the wire, hiding the bugs under test.
- Host churn / OOM: Avoid multi-GB allocations — test_large_offset_wire.py uses sparse files (truncate/seek+single byte) so 4GB/INT64_MAX boundaries cost ~kilobytes of disk and no RAM. Mesh stacks (test_multihop_mesh_dropin.py) are module-scoped and tear down promptly; mark memory-heavy ones to skip when a churn/OOM signal is present.
- Reference-xrootd cross-checks (test_dropin_byte_for_byte, optional XrdHttp mapping cross-check) must shutil.which('xrootd')/('cmsd') and pytest.skip cleanly when absent (mirrors cms_mesh_lib.have_binaries()). For GSI/krb5/SSS files, generate the keytab/secret in-fixture and skip if crypto libs/binaries are missing.

REAL PRODUCT-BEHAVIOR FINDINGS WORTH A FOLLOW-UP (verified against source, not assumptions):
- kXR_set IS login-gated in product code (src/protocols/root/handshake/dispatch_session.c:140 calls require-login before xrootd_handle_set) but has ZERO tests — a behavioral contract currently unguarded. Worth confirming whether unknown options return kXR_ok (advisory) or error, since the inventory marks the whitelist 'TBD'.
- krb5 auth (src/auth/krb5/auth.c, src/auth/krb5/config.c) exists and is compile-guarded (XROOTD_HAVE_KRB5; XROOTD_AUTH_KRB5 is the runtime auth-mode enum value) but has NO tests at all — a drop-in claiming krb5 support is presently unverified end-to-end; even an advertise + malformed-token-safety test would be a meaningful first guard. Follow-up: decide if krb5 is a supported drop-in mode or should be documented as experimental.
- dirlist chunking uses a 65536-byte accumulator (src/protocols/root/dirlist/handler.c:68 chunk_cap, flushed as kXR_oksofar) — the exactly-at-64KB frame boundary is a fragile, untested seam; recommend the boundary scenario as a regression anchor.
- The inventory's test_wire_protocol_security.py defines kXR_pgread incorrectly (3026+1=3027 which is actually kXR_locate, then reassigns 3029 'for invalid opcode tests'); new pgread tests must use the real opcode kXR_pgread=3030 (and kXR_pgwrite=3026) — do not copy the stale constant from that file.
- PROPPATCH intentionally returns 207+200 (not 501) to avoid breaking rucio/Cyberduck; this is a deliberate divergence from official XrdHttp and should be locked by a regression test so a future 'correctness' refactor doesn't reintroduce the client-hang.
- EXDEV/ELOOP map to kXR_NotAuthorized / HTTP 403 (kernel-enforced confinement via openat2 RESOLVE_BENEATH), not 500 — a precise mapping a drop-in must preserve; matrix test guards it.
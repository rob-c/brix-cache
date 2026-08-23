def _check_alice_put(data, port, token):
    status, _ = http("PUT", "/alice/hello.txt", port, token, b"hi from alice\n")
    ok(status in (200, 201, 204), f"alice PUT accepted (HTTP {status})")
    path = os.path.join(data, "alice", "hello.txt")
    stat = os.stat(path) if os.path.exists(path) else None
    owned = stat is not None and stat.st_uid == UID_ALICE and stat.st_gid == UID_ALICE
    ok(owned, "alice's file owned by the MAPPED user (1001:1001), not worker/root")


def _check_bob_put(data, port, token):
    status, _ = http("PUT", "/bob/b.txt", port, token, b"bob\n")
    path = os.path.join(data, "bob", "b.txt")
    stat = os.stat(path) if os.path.exists(path) else None
    owned = stat is not None and stat.st_uid == UID_BOB
    ok(status in (200, 201, 204) and owned, "bob's file owned by bob (1002)")


def _check_baseline_reads(port, token):
    status, body = http("GET", "/alice/hello.txt", port, token)
    ok(status == 200 and body == b"hi from alice\n", "alice GET own file")
    status, _ = http("GET", "/bobsecret/s.txt", port, token)
    ok(status in (403, 404, 401), f"alice DENIED reading bob's 0700 file (HTTP {status})")


def _baseline_identity(key, data, port, tok_alice, tok_bob):
    _check_alice_put(data, port, tok_alice)
    _check_bob_put(data, port, tok_bob)
    _check_baseline_reads(port, tok_alice)


def _escalation_denied(key, data, port, subject, label):
    token = mint(key, subject)
    status, _ = http("PUT", f"/pub/{subject}_evil.txt", port, token, b"escalate\n")
    path = os.path.join(data, "pub", f"{subject}_evil.txt")
    created = os.path.exists(path)
    bad_owner = created and os.stat(path).st_uid < 1000
    denied = status not in (200, 201, 204) and not created and not bad_owner
    ok(denied, f"{label} -> DENIED (HTTP {status}, file_created={created})")


def _check_escalation_guards(key, data, port):
    cases = (
        ("root", "escalate to root (uid 0)"),
        ("sys100", "escalate to sys uid 100 (< floor)"),
        ("svc", "impersonate the worker/service account (uid 1500)"),
        ("dockerite", "member of forbidden 'docker' group (gid 1600)"),
        ("mallory", "unmapped principal"),
    )
    for subject, label in cases:
        _escalation_denied(key, data, port, subject, label)


def _check_confinement(data, port, token):
    status, body = http("GET", "/escape/passwd", port, token)
    leaked = status == 200 and b"root:x:0:0" in body
    ok(not leaked, f"symlink escape /escape/passwd blocked (HTTP {status})")
    sentinel = os.path.join(os.path.dirname(data), "OUTSIDE")
    http("PUT", "/../OUTSIDE", port, token, b"x\n")
    http("PUT", "/%2e%2e/OUTSIDE", port, token, b"x\n")
    ok(not os.path.exists(sentinel), "path-traversal PUT did not escape the export root")


def _start_s3_checks(key, data, s3port):
    available = wait_port(s3port, 5)
    if not available:
        ok(False, "S3 server did not come up on its port")
        return False
    run_s3(data, s3port)
    run_s3_sigv4_errors(key, data, s3port)
    run_s3_extended(key, data, s3port)
    return True


def _run_protocol_checks(key, data, port, s3port, s3_available):
    active_s3_port = s3port if s3_available else 0
    run_root_battery(key, data)
    run_cross_tenant_read(key, data, port, active_s3_port)
    run_cross_tenant_write(key, data, port, active_s3_port)
    run_create_ownership(key, data, port, active_s3_port)
    run_recursive_propfind(key, data, port)
    run_confinement_extended(key, data, port, active_s3_port)
    run_token_principal_attacks(key, data, port)
    run_webdav_methods(key, data, port)
    run_webdav_errors(key, data, port)
    run_cross_cutting(key, data, port, active_s3_port)
    run_auth_matrix(key, data, port)
    run_root_deep(key, data, port)
    if s3_available:
        run_s3_deep(key, data, s3port)
    run_traversal_matrix(key, data, port, active_s3_port)


def _deep_batches():
    return (run_root_protocol_depth, run_webdav_method_state,
                run_s3_multipart_adversarial, run_concurrency_state_race,
                run_broker_resource_limits, run_confine_encoding_exhaustive,
                run_crossproto_ownership_invariant, run_malformed_hostile_inputs,
                run_auth_scheme_confusion,
                run_http_protocol_abuse, run_s3_presigned,
                run_crossproto_chmod_chains, run_samefile_contention,
                run_group_read_dac, run_group_write_dac, run_permission_matrix,
                run_group_dir_dac, run_setgid_inheritance, run_sticky_bit_dac, run_mixed_owner_trees, run_multiuser_party, run_chown_chgrp_dac, run_manygroups_dac, run_boundary_mapping, run_group_concurrency, run_group_xattr_lock, run_group_traversal_depth,
                run_stream_extended_ops, run_native_tpc, run_dataplane_integrity, run_connection_errors, run_protocol_features_s3, run_protocol_features_webdav,
                run_combo_setgid_via_copymove, run_combo_symlink_crossproto_toctou, run_combo_multipart_lock_identity, run_combo_authfail_resource_state, run_combo_broker_pressure, run_combo_encoding_group_targets, run_combo_concurrent_crossproto, run_combo_xattr_namespace_group, run_combo_idmap_edge_full_matrix, run_combo_rare_opcodes, run_combo_connection_state_identity, run_combo_error_rollback,
                run_s3_subresource_fallthrough, run_s3_post_form_and_bucketops, run_webdav_undispatched_methods, run_webdav_property_exotic, run_http_smuggling_desync_deep, run_conditional_header_matrix, run_content_negotiation_ranges, run_frm_prepare_stage, run_broker_internals_stress, run_resource_dos_limits, run_raw_kxr_wire, run_header_injection_matrix, run_tpc_pull_push_matrix, run_multistep_lifecycle_invariants,
                run_http_tpc_webdav, run_checksum_digest_oracle, run_raw_kxr_deep, run_query_subcode_oracle, run_scoped_token_dac_matrix, run_special_file_rename_matrix, run_broker_dos_resilience, run_deep_novel_combos_r8,
                run_s3_conditional_impersonation, run_s3_checksum_verify_impersonation, run_s3_acl_tagging_dac, run_compression_impersonation, run_raw_kxr_authed, run_phase_features_combos)


def _guard_batch(function, args, data):
    import traceback

    _reset_fixtures(data)
    try:
        function(*args)
    except Exception as error:  # noqa: BLE001
        traceback.print_exc()
        ok(False, f"{function.__name__} raised an exception: {error!r}")


def _run_deep_batches(key, data, port, s3port):
    args = (key, data, port, s3port)
    for function in _deep_batches():
        _guard_batch(function, args, data)


def _owner_case(index, token_alice, token_bob):
    identities = (
        ("alice", token_alice, UID_ALICE),
        ("bob", token_bob, UID_BOB),
    )
    subject, token, uid = identities[index % 2]
    return subject, token, uid, f"c_{subject}_{index}.txt"


def _owner_worker(index, data, port, token_alice, token_bob, results):
    subject, token, uid, name = _owner_case(index, token_alice, token_bob)
    http("PUT", f"/{subject}/{name}", port, token, f"{subject}{index}\n".encode())
    results[index] = (subject, name, uid)


def _owner_mismatch(data, result):
    subject, name, expected_uid = result
    path = os.path.join(data, subject, name)
    return not os.path.exists(path) or os.stat(path).st_uid != expected_uid


def _start_threads(threads):
    for thread in threads:
        thread.start()


def _join_threads(threads):
    for thread in threads:
        thread.join()


def _run_owner_concurrency(data, port, token_alice, token_bob):
    count = 24
    results = {}
    worker_args = (data, port, token_alice, token_bob, results)
    threads = [
        threading.Thread(target=_owner_worker, args=(index, *worker_args))
        for index in range(count)
    ]
    _start_threads(threads)
    _join_threads(threads)
    leaks = sum(_owner_mismatch(data, results[index]) for index in range(count))
    ok(leaks == 0, f"interleaved alice/bob ({count} concurrent PUTs): every file "
       f"correct owner (no setfsuid leak); mismatches={leaks}")


def _check_identity_summary(data):
    path = os.path.join(data, "alice", "hello.txt")
    uid = os.stat(path).st_uid if os.path.exists(path) else -1
    valid = uid == UID_ALICE and uid != UID_SVC and uid != 0
    ok(valid, "no worker/broker identity leaks into created-file ownership")


def run_battery(key, data, port, s3port, sock):
    token_alice = mint(key, "alice")
    token_bob = mint(key, "bob")
    _baseline_identity(key, data, port, token_alice, token_bob)
    _check_escalation_guards(key, data, port)
    _check_confinement(data, port, token_alice)
    run_namespace_ops(key, data, port)
    run_dirlist_confidentiality(key, data, port)
    run_lock_proppatch(key, data, port)
    s3_available = _start_s3_checks(key, data, s3port)
    _run_protocol_checks(key, data, port, s3port, s3_available)
    active_s3_port = s3port if s3_available else 0
    _run_deep_batches(key, data, port, active_s3_port)
    _run_owner_concurrency(data, port, token_alice, token_bob)
    run_mixed_concurrency(key, data, port, active_s3_port)
    _check_identity_summary(data)
    run_broker_failclosed(key, data, port, active_s3_port, sock, token_alice)


def _namespace_mkcol(data, port, token):
    status, _ = http("MKCOL", "/alice/ndir", port, token)
    path = os.path.join(data, "alice", "ndir")
    owned = os.path.isdir(path) and os.stat(path).st_uid == UID_ALICE
    ok(status in (201, 200) and owned,
       f"MKCOL: new dir owned by mapped user alice (HTTP {status})")


def _namespace_mkcol_denied(data, port, token):
    status, _ = http("MKCOL", "/bobsecret/evil", port, token)
    missing = not os.path.exists(os.path.join(data, "bobsecret", "evil"))
    ok(status not in (200, 201) and missing,
       f"MKCOL inside bob's 0700 dir -> denied (HTTP {status})")


def _namespace_move(data, port, token):
    http("PUT", "/alice/mv_src.txt", port, token, b"movable\n")
    status, _ = http("MOVE", "/alice/mv_src.txt", port, token,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/mv_dst.txt"})
    destination = os.path.join(data, "alice", "mv_dst.txt")
    source = os.path.join(data, "alice", "mv_src.txt")
    owned = os.path.exists(destination) and os.stat(destination).st_uid == UID_ALICE
    ok(status in (201, 204) and owned and not os.path.exists(source),
       f"MOVE: dest owned by alice, src gone (HTTP {status})")


def _namespace_copy(data, port, token):
    status, _ = http("COPY", "/alice/mv_dst.txt", port, token,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/cp_dst.txt"})
    path = os.path.join(data, "alice", "cp_dst.txt")
    owned = os.path.exists(path) and os.stat(path).st_uid == UID_ALICE
    ok(status in (201, 204) and owned,
       f"COPY: dest owned by alice (HTTP {status})")


def _namespace_delete(data, port, token):
    status, _ = http("DELETE", "/alice/cp_dst.txt", port, token)
    path = os.path.join(data, "alice", "cp_dst.txt")
    ok(status in (200, 204) and not os.path.exists(path),
       f"DELETE as alice (HTTP {status})")


def run_namespace_ops(key, data, port):
    """Exercise namespace mutations as the mapped user."""
    token = mint(key, "alice")
    _namespace_mkcol(data, port, token)
    _namespace_mkcol_denied(data, port, token)
    _namespace_move(data, port, token)
    _namespace_copy(data, port, token)
    _namespace_delete(data, port, token)


def _propfind_private(port, token):
    status, body = http("PROPFIND", "/svconly/", port, token,
                    data=b'<?xml version="1.0"?><propfind xmlns="DAV:">'
                         b'<prop><displayname/></prop></propfind>',
                    hdrs={"Depth": "1", "Content-Type": "application/xml"})
    leaked = status in (200, 207) and b"secret-name.txt" in (body or b"")
    ok(not leaked, "PROPFIND of a dir alice cannot read does NOT leak its "
       f"entries (HTTP {status}, leaked={leaked})")


def _propfind_own(port, token):
    status, _ = http("PROPFIND", "/alice/", port, token,
                    data=b'<?xml version="1.0"?><propfind xmlns="DAV:">'
                         b'<prop><displayname/></prop></propfind>',
                    hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(status in (200, 207), f"PROPFIND of alice's own dir works (HTTP {status})")


def _search_body():
    return (
        b'<?xml version="1.0"?>'
        b'<D:searchrequest xmlns:D="DAV:"><D:basicsearch>'
        b'<D:select><D:prop><D:displayname/></D:prop></D:select>'
        b'<D:from><D:scope><D:href>/svconly/</D:href>'
        b'<D:depth>1</D:depth></D:scope></D:from>'
        b'</D:basicsearch></D:searchrequest>'
    )


def _search_private(port, token, search_body):
    status, body = http("SEARCH", "/svconly/", port, token,
                    data=search_body,
                    hdrs={"Content-Type": "application/xml"})
    leaked = status in (200, 207) and b"secret-name.txt" in (body or b"")
    ok(not leaked, "SEARCH of a dir alice cannot read does NOT leak its entries "
       f"(HTTP {status}, leaked={leaked})")


def _search_own(port, token, search_body):
    search_own = search_body.replace(b"/svconly/", b"/alice/")
    status, body = http("SEARCH", "/alice/", port, token,
                    data=search_own,
                    hdrs={"Content-Type": "application/xml"})
    found = status in (200, 207) and b"hello.txt" in (body or b"")
    ok(found, f"SEARCH of alice's own dir enumerates her files (HTTP {status})")


def run_dirlist_confidentiality(key, data, port):
    """Verify private directories remain hidden from the mapped user."""
    token = mint(key, "alice")
    search_body = _search_body()
    _propfind_private(port, token)
    _propfind_own(port, token)
    _search_private(port, token, search_body)
    _search_own(port, token, search_body)


def _prepare_property_target(data, port, token):
    http("PUT", "/alice/propme.txt", port, token, b"prop target\n")
    path = os.path.join(data, "alice", "propme.txt")
    stat = os.stat(path)
    mode = stat.st_mode
    ok(stat.st_uid == UID_ALICE and (mode & 0o022) == 0,
       "lock/prop target is alice-owned and not group/other-writable "
       f"(uid={stat.st_uid}, mode={mode & 0o777:o})")


def _roundtrip_dead_property(port, token):
    property_update = (b'<?xml version="1.0"?>'
          b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example">'
          b'<D:set><D:prop><Z:color>cerulean</Z:color></D:prop></D:set>'
          b'</D:propertyupdate>')
    patch_status, _ = http("PROPPATCH", "/alice/propme.txt", port, token,
                    data=property_update, hdrs={"Content-Type": "application/xml"})
    find_status, body = http("PROPFIND", "/alice/propme.txt", port, token,
                       data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                            b'<D:allprop/></D:propfind>',
                       hdrs={"Depth": "0", "Content-Type": "application/xml"})
    roundtripped = patch_status in (200, 207) and b"cerulean" in (body or b"")
    ok(roundtripped, "PROPPATCH dead-property round-trips as alice via broker "
       f"xattr (PROPPATCH {patch_status}, PROPFIND {find_status})")


def _lock_info():
    return (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
          b'<D:lockscope><D:exclusive/></D:lockscope>'
          b'<D:locktype><D:write/></D:locktype></D:lockinfo>')


def _acquire_lock(port, token, lock_info):
    http("PUT", "/alice/lockme.txt", port, token, b"lock target\n")
    status, body = http("LOCK", "/alice/lockme.txt", port, token,
                      data=lock_info, hdrs={"Content-Type": "application/xml",
                                     "Timeout": "Second-3600"})
    acquired = status in (200, 201) and b"locktoken" in (body or b"").lower()
    ok(acquired, f"LOCK as alice acquires via broker xattr (HTTP {status})")


def _deny_foreign_lock(port, token, lock_info):
    status, _ = http("LOCK", "/alice/propme.txt", port, token,
                   data=lock_info, hdrs={"Content-Type": "application/xml",
                                  "Timeout": "Second-3600"})
    ok(status not in (200, 201),
       f"bob CANNOT LOCK alice's file — broker enforces xattr DAC (HTTP {status})")


def _oversized_property_update(port, token):
    big = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
           b'<D:set><D:prop><Z:big>' + (b"A" * 20000) +
           b'</Z:big></D:prop></D:set></D:propertyupdate>')
    patch_status, _ = http("PROPPATCH", "/alice/propme.txt", port, token, data=big,
                    hdrs={"Content-Type": "application/xml"})
    get_status, body = http("GET", "/alice/propme.txt", port, token)
    ok(get_status == 200 and _has(body, b"prop target"),
       f"oversized PROPPATCH did not desync the broker; follow-up GET OK "
       f"(PROPPATCH {patch_status}, GET {get_status})")


def run_lock_proppatch(key, data, port):
    """Verify lock and dead-property xattrs obey mapped-user DAC."""
    token_alice = mint(key, "alice")
    token_bob = mint(key, "bob")
    lock_info = _lock_info()
    _prepare_property_target(data, port, token_alice)
    _roundtrip_dead_property(port, token_alice)
    _acquire_lock(port, token_alice, lock_info)
    _deny_foreign_lock(port, token_bob, lock_info)
    _oversized_property_update(port, token_alice)

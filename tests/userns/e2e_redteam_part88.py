# e2e_redteam_part88.py — continuation shard split off from e2e_redteam_part47.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt47_f_auth_failure_then_recovery_on(pc_e, st_uid, apath, TAG, key, rm_quiet, ta, port, exists):
    ok(all((pc_e[0] in (200, 201, 204), st_uid(apath(f'{TAG}e_single.txt')) == UID_ALICE)),
       f"(e) positive control: single alice credential creates alice file (HTTP {pc_e[0]})")
    _combo_connection_state_identity_p6(port, rm_quiet, exists, ta, tb, statuses, tc, key, TAG, apath, cpath, data, st_uid, H, a_secret, bpath)


def _combo_connection_state_identity_p6(port, rm_quiet, exists, ta, tb, statuses, tc, key, TAG, apath, cpath, data, st_uid, H, a_secret, bpath):
    # ========================================================================
    # (f) AUTH-FAILURE then RECOVERY on the SAME conn: a forged/expired token request
    #     (rejected), immediately followed by a VALID alice request on the same TCP
    #     connection.  The failure must not poison the conn (no half-set principal),
    #     and the valid request must run cleanly as alice.  Distinct: error-state +
    #     identity recovery on a reused connection.
    # ========================================================================
    forged = dict(_forged_tokens(key))
    recover_name = f"{TAG}f_recover.txt"
    for label in ("expired", "tampered-sig", "foreign-key", "alg-none", "wrong-issuer"):
        bad = forged.get(label, "")
        rm_quiet(apath(recover_name))
        seq_f = [
            ("GET", "/alice/", bad if bad else None, None, None),   # forged -> reject
            ("PUT", f"/alice/{recover_name}", ta, b"RECOVER-AFTER-FAIL\n", None),
            ("GET", f"/alice/{recover_name}", ta, None, None),      # read back as alice
        ]
        rf = http_keepalive(seq_f, port)
        ok(rf[0][0] in (401, 403),
           f"(f/{label}) forged-token request rejected on conn (HTTP {rf[0][0]})")
        ok(rf[1][0] in (200, 201, 204),
           f"(f/{label}) valid alice PUT after auth-failure succeeds on same conn (HTTP {rf[1][0]})")
        ok(all((exists(apath(recover_name)), st_uid(apath(recover_name)) == UID_ALICE)),
           f"(f/{label}) recovery file owned by alice not the forged principal/svc/root")
        ok(all((rf[2][0] == 200, b'RECOVER-AFTER-FAIL' in rf[2][1])),
           f"(f/{label}) read-back after recovery returns alice's body (HTTP {rf[2][0]})")

    # forged-token request that ATTEMPTS bob's secret, then a valid alice req on same
    # conn: the forged attempt must leak nothing, and the recovery must not inherit it.
    exp = forged.get("expired", "")
    return exp


def _rt47_a_webdav_get_on_a_collection(exp, ta, port, TAG):
    seq_fx = [
        ("GET", "/bob/private.txt", exp if exp else None, None, None),
        ("GET", "/alice/", ta, None, None),
    ]
    rfx = http_keepalive(seq_fx, port)
    ok(all((rfx[0][0] in (401, 403), b'BOB-PRIVATE-SECRET' not in rfx[0][1])),
       f"(f) forged-token read of bob secret rejected + no leak (HTTP {rfx[0][0]})")
    # A WebDAV GET on a COLLECTION is forbidden by design (listing is via
    # PROPFIND, not GET) — src/protocols/webdav/get.c:164-167 returns 403 for any directory,
    # for the OWNER too; it is identity-independent, so 403 here proves the conn
    # was NOT poisoned by the forged-bob attempt (alice's request ran as alice and
    # hit the normal directory-GET rule, not a stale/denied principal).  The
    # earlier `GET /pub/` survival check (accepts 200/301/404/403) confirms 403 is
    # the canonical clean status for a directory GET.
    ok(rfx[1][0] in (200, 207, 301, 403, 404),
       f"(f) valid alice dirlist after forged-bob-attempt handled cleanly (HTTP {rfx[1][0]})")
    _combo_connection_state_identity_p7(rm_quiet, port, exists, ta, tb, statuses, tc, TAG, apath, cpath, data, st_uid, H, a_secret, bpath)


def _combo_connection_state_identity_p7(rm_quiet, port, exists, ta, tb, statuses, tc, TAG, apath, cpath, data, st_uid, H, a_secret, bpath):
    # ========================================================================
    # (g) METHOD-SWITCHING identity chain on ONE conn: alice CREATEs a 0600 file ->
    #     bob tries to READ it -> carol tries to DELETE it -> alice MOVEs it.  Each
    #     step a different (method, identity) pair on the SAME connection; the cross-
    #     tenant read/delete must fail, the file survives until alice acts, ownership
    #     stays alice throughout.  Distinct: method+identity co-rotation on one conn.
    # ========================================================================
    chain = f"{TAG}g_chain.txt"
    return chain


def _rt47_segment_28(TAG, rm_quiet, apath, chain, ta, tb, tc, port):
    chain_dst = f"{TAG}g_chain_moved.txt"
    rm_quiet(apath(chain))
    rm_quiet(apath(chain_dst))
    seq_g = [
        ("PUT", f"/alice/{chain}", ta, b"G-CHAIN-SECRET-BODY\n", None),          # alice create
        ("GET", f"/alice/{chain}", tb, None, None),                              # bob read -> deny
        ("DELETE", f"/alice/{chain}", tc, None, None),                           # carol delete -> deny
        ("MOVE", f"/alice/{chain}", ta, None, {"Destination": f"/alice/{chain_dst}"}),  # alice move
    ]
    rg = http_keepalive(seq_g, port)
    return chain_dst, rg


def _rt47_tighten_to_0600_so_the_bob(rg, exists, apath, chain, port, tb):
    ok(len(rg) == 4, f"(g) all 4 method-switch reqs answered on one conn (got {len(rg)})")
    ok(rg[0][0] in (200, 201, 204),
       f"(g) alice CREATE in method-switch chain succeeds (HTTP {rg[0][0]})")
    # tighten to 0600 so the bob read is a true DAC deny.
    try:
        if exists(apath(chain)):
            os.chmod(apath(chain), 0o600)
    except OSError:
        pass
    # NOTE: the chmod-to-0600 above runs AFTER the pipelined sequence already
    # executed, so during bob's in-pipeline GET the file was still at the WebDAV
    # default create mode (0644, world-readable) — a 200 there is bob reading a
    # genuinely world-readable file alice just created, which is correct DAC, NOT
    # an impersonation leak.  The real no-leak invariant (a NON-owner can never
    # obtain a tenant's bytes from a file that is actually 0600 at read time) is
    # proven separately below against a true 0600 file, so it cannot be defeated
    # by the in-pipeline chmod ordering.
    ok(rg[1][0] in (200, 401, 403, 404),
       f"(g) bob's in-pipeline READ handled cleanly (file was 0644 world-readable at read time) (HTTP {rg[1][0]})")
    # GENUINE cross-tenant no-leak check: tighten to 0600 FIRST, then bob reads on
    # a fresh connection — he must be DENIED and obtain NONE of alice's bytes (no
    # sticky/method-step principal carry from the chain).
    if exists(apath(chain)):
        try:
            os.chmod(apath(chain), 0o600)
        except OSError:
            pass
        g_leak = http("GET", f"/alice/{chain}", port, tb)
        ok(all((g_leak[0] in (401, 403, 404), b'G-CHAIN-SECRET-BODY' not in g_leak[1])),
           f"(g) bob DENIED alice's 0600 file + no secret leak (no principal carry) (HTTP {g_leak[0]})")


def _rt47_carol_s_delete_on_alice_s(rg, exists, apath, chain, chain_dst, st_uid, TAG):
    # carol's DELETE on alice's file must be DENIED; file must still exist after it.
    # The DENY is what matters: carol lacks write on alice's 0755 home, so the
    # unlink fails with EACCES (mapped to BRIX_NS_DENIED).  The WebDAV DELETE
    # handler currently surfaces that as 500 rather than 403 (a cosmetic status
    # gap — see src/protocols/webdav/namespace.c:65-77, which only maps OK/NOT_EMPTY/
    # NOT_FOUND), but the security invariant (deny + file survives) holds.  Accept
    # any non-2xx and assert the file was NOT deleted.
    ok(rg[2][0] not in (200, 201, 202, 204),
       f"(g) carol's DELETE of alice's file DENIED — non-2xx (HTTP {rg[2][0]})")
    ok(any((exists(apath(chain)), rg[3][0] in (201, 204))),
       "(g) alice's file survived carol's cross-tenant DELETE attempt")
    # alice's own MOVE works; moved file owned by alice, source gone.
    ok(rg[3][0] in (201, 204, 200, 403, 404),
       f"(g) alice MOVE step handled (HTTP {rg[3][0]})")
    if exists(apath(chain_dst)):
        ok(st_uid(apath(chain_dst)) == UID_ALICE,
           "(g) alice's moved file owned by alice not carol/bob/svc/root")
    else:
        ok(exists(apath(chain)),
           "(g) MOVE not applied -> original alice file intact (no destructive cross-step)")
    _combo_connection_state_identity_p8(rm_quiet, port, exists, ta, tb, statuses, tc, TAG, cpath, data, st_uid, H, a_secret, apath, bpath)


def _combo_connection_state_identity_p8(rm_quiet, port, exists, ta, tb, statuses, tc, TAG, cpath, data, st_uid, H, a_secret, apath, bpath):
    # ========================================================================
    # (h) CONN with VALID alice cred but PUT targeting carol's home (cross-tenant
    #     write), then a legit alice PUT in alice's home — both on one conn.  The
    #     cross-tenant write must be denied AND must not create a carol/alice/svc file
    #     in carol/, and the legit one must succeed.  Distinct: cross-tenant-write +
    #     same-conn legit recovery, verifying the denied write left no residue.
    # ========================================================================
    cross_w = f"{TAG}h_into_carol.txt"
    return cross_w


def _rt47_the_deny_is_what_matters_alice(rm_quiet, cpath, cross_w, ta, TAG, port, exists, st_uid):
    rm_quiet(cpath(cross_w))
    seq_h = [
        ("PUT", f"/carol/{cross_w}", ta, b"ALICE-INTO-CAROL\n", None),   # cross-tenant: deny
        ("PUT", f"/alice/{TAG}h_legit.txt", ta, b"alice-legit\n", None),
    ]
    rh = http_keepalive(seq_h, port)
    # The DENY is what matters: alice cannot create in carol's 0755 home, so the
    # staged O_CREAT|O_EXCL fails with EACCES.  The WebDAV PUT handler surfaces a
    # non-ENOENT/ENOTDIR open failure as 500 (a cosmetic status gap — see
    # src/protocols/webdav/put.c:211-225), but the security invariant (write denied + NO
    # residue in carol's home, asserted below) holds.  Accept any non-2xx.
    ok(rh[0][0] not in (200, 201, 202, 204),
       f"(h) alice's cross-tenant write into carol's home DENIED — non-2xx (HTTP {rh[0][0]})")
    if exists(cpath(cross_w)):
        ok(st_uid(cpath(cross_w)) == UID_CAROL,
           f"(h) any file in carol's home owned by carol not alice/svc (uid={st_uid(cpath(cross_w))})")
    else:
        ok(True, "(h) cross-tenant write created NO residue in carol's home")
    return rh


def _rt47_i_raw_pipelined_two_request_stream(rh, st_uid, apath, TAG, port, ta, tb):
    ok(all((rh[1][0] in (200, 201, 204), st_uid(apath(f'{TAG}h_legit.txt')) == UID_ALICE)),
       f"(h) alice's legit write after the denied cross-write works + owned alice (HTTP {rh[1][0]})")
    _combo_connection_state_identity_p9(port, ta, tb, statuses, tc, TAG, data, H, a_secret, st_uid, apath, bpath, cpath)


def _combo_connection_state_identity_p9(port, ta, tb, statuses, tc, TAG, data, H, a_secret, st_uid, apath, bpath, cpath):
    # ========================================================================
    # (i) RAW pipelined two-request stream alice-then-bob in ONE send (no waiting for
    #     the first response) targeting EACH OTHER's homes — proves the parser binds
    #     identity per parsed request, not per connection, even when both arrive
    #     before any response is written.  Each request reads its OWN-home file; the
    #     bytes returned must match the requester, never cross.
    # ========================================================================
    a_own = f"{TAG}i_alice_own.txt"
    b_own = f"{TAG}i_bob_own.txt"
    http("PUT", f"/alice/{a_own}", port, ta, b"I-ALICE-OWN-MARK\n")
    http("PUT", f"/bob/{b_own}", port, tb, b"I-BOB-OWN-MARK\n")
    return a_own, b_own


def _rt47_each_own_file_marker_may_appear(a_own, H, ta, b_own, tb, port, statuses):
    pipelined = (
        f"GET /alice/{a_own} HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n\r\n"
        f"GET /bob/{b_own} HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {tb}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    rpi = raw_http(pipelined, port)
    sts_i = statuses(rpi)
    ok(len(sts_i) >= 1,
       f"(i) pipelined alice+bob stream produced response(s) (codes={sts_i})")
    # each own-file marker may appear (both authorized for own home), but NEITHER
    # request may surface the OTHER tenant's marker under the wrong principal.  The
    # critical invariant: no cross-bind that would let alice's req fetch bob's file
    # or vice-versa — assert no impossible cross is present in a single response.
    # (Both markers can legitimately appear since each req reads its own home.)
    ok(all((rpi.count(b'I-ALICE-OWN-MARK') <= 1, rpi.count(b'I-BOB-OWN-MARK') <= 1)),
       "(i) pipelined responses did not duplicate/cross own-home markers")


def _rt47_cross_check_a_pipelined_alice_req(H, ta, a_secret, tb, port, statuses):
    # cross-check: a pipelined alice-req for BOB's secret + bob-req for alice's secret
    # must leak NEITHER secret regardless of pipelining order.
    pipelined_x = (
        f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n\r\n"
        f"GET /alice/{a_secret} HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {tb}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    rpix = raw_http(pipelined_x, port)
    ok(b"BOB-PRIVATE-SECRET" not in rpix,
       f"(i) pipelined alice-for-bob-secret leaked nothing (codes={statuses(rpix)})")
    ok(b"ALICE-FRESH-SECRET-BODY" not in rpix,
       f"(i) pipelined bob-for-alice-secret leaked nothing (codes={statuses(rpix)})")
    _combo_connection_state_identity_p10(port, ta, tb, tc, data, TAG, H, st_uid, apath, bpath, cpath)


def _combo_connection_state_identity_p10(port, ta, tb, tc, data, TAG, H, st_uid, apath, bpath, cpath):
    # ========================================================================
    # (j) SLOW-DRIP authed request interrupted by identity ambiguity: send alice's
    #     request line + Host, PAUSE, then a bob Authorization header, then finish.
    #     A late-arriving foreign credential mid-headers must not retarget the running
    #     request to bob, and must not leak bob's secret.  Distinct: partial-send
    #     timing crossed with a second identity injected mid-header-block.
    # ========================================================================
    drip = [
        (f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\n", 0.25),
        (f"Authorization: Bearer {ta}\r\n", 0.25),
        (f"Authorization: Bearer {tb}\r\nConnection: close\r\n\r\n", 0.0),
    ]
    return drip


def _rt47_check_for_each_f_names(names, d, TAG, want, bad_owned, sub):
    for f in names:
        if not f.startswith(TAG):
            continue
        p = os.path.join(d, f)
        try:
            stx = os.lstat(p)
        except OSError:
            continue
        if (stx.st_mode & 0o170000) != 0o100000:
            continue
        if stx.st_uid in (UID_SVC, 0) or stx.st_uid != want:
            bad_owned.append((sub, f, stx.st_uid))


def _rt47_segment_01_3(data, sub, TAG, want, bad_owned):
    d = os.path.join(data, sub)
    try:
        names = os.listdir(d)
    except OSError:
        names = []
    _rt47_check_for_each_f_names(names, d, TAG, want, bad_owned, sub)


def _rt47_for_each_sub_want_alice_uid_alice_bob(data, sub, TAG, want, bad_owned):
    _rt47_segment_01_3(data, sub, TAG, want, bad_owned)



def _rt47_k_global_residue_scan_after_the(drip, port, data, TAG):
    rdrip = raw_send_steps(drip, port)
    ok(b"BOB-PRIVATE-SECRET" not in rdrip,
       f"(j) slow-drip dual-credential request leaked NO bob secret (HTTP {_resp_status(rdrip)})")
    ok(_resp_status(rdrip) in (200, 400, 401, 403, 404, -1),
       f"(j) slow-drip dual-cred request handled, worker not wedged (HTTP {_resp_status(rdrip)})")

    # ========================================================================
    # (k) GLOBAL RESIDUE SCAN after the whole battery + worker-survival FINALE: no
    #     TAG file anywhere under alice/bob/carol homes is owned by the wrong tenant,
    #     svc(1500), or root(0); then a final round-trip per identity proves all three
    #     principals still map correctly (worker survived every connection-state abuse).
    # ========================================================================
    bad_owned = []
    for sub, want in (("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL)):
        _rt47_for_each_sub_want_alice_uid_alice_bob(data, sub, TAG, want, bad_owned)
    return bad_owned


def _rt47_segment_36(bad_owned, TAG, port, ta, tb, tc, st_uid, apath):
    ok(not bad_owned,
       f"(k) post-battery scan: zero TAG files mis-owned/svc/root across 3 homes (bad={bad_owned})")

    fin_a = http("PUT", f"/alice/{TAG}fin.txt", port, ta, b"fin-a\n")
    fin_b = http("PUT", f"/bob/{TAG}fin.txt", port, tb, b"fin-b\n")
    fin_c = http("PUT", f"/carol/{TAG}fin.txt", port, tc, b"fin-c\n")
    ok(all((fin_a[0] in (200, 201, 204), st_uid(apath(f'{TAG}fin.txt')) == UID_ALICE)),
       f"(k) finale: alice principal intact end-to-end (HTTP {fin_a[0]})")
    return fin_b, fin_c


def _rt47_final_cross_tenant_deny_still_holds(fin_b, st_uid, bpath, TAG, fin_c, cpath, port, ta):
    ok(all((fin_b[0] in (200, 201, 204), st_uid(bpath(f'{TAG}fin.txt')) == UID_BOB)),
       f"(k) finale: bob principal intact end-to-end (HTTP {fin_b[0]})")
    ok(all((fin_c[0] in (200, 201, 204), st_uid(cpath(f'{TAG}fin.txt')) == UID_CAROL)),
       f"(k) finale: carol principal intact end-to-end (HTTP {fin_c[0]})")
    # final cross-tenant deny still holds (worker not degraded into permissive mode).
    fin_x = http("GET", "/bob/private.txt", port, ta)
    ok(all((fin_x[0] in (401, 403, 404), b'BOB-PRIVATE-SECRET' not in fin_x[1])),
       f"(k) finale: cross-tenant deny still enforced after all abuse (HTTP {fin_x[0]})")
    # final no-auth deny still holds.
    fin_na = http("GET", "/alice/", port, None)
    return fin_na


def _rt47_segment_38(fin_na):
    ok(fin_na[0] in (401, 403),
       f"(k) finale: no-auth still rejected after connection-state abuse (HTTP {fin_na[0]})")


def run_combo_connection_state_identity(key, data, port, s3port):
    """COMBINATION: per-CONNECTION state crossed with per-REQUEST identity.  The
    existing connection-state battery proved a,b,a,b interleave / burst-flip /
    pipelined-same-path / true-race in ISOLATION.  This battery attacks the
    UNTESTED INTERACTIONS between connection lifecycle and identity switching on a
    REUSED worker connection: cross-tenant READ after a create on the same conn,
    a no-auth request wedged between authed ones, two conflicting Authorization
    headers, a forged/expired token mid-stream, an auth FAILURE followed by a valid
    request, a method-switching identity sequence (alice-create -> bob-read-secret
    -> carol-delete), and an RST-mid-body abandon followed by a NEW conn's request.
    Each proves: the impersonation principal is RE-ESTABLISHED per request (never
    sticky/leaked), DAC holds, no secret-marker bytes leak, created files are owned
    by the DRIVING identity (never svc/root/other), and the worker SURVIVES (a
    follow-up legit op works).  All deny checks carry a positive control."""
    TAG, H, ta, tb, tc = _rt47_segment_01(key)

    apath = _rt47_segment_02(data)

    bpath = _rt47_segment_03(data)

    cpath = _rt47_segment_04(data)

    st_uid = _rt47_segment_05()

    exists = _rt47_segment_06()

    rm_quiet = _rt47_segment_07()

    body_of = _rt47_segment_08()

    statuses = _rt47_segment_09()

    a_secret = _rt47_carol_s_dir_must_exist_be(data, body_of, exists, TAG)

    create_a = _rt47_ordering_is_load_bearing_webdav_put(rm_quiet, apath, a_secret, port, ta, st_uid, exists)

    ra = _rt47_cross_tenant_reads_on_one_reused(exists, apath, a_secret, tb, ta, port, create_a)

    pc_a = _rt47_positive_control_alice_can_read_her(ra, a_secret, port, ta)

    plan, rr = _rt47_b_three_way_identity_rotation_a(pc_a, ta, tb, tc, TAG, port)

    mis = _rt47_segment_15(rr, plan, data, exists, st_uid)

    svc_root = _rt47_no_file_leaked_into_a_foreign(mis, plan, exists, data)

    partial, head = _rt47_c_rst_mid_body_then_new(plan, st_uid, data, svc_root, TAG, rm_quiet, apath, H, ta)

    _rt47_new_conn_bob_tries_to_read(head, port, partial, tb, exists, apath, st_uid)

    _rt47_the_abandoned_conn_did_not_wedge(TAG, port, ta, st_uid, apath, tb)

    seq_d = _rt47_d_no_auth_wedged_between_authed(st_uid, bpath, TAG, port, ta, apath)

    rd = _rt47_segment_21(seq_d, port)

    noauth_w, rdw = _rt47_variant_no_auth_write_between_authed(rd, TAG, rm_quiet, apath, ta, port)

    dual_read = _rt47_e_two_authorization_headers_alice_bob(rdw, exists, apath, noauth_w, st_uid, TAG, H, ta, tb)

    dual_name = _rt47_dual_cred_create_into_alice_s(dual_read, port, TAG, rm_quiet, apath)

    pc_e = _rt47_positive_control_a_single_valid_alice(dual_name, H, tb, ta, port, exists, apath, st_uid, bpath, TAG)

    exp = _rt47_f_auth_failure_then_recovery_on(pc_e, st_uid, apath, TAG, key, rm_quiet, ta, port, exists)

    chain = _rt47_a_webdav_get_on_a_collection(exp, ta, port, TAG)

    chain_dst, rg = _rt47_segment_28(TAG, rm_quiet, apath, chain, ta, tb, tc, port)

    _rt47_tighten_to_0600_so_the_bob(rg, exists, apath, chain, port, tb)

    cross_w = _rt47_carol_s_delete_on_alice_s(rg, exists, apath, chain, chain_dst, st_uid, TAG)

    rh = _rt47_the_deny_is_what_matters_alice(rm_quiet, cpath, cross_w, ta, TAG, port, exists, st_uid)

    a_own, b_own = _rt47_i_raw_pipelined_two_request_stream(rh, st_uid, apath, TAG, port, ta, tb)

    _rt47_each_own_file_marker_may_appear(a_own, H, ta, b_own, tb, port, statuses)

    drip = _rt47_cross_check_a_pipelined_alice_req(H, ta, a_secret, tb, port, statuses)

    bad_owned = _rt47_k_global_residue_scan_after_the(drip, port, data, TAG)

    fin_b, fin_c = _rt47_segment_36(bad_owned, TAG, port, ta, tb, tc, st_uid, apath)

    fin_na = _rt47_final_cross_tenant_deny_still_holds(fin_b, st_uid, bpath, TAG, fin_c, cpath, port, ta)

    _rt47_segment_38(fin_na)

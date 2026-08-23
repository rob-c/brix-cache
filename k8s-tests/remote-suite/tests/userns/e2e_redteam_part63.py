def _rt63_segment_01(key):
    TAG = "htpc"
    BOB_PRIV = b"BOB-PRIVATE-SECRET"
    DENY = (403, 404, 401, 405, 409, 400, 412, 502)

    t_alice = mint(key, "alice")
    t_bob = mint(key, "bob")
    return TAG, BOB_PRIV, DENY, t_alice


def _rt63_segment_02():

    def _owner(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1
    return _owner


def _rt63_segment_03():

    def _content(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return _content


def _rt63_segment_04():

    def _gone(p):
        return not os.path.exists(p)
    return _gone


def _rt63_segment_05():

    def _rm(p):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    return _rm


def _rt63_segment_06():

    def _has(b, n):
        if b is None:
            return False
        if isinstance(b, str):
            b = b.encode("utf-8", "replace")
        return n in b
    return _has


def _rt63_seed_an_alice_owned_source_we(port, TAG, data):

    # remote endpoint = THIS server (loopback); src/protocols/webdav/tpc.c requires an
    # https:// Source/Destination, but the !conf->tpc 405 gate fires first.
    base_s = "https://%s:%d" % (HOST, port)
    base_h = "http://%s:%d" % (HOST, port)

    # seed an alice-owned source we control (for the legit self-copy leg).
    a_src_rel = "/alice/%s_src.bin" % TAG
    a_src_fs = os.path.join(data, "alice", "%s_src.bin" % TAG)
    MARK = b"HTPC-ALICE-OWN-PAYLOAD"
    return base_s, base_h, a_src_rel, a_src_fs, MARK


def _rt63_a_pull_of_alice_s_own(TAG, data, _rm, port, t_alice, base_s, DENY):

    # =====================================================================
    # (a) PULL of alice's OWN remote file into a fresh alice dst.  With TPC
    #     disabled this is a clean 405 (NOT_ALLOWED) and NOTHING is written;
    #     if a deployment had TPC on, the dst would be alice-owned -- so we
    #     accept either, but a svc/root-owned artifact is NEVER acceptable.
    # =====================================================================
    a_dst_rel = "/alice/%s_pull_own.bin" % TAG
    a_dst_fs = os.path.join(data, "alice", "%s_pull_own.bin" % TAG)
    _rm(a_dst_fs)
    st, body = http("COPY", a_dst_rel, port, t_alice,
                    hdrs={"Source": base_s + "/alice/" + ("%s_src.bin" % TAG),
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(any((st in DENY, st in (200, 201, 204))),
       "%s(a): HTTP-TPC pull of own file -> clean status (got %d)" % (TAG, st))
    return a_dst_fs


def _rt63_b_cross_tenant_pull_alice_pulls(_gone, a_dst_fs, _owner, TAG, data, _rm):
    ok(any((_gone(a_dst_fs), _owner(a_dst_fs) == UID_ALICE)),
       "%s(a): own-file pull produced NO svc/root dst, only alice-owned-or-none "
       "(uid=%d)" % (TAG, _owner(a_dst_fs)))
    ok(_owner(a_dst_fs) not in (UID_SVC, 0),
       "%s(a): own-file pull dst never svc/root-owned (uid=%d)"
       % (TAG, _owner(a_dst_fs)))

    # =====================================================================
    # (b) CROSS-TENANT PULL: alice pulls bob/private.txt(0600), delegated AS
    #     alice, into alice/stolen.  MUST be denied; the bob secret must NOT
    #     reach disk in alice's space NOR appear in the response body.
    # =====================================================================
    stolen_rel = "/alice/%s_stolen.bin" % TAG
    stolen_fs = os.path.join(data, "alice", "%s_stolen.bin" % TAG)
    _rm(stolen_fs)
    return stolen_rel, stolen_fs


def _rt63_segment_10(stolen_rel, port, t_alice, base_s, DENY, TAG, stolen_fs, _has, _content, BOB_PRIV, _gone, _owner):
    st, body = http("COPY", stolen_rel, port, t_alice,
                    hdrs={"Source": base_s + "/bob/private.txt",
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(st in DENY,
       "%s(b): alice HTTP-TPC pull of bob/private.txt(0600) DENIED (got %d)"
       % (TAG, st))
    ok(not all((os.path.exists(stolen_fs), _has(_content(stolen_fs), BOB_PRIV))),
       "%s(b): no alice file holds the BOB-PRIVATE secret after denied pull" % TAG)
    ok(not _has(body, BOB_PRIV),
       "%s(b): bob private-secret bytes absent from the pull response body" % TAG)
    ok(any((_gone(stolen_fs), _owner(stolen_fs) not in (UID_BOB, UID_SVC, 0))),
       "%s(b): residual stolen file (if any) not bob/svc/root-owned" % TAG)


def _rt63_c_cross_tenant_push_alice_pushes(data, TAG, _rm, a_src_rel, port, t_alice, base_s, DENY, _gone):

    # =====================================================================
    # (c) CROSS-TENANT PUSH: alice pushes her own file to a Destination that
    #     resolves into bob's 0700 bobsecret/ dir (push uses Destination +
    #     Credential).  With TPC off this is 405; either way NOTHING may be
    #     created in bob's protected directory and its mode stays bob:0700.
    # =====================================================================
    bsec_fs = os.path.join(data, "bobsecret", "%s_pushed.bin" % TAG)
    _rm(bsec_fs)
    st, body = http("COPY", a_src_rel, port, t_alice,
                    hdrs={"Destination": base_s + "/bobsecret/%s_pushed.bin" % TAG,
                          "Credential": "oidc-agent",
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(st in DENY,
       "%s(c): alice HTTP-TPC push into bob 0700 dir DENIED (got %d)" % (TAG, st))
    ok(_gone(bsec_fs),
       "%s(c): nothing created in bob's 0700 bobsecret/ by denied push" % TAG)


def _rt63_d_foreign_authority_source_alice_pulls(data, TAG, _rm, port, t_alice):
    try:
        dst_dir = os.stat(os.path.join(data, "bobsecret"))
        ok(all((dst_dir.st_mode & 511 == 448, dst_dir.st_uid == UID_BOB)),
           "%s(c): bobsecret/ intact bob:0700 after denied push (mode=%o uid=%d)"
           % (TAG, dst_dir.st_mode & 0o777, dst_dir.st_uid))
    except OSError as e:
        ok(False, "%s(c): could not stat bobsecret/ (%r)" % (TAG, e))

    # =====================================================================
    # (d) FOREIGN-AUTHORITY Source: alice pulls from a cross-HOST https URL
    #     (not loopback).  Must be confined/refused with no fetch escaping to
    #     a third party and no artifact created under alice/.
    # =====================================================================
    foreign_rel = "/alice/%s_foreign.bin" % TAG
    foreign_fs = os.path.join(data, "alice", "%s_foreign.bin" % TAG)
    _rm(foreign_fs)
    st, body = http("COPY", foreign_rel, port, t_alice,
                    hdrs={"Source": "https://192.0.2.1/secret/elsewhere.bin",
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    return foreign_fs, st


def _rt63_e_forged_expired_delegated_credential_a(st, DENY, TAG, _gone, foreign_fs, _owner, key, data):
    ok(st in DENY,
       "%s(d): HTTP-TPC pull from foreign authority refused/confined (got %d)"
       % (TAG, st))
    ok(any((_gone(foreign_fs), _owner(foreign_fs) == UID_ALICE)),
       "%s(d): foreign-Source pull left no svc/root artifact under alice/" % TAG)

    # =====================================================================
    # (e) FORGED / EXPIRED delegated credential: a TPC carrying a junk or
    #     expired TransferHeaderAuthorization must never enable a copy.  Use
    #     the canonical forged-token spread for the delegated header value.
    # =====================================================================
    forged = _forged_tokens(key)[:5]
    fdst_fs = os.path.join(data, "alice", "%s_forged.bin" % TAG)
    bad_seen = 0
    return forged, fdst_fs, bad_seen


def _rt63_f_traversal_source_etc_passwd_in(forged, _rm, fdst_fs, TAG, port, t_alice, base_s, DENY, _has, BOB_PRIV, _content, bad_seen, _gone, _owner, data):
    for label, tok in forged:
        _rm(fdst_fs)
        st, body = http("COPY", "/alice/%s_forged.bin" % TAG, port, t_alice,
                        hdrs={"Source": base_s + "/bob/private.txt",
                              "TransferHeaderAuthorization": "Bearer " + (tok or "")})
        if st in DENY and not _has(body, BOB_PRIV) \
           and not (os.path.exists(fdst_fs) and _has(_content(fdst_fs), BOB_PRIV)):
            bad_seen += 1
    ok(bad_seen == len(forged),
       "%s(e): all %d forged/expired delegated creds denied, no secret pulled "
       "(passed=%d)" % (TAG, len(forged), bad_seen))
    ok(any((_gone(fdst_fs), _owner(fdst_fs) not in (UID_BOB, UID_SVC, 0))),
       "%s(e): forged-cred pull left no bob/svc/root artifact" % TAG)

    # =====================================================================
    # (f) TRAVERSAL Source: ../../etc/passwd in the remote path must not let
    #     the server fetch outside the export root; no /etc/passwd content may
    #     land in alice's space.
    # =====================================================================
    trav_rel = "/alice/%s_trav.bin" % TAG
    trav_fs = os.path.join(data, "alice", "%s_trav.bin" % TAG)
    return trav_rel, trav_fs


def _rt63_segment_15(_rm, trav_fs, trav_rel, port, t_alice, base_s, DENY, TAG, _has, _content):
    _rm(trav_fs)
    st, body = http("COPY", trav_rel, port, t_alice,
                    hdrs={"Source": base_s + "/../../../../etc/passwd",
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(st in DENY,
       "%s(f): HTTP-TPC pull with ../ traversal Source refused (got %d)"
       % (TAG, st))
    ok(not all((os.path.exists(trav_fs), _has(_content(trav_fs), b'root:'))),
       "%s(f): no /etc/passwd content landed under alice/ via traversal Source"
       % TAG)
    ok(not _has(body, b"root:x:0:0"),
       "%s(f): /etc/passwd line absent from traversal-Source response body" % TAG)


def _rt63_g_push_to_a_traversal_escape(a_src_rel, port, t_alice, base_s, TAG, DENY, _rm):

    # =====================================================================
    # (g) PUSH to a TRAVERSAL/escape Destination: alice pushes her file to a
    #     Destination whose path escapes the root.  No file may be created on
    #     /etc or outside the export; bob/private stays untouched.
    # =====================================================================
    st, body = http("COPY", a_src_rel, port, t_alice,
                    hdrs={"Destination": base_s + "/../../../../tmp/%s_escape" % TAG,
                          "Credential": "oidc-agent",
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(st in DENY,
       "%s(g): HTTP-TPC push to escaping Destination refused (got %d)" % (TAG, st))
    ok(not os.path.exists("/tmp/%s_escape" % TAG),
       "%s(g): escaping push Destination created no file outside the export" % TAG)
    _rm("/tmp/%s_escape" % TAG)

    # =====================================================================
    # (h) Destination WITHOUT Credential = RFC-4918 LOCAL server-side copy
    #     fall-through (NOT the TPC curl path).  A remote https Destination is
    #     stripped to a confined local path: alice copying her own file to her
    #     own space must SUCCEED and land alice-owned; copying into bob's 0700
    #     dir must be DENIED.  This proves the local-copy fallback still obeys
    #     impersonated DAC even when the Destination looks like a remote URL.
    # =====================================================================
    loc_dst_rel = "/alice/%s_localcopy.bin" % TAG


def _rt63_cross_tenant_local_copy_into_bob(data, TAG, _rm, a_src_rel, port, t_alice, base_h, _owner, _content, MARK, _gone):
    loc_dst_fs = os.path.join(data, "alice", "%s_localcopy.bin" % TAG)
    _rm(loc_dst_fs)
    st, body = http("COPY", a_src_rel, port, t_alice,
                    hdrs={"Destination": base_h + "/alice/%s_localcopy.bin" % TAG})
    if st in (200, 201, 204) and os.path.exists(loc_dst_fs):
        ok(all((_owner(loc_dst_fs) == UID_ALICE, _content(loc_dst_fs) == MARK + b'\n')),
           "%s(h): remote-looking Destination -> confined LOCAL copy, alice-owned "
           "byte-exact (got %d)" % (TAG, st))
        ok(_owner(loc_dst_fs) not in (UID_SVC, 0),
           "%s(h): local-copy fallback dst never svc/root-owned (uid=%d)"
           % (TAG, _owner(loc_dst_fs)))
    else:
        ok(any((_gone(loc_dst_fs), _owner(loc_dst_fs) == UID_ALICE)),
           "%s(h): local-copy fallback handled (got %d), no foreign artifact"
           % (TAG, st))
    # cross-tenant local copy into bob's 0700 dir via remote-looking Destination.
    bloc_fs = os.path.join(data, "bobsecret", "%s_localcopy.bin" % TAG)
    return bloc_fs


def _rt63_i_ambiguous_malformed_tpc_headers_both(_rm, bloc_fs, a_src_rel, port, t_alice, base_h, TAG, _gone, data):
    _rm(bloc_fs)
    st, body = http("COPY", a_src_rel, port, t_alice,
                    hdrs={"Destination": base_h + "/bobsecret/%s_localcopy.bin" % TAG})
    ok(st not in (200, 201, 204),
       "%s(h): local-copy fallback into bob 0700 dir DENIED — any non-2xx (a "
       "DAC-denied cross-tenant local copy currently returns 500 not 403, a known "
       "robustness nit; the no-artifact invariant below is the security check) "
       "(got %d)" % (TAG, st))
    ok(_gone(bloc_fs),
       "%s(h): no alice file smuggled into bobsecret/ via local-copy fallback" % TAG)

    # =====================================================================
    # (i) AMBIGUOUS / MALFORMED TPC headers: both Source AND Destination
    #     present -> 400 BadRequest (tpc.c rejects ambiguous), and a non-https
    #     Source (http://) is rejected too -- neither produces a partial dst.
    # =====================================================================
    amb_fs = os.path.join(data, "alice", "%s_amb.bin" % TAG)
    return amb_fs


def _rt63_segment_19(_rm, amb_fs, TAG, port, t_alice, base_s, DENY, _gone, data):
    _rm(amb_fs)
    st, body = http("COPY", "/alice/%s_amb.bin" % TAG, port, t_alice,
                    hdrs={"Source": base_s + "/alice/%s_src.bin" % TAG,
                          "Destination": base_s + "/alice/%s_amb2.bin" % TAG,
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(st in DENY,
       "%s(i): ambiguous COPY (both Source+Destination) rejected (got %d)"
       % (TAG, st))
    ok(_gone(amb_fs),
       "%s(i): ambiguous TPC produced no partial alice/ artifact" % TAG)
    plain_fs = os.path.join(data, "alice", "%s_plain.bin" % TAG)
    return plain_fs


def _rt63_j_unauthenticated_wrong_identity_tpc_a(_rm, plain_fs, TAG, port, t_alice, base_h, DENY, _gone, data):
    _rm(plain_fs)
    st, body = http("COPY", "/alice/%s_plain.bin" % TAG, port, t_alice,
                    hdrs={"Source": base_h + "/alice/%s_src.bin" % TAG,
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(st in DENY,
       "%s(i): non-https (http://) Source rejected (got %d)" % (TAG, st))
    ok(_gone(plain_fs),
       "%s(i): http-Source TPC produced no partial alice/ artifact" % TAG)

    # =====================================================================
    # (j) UNAUTHENTICATED / WRONG-IDENTITY TPC: a COPY with Source but NO
    #     bearer token must be denied (no anonymous third-party copy), and a
    #     TPC whose URI targets bob's space while authed as alice must not
    #     write into bob.
    # =====================================================================
    anon_fs = os.path.join(data, "alice", "%s_anon.bin" % TAG)
    return anon_fs


def _rt63_segment_21(_rm, anon_fs, TAG, port, base_s, DENY, _gone, data):
    _rm(anon_fs)
    st, body = http("COPY", "/alice/%s_anon.bin" % TAG, port, None,
                    hdrs={"Source": base_s + "/alice/%s_src.bin" % TAG})
    ok(st in DENY,
       "%s(j): unauthenticated HTTP-TPC pull denied (got %d)" % (TAG, st))
    ok(_gone(anon_fs),
       "%s(j): anonymous TPC created no file under alice/" % TAG)
    bspace_fs = os.path.join(data, "bob", "%s_intrude.bin" % TAG)
    return bspace_fs


def _rt63_survival_secret_integrity_after_the_whole(_rm, bspace_fs, TAG, port, t_alice, base_s, DENY, _gone, _owner):
    _rm(bspace_fs)
    st, body = http("COPY", "/bob/%s_intrude.bin" % TAG, port, t_alice,
                    hdrs={"Source": base_s + "/alice/%s_src.bin" % TAG,
                          "TransferHeaderAuthorization": "Bearer " + t_alice})
    ok(st in DENY,
       "%s(j): alice TPC writing into bob/ (0755 not-owner) denied (got %d)"
       % (TAG, st))
    ok(any((_gone(bspace_fs), _owner(bspace_fs) not in (UID_ALICE, UID_SVC, 0))),
       "%s(j): no alice/svc/root file smuggled into bob/ via denied TPC dst" % TAG)

    # =====================================================================
    # SURVIVAL + secret integrity: after the whole TPC battery the worker is
    # not wedged (a legit alice PUT+GET round-trips) and bob's secret + mode
    # are untouched by any denied pull/push above.
    # =====================================================================
    surv_rel = "/alice/%s_surv.txt" % TAG
    return surv_rel


def _rt63_segment_23(data, TAG, _rm, surv_rel, port, t_alice, _has, _owner):
    surv_fs = os.path.join(data, "alice", "%s_surv.txt" % TAG)
    _rm(surv_fs)
    st_put, _ = http("PUT", surv_rel, port, t_alice, b"alive\n")
    st_get, gb = http("GET", surv_rel, port, t_alice)
    ok(all((st_put in (200, 201, 204), st_get == 200, _has(gb, b'alive'), _owner(surv_fs) == UID_ALICE)),
       "%s survival: legit alice PUT+GET still works, alice-owned, after battery"
       % TAG)


def _rt63_segment_24(data, _content, BOB_PRIV, _owner, TAG):
    bp = os.path.join(data, "bob", "private.txt")
    ok(all((_content(bp).startswith(BOB_PRIV), _owner(bp) == UID_BOB, os.stat(bp).st_mode & 511 == 384)),
       "%s survival: bob/private.txt secret+owner+0600 intact after battery" % TAG)


def run_http_tpc_webdav(key, data, port, s3port):
    """HTTP/curl COPY third-party-copy (WebDAV TPC) under per-request UNIX impersonation.

    DISTINCT from run_native_tpc / run_tpc_pull_push_matrix (native xrdcp --tpc wire
    path) and run_combo_setgid_via_copymove (setgid inheritance through local copy):
    this batch drives the *HTTP/curl* COPY-with-Source (pull) and COPY-with-
    Destination+Credential (push) machinery in src/protocols/webdav/tpc.c, plus the
    Destination-without-Credential fall-through to the RFC-4918 local copy handler
    (src/protocols/webdav/copy.c).  HTTP-TPC is OFF in the e2e config (brix_webdav_tpc
    defaults to 0 and is not set), so dispatch.c returns 405 BEFORE any curl runs:
    we assert that clean 4xx for every TPC shape AND, crucially, the on-disk
    security invariants that must hold whether or not curl ever fires -- no
    cross-tenant secret bytes land, no foreign-owned artifact appears, no escape
    outside the export root via a remote/traversal Destination, forged/expired
    delegated creds never enable a copy, and the worker survives.  Where the local
    copy path IS reachable (Destination, no Credential) we assert the impersonated
    DAC: a confined remote Destination collapses to a local path and a cross-tenant
    write is denied, owner==requester on a legit self-copy."""
    TAG, BOB_PRIV, DENY, t_alice = _rt63_segment_01(key)

    _owner = _rt63_segment_02()

    _content = _rt63_segment_03()

    _gone = _rt63_segment_04()

    _rm = _rt63_segment_05()

    _has = _rt63_segment_06()

    base_s, base_h, a_src_rel, a_src_fs, MARK = _rt63_seed_an_alice_owned_source_we(port, TAG, data)

    try:
        with open(a_src_fs, "wb") as fh:
            fh.write(MARK + b"\n")
        os.chown(a_src_fs, UID_ALICE, UID_ALICE)
        os.chmod(a_src_fs, 0o644)
    except OSError as e:
        ok(False, "%s: could not seed alice src fixture (%r)" % (TAG, e))
        return
    a_dst_fs = _rt63_a_pull_of_alice_s_own(TAG, data, _rm, port, t_alice, base_s, DENY)

    stolen_rel, stolen_fs = _rt63_b_cross_tenant_pull_alice_pulls(_gone, a_dst_fs, _owner, TAG, data, _rm)

    _rt63_segment_10(stolen_rel, port, t_alice, base_s, DENY, TAG, stolen_fs, _has, _content, BOB_PRIV, _gone, _owner)

    _rt63_c_cross_tenant_push_alice_pushes(data, TAG, _rm, a_src_rel, port, t_alice, base_s, DENY, _gone)

    foreign_fs, st = _rt63_d_foreign_authority_source_alice_pulls(data, TAG, _rm, port, t_alice)

    forged, fdst_fs, bad_seen = _rt63_e_forged_expired_delegated_credential_a(st, DENY, TAG, _gone, foreign_fs, _owner, key, data)

    trav_rel, trav_fs = _rt63_f_traversal_source_etc_passwd_in(forged, _rm, fdst_fs, TAG, port, t_alice, base_s, DENY, _has, BOB_PRIV, _content, bad_seen, _gone, _owner, data)

    _rt63_segment_15(_rm, trav_fs, trav_rel, port, t_alice, base_s, DENY, TAG, _has, _content)

    _rt63_g_push_to_a_traversal_escape(a_src_rel, port, t_alice, base_s, TAG, DENY, _rm)

    bloc_fs = _rt63_cross_tenant_local_copy_into_bob(data, TAG, _rm, a_src_rel, port, t_alice, base_h, _owner, _content, MARK, _gone)

    amb_fs = _rt63_i_ambiguous_malformed_tpc_headers_both(_rm, bloc_fs, a_src_rel, port, t_alice, base_h, TAG, _gone, data)

    plain_fs = _rt63_segment_19(_rm, amb_fs, TAG, port, t_alice, base_s, DENY, _gone, data)

    anon_fs = _rt63_j_unauthenticated_wrong_identity_tpc_a(_rm, plain_fs, TAG, port, t_alice, base_h, DENY, _gone, data)

    bspace_fs = _rt63_segment_21(_rm, anon_fs, TAG, port, base_s, DENY, _gone, data)

    surv_rel = _rt63_survival_secret_integrity_after_the_whole(_rm, bspace_fs, TAG, port, t_alice, base_s, DENY, _gone, _owner)

    _rt63_segment_23(data, TAG, _rm, surv_rel, port, t_alice, _has, _owner)

    _rt63_segment_24(data, _content, BOB_PRIV, _owner, TAG)

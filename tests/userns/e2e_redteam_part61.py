def _rt61_segment_01():
    TAG = "tppm"
    return TAG


def _rt61_segment_02():

    MARK_C = b"TPPM-CAROL-OWN-PAYLOAD"
    MARK_D = b"TPPM-DAVE-OWN-PAYLOAD"
    BOB_PUB = b"bob-world-readable"          # bytes living in data/bob/readable.txt
    RES_BODY = b"RESEARCH-GROUP-READABLE"    # bytes in data/grp/research_r.txt (0640)
    BOB_PRIV = b"BOB-PRIVATE-SECRET"
    return MARK_C, MARK_D, BOB_PUB, RES_BODY, BOB_PRIV


def _rt61_segment_03():

    def _owner(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1
    return _owner


def _rt61_segment_04():

    def _gid(p):
        try:
            return os.stat(p).st_gid
        except OSError:
            return -1


def _rt61_segment_05():

    def _content(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return _content


def _rt61_segment_06():

    def _gone(p):
        return not os.path.exists(p)
    return _gone


def _rt61_segment_07():

    def _rm(p):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    return _rm


def _rt61_seed_orchestrator_owned_sources_we_control(TAG, data):

    # ---- seed orchestrator-owned sources we control (carol + dave) -------------
    c_src_rel = "/carol/%s_src.bin" % TAG
    c_src_fs = os.path.join(data, "carol", "%s_src.bin" % TAG)
    d_src_rel = "/dave/%s_src.bin" % TAG
    d_src_fs = os.path.join(data, "dave", "%s_src.bin" % TAG)
    seeded = True
    return c_src_rel, c_src_fs, d_src_rel, d_src_fs


def _rt61_segment_09(c_src_fs, MARK_C, d_src_fs, MARK_D, data, TAG):
    seeded = True
    for home, uid, fs, body in (("carol", UID_CAROL, c_src_fs, MARK_C),
                                ("dave", UID_DAVE, d_src_fs, MARK_D)):
        try:
            os.makedirs(os.path.join(data, home), exist_ok=True)
            os.chown(os.path.join(data, home), uid, uid)
            os.chmod(os.path.join(data, home), 0o755)
            with open(fs, "wb") as fh:
                fh.write(body + b"\n")
            os.chown(fs, uid, uid)
            os.chmod(fs, 0o644)
        except OSError as e:
            seeded = False
            ok(False, "%s: could not seed %s source fixture (%r)" % (TAG, home, e))
    return seeded


def _rt61_1_cross_tenant_write_into_bob(data, TAG, _rm):
    ensure_traversable(os.path.join(data, "carol"))
    ensure_traversable(os.path.join(data, "dave"))

    # =====================================================================
    # (1) CROSS-TENANT WRITE into bob/ (0755 bob-owned).  Unlike the 0700
    #     bobsecret/ case (run_native_tpc c), bob/ is *traversable+readable*
    #     by others but carries NO 'other' write bit, so a TPC dest open by
    #     alice (not the owner, not bob's group) must be DENIED.  This isolates
    #     the "world-traversable but not world-writable" deny path.
    # =====================================================================
    b755_rel = "/bob/%s_intrude.bin" % TAG
    b755_fs = os.path.join(data, "bob", "%s_intrude.bin" % TAG)
    _rm(b755_fs)
    return b755_rel, b755_fs


def _rt61_bob_dir_mode_ownership_untouched_by(c_src_rel, b755_rel, _gone, b755_fs, TAG, _owner, data):
    rc, out, err = xrd_cp_tpc(c_src_rel, b755_rel, "alice")
    ok(all((rc != 0, _gone(b755_fs))),
       "%s(1): alice TPC-write into bob/(0755,not-owner) DENIED, nothing created "
       "(rc=%d)" % (TAG, rc))
    ok(any((_gone(b755_fs), _owner(b755_fs) not in (UID_ALICE, UID_SVC, 0))),
       "%s(1): no alice/svc/root file smuggled into bob/ via denied TPC" % TAG)
    # bob/ dir mode + ownership untouched by the denied dest open.
    bdmode = os.stat(os.path.join(data, "bob")).st_mode & 0o777
    ok(all((bdmode == 493, _owner(os.path.join(data, 'bob')) == UID_BOB)),
       "%s(1): bob/ dir intact bob:0755 after denied TPC (mode=%o)" % (TAG, bdmode))


def _rt61_2_cross_tenant_read_of_a(TAG, data, _rm, _owner, BOB_PUB, _content, BOB_PRIV, _gone):

    # =====================================================================
    # (2) CROSS-TENANT READ of a 0644 WORLD-readable source IS ALLOWED.
    #     alice TPC-pulls bob/readable.txt -> alice/ok.  Distinct POSITIVE
    #     cross-tenant leg: the world read bit legitimately grants the pull,
    #     dst must end up alice-owned + byte-exact (proving TPC honours the
    #     'other' read bit, not a blanket cross-tenant block).  And critically
    #     this is NOT bob's 0600 secret --- no private bytes appear.
    # =====================================================================
    ok_dst_rel = "/alice/%s_pub_pull.bin" % TAG
    ok_dst_fs = os.path.join(data, "alice", "%s_pub_pull.bin" % TAG)
    _rm(ok_dst_fs)
    rc, out, err = xrd_cp_tpc("/bob/readable.txt", ok_dst_rel, "alice")
    if rc == 0 and os.path.exists(ok_dst_fs):
        ok(_owner(ok_dst_fs) == UID_ALICE,
           "%s(2): alice TPC-pull of bob world-readable(0644) lands alice-owned "
           "uid=%d (rc=%d)" % (TAG, _owner(ok_dst_fs), rc))
        ok(_owner(ok_dst_fs) not in (UID_BOB, UID_SVC, 0),
           "%s(2): world-read pull dst NOT bob/svc/root-owned (uid=%d)"
           % (TAG, _owner(ok_dst_fs)))
        ok(BOB_PUB in _content(ok_dst_fs),
           "%s(2): world-read pull dst is byte-exact copy of bob/readable.txt" % TAG)
        ok(BOB_PRIV not in _content(ok_dst_fs),
           "%s(2): world-read pull carried NO bob private-secret bytes" % TAG)
    else:
        # If the server cannot TPC at all, accept gracefully but never with a
        # foreign-owned artifact, and never with the private secret leaked.
        ok(any((_gone(ok_dst_fs), _owner(ok_dst_fs) == UID_ALICE)),
           "%s(2): world-read TPC unsupported/handled (rc=%d), no foreign artifact"
           % (TAG, rc))
        ok(BOB_PRIV not in _content(ok_dst_fs),
           "%s(2): world-read TPC (handled) leaked no bob private secret" % TAG)


def _rt61_3_group_mediated_read_through_tpc(TAG, data, _rm):

    # =====================================================================
    # (3) GROUP-MEDIATED READ through TPC.  grp/research_r.txt is bob:research
    #     0640 (no other bits).  research = {bob, dave}.  dave is a MEMBER so
    #     his TPC-pull is granted *by group*; carol is NOT in research so her
    #     identical pull must be DENIED with the body never reaching disk.
    #     This is the group dimension neither prior batch tests on the READ
    #     side of a TPC (combo only forced group on the WRITE/setgid side).
    # =====================================================================
    res_rel = "/grp/research_r.txt"
    dave_ok_rel = "/dave/%s_grp_pull.bin" % TAG
    dave_ok_fs = os.path.join(data, "dave", "%s_grp_pull.bin" % TAG)
    _rm(dave_ok_fs)
    rc, out, err = xrd_cp_tpc(res_rel, dave_ok_rel, "dave")
    return res_rel, dave_ok_fs, rc


def _rt61_carol_is_not_in_research_her(rc, dave_ok_fs, RES_BODY, _content, _owner, TAG, _gone, data, _rm, res_rel):
    if rc == 0 and os.path.exists(dave_ok_fs):
        ok(all((RES_BODY in _content(dave_ok_fs), _owner(dave_ok_fs) == UID_DAVE)),
           "%s(3): dave(research member) TPC-pull of 0640 group file ALLOWED, "
           "dave-owned + byte-exact (rc=%d)" % (TAG, rc))
        ok(_owner(dave_ok_fs) not in (UID_BOB, UID_SVC, 0),
           "%s(3): dave's group-read pull dst NOT bob/svc/root-owned (uid=%d)"
           % (TAG, _owner(dave_ok_fs)))
    else:
        ok(any((_gone(dave_ok_fs), _owner(dave_ok_fs) == UID_DAVE)),
           "%s(3): dave group-read TPC unsupported/handled (rc=%d), no foreign dst"
           % (TAG, rc))
    # carol is NOT in research -> her pull of the SAME 0640 file is denied and
    # the research body never lands in carol's space.
    carol_steal_rel = "/carol/%s_grp_steal.bin" % TAG
    carol_steal_fs = os.path.join(data, "carol", "%s_grp_steal.bin" % TAG)
    _rm(carol_steal_fs)
    rc, out, err = xrd_cp_tpc(res_rel, carol_steal_rel, "carol")
    return carol_steal_fs, rc, out, err


def _rt61_4_push_side_mode_second_the(carol_steal_fs, RES_BODY, _content, out, err, rc, TAG, data):
    cleaked = (os.path.exists(carol_steal_fs) and RES_BODY in _content(carol_steal_fs)) \
        or (RES_BODY in (out or "").encode()) or (RES_BODY in (err or "").encode())
    ok(all((rc != 0, not cleaked)),
       "%s(3): carol(non-research) TPC-pull of 0640 research file DENIED, no leak "
       "(rc=%d)" % (TAG, rc))
    ok(not all((os.path.exists(carol_steal_fs), RES_BODY in _content(carol_steal_fs))),
       "%s(3): no carol file holds the research-group body bytes" % TAG)
    _tpc_pull_push_matrix_p2(TAG, data, _rm, c_src_rel, d_src_rel, BOB_PRIV, _gone, MARK_C, _owner, _content, MARK_D)


def _tpc_pull_push_matrix_p2(TAG, data, _rm, c_src_rel, d_src_rel, BOB_PRIV, _gone, MARK_C, _owner, _content, MARK_D):
    # =====================================================================
    # (4) PUSH-SIDE mode 'second' (the orchestration mode NOT exercised by
    #     run_native_tpc, which used first/delegate).  The mode only changes
    #     which endpoint drives the data pull; DAC must hold identically.
    #     Own-file copy under mode=second -> requester-owned if it lands; the
    #     cross-tenant private pull under mode=second stays denied.
    # =====================================================================
    sec_own_rel = "/carol/%s_sec_own.bin" % TAG
    sec_own_fs = os.path.join(data, "carol", "%s_sec_own.bin" % TAG)
    return sec_own_rel, sec_own_fs


def _rt61_segment_16(_rm, sec_own_fs, c_src_rel, sec_own_rel, _owner, _content, MARK_C, TAG, _gone, data):
    _rm(sec_own_fs)
    rc, out, err = xrd_cp_tpc(c_src_rel, sec_own_rel, "carol", mode="second")
    if rc == 0 and os.path.exists(sec_own_fs):
        ok(all((_owner(sec_own_fs) == UID_CAROL, _content(sec_own_fs) == MARK_C + b'\n')),
           "%s(4): mode=second carol own-copy carol-owned + byte-exact (rc=%d)"
           % (TAG, rc))
        ok(_owner(sec_own_fs) not in (UID_SVC, 0),
           "%s(4): mode=second own-copy never svc/root-owned (uid=%d)"
           % (TAG, _owner(sec_own_fs)))
    else:
        ok(any((_gone(sec_own_fs), _owner(sec_own_fs) == UID_CAROL)),
           "%s(4): mode=second own-copy unsupported/handled (rc=%d), no foreign dst"
           % (TAG, rc))
    sec_steal_rel = "/carol/%s_sec_steal.bin" % TAG
    sec_steal_fs = os.path.join(data, "carol", "%s_sec_steal.bin" % TAG)
    return sec_steal_rel, sec_steal_fs


def _rt61_5_nonexistent_source_clean_error_no(_rm, sec_steal_fs, sec_steal_rel, BOB_PRIV, _content, TAG):
    _rm(sec_steal_fs)
    rc, out, err = xrd_cp_tpc("/bob/private.txt", sec_steal_rel, "carol", mode="second")
    sleaked = (os.path.exists(sec_steal_fs) and BOB_PRIV in _content(sec_steal_fs)) \
        or (BOB_PRIV in (out or "").encode()) or (BOB_PRIV in (err or "").encode())
    ok(all((rc != 0, not sleaked)),
       "%s(4): mode=second cross-tenant pull of bob/private.txt(0600) DENIED, no "
       "leak (rc=%d)" % (TAG, rc))

    # =====================================================================
    # (5) NONEXISTENT SOURCE -> clean error, NO partial destination file.
    #     A TPC whose source open fails (ENOENT) must not leave a 0-byte or
    #     partial dst behind in the orchestrator's own space.
    # =====================================================================
    miss_rel = "/carol/%s_does_not_exist_%d.bin" % (TAG, int(time.time()))
    return miss_rel


def _rt61_segment_18(TAG, data, _rm, miss_rel):
    miss_dst_rel = "/carol/%s_miss_dst.bin" % TAG
    miss_dst_fs = os.path.join(data, "carol", "%s_miss_dst.bin" % TAG)
    _rm(miss_dst_fs)
    rc, out, err = xrd_cp_tpc(miss_rel, miss_dst_rel, "carol")
    ok(rc != 0,
       "%s(5): TPC of a nonexistent source fails cleanly (rc=%d)" % (TAG, rc))
    return miss_dst_fs


def _rt61_6_pub_0777_artifacts_created_by(_gone, miss_dst_fs, TAG, data):
    ok(_gone(miss_dst_fs),
       "%s(5): nonexistent-source TPC left NO partial destination file" % TAG)

    # =====================================================================
    # (6) pub/(0777) artifacts created by carol and dave (orchestrators
    #     DISTINCT from the alice/bob pair run_native_tpc(g) already proved):
    #     each lands owned by the COPIER, never svc/root, and dave's copy after
    #     carol's shows no principal bleed on the shared worker.
    _tpc_pull_push_matrix_p3(TAG, data, _rm, c_src_rel, d_src_rel, MARK_C, BOB_PRIV, _gone, _content, MARK_D, _owner)


def _tpc_pull_push_matrix_p3(TAG, data, _rm, c_src_rel, d_src_rel, MARK_C, BOB_PRIV, _gone, _content, MARK_D, _owner):
    # =====================================================================
    pub_c_rel = "/pub/%s_pub_carol.bin" % TAG
    pub_c_fs = os.path.join(data, "pub", "%s_pub_carol.bin" % TAG)
    pub_d_rel = "/pub/%s_pub_dave.bin" % TAG
    pub_d_fs = os.path.join(data, "pub", "%s_pub_dave.bin" % TAG)
    return pub_c_rel, pub_c_fs, pub_d_rel, pub_d_fs


def _rt61_segment_20(_rm, pub_c_fs, pub_d_fs, c_src_rel, pub_c_rel, _owner, TAG, _gone, d_src_rel, pub_d_rel, rc):
    _rm(pub_c_fs)
    _rm(pub_d_fs)
    rc, out, err = xrd_cp_tpc(c_src_rel, pub_c_rel, "carol")
    if rc == 0 and os.path.exists(pub_c_fs):
        ok(all((_owner(pub_c_fs) == UID_CAROL, _owner(pub_c_fs) not in (UID_SVC, 0))),
           "%s(6): carol TPC into pub/(0777) owned by carol not svc (uid=%d)"
           % (TAG, _owner(pub_c_fs)))
    else:
        ok(any((_gone(pub_c_fs), all((_owner(pub_c_fs) == UID_CAROL, _owner(pub_c_fs) not in (UID_SVC, 0))))),
           "%s(6): carol pub/ TPC unsupported/handled (rc=%d), no svc/root artifact"
           % (TAG, rc))
    rc, out, err = xrd_cp_tpc(d_src_rel, pub_d_rel, "dave")
    return rc


def _rt61_survival_secret_integrity_after_the_whole(rc, pub_d_fs, _owner, TAG, _content, MARK_D, _gone, _rm, c_src_rel, MARK_C):
    if rc == 0 and os.path.exists(pub_d_fs):
        ok(all((_owner(pub_d_fs) == UID_DAVE, _owner(pub_d_fs) not in (UID_CAROL, UID_SVC, 0))),
           "%s(6): dave TPC into same pub/ owned by dave, no carol/svc bleed "
           "(uid=%d)" % (TAG, _owner(pub_d_fs)))
        ok(_content(pub_d_fs) == MARK_D + b"\n",
           "%s(6): dave pub/ TPC dst byte-exact (no carol content bleed)" % TAG)
    else:
        ok(any((_gone(pub_d_fs), _owner(pub_d_fs) == UID_DAVE)),
           "%s(6): dave pub/ TPC unsupported/handled (rc=%d), no foreign artifact"
           % (TAG, rc))
    _tpc_pull_push_matrix_p4(_rm, c_src_rel, TAG, MARK_C, BOB_PRIV, _content, _owner, data)


def _tpc_pull_push_matrix_p4(_rm, c_src_rel, TAG, MARK_C, BOB_PRIV, _content, _owner, data):
    # =====================================================================
    # SURVIVAL + secret-integrity: after the whole matrix the broker/worker is
    # not wedged, and none of bob's protected fixtures were disturbed by any
    # denied dest-open / cross-tenant pull above.
    # =====================================================================
    surv = os.path.join(WORK, "%s_surv_dl.bin" % TAG)
    _rm(surv)
    rc_c, _o, _e = xrd_cp_down(c_src_rel, surv, "carol")
    ok(all((rc_c == 0, os.path.exists(surv), MARK_C in _content(surv))),
       "%s survival: carol legit read still works after the matrix (rc=%d)"
       % (TAG, rc_c))


def _rt61_segment_22(_content, data, BOB_PRIV, _owner, TAG):
    ok(all((_content(os.path.join(data, 'bob', 'private.txt')).startswith(BOB_PRIV), _owner(os.path.join(data, 'bob', 'private.txt')) == UID_BOB)),
       "%s survival: bob/private.txt secret + ownership intact after matrix" % TAG)
    ok(all((_owner(os.path.join(data, 'grp', 'research_r.txt')) == UID_BOB, os.stat(os.path.join(data, 'grp', 'research_r.txt')).st_gid == GID_RESEARCH)),
       "%s survival: grp/research_r.txt still bob:research after group-deny" % TAG)


def run_tpc_pull_push_matrix(key, data, port, s3port):
    """Native xrdcp --tpc loopback MATRIX under per-request UNIX impersonation.
    Distinct from run_native_tpc (owner/0700-dest/unmapped) and from
    run_combo_setgid_via_copymove (setgid-group inheritance through copy/TPC):
    this batch proves the ORTHOGONAL DAC dimensions of a third-party copy ---
    (1) cross-tenant WRITE into a 0755 dir the orchestrator does NOT own (no
    'other' write bit) is denied; (2) cross-tenant READ of a 0644 WORLD-readable
    source IS allowed and lands owner==orchestrator, byte-exact (a POSITIVE
    cross-tenant leg, not a denial); (3) GROUP-mediated read through TPC: a
    research-group member (dave) may pull a 0640 research file, a non-member
    (carol) may not, with no secret bytes on disk; (4) the push-side mode
    'second' (vs first/delegate already covered) still obeys DAC; (5) a
    NONEXISTENT source yields a clean error with NO partial destination file;
    (6) pub/(0777) artifacts created by carol/dave (orchestrators distinct from
    the alice/bob pair already tested) are owned by the COPIER, never svc/root.
    The invariant: a TPC is just a delegated open+read+write, so every endpoint
    obeys the orchestrator's impersonated identity --- the world bit grants,
    the missing other-write bit and the group boundary both deny."""
    TAG = _rt61_segment_01()

    if not xrd_avail():
        ok(True, "%s: TPC pull/push matrix SKIPPED (native client absent)" % TAG)
        return
    MARK_C, MARK_D, BOB_PUB, RES_BODY, BOB_PRIV = _rt61_segment_02()

    _owner = _rt61_segment_03()

    _rt61_segment_04()

    _content = _rt61_segment_05()

    _gone = _rt61_segment_06()

    _rm = _rt61_segment_07()

    c_src_rel, c_src_fs, d_src_rel, d_src_fs = _rt61_seed_orchestrator_owned_sources_we_control(TAG, data)

    seeded = _rt61_segment_09(c_src_fs, MARK_C, d_src_fs, MARK_D, data, TAG)

    if not seeded:
        return
    b755_rel, b755_fs = _rt61_1_cross_tenant_write_into_bob(data, TAG, _rm)

    _rt61_bob_dir_mode_ownership_untouched_by(c_src_rel, b755_rel, _gone, b755_fs, TAG, _owner, data)

    _rt61_2_cross_tenant_read_of_a(TAG, data, _rm, _owner, BOB_PUB, _content, BOB_PRIV, _gone)

    res_rel, dave_ok_fs, rc = _rt61_3_group_mediated_read_through_tpc(TAG, data, _rm)

    carol_steal_fs, rc, out, err = _rt61_carol_is_not_in_research_her(rc, dave_ok_fs, RES_BODY, _content, _owner, TAG, _gone, data, _rm, res_rel)

    sec_own_rel, sec_own_fs = _rt61_4_push_side_mode_second_the(carol_steal_fs, RES_BODY, _content, out, err, rc, TAG, data)

    sec_steal_rel, sec_steal_fs = _rt61_segment_16(_rm, sec_own_fs, c_src_rel, sec_own_rel, _owner, _content, MARK_C, TAG, _gone, data)

    miss_rel = _rt61_5_nonexistent_source_clean_error_no(_rm, sec_steal_fs, sec_steal_rel, BOB_PRIV, _content, TAG)

    miss_dst_fs = _rt61_segment_18(TAG, data, _rm, miss_rel)

    pub_c_rel, pub_c_fs, pub_d_rel, pub_d_fs = _rt61_6_pub_0777_artifacts_created_by(_gone, miss_dst_fs, TAG, data)

    rc = _rt61_segment_20(_rm, pub_c_fs, pub_d_fs, c_src_rel, pub_c_rel, _owner, TAG, _gone, d_src_rel, pub_d_rel, rc)

    _rt61_survival_secret_integrity_after_the_whole(rc, pub_d_fs, _owner, TAG, _content, MARK_D, _gone, _rm, c_src_rel, MARK_C)

    _rt61_segment_22(_content, data, BOB_PRIV, _owner, TAG)

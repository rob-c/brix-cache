def _rt32_segment_01():
    TAG = "ntpc"
    return TAG


def _rt32_seed_fixtures_we_control_created_as(TAG, data):

    MARK_A = b"NTPC-ALICE-OWN-SECRET-PAYLOAD"
    MARK_B = b"NTPC-BOB-OWN-SECRET-PAYLOAD"
    BOB_PRIV = b"BOB-PRIVATE-SECRET"          # bytes living in data/bob/private.txt

    # ---- Seed fixtures we control (created as in-ns root, then chown'd) ----------
    a_src_rel = "/alice/%s_src.bin" % TAG
    a_src_fs = os.path.join(data, "alice", "%s_src.bin" % TAG)
    return MARK_A, MARK_B, BOB_PRIV, a_src_rel, a_src_fs


def _rt32_segment_03(TAG, data):
    b_src_rel = "/bob/%s_src.bin" % TAG
    b_src_fs = os.path.join(data, "bob", "%s_src.bin" % TAG)
    return b_src_rel, b_src_fs


def _rt32_segment_04():

    def _owner(path):
        try:
            return os.stat(path).st_uid
        except OSError:
            return -1
    return _owner


def _rt32_segment_05():

    def _content(path):
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return _content


def _rt32_segment_06():

    def _gone(path):
        return not os.path.exists(path)
    return _gone


def _rt32_a_alice_tpc_copies_her_own(TAG, data, a_src_rel):

    # =================================================================
    # (a) alice TPC-copies her OWN file alice/src -> alice/dst
    #     dst owned by alice (1001), byte-exact, no svc/root ownership.
    # =================================================================
    a_dst_rel = "/alice/%s_dst.bin" % TAG
    a_dst_fs = os.path.join(data, "alice", "%s_dst.bin" % TAG)
    try:
        if os.path.exists(a_dst_fs):
            os.remove(a_dst_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc(a_src_rel, a_dst_rel, "alice")
    tpc_supported = (rc == 0 and os.path.exists(a_dst_fs))
    return a_dst_fs, rc, tpc_supported


def _rt32_positive_control_regardless_of_tpc_support(tpc_supported, _owner, a_dst_fs, TAG, rc, _content, MARK_A, _gone, data):
    if tpc_supported:
        ok(_owner(a_dst_fs) == UID_ALICE,
           "%s(a): alice self-TPC dst owned by alice uid=%d (rc=%d)"
           % (TAG, _owner(a_dst_fs), rc))
        ok(_owner(a_dst_fs) not in (UID_SVC, 0),
           "%s(a): self-TPC dst NOT owned by svc/root (uid=%d)"
           % (TAG, _owner(a_dst_fs)))
        ok(_content(a_dst_fs) == MARK_A + b"\n",
           "%s(a): self-TPC dst is byte-exact copy of source" % TAG)
    else:
        # Unsupported / refused: accept as handled, but assert NO svc/root artifact.
        ok(any((_gone(a_dst_fs), _owner(a_dst_fs) == UID_ALICE)),
           "%s(a): self-TPC unsupported/handled (rc=%d), no svc/root dst artifact"
           % (TAG, rc))
        ok(_owner(a_dst_fs) not in (UID_SVC, 0),
           "%s(a): self-TPC produced no svc/root-owned artifact (uid=%d)"
           % (TAG, _owner(a_dst_fs)))

    # Positive control regardless of TPC support: plain copy of own file works and
    # is alice-owned (proves the deny cases below are real, not blanket failure).
    a_ctl_rel = "/alice/%s_ctl.bin" % TAG
    a_ctl_fs = os.path.join(data, "alice", "%s_ctl.bin" % TAG)
    try:
        if os.path.exists(a_ctl_fs):
            os.remove(a_ctl_fs)
    except OSError:
        pass
    cdn = os.path.join(WORK, "%s_a_ctl_dl.bin" % TAG)
    return a_ctl_rel, a_ctl_fs, cdn


def _rt32_b_cross_tenant_source_alice_tpc(a_src_rel, cdn, a_ctl_rel, _owner, a_ctl_fs, _content, MARK_A, TAG, data):
    rc_d, _o, _e = xrd_cp_down(a_src_rel, cdn, "alice")
    rc_u, _o, _e = xrd_cp_up(cdn, a_ctl_rel.lstrip("/"), "alice")
    ok(all((rc_d == 0, rc_u == 0, _owner(a_ctl_fs) == UID_ALICE, _content(a_ctl_fs) == MARK_A + b'\n')),
       "%s control: alice plain down+up of own file works, alice-owned (rc=%d/%d)"
       % (TAG, rc_d, rc_u))

    # =================================================================
    # (b) CROSS-TENANT SOURCE: alice TPC-pulls bob/private.txt (0600)
    #     into alice/stolen -> DENIED, no stolen file with the secret.
    # =================================================================
    stolen_rel = "/alice/%s_stolen.bin" % TAG
    stolen_fs = os.path.join(data, "alice", "%s_stolen.bin" % TAG)
    return stolen_rel, stolen_fs


def _rt32_segment_01_3(stolen_fs):
    if os.path.exists(stolen_fs):
        os.remove(stolen_fs)


def _rt32_try_body(stolen_fs):
    _rt32_segment_01_3(stolen_fs)



def _rt32_segment_10(stolen_fs, stolen_rel, BOB_PRIV, _content, TAG):
    try:
        _rt32_try_body(stolen_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc("/bob/private.txt", stolen_rel, "alice")
    leaked_priv = (os.path.exists(stolen_fs) and BOB_PRIV in _content(stolen_fs)) \
        or (BOB_PRIV in (out or "").encode()) or (BOB_PRIV in (err or "").encode())
    ok(all((rc != 0, not leaked_priv)),
       "%s(b): alice TPC-pull of bob/private.txt(0600) DENIED (rc=%d)" % (TAG, rc))
    ok(not all((os.path.exists(stolen_fs), BOB_PRIV in _content(stolen_fs))),
       "%s(b): no stolen file in alice/ carries the BOB-PRIVATE secret marker" % TAG)
    return out, err


def _rt32_the_source_secret_must_not_have(BOB_PRIV, out, err, TAG, stolen_fs, _content, _owner, data):
    ok(all((BOB_PRIV not in any((out, '')).encode(), BOB_PRIV not in any((err, '')).encode())),
       "%s(b): bob private secret bytes absent from TPC stdout/stderr" % TAG)
    # The source secret must not have ended up anywhere alice-readable; if any file
    # was created it must NOT be a bob-owned secret smuggled in.
    if os.path.exists(stolen_fs):
        ok(all((BOB_PRIV not in _content(stolen_fs), _owner(stolen_fs) != UID_BOB)),
           "%s(b): residual alice/stolen (if any) holds no bob secret/ownership"
           % TAG)
    else:
        ok(True, "%s(b): no alice/stolen artifact created at all" % TAG)

    # =================================================================
    # (c) CROSS-TENANT DEST: alice TPC-copies alice/src -> bobsecret/x
    #     (bob 0700) -> DENIED, nothing created in bob's dir.
    # =================================================================
    bdst_rel = "/bobsecret/%s_x.bin" % TAG
    bdst_fs = os.path.join(data, "bobsecret", "%s_x.bin" % TAG)
    try:
        if os.path.exists(bdst_fs):
            os.remove(bdst_fs)
    except OSError:
        pass
    return bdst_rel, bdst_fs


def _rt32_bobsecret_dir_mode_must_be_untouched(a_src_rel, bdst_rel, _gone, bdst_fs, TAG, _owner, data):
    rc, out, err = xrd_cp_tpc(a_src_rel, bdst_rel, "alice")
    ok(all((rc != 0, _gone(bdst_fs))),
       "%s(c): alice TPC into bob's 0700 dir DENIED, nothing created (rc=%d)"
       % (TAG, rc))
    ok(any((_gone(bdst_fs), _owner(bdst_fs) not in (UID_ALICE, UID_SVC, 0))),
       "%s(c): no alice/svc/root-owned file smuggled into bobsecret/" % TAG)
    # bobsecret/ dir mode must be untouched (still bob 0700).
    try:
        dmode = os.stat(os.path.join(data, "bobsecret")).st_mode & 0o777
        downer = os.stat(os.path.join(data, "bobsecret")).st_uid
        ok(all((dmode == 448, downer == UID_BOB)),
           "%s(c): bobsecret/ dir intact bob:0700 after deny (mode=%o uid=%d)"
           % (TAG, dmode, downer))
    except OSError as e:
        ok(False, "%s(c): could not stat bobsecret/ (%r)" % (TAG, e))

    # =================================================================
    # (d) bob TPC-copies his OWN file -> owned by bob.
    # =================================================================
    b_dst_rel = "/bob/%s_dst.bin" % TAG
    return b_dst_rel


def _rt32_segment_01_4(st_fs):
    if os.path.exists(st_fs):
        os.remove(st_fs)


def _rt32_try_body_2(st_fs):
    _rt32_segment_01_4(st_fs)



def _rt32_segment_01_2(TAG, mode, data, BOB_PRIV, _content):
    st_rel = "/alice/%s_steal_%s.bin" % (TAG, mode)
    st_fs = os.path.join(data, "alice", "%s_steal_%s.bin" % (TAG, mode))
    try:
        _rt32_try_body_2(st_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc("/bob/private.txt", st_rel, "alice", mode=mode)
    leaked = (os.path.exists(st_fs) and BOB_PRIV in _content(st_fs)) \
        or (BOB_PRIV in (out or "").encode()) \
        or (BOB_PRIV in (err or "").encode())
    return rc, leaked


def _rt32_own_file_copy_under_this_mode(rc, leaked, TAG, mode, data, a_src_rel):
    ok(all((rc != 0, not leaked)),
       "%s(e): TPC mode=%s cross-tenant pull of bob secret DENIED, no leak (rc=%d)"
       % (TAG, mode, rc))
    # own-file copy under this mode: requester-owned if it materializes.
    od_rel = "/alice/%s_mode_%s.bin" % (TAG, mode)
    od_fs = os.path.join(data, "alice", "%s_mode_%s.bin" % (TAG, mode))
    try:
        if os.path.exists(od_fs):
            os.remove(od_fs)
    except OSError:
        pass
    rc2, _o2, _e2 = xrd_cp_tpc(a_src_rel, od_rel, "alice", mode=mode)
    return od_fs, rc2


def _rt32_segment_03_2(rc2, od_fs, _owner, _content, MARK_A, TAG, mode, _gone):
    if rc2 == 0 and os.path.exists(od_fs):
        ok(all((_owner(od_fs) == UID_ALICE, _content(od_fs) == MARK_A + b'\n')),
           "%s(e): TPC mode=%s own-copy alice-owned + byte-exact (rc=%d)"
           % (TAG, mode, rc2))
    else:
        ok(any((_gone(od_fs), _owner(od_fs) == UID_ALICE)),
           "%s(e): TPC mode=%s own-copy unsupported/handled, no foreign artifact"
           " (rc=%d)" % (TAG, mode, rc2))
    ok(_owner(od_fs) not in (UID_SVC, 0) if os.path.exists(od_fs) else True,
       "%s(e): TPC mode=%s own-copy never svc/root-owned" % (TAG, mode))


def _rt32_for_each_mode_first_delegate(TAG, mode, data, BOB_PRIV, _content, a_src_rel, _gone, _owner, MARK_A):
    rc, leaked = _rt32_segment_01_2(TAG, mode, data, BOB_PRIV, _content)

    od_fs, rc2 = _rt32_own_file_copy_under_this_mode(rc, leaked, TAG, mode, data, a_src_rel)

    _rt32_segment_03_2(rc2, od_fs, _owner, _content, MARK_A, TAG, mode, _gone)



def _rt32_segment_01_5(b_dst_fs):
    if os.path.exists(b_dst_fs):
        os.remove(b_dst_fs)


def _rt32_try_body_3(b_dst_fs):
    _rt32_segment_01_5(b_dst_fs)



def _rt32_e_tpc_mode_variants_first_and(data, TAG, b_src_rel, b_dst_rel, _owner, _content, MARK_B, _gone, BOB_PRIV, a_src_rel, MARK_A):
    b_dst_fs = os.path.join(data, "bob", "%s_dst.bin" % TAG)
    try:
        _rt32_try_body_3(b_dst_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc(b_src_rel, b_dst_rel, "bob")
    if rc == 0 and os.path.exists(b_dst_fs):
        ok(_owner(b_dst_fs) == UID_BOB,
           "%s(d): bob self-TPC dst owned by bob uid=%d (rc=%d)"
           % (TAG, _owner(b_dst_fs), rc))
        ok(_owner(b_dst_fs) not in (UID_ALICE, UID_SVC, 0),
           "%s(d): bob self-TPC dst NOT owned by alice/svc/root (uid=%d)"
           % (TAG, _owner(b_dst_fs)))
        ok(_content(b_dst_fs) == MARK_B + b"\n",
           "%s(d): bob self-TPC dst byte-exact" % TAG)
    else:
        ok(any((_gone(b_dst_fs), _owner(b_dst_fs) == UID_BOB)),
           "%s(d): bob self-TPC unsupported/handled (rc=%d), no foreign-owned dst"
           % (TAG, rc))
        ok(_owner(b_dst_fs) not in (UID_ALICE, UID_SVC, 0),
           "%s(d): bob self-TPC left no alice/svc/root artifact (uid=%d)"
           % (TAG, _owner(b_dst_fs)))

    # =================================================================
    # (e) TPC mode variants 'first' and 'delegate' (cross-tenant + own).
    #     Cross-tenant source must stay denied under EVERY mode; own copy
    #     under each mode, if it lands, must be requester-owned.
    # =================================================================
    for mode in ("first", "delegate"):
        # cross-tenant pull of bob's private must fail under this mode.
        _rt32_for_each_mode_first_delegate(TAG, mode, data, BOB_PRIV, _content, a_src_rel, _gone, _owner, MARK_A)


def _rt32_f_forged_non_mappable_principal_tpc(TAG, data, a_src_rel, _gone, out, err):

    # =================================================================
    # (f) FORGED / NON-MAPPABLE principal TPC -> denied, nothing created.
    #     A token whose sub does not map to a provisioned user must not be
    #     able to orchestrate a copy into alice's space.
    # =================================================================
    forged_rel = "/alice/%s_forged.bin" % TAG
    forged_fs = os.path.join(data, "alice", "%s_forged.bin" % TAG)
    try:
        if os.path.exists(forged_fs):
            os.remove(forged_fs)
    except OSError:
        pass
    # 'nobody-xyz' is not a provisioned identity; mint() builds a structurally valid
    # token but the broker has no uid mapping for it -> must be refused (fail-closed).
    rc, out, err = xrd_cp_tpc(a_src_rel, forged_rel, "nobody-xyz")
    ok(all((rc != 0, _gone(forged_fs))),
       "%s(f): TPC by unmapped principal DENIED, nothing created (rc=%d)"
       % (TAG, rc))
    return forged_fs, out, err


def _rt32_same_forged_principal_cannot_pull_bob(MARK_A, out, err, TAG, _gone, forged_fs, _owner, data):
    ok(all((MARK_A not in any((out, '')).encode(), MARK_A not in any((err, '')).encode())),
       "%s(f): unmapped-principal TPC leaked no alice source bytes" % TAG)
    ok(any((_gone(forged_fs), _owner(forged_fs) not in (UID_SVC, 0))),
       "%s(f): unmapped-principal TPC produced no svc/root artifact" % TAG)
    # Same forged principal cannot pull bob's secret either (no identity confusion).
    fsteal_rel = "/alice/%s_forged_steal.bin" % TAG
    fsteal_fs = os.path.join(data, "alice", "%s_forged_steal.bin" % TAG)
    try:
        if os.path.exists(fsteal_fs):
            os.remove(fsteal_fs)
    except OSError:
        pass
    return fsteal_rel, fsteal_fs


def _rt32_g_tpc_into_pub_0777_svc(fsteal_rel, fsteal_fs, BOB_PRIV, _content, TAG, data):
    rc, out, err = xrd_cp_tpc("/bob/private.txt", fsteal_rel, "nobody-xyz")
    fleak = (os.path.exists(fsteal_fs) and BOB_PRIV in _content(fsteal_fs)) \
        or (BOB_PRIV in (out or "").encode()) or (BOB_PRIV in (err or "").encode())
    ok(all((rc != 0, not fleak)),
       "%s(f): unmapped principal cannot TPC-steal bob secret (rc=%d)" % (TAG, rc))

    # =================================================================
    # (g) TPC into pub/ (0777, svc-owned) -> dst owned by the COPIER, not svc.
    #     Proves impersonation governs ownership even in a world-writable dir.
    # =================================================================
    pub_a_rel = "/pub/%s_pub_alice.bin" % TAG
    pub_a_fs = os.path.join(data, "pub", "%s_pub_alice.bin" % TAG)
    return pub_a_rel, pub_a_fs


def _rt32_segment_01_6(p):
    try:
        if os.path.exists(p):
            os.remove(p)
    except OSError:
        pass


def _rt32_for_each_p_pub_a_fs_pub_b(p):
    _rt32_segment_01_6(p)



def _rt32_segment_17(TAG, data, pub_a_fs, a_src_rel, pub_a_rel, _owner, _content, MARK_A, _gone):
    pub_b_rel = "/pub/%s_pub_bob.bin" % TAG
    pub_b_fs = os.path.join(data, "pub", "%s_pub_bob.bin" % TAG)
    for p in (pub_a_fs, pub_b_fs):
        _rt32_for_each_p_pub_a_fs_pub_b(p)
    rc, out, err = xrd_cp_tpc(a_src_rel, pub_a_rel, "alice")
    if rc == 0 and os.path.exists(pub_a_fs):
        ok(_owner(pub_a_fs) == UID_ALICE,
           "%s(g): alice TPC into pub/(0777) owned by alice not svc (uid=%d, rc=%d)"
           % (TAG, _owner(pub_a_fs), rc))
        ok(_owner(pub_a_fs) not in (UID_SVC, 0),
           "%s(g): pub/ TPC dst NOT svc/root-owned (uid=%d)" % (TAG, _owner(pub_a_fs)))
        ok(_content(pub_a_fs) == MARK_A + b"\n",
           "%s(g): pub/ TPC dst byte-exact" % TAG)
    else:
        ok(any((_gone(pub_a_fs), _owner(pub_a_fs) == UID_ALICE)),
           "%s(g): pub/ TPC unsupported/handled (rc=%d), no svc-owned artifact"
           % (TAG, rc))
        ok(_owner(pub_a_fs) not in (UID_SVC, 0) if os.path.exists(pub_a_fs) else True,
           "%s(g): pub/ TPC left no svc/root-owned artifact" % TAG)
    return pub_b_rel, pub_b_fs


def _rt32_bob_tpc_into_the_same_0777(b_src_rel, pub_b_rel, pub_b_fs, _owner, TAG, _content, MARK_B, _gone, a_src_rel, MARK_A):
    # bob TPC into the SAME 0777 dir must land bob-owned (no principal bleed from
    # the previous alice TPC on a shared worker).
    rc, out, err = xrd_cp_tpc(b_src_rel, pub_b_rel, "bob")
    if rc == 0 and os.path.exists(pub_b_fs):
        ok(all((_owner(pub_b_fs) == UID_BOB, _owner(pub_b_fs) not in (UID_ALICE, UID_SVC, 0))),
           "%s(g): bob TPC into pub/ owned by bob, no alice/svc bleed (uid=%d)"
           % (TAG, _owner(pub_b_fs)))
        ok(_content(pub_b_fs) == MARK_B + b"\n",
           "%s(g): bob pub/ TPC dst byte-exact" % TAG)
    else:
        ok(any((_gone(pub_b_fs), _owner(pub_b_fs) == UID_BOB)),
           "%s(g): bob pub/ TPC unsupported/handled (rc=%d), no foreign artifact"
           % (TAG, rc))
        ok(_owner(pub_b_fs) not in (UID_ALICE, UID_SVC, 0)
           if os.path.exists(pub_b_fs) else True,
           "%s(g): bob pub/ TPC never alice/svc/root-owned" % TAG)

    # =================================================================
    # WORKER-SURVIVAL: after all the denied / forged orchestration, a fresh
    # legit op by both tenants must still succeed (broker/worker not wedged).
    # =================================================================
    surv = os.path.join(WORK, "%s_surv_dl.bin" % TAG)
    rc_a, _o, _e = xrd_cp_down(a_src_rel, surv, "alice")
    ok(all((rc_a == 0, os.path.exists(surv), MARK_A in _content(surv))),
       "%s survival: alice legit read still works after TPC attacks (rc=%d)"
       % (TAG, rc_a))


def _rt32_and_bob_s_private_secret_was(TAG, _content, data, BOB_PRIV, _owner):
    rc_s, out_s, _e = xrd_fs(["stat", "/bob/private.txt"], "bob")
    ok(rc_s == 0, "%s survival: bob legit stat still works post-attack (rc=%d)"
       % (TAG, rc_s))
    # And bob's private secret was never disturbed by any of the above.
    ok(any((_content(os.path.join(data, 'bob', 'private.txt')) == BOB_PRIV, BOB_PRIV in _content(os.path.join(data, 'bob', 'private.txt')))),
       "%s survival: bob/private.txt secret intact after all TPC attempts" % TAG)
    ok(_owner(os.path.join(data, "bob", "private.txt")) == UID_BOB,
       "%s survival: bob/private.txt still bob-owned (uid=%d)"
       % (TAG, _owner(os.path.join(data, "bob", "private.txt"))))


def run_native_tpc(key, data, port, s3port):
    """Native THIRD-PARTY COPY (xrdcp --tpc) under per-request UNIX impersonation.
    Loopback TPC: source and destination are BOTH the impersonation stream server,
    so the orchestrated server-to-server copy still runs through the broker and the
    written destination MUST be owned by the mapped requester (never svc/root).  A
    cross-tenant SOURCE (pull bob's 0600) or cross-tenant DEST (push into bob's 0700
    dir) MUST be denied with nothing created/leaked.  If the server does not support
    --tpc at all we accept the legit case gracefully as handled, but the cross-tenant
    DENY/no-leak invariants are still asserted unconditionally."""
    TAG = _rt32_segment_01()

    if not xrd_avail():
        ok(True, "native TPC suite skipped (native client absent)")
        return
    MARK_A, MARK_B, BOB_PRIV, a_src_rel, a_src_fs = _rt32_seed_fixtures_we_control_created_as(TAG, data)

    b_src_rel, b_src_fs = _rt32_segment_03(TAG, data)

    try:
        with open(a_src_fs, "wb") as fh:
            fh.write(MARK_A + b"\n")
        os.chown(a_src_fs, UID_ALICE, UID_ALICE)
        os.chmod(a_src_fs, 0o644)
    except OSError as e:
        ok(False, "%s: could not seed alice src fixture (%r)" % (TAG, e))
        return
    try:
        with open(b_src_fs, "wb") as fh:
            fh.write(MARK_B + b"\n")
        os.chown(b_src_fs, UID_BOB, UID_BOB)
        os.chmod(b_src_fs, 0o600)
    except OSError as e:
        ok(False, "%s: could not seed bob src fixture (%r)" % (TAG, e))
        return
    _owner = _rt32_segment_04()

    _content = _rt32_segment_05()

    _gone = _rt32_segment_06()

    a_dst_fs, rc, tpc_supported = _rt32_a_alice_tpc_copies_her_own(TAG, data, a_src_rel)

    a_ctl_rel, a_ctl_fs, cdn = _rt32_positive_control_regardless_of_tpc_support(tpc_supported, _owner, a_dst_fs, TAG, rc, _content, MARK_A, _gone, data)

    stolen_rel, stolen_fs = _rt32_b_cross_tenant_source_alice_tpc(a_src_rel, cdn, a_ctl_rel, _owner, a_ctl_fs, _content, MARK_A, TAG, data)

    out, err = _rt32_segment_10(stolen_fs, stolen_rel, BOB_PRIV, _content, TAG)

    bdst_rel, bdst_fs = _rt32_the_source_secret_must_not_have(BOB_PRIV, out, err, TAG, stolen_fs, _content, _owner, data)

    b_dst_rel = _rt32_bobsecret_dir_mode_must_be_untouched(a_src_rel, bdst_rel, _gone, bdst_fs, TAG, _owner, data)

    _rt32_e_tpc_mode_variants_first_and(data, TAG, b_src_rel, b_dst_rel, _owner, _content, MARK_B, _gone, BOB_PRIV, a_src_rel, MARK_A)

    forged_fs, out, err = _rt32_f_forged_non_mappable_principal_tpc(TAG, data, a_src_rel, _gone, out, err)

    fsteal_rel, fsteal_fs = _rt32_same_forged_principal_cannot_pull_bob(MARK_A, out, err, TAG, _gone, forged_fs, _owner, data)

    pub_a_rel, pub_a_fs = _rt32_g_tpc_into_pub_0777_svc(fsteal_rel, fsteal_fs, BOB_PRIV, _content, TAG, data)

    pub_b_rel, pub_b_fs = _rt32_segment_17(TAG, data, pub_a_fs, a_src_rel, pub_a_rel, _owner, _content, MARK_A, _gone)

    _rt32_bob_tpc_into_the_same_0777(b_src_rel, pub_b_rel, pub_b_fs, _owner, TAG, _content, MARK_B, _gone, a_src_rel, MARK_A)

    _rt32_and_bob_s_private_secret_was(TAG, _content, data, BOB_PRIV, _owner)

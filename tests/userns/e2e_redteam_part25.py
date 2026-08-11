def _rt25_segment_01(key):
    TAG = "chgr"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    tc = mint(key, "carol")
    td = mint(key, "dave")
    return TAG, ta, tb, tc, td


def _rt25_segment_02(s3port):
    have_s3 = bool(s3port)
    have_root = xrd_avail()
    return have_s3, have_root


def _rt25_segment_03(data):

    def rel(*parts):
        return os.path.join(data, *parts)
    return rel


def _rt25_segment_04():

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1
    return uid_of


def _rt25_segment_05():

    def gid_of(p):
        try:
            return os.stat(p).st_gid
        except OSError:
            return -1
    return gid_of


def _rt25_segment_06():

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt25_st_uid_invariant_a_created_file():

    # st_uid invariant: a created file must be owned by the EXPECTED mapping user
    # and NEVER by root(0) / svc(1500) / any other tenant uid.
    OTHER = {0, UID_SVC}
    return OTHER


def _rt25_segment_08(uid_of, OTHER):

    def owned_by(p, want, *forbid):
        u = uid_of(p)
        bad = OTHER | set(forbid)
        return os.path.exists(p) and u == want and u not in bad
    return owned_by


def _rt25_section_a_setgid_dir_group_inheritance(TAG, port, tc, rel, owned_by, uid_of, gid_of):

    # ===================================================================
    # SECTION A — SETGID-DIR GROUP INHERITANCE is the only chgrp path, and it
    # only grants a group the actor is a MEMBER of.  sgiddir is 2770 alice:staff;
    # a staff member (carol) who creates there gets a file owned BY carol with
    # group INHERITED = staff (a group carol is genuinely in).  A non-member
    # (bob) cannot even enter the 2770 dir, so no inheritance can leak staff to him.
    # ===================================================================
    # (A1) carol (staff member) PUTs into the setgid staff dir -> created, owned carol.
    st, _ = http("PUT", "/sgiddir/%s_carol.txt" % TAG, port, tc,
                 b"carol-in-setgid\n")
    cp = rel("sgiddir", "%s_carol.txt" % TAG)
    ok(all((st in (200, 201, 204), owned_by(cp, UID_CAROL, UID_ALICE, UID_BOB))),
       "setgid dir: carol's file owned by carol 1003, not svc/root/alice "
       "(HTTP %s, uid=%s)" % (st, uid_of(cp)))
    # (A2) ...and the file INHERITED group=staff (2001) via the setgid bit — a
    #      group carol is a legit member of, so this is NOT an escalation.
    ok(all((os.path.exists(cp), gid_of(cp) == GID_STAFF)),
       "setgid dir: carol's created file inherited group=staff 2001 (legit member) "
       "(gid=%s)" % gid_of(cp))
    # (A3) carol is genuinely IN staff, so the inherited gid is a group she holds —
    #      assert the inherited group is one of carol's groups {staff, shared, proj},
    #      never a group she is not in (research 2002).
    ok(all((gid_of(cp) in (GID_STAFF, GID_SHARED, GID_PROJ), gid_of(cp) != GID_RESEARCH)),
       "setgid inheritance only granted a group carol is a member of, not research "
       "(gid=%s)" % gid_of(cp))


def _rt25_a5_deny_control_bob_is_not(TAG, port, ta, rel, owned_by, gid_of, uid_of, tb):
    # (A4) alice (owner of the dir, in staff) also inherits staff there, owned alice.
    st, _ = http("PUT", "/sgiddir/%s_alice.txt" % TAG, port, ta, b"alice-in-setgid\n")
    ap = rel("sgiddir", "%s_alice.txt" % TAG)
    ok(all((st in (200, 201, 204), owned_by(ap, UID_ALICE, UID_BOB), gid_of(ap) == GID_STAFF)),
       "setgid dir: alice's file owned alice 1001 + group staff inherited "
       "(HTTP %s, uid=%s, gid=%s)" % (st, uid_of(ap), gid_of(ap)))
    # (A5) DENY CONTROL — bob is NOT in staff -> cannot enter the 2770 dir at all,
    #      so he can NEVER acquire group=staff via setgid inheritance.
    st, _ = http("PUT", "/sgiddir/%s_bob.txt" % TAG, port, tb, b"bob-escalate\n")
    bsg = rel("sgiddir", "%s_bob.txt" % TAG)
    return st, bsg


def _rt25_a5b_and_if_any_byte_were(bsg, st, gid_of, TAG, port, td, rel):
    ok(not os.path.exists(bsg),
       "setgid dir: bob (NOT staff) cannot create -> no staff-group inheritance "
       "escalation (HTTP %s, exists=%s)" % (st, os.path.exists(bsg)))
    # (A5b) and if any byte WERE written it must not be staff-grouped (defence-in-depth).
    ok(not all((os.path.exists(bsg), gid_of(bsg) == GID_STAFF)),
       "setgid dir: no bob-owned file ended up grouped to staff (gid=%s)"
       % gid_of(bsg))
    # (A6) dave (research, not staff/shared) also cannot enter the 2770 staff dir.
    st, _ = http("PUT", "/sgiddir/%s_dave.txt" % TAG, port, td, b"dave-escalate\n")
    dsg = rel("sgiddir", "%s_dave.txt" % TAG)
    ok(not os.path.exists(dsg),
       "setgid dir: dave (NOT staff) cannot create -> no inheritance escalation "
       "(HTTP %s)" % st)


def _rt25_section_b_re_create_overwrite_never(TAG, port, tc, rel, uid_of, ta):

    # ===================================================================
    # SECTION B — RE-CREATE / OVERWRITE never reassigns OWNER to the prior owner.
    # carol creates a file (owned carol); alice then PUT-overwrites it in the
    # staff dir (alice has dir-write via group) -> staged replace makes the file
    # ALICE-owned.  Neither user could chown it to the other; ownership tracks the
    # ACTOR who created the inode, never a stale owner and never root/svc.
    # ===================================================================
    st, _ = http("PUT", "/staffdir/%s_b.txt" % TAG, port, tc, b"by-carol\n")
    bf = rel("staffdir", "%s_b.txt" % TAG)
    first_owner = uid_of(bf)
    ok(all((st in (200, 201, 204), first_owner == UID_CAROL)),
       "staff dir: file first created by carol owned carol 1003 (HTTP %s, uid=%s)"
       % (st, first_owner))
    st, _ = http("PUT", "/staffdir/%s_b.txt" % TAG, port, ta, b"rewritten-by-alice\n")
    return bf


def _rt25_section_c_webdav_move_copy_preserve(uid_of, bf, OTHER, body_of, TAG, port, ta, rel, st):
    ok(all((uid_of(bf) == UID_ALICE, uid_of(bf) not in OTHER)),
       "staff dir: alice's staged overwrite made the inode alice-owned, NOT "
       "chowned to carol/svc/root (uid=%s)" % uid_of(bf))
    # the body is alice's; no stale carol bytes, and never owned by svc/root.
    ok(all((b'rewritten-by-alice' in body_of(bf), uid_of(bf) not in OTHER)),
       "staff dir: overwritten body is alice's and owner is a real tenant uid "
       "(uid=%s)" % uid_of(bf))

    # ===================================================================
    # SECTION C — WebDAV MOVE / COPY preserve the ACTOR as owner; a tenant cannot
    # use MOVE/COPY to launder a file into another uid's or root's/svc's ownership.
    # ===================================================================
    http("PUT", "/alice/%s_mv_src.txt" % TAG, port, ta, b"alice-move-src\n")
    st, _ = http("MOVE", "/alice/%s_mv_src.txt" % TAG, port, ta,
                 hdrs={"Destination": "http://%s:%d/alice/%s_mv_dst.txt"
                                      % (HOST, port, TAG)})
    mvd = rel("alice", "%s_mv_dst.txt" % TAG)
    return st, mvd


def _rt25_carol_copying_alice_s_file_carol(st, owned_by, mvd, uid_of, TAG, port, ta, rel, tc):
    ok(all((st in (201, 204), owned_by(mvd, UID_ALICE, UID_BOB))),
       "MOVE dest stays alice-owned, not laundered to svc/root/bob (HTTP %s, uid=%s)"
       % (st, uid_of(mvd)))
    st, _ = http("COPY", "/alice/%s_mv_dst.txt" % TAG, port, ta,
                 hdrs={"Destination": "http://%s:%d/alice/%s_cp_dst.txt"
                                      % (HOST, port, TAG)})
    cpd = rel("alice", "%s_cp_dst.txt" % TAG)
    ok(all((st in (201, 204), owned_by(cpd, UID_ALICE, UID_BOB))),
       "COPY dest owned by the copying actor alice, never svc/root/bob "
       "(HTTP %s, uid=%s)" % (st, uid_of(cpd)))
    # carol COPYing alice's file (carol can read it via staff? no — it's in /alice
    # 0755, file is 0644 world-readable after copy chain) into HER OWN dir would be
    # owned by CAROL, not alice — but more importantly never root/svc.  Use a
    # world-readable source so the read leg is allowed and we isolate the chown
    # invariant: the resulting inode is the actor's, regardless of source owner.
    st, _ = http("COPY", "/grp/world_r.txt", port, tc,
                 hdrs={"Destination": "http://%s:%d/staffdir/%s_carol_cp.txt"
                                      % (HOST, port, TAG)})
    return st


def _rt25_section_d_webdav_proppatch_cannot_set(rel, TAG, uid_of, OTHER, st, port, ta, gid_of):
    ccp = rel("staffdir", "%s_carol_cp.txt" % TAG)
    if os.path.exists(ccp):
        ok(all((uid_of(ccp) == UID_CAROL, uid_of(ccp) not in OTHER)),
           "COPY of alice's world-readable file by carol -> owned CAROL (actor), "
           "not alice/svc/root (uid=%s)" % uid_of(ccp))
    else:
        ok(st not in (200, 201, 204),
           "carol COPY into staff dir refused cleanly (no svc/root-owned inode) "
           "(HTTP %s)" % st)
    _chown_chgrp_dac_p2(have_s3, have_root, port, ta, rel, tc, gid_of, tb, TAG, uid_of, s3port, OTHER, owned_by, body_of)


def _chown_chgrp_dac_p2(have_s3, have_root, port, ta, rel, tc, gid_of, tb, TAG, uid_of, s3port, OTHER, owned_by, body_of):
    # ===================================================================
    # SECTION D — WebDAV PROPPATCH cannot set owner / group / unix-mode dead
    # properties to escalate.  We PROPPATCH a uniquely-named set of properties that
    # NAME ownership concepts (owner, group, unix mode), then assert the file's
    # REAL st_uid / st_gid did not move to root/svc/another tenant or a non-member
    # group.  PROPPATCH stores DEAD properties as user.* xattrs; it must never be
    # wired to chown/chgrp/chmod the inode.
    # ===================================================================
    http("PUT", "/alice/%s_pp.txt" % TAG, port, ta, b"proppatch-target\n")
    ppf = rel("alice", "%s_pp.txt" % TAG)
    before_uid, before_gid = uid_of(ppf), gid_of(ppf)
    return ppf, before_uid, before_gid


def _rt25_segment_16(TAG, port, ta, uid_of, ppf, before_uid, OTHER, gid_of, before_gid):
    escalate_pp = (
        b'<?xml version="1.0"?>'
        b'<D:propertyupdate xmlns:D="DAV:" xmlns:U="urn:unix">'
        b'<D:set><D:prop>'
        b'<U:owner>root</U:owner>'
        b'<U:uid>0</U:uid>'
        b'<U:group>docker</U:group>'
        b'<U:gid>50</U:gid>'
        b'<U:mode>06777</U:mode>'
        b'</D:prop></D:set>'
        b'</D:propertyupdate>')
    st_pp, _ = http("PROPPATCH", "/alice/%s_pp.txt" % TAG, port, ta,
                    data=escalate_pp, hdrs={"Content-Type": "application/xml"})
    ok(all((uid_of(ppf) == before_uid == UID_ALICE, uid_of(ppf) not in OTHER)),
       "PROPPATCH naming owner=root/uid=0 did NOT chown the inode "
       "(PROPPATCH %s, uid=%s)" % (st_pp, uid_of(ppf)))
    ok(gid_of(ppf) == before_gid,
       "PROPPATCH naming group=docker/gid=50 did NOT chgrp the inode "
       "(gid=%s, was=%s)" % (gid_of(ppf), before_gid))
    try:
        ppmode = os.stat(ppf).st_mode & 0o7777
    except OSError:
        ppmode = -1
    return ppmode


def _rt25_carol_staff_can_dir_write_via(ppmode, TAG, port, tc, rel, gid_of):
    ok(all((ppmode != -1, ppmode & 2048 == 0, ppmode & 1024 == 0)),
       "PROPPATCH naming mode=06777 did NOT set setuid/setgid bits on the inode "
       "(mode=%o)" % ppmode)
    # carol (staff, can dir-write via group) PROPPATCHes alice's-group file naming
    # group=research (a group NEITHER she nor the file is in) -> no chgrp.
    http("PUT", "/staffdir/%s_pp2.txt" % TAG, port, tc, b"carol-pp\n")
    pp2 = rel("staffdir", "%s_pp2.txt" % TAG)
    g_before = gid_of(pp2)
    pp_grp = (b'<?xml version="1.0"?>'
              b'<D:propertyupdate xmlns:D="DAV:" xmlns:U="urn:unix">'
              b'<D:set><D:prop><U:gid>2002</U:gid><U:group>research</U:group>'
              b'</D:prop></D:set></D:propertyupdate>')
    return pp2, g_before, pp_grp


def _rt25_section_e_pub_0777_svc_svc(TAG, port, tc, pp_grp, gid_of, pp2, g_before, ta, rel, owned_by, uid_of):
    http("PROPPATCH", "/staffdir/%s_pp2.txt" % TAG, port, tc,
         data=pp_grp, hdrs={"Content-Type": "application/xml"})
    ok(all((gid_of(pp2) == g_before, gid_of(pp2) != GID_RESEARCH)),
       "PROPPATCH cannot move a file into the research group carol isn't in "
       "(gid=%s, was=%s)" % (gid_of(pp2), g_before))
    _chown_chgrp_dac_p3(have_s3, have_root, port, ta, rel, tb, TAG, s3port, owned_by, gid_of, uid_of, body_of)


def _chown_chgrp_dac_p3(have_s3, have_root, port, ta, rel, tb, TAG, s3port, owned_by, gid_of, uid_of, body_of):
    # ===================================================================
    # SECTION E — pub/ (0777 svc:svc) creation: the writer owns the file, never
    # svc, and the file does NOT inherit svc's group (no setgid on pub).  This is
    # the classic shared-spool chown trap.
    # ===================================================================
    st, _ = http("PUT", "/pub/%s_pub.txt" % TAG, port, ta, b"alice-in-pub\n")
    pubf = rel("pub", "%s_pub.txt" % TAG)
    ok(all((st in (200, 201, 204), owned_by(pubf, UID_ALICE, UID_BOB))),
       "pub 0777: alice's file owned alice, NEVER the svc dir-owner 1500 "
       "(HTTP %s, uid=%s)" % (st, uid_of(pubf)))
    return pubf


def _rt25_section_f_s3_alice_leg_only(pubf, gid_of, TAG, port, tb, rel, owned_by, uid_of, have_s3, s3port, body_of):
    ok(all((os.path.exists(pubf), gid_of(pubf) != UID_SVC)),
       "pub 0777 (not setgid): file did NOT inherit svc's group (gid=%s)"
       % gid_of(pubf))
    st, _ = http("PUT", "/pub/%s_pub_bob.txt" % TAG, port, tb, b"bob-in-pub\n")
    pubb = rel("pub", "%s_pub_bob.txt" % TAG)
    ok(all((st in (200, 201, 204), owned_by(pubb, UID_BOB, UID_ALICE))),
       "pub 0777: bob's file owned bob 1002, not alice/svc/root "
       "(HTTP %s, uid=%s)" % (st, uid_of(pubb)))

    # ===================================================================
    # SECTION F — S3 (alice leg only) ownership invariant under copy/recreate.
    # A CopyObject and an overwrite must keep the object owned by alice (1001),
    # never svc/root — S3 has no chown verb the tenant could abuse either.
    # ===================================================================
    if have_s3:
        s3("PUT", "alice/%s_s3.txt" % TAG, s3port, data=b"s3-alice\n")
        sf = rel("alice", "%s_s3.txt" % TAG)
        ok(owned_by(sf, UID_ALICE, UID_BOB),
           "S3 PUT object owned alice 1001, not svc/root/bob (uid=%s)" % uid_of(sf))
        st, _ = s3("PUT", "alice/%s_s3_cp.txt" % TAG, s3port,
                   extra_hdrs={"x-amz-copy-source":
                               "/%s/alice/%s_s3.txt" % (S3_BUCKET, TAG)})
        scp = rel("alice", "%s_s3_cp.txt" % TAG)
        ok(all((st in (200, 201), owned_by(scp, UID_ALICE, UID_BOB))),
           "S3 CopyObject result owned alice, never chowned to svc/root "
           "(HTTP %s, uid=%s)" % (st, uid_of(scp)))
        # overwrite keeps the actor's uid (no ownership carry-over to svc/root).
        s3("PUT", "alice/%s_s3.txt" % TAG, s3port, data=b"s3-alice-v2\n")
        ok(all((owned_by(sf, UID_ALICE, UID_BOB), b's3-alice-v2' in body_of(sf))),
           "S3 overwrite keeps object alice-owned, body updated (uid=%s)"
           % uid_of(sf))
    else:
        ok(True, "S3 ownership-invariant leg skipped (S3 endpoint down)")
        ok(True, "S3 CopyObject ownership leg skipped (S3 endpoint down)")
        ok(True, "S3 overwrite ownership leg skipped (S3 endpoint down)")
    _chown_chgrp_dac_p4(have_root, port, ta, rel, TAG, uid_of, owned_by, gid_of)


def _rt25_carol_creates_in_the_setgid_staff_2(lf, TAG, rel, owned_by, uid_of):
    rc, _o, _e = xrd_cp_up(lf, "/alice/%s_root.bin" % TAG, "alice")
    rf = rel("alice", "%s_root.bin" % TAG)
    ok(all((rc == 0, owned_by(rf, UID_ALICE, UID_BOB))),
       "root:// xrdcp create owned alice 1001, not svc/root/bob "
       "(rc=%s, uid=%s)" % (rc, uid_of(rf)))
    # carol creates in the setgid staff dir via root:// -> owned carol,
    # group staff inherited (a group carol is in) — cross-protocol parity
    # with the WebDAV setgid leg above.
    rc, _o, _e = xrd_cp_up(lf, "/sgiddir/%s_root_carol.bin" % TAG, "carol")
    rcf = rel("sgiddir", "%s_root_carol.bin" % TAG)
    return rc, rcf


def _rt25_bob_not_staff_cannot_create_in(rc, rcf, owned_by, gid_of, uid_of, lf, TAG, rel):
    if rc == 0 and os.path.exists(rcf):
        ok(all((owned_by(rcf, UID_CAROL, UID_ALICE, UID_BOB), gid_of(rcf) == GID_STAFF)),
           "root:// setgid dir: carol's file owned carol + group staff "
           "inherited (legit) (uid=%s, gid=%s)"
           % (uid_of(rcf), gid_of(rcf)))
    else:
        ok(any((rc != 0, not os.path.exists(rcf))),
           "root:// carol create in setgid dir refused cleanly (rc=%s)" % rc)
    # bob (NOT staff) cannot create in the 2770 staff dir via root:// either.
    rc, _o, _e = xrd_cp_up(lf, "/sgiddir/%s_root_bob.bin" % TAG, "bob")
    rbf = rel("sgiddir", "%s_root_bob.bin" % TAG)
    ok(all((rc != 0, not os.path.exists(rbf))),
       "root:// setgid dir: bob (NOT staff) denied -> no staff inheritance "
       "escalation (rc=%s)" % rc)
    return rc


def _rt25_when_lf(lf, TAG, rel, owned_by, uid_of, gid_of):
    rc, rcf = _rt25_carol_creates_in_the_setgid_staff_2(lf, TAG, rel, owned_by, uid_of)

    rc = _rt25_bob_not_staff_cannot_create_in(rc, rcf, owned_by, gid_of, uid_of, lf, TAG, rel)

    return rc


def _rt25_carol_creates_in_the_setgid_staff(TAG, rel, owned_by, uid_of, gid_of):
    lf = os.path.join(WORK, "%s_root_up.bin" % TAG)
    try:
        with open(lf, "wb") as fh:
            fh.write(b"root-alice-create\n")
    except OSError:
        lf = None
    if lf:
        rc = _rt25_when_lf(lf, TAG, rel, owned_by, uid_of, gid_of)
    else:
        ok(True, "root:// create ownership leg skipped (scratch write failed)")
        ok(True, "root:// setgid carol leg skipped (scratch write failed)")
        ok(True, "root:// setgid bob-deny leg skipped (scratch write failed)")
    # MV via root:// keeps the actor's uid (alice moves her own file).
    if lf and os.path.exists(rel("alice", "%s_root.bin" % TAG)):
        rc, _o, _e = xrd_fs(["mv", "/alice/%s_root.bin" % TAG,
                             "/alice/%s_root_mv.bin" % TAG], "alice")
        mvf = rel("alice", "%s_root_mv.bin" % TAG)
        ok(all((rc == 0, owned_by(mvf, UID_ALICE, UID_BOB))),
           "root:// mv keeps alice-owned, never relabelled to svc/root/bob "
           "(rc=%s, uid=%s)" % (rc, uid_of(mvf)))
    else:
        ok(True, "root:// mv ownership leg skipped (source absent)")


def _rt25_when_have_root(TAG, rel, owned_by, uid_of, gid_of):
    _rt25_carol_creates_in_the_setgid_staff(TAG, rel, owned_by, uid_of, gid_of)



def _rt25_segment_01_2(rel, sub, TAG, uid_of, leaked_owner):
    d = rel(sub)
    try:
        names = os.listdir(d)
    except OSError:
        names = []
    for n in names:
        if not n.startswith(TAG):
            continue
        u = uid_of(os.path.join(d, n))
        if u in (0, UID_SVC):
            leaked_owner.append("%s/%s=%d" % (sub, n, u))


def _rt25_for_each_sub_alice_bob_pub_sgiddir_staffdir(rel, sub, uid_of, TAG, leaked_owner):
    _rt25_segment_01_2(rel, sub, TAG, uid_of, leaked_owner)



def _rt25_section_g_root_native_stream_ownership(have_root, TAG, rel, owned_by, uid_of, gid_of, port, ta, st):

    # ===================================================================
    # SECTION G — root:// (native stream) ownership invariant.  root:// exposes NO
    # chown subcommand, so the only test is that every create / mv keeps the
    # mapped user's uid and never lands as svc/root.  Also a cross-tenant MV must
    # not relabel ownership.  GUARDED by xrd_avail().
    # ===================================================================
    if have_root:
        _rt25_when_have_root(TAG, rel, owned_by, uid_of, gid_of)
    else:
        ok(True, "root:// create ownership leg skipped (native client absent)")
        ok(True, "root:// setgid carol leg skipped (native client absent)")
        ok(True, "root:// setgid bob-deny leg skipped (native client absent)")
        ok(True, "root:// mv ownership leg skipped (native client absent)")
    _chown_chgrp_dac_p5(port, ta, rel, uid_of, TAG)


def _chown_chgrp_dac_p5(port, ta, rel, uid_of, TAG):
    # ===================================================================
    # SECTION H — GLOBAL SWEEP: after every op above, NO file under any of the
    # exercised dirs may be owned by uid 0 or svc(1500).  This is the broad
    # anti-escalation backstop (a single leaked chown anywhere trips it), plus a
    # worker-survival check that the run did not crash the worker.
    # ===================================================================
    leaked_owner = []
    for sub in ("alice", "bob", "pub", "sgiddir", "staffdir"):
        _rt25_for_each_sub_alice_bob_pub_sgiddir_staffdir(rel, sub, uid_of, TAG, leaked_owner)
    ok(not leaked_owner,
       "global: no %s-tagged file ended up owned by root(0)/svc(1500) (leaks=%s)"
       % (TAG, leaked_owner or "none"))
    # worker still serving (a chown/PROPPATCH abuse must not desync/crash it).
    st, b = http("GET", "/grp/world_r.txt", port, ta)
    return st, b


def _rt25_segment_21(st, b):
    ok(all((st == 200, b'WORLD-READABLE' in any((b, b'')))),
       "worker survived the chown/chgrp/PROPPATCH battery; still serving (HTTP %s)"
       % st)


def run_chown_chgrp_dac(key, data, port, s3port):
    """OWNERSHIP / GROUP-CHANGE anti-escalation matrix.  The broker holds NO
    CAP_CHOWN, so NO protocol sequence may reassign a file's OWNER to another uid
    (root 0 / svc 1500 / another tenant) and NO sequence may GROUP a file to a
    group the creator is not a member of.  The ONLY legitimate group-set path is
    SETGID-directory inheritance, which still only grants a group the actor (or the
    dir) already carries.  We verify: (a) created files keep the creator's uid
    across WebDAV/S3/root MOVE/COPY/recreate; (b) a member creating in a 2770
    setgid staff dir inherits group=staff ONLY when a member (carol yes, bob's
    create denied outright); (c) WebDAV PROPPATCH cannot set owner/group/mode
    dead-properties to escalate; (d) no op yields uid 0/1500/other-tenant or a
    non-member group.  Each cell is one ok()."""
    TAG, ta, tb, tc, td = _rt25_segment_01(key)

    have_s3, have_root = _rt25_segment_02(s3port)

    rel = _rt25_segment_03(data)

    uid_of = _rt25_segment_04()

    gid_of = _rt25_segment_05()

    body_of = _rt25_segment_06()

    OTHER = _rt25_st_uid_invariant_a_created_file()

    owned_by = _rt25_segment_08(uid_of, OTHER)

    _rt25_section_a_setgid_dir_group_inheritance(TAG, port, tc, rel, owned_by, uid_of, gid_of)

    st, bsg = _rt25_a5_deny_control_bob_is_not(TAG, port, ta, rel, owned_by, gid_of, uid_of, tb)

    _rt25_a5b_and_if_any_byte_were(bsg, st, gid_of, TAG, port, td, rel)

    bf = _rt25_section_b_re_create_overwrite_never(TAG, port, tc, rel, uid_of, ta)

    st, mvd = _rt25_section_c_webdav_move_copy_preserve(uid_of, bf, OTHER, body_of, TAG, port, ta, rel, st)

    st = _rt25_carol_copying_alice_s_file_carol(st, owned_by, mvd, uid_of, TAG, port, ta, rel, tc)

    ppf, before_uid, before_gid = _rt25_section_d_webdav_proppatch_cannot_set(rel, TAG, uid_of, OTHER, st, port, ta, gid_of)

    ppmode = _rt25_segment_16(TAG, port, ta, uid_of, ppf, before_uid, OTHER, gid_of, before_gid)

    pp2, g_before, pp_grp = _rt25_carol_staff_can_dir_write_via(ppmode, TAG, port, tc, rel, gid_of)

    pubf = _rt25_section_e_pub_0777_svc_svc(TAG, port, tc, pp_grp, gid_of, pp2, g_before, ta, rel, owned_by, uid_of)

    _rt25_section_f_s3_alice_leg_only(pubf, gid_of, TAG, port, tb, rel, owned_by, uid_of, have_s3, s3port, body_of)

    st, b = _rt25_section_g_root_native_stream_ownership(have_root, TAG, rel, owned_by, uid_of, gid_of, port, ta, st)

    _rt25_segment_21(st, b)

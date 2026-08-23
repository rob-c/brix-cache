def _rt21_setgid_directory_group_inheritance_under_per():
    # =========================================================================
    # SETGID DIRECTORY GROUP INHERITANCE under per-request UNIX impersonation.
    #
    # sgiddir/ is 2770 alice:staff (SETGID bit). When a staff member creates a
    # file inside it, the kernel forces the new file's GROUP to staff (2001),
    # inherited from the directory, NOT the creator's primary group. The OWNER
    # is the creating (mapped) user. New subdirectories ALSO inherit the setgid
    # bit + the staff group.
    #
    # Security properties exercised:
    #   - INVARIANT: created file group == GID_STAFF (inherited), owner == creator
    #   - INVARIANT: nested subdir is setgid + group staff (bit propagates)
    #   - DENY:      a non-staff member (bob) cannot read the group-0640 file
    #               created via inheritance; secret marker bytes never leak
    #   - POSITIVE:  a DIFFERENT staff member (alice) CAN read it via the group
    #   - MULTI-PARTY: one member writes group-writable, another overwrites it
    #
    # All creates flow through the broker create path (setfsuid/setfsgid +
    # setgroups for the mapped user); kernel applies setgid semantics on top.
    # =========================================================================
    TAG = "sgi"
    GID_STAFF = 2001
    GID_RESEARCH = 2002
    UID_ALICE = 1001
    UID_CAROL = 1003
    return TAG, GID_STAFF, GID_RESEARCH, UID_ALICE, UID_CAROL


def _rt21_segment_02(data):
    SECRET = b"MATRIX-SECRET-BODY"

    sgiddir = os.path.join(data, "sgiddir")
    return sgiddir


def _rt21_tolerant_search_for_marker_bytes_in():

    def find_in_body(body, needle):
        # Tolerant search for marker bytes in a (possibly multipart/xml) body.
        if body is None:
            return False
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return needle in body
    return find_in_body


def _rt21_segment_04():

    def stat_safe(p):
        try:
            return os.stat(p)
        except OSError:
            return None
    return stat_safe


def _rt21_carol_alice_are_staff_bob_dave(key, stat_safe, sgiddir):

    # carol & alice are staff; bob & dave are not (research); use tokens.
    t_carol = mint(key, "carol")
    t_alice = mint(key, "alice")
    t_bob = mint(key, "bob")
    t_dave = mint(key, "dave")

    # -------------------------------------------------------------------------
    # PRE-FLIGHT INVARIANT: sgiddir really is setgid + group staff on disk.
    # If this is false the whole dimension is meaningless, so assert it first.
    # -------------------------------------------------------------------------
    st_dir = stat_safe(sgiddir)
    return t_carol, t_alice, t_bob, st_dir


def _rt21_part_a_webdav_put_by_a(st_dir, GID_STAFF, TAG, data, sgiddir):
    ok(st_dir is not None, "sgi: sgiddir/ exists on disk (rc=stat)")
    if st_dir is not None:
        ok((st_dir.st_mode & 0o2000) != 0,
           "sgi: sgiddir/ has SETGID bit set (mode={:o})".format(st_dir.st_mode))
        ok(st_dir.st_gid == GID_STAFF,
           "sgi: sgiddir/ group == staff ({})".format(st_dir.st_gid))

    # =========================================================================
    # PART A — WebDAV PUT by a staff member (carol) -> setgid inheritance.
    # carol's PRIMARY group is staff too, but the meaningful check is that the
    # file lands group=staff via the dir, owner=carol; we then prove a SECOND
    # staff member (alice) reaches it by group and a NON-member (bob) cannot.
    # =========================================================================
    relA = "sgiddir/{}_carol_put.txt".format(TAG)
    pathA = os.path.join(data, "{}_carol_put.txt".format(TAG))
    pathA = os.path.join(sgiddir, "{}_carol_put.txt".format(TAG))
    return relA, pathA


def _rt21_segment_07(relA, port, t_carol, stat_safe, pathA):
    bodyA = b"SGI-CAROL-INHERIT-BODY"
    stp, _ = http("PUT", "/" + relA, port, token=t_carol, data=bodyA)
    ok(stp in (200, 201, 204),
       "sgi: carol PUT into setgid dir succeeded (HTTP {})".format(stp))

    stA = stat_safe(pathA)
    ok(stA is not None, "sgi: carol-created file exists on disk after PUT (rc=stat)")
    return bodyA, stp, stA


def _rt21_positive_control_a_different_staff_member(stA, GID_STAFF, stp, UID_CAROL, pathA, relA, port, t_alice, find_in_body, bodyA):
    if stA is not None:
        ok(stA.st_gid == GID_STAFF,
           "sgi: INHERIT carol's file group == staff ({}) not carol-primary (HTTP {})".format(stA.st_gid, stp))
        ok(stA.st_uid == UID_CAROL,
           "sgi: carol-created file OWNER == carol uid {} (HTTP {})".format(UID_CAROL, stp))

    # Make it group-readable-only (0640) so OTHER bits cannot leak it.
    try:
        os.chmod(pathA, 0o640)
        chmodA_ok = True
    except OSError:
        chmodA_ok = False
    ok(chmodA_ok, "sgi: chmod 0640 on carol-created file (rc=os.chmod)")

    # POSITIVE CONTROL: a DIFFERENT staff member (alice) reads via inherited group.
    sta, ba = http("GET", "/" + relA, port, token=t_alice)
    ok(all((sta == 200, find_in_body(ba, bodyA))),
       "sgi: POSITIVE alice (staff) reads group-inherited file (HTTP {})".format(sta))


def _rt21_part_b_nested_subdir_inside_sgiddir(relA, port, t_bob, find_in_body, bodyA, TAG, sgiddir):

    # DENY: bob (research, NOT staff) cannot read the 0640 group=staff file.
    stb, bb = http("GET", "/" + relA, port, token=t_bob)
    ok(stb in (403, 401, 404, 500),
       "sgi: DENY bob (non-staff) read of group-inherited 0640 file rejected (HTTP {})".format(stb))
    ok(not find_in_body(bb, bodyA),
       "sgi: NO-LEAK carol-body bytes absent from bob's denied read (HTTP {})".format(stb))

    # =========================================================================
    # PART B — nested SUBDIR inside sgiddir via WebDAV MKCOL -> setgid + group
    # must PROPAGATE to the child directory; a file created inside the child
    # also inherits staff. This proves the bit is sticky down the tree.
    # =========================================================================
    relSub = "sgiddir/{}_sub".format(TAG)
    pathSub = os.path.join(sgiddir, "{}_sub".format(TAG))
    return relSub, pathSub


def _rt21_segment_10(relSub, port, t_carol, stat_safe, pathSub, GID_STAFF):
    stm, _ = http("MKCOL", "/" + relSub, port, token=t_carol)
    ok(stm in (200, 201, 204),
       "sgi: carol MKCOL nested subdir in setgid dir (HTTP {})".format(stm))

    stSub = stat_safe(pathSub)
    ok(stSub is not None, "sgi: nested subdir exists on disk (rc=stat)")
    if stSub is not None:
        ok((stSub.st_mode & 0o2000) != 0,
           "sgi: PROPAGATE nested subdir keeps SETGID bit (mode={:o})".format(stSub.st_mode))
        ok(stSub.st_gid == GID_STAFF,
           "sgi: PROPAGATE nested subdir group == staff ({}) (HTTP {})".format(stSub.st_gid, stm))


def _rt21_file_inside_the_nested_setgid_subdir(relSub, TAG, pathSub, port, t_carol):

    # File inside the nested setgid subdir. MKCOL created sgi_sub mode 02755
    # (owner carol, group staff, group r-x): the setgid bit + staff group
    # PROPAGATE, but a group-WRITE bit does NOT. So the OWNER (carol) can create
    # inside it (and the file inherits staff via setgid), while a different staff
    # member who is only a GROUP member (alice) is correctly DENIED write by POSIX
    # DAC. This proves setgid group inheritance AND that inheritance never grants
    # write the directory mode withholds.
    relSubF = relSub + "/{}_child.txt".format(TAG)
    pathSubF = os.path.join(pathSub, "{}_child.txt".format(TAG))
    bodySubF = b"SGI-NESTED-CHILD-BODY"
    # Owner (carol) creates -> succeeds, group inherited from setgid dir.
    stsf, _ = http("PUT", "/" + relSubF, port, token=t_carol, data=bodySubF)
    ok(stsf in (200, 201, 204),
       "sgi: carol (owner) PUT into nested setgid subdir (HTTP {})".format(stsf))
    return pathSubF, stsf


def _rt21_dac_alice_is_in_staff_but(stat_safe, pathSubF, GID_STAFF, stsf, UID_CAROL, relSub, TAG, pathSub):
    stSubF = stat_safe(pathSubF)
    ok(stSubF is not None, "sgi: nested-child file exists on disk (rc=stat)")
    if stSubF is not None:
        ok(stSubF.st_gid == GID_STAFF,
           "sgi: INHERIT nested-child group == staff ({}) (HTTP {})".format(stSubF.st_gid, stsf))
        ok(stSubF.st_uid == UID_CAROL,
           "sgi: nested-child OWNER == carol uid {} (HTTP {})".format(UID_CAROL, stsf))
    # DAC: alice is in staff but NOT the owner and the subdir is group r-x only
    # (0755), so she may NOT create a sibling file. Inheritance must not leak the
    # write bit the directory mode withholds.
    relSubF2 = relSub + "/{}_alice_child.txt".format(TAG)
    pathSubF2 = os.path.join(pathSub, "{}_alice_child.txt".format(TAG))
    return relSubF2, pathSubF2


def _rt21_part_c_multi_party_group_write(relSubF2, port, t_alice, stat_safe, pathSubF2, TAG, sgiddir):
    stsf2, _ = http("PUT", "/" + relSubF2, port, token=t_alice, data=b"SGI-ALICE-DENIED")
    ok(stsf2 in (403, 401, 409, 500),
       "sgi: DENY alice write into non-group-writable 0755 setgid subdir (HTTP {})".format(stsf2))
    ok(stat_safe(pathSubF2) is None,
       "sgi: alice's denied file never landed in the nested subdir (no DAC bypass)")

    # =========================================================================
    # PART C — MULTI-PARTY group-write contention: carol creates a group-writable
    # file (0660, group=staff inherited), alice OVERWRITES it via the group write
    # bit. Owner stays carol, group stays staff, body == alice's new content.
    # Then bob (non-staff) is DENIED the overwrite and his bytes never land.
    # =========================================================================
    relGW = "sgiddir/{}_groupwrite.txt".format(TAG)
    pathGW = os.path.join(sgiddir, "{}_groupwrite.txt".format(TAG))
    return relGW, pathGW


def _rt21_segment_14(relGW, port, t_carol, pathGW):
    body_c = b"SGI-GW-FROM-CAROL"
    stc, _ = http("PUT", "/" + relGW, port, token=t_carol, data=body_c)
    ok(stc in (200, 201, 204),
       "sgi: carol creates group-writable file (HTTP {})".format(stc))
    try:
        os.chmod(pathGW, 0o660)
        chmodGW_ok = True
    except OSError:
        chmodGW_ok = False
    ok(chmodGW_ok, "sgi: chmod 0660 group-writable (rc=os.chmod)")
    return body_c


def _rt21_positive_alice_staff_member_not_owner(stat_safe, pathGW, GID_STAFF, relGW, port, t_alice):
    stGW0 = stat_safe(pathGW)
    if stGW0 is not None:
        ok(stGW0.st_gid == GID_STAFF,
           "sgi: group-writable file group == staff ({})".format(stGW0.st_gid))

    # POSITIVE: alice (staff member, not owner) overwrites via GROUP write bit.
    body_a = b"SGI-GW-OVERWRITTEN-BY-ALICE"
    sta2, _ = http("PUT", "/" + relGW, port, token=t_alice, data=body_a)
    ok(sta2 in (200, 201, 204),
       "sgi: POSITIVE alice overwrites group-writable file via group bit (HTTP {})".format(sta2))
    return body_a, sta2


def _rt21_confirm_alice_s_bytes_actually_landed(stat_safe, pathGW, UID_ALICE, sta2, GID_STAFF, relGW, port, t_carol, find_in_body, body_a):
    stGW1 = stat_safe(pathGW)
    ok(stGW1 is not None, "sgi: group-writable file still present after overwrite (rc=stat)")
    if stGW1 is not None:
        ok(all((stGW1.st_uid == UID_ALICE, stGW1.st_uid != UID_SVC, stGW1.st_uid != 0)),
           "sgi: staged-write overwrite makes the WRITER alice {} the owner, a real mapped user (not svc/root) (HTTP {})".format(UID_ALICE, sta2))
        ok(stGW1.st_gid == GID_STAFF,
           "sgi: overwrite preserves GROUP staff ({}) (HTTP {})".format(stGW1.st_gid, sta2))
    # Confirm alice's bytes actually landed (read back as staff).
    stgr, bgr = http("GET", "/" + relGW, port, token=t_carol)
    ok(all((stgr == 200, find_in_body(bgr, body_a))),
       "sgi: overwritten body == alice's content on readback (HTTP {})".format(stgr))
    return stgr, bgr


def _rt21_deny_bob_non_staff_attempts_to(find_in_body, bgr, body_c, stgr, relGW, port, t_bob, stat_safe, pathGW):
    ok(not find_in_body(bgr, body_c),
       "sgi: NO-STALE carol's original bytes gone after overwrite (HTTP {})".format(stgr))

    # DENY: bob (non-staff) attempts to overwrite the 0660 group=staff file.
    body_b = b"SGI-GW-BOB-INTRUSION"
    stbw, _ = http("PUT", "/" + relGW, port, token=t_bob, data=body_b)
    ok(stbw in (403, 401, 404, 500),
       "sgi: DENY bob (non-staff) overwrite of group-writable file rejected (HTTP {})".format(stbw))
    stGW2 = stat_safe(pathGW)
    return body_b, stGW2


def _rt21_segment_01(TAG, sgiddir):
    rel_deny = "sgiddir/{}_dave_deny.txt".format(TAG)
    path_deny = os.path.join(sgiddir, "{}_dave_deny.txt".format(TAG))
    src_deny = os.path.join(WORK, "{}_dave_src.txt".format(TAG))
    try:
        with open(src_deny, "wb") as f:
            f.write(b"SGI-DAVE-SHOULD-NOT-LAND")
    except OSError:
        pass
    rcd, _od, _ed = xrd_cp_up(src_deny, "/" + rel_deny, "dave")
    return path_deny, rcd


def _rt21_positive_inheritance_via_root_a_staff(rcd, path_deny, TAG, sgiddir):
    ok(all((rcd != 0, not os.path.exists(path_deny))),
       "sgi: DENY dave (non-staff) root:// create in 2770 staff setgid dir (rc={})".format(rcd))

    # POSITIVE inheritance via root://: a STAFF member (carol) CAN create here,
    # owner=carol, group forced to staff by the dir's setgid bit.
    relRoot = "sgiddir/{}_carol_root.txt".format(TAG)
    pathRoot = os.path.join(sgiddir, "{}_carol_root.txt".format(TAG))
    local_src = os.path.join(WORK, "{}_carol_src.txt".format(TAG))
    body_root = b"SGI-CAROL-ROOT-BODY"
    return relRoot, pathRoot, local_src, body_root


def _rt21_segment_03(local_src, body_root, relRoot, stat_safe, pathRoot):
    try:
        with open(local_src, "wb") as f:
            f.write(body_root)
        wrote_src = True
    except OSError:
        wrote_src = False
    ok(wrote_src, "sgi: staged local source for root:// upload (rc=open)")

    rc, out, err = xrd_cp_up(local_src, "/" + relRoot, "carol")
    ok(rc == 0, "sgi: carol (staff) xrdcp upload into setgid dir (rc={})".format(rc))
    stRoot = stat_safe(pathRoot)
    return rc, stRoot


def _rt21_setgid_dir_forces_staff_2001_as(stRoot, GID_STAFF, GID_RESEARCH, rc, UID_CAROL, pathRoot, relRoot):
    ok(stRoot is not None, "sgi: carol-uploaded file exists on disk (rc=stat)")
    if stRoot is not None:
        # setgid dir forces staff(2001) as the file group regardless of creator.
        ok(stRoot.st_gid == GID_STAFF,
           "sgi: INHERIT root:// carol file group == staff ({}) NOT research ({}) (rc={})".format(
               stRoot.st_gid, GID_RESEARCH, rc))
        ok(stRoot.st_uid == UID_CAROL,
           "sgi: root:// carol file OWNER == carol uid {} (rc={})".format(UID_CAROL, rc))

    # Tighten to 0640 group=staff; bob (non-staff) must be denied the read.
    try:
        os.chmod(pathRoot, 0o640)
        chmodR_ok = True
    except OSError:
        chmodR_ok = False
    ok(chmodR_ok, "sgi: chmod 0640 on root-created file (rc=os.chmod)")

    # POSITIVE: alice (staff) reads via group with xrdfs cat.
    rca, outa, erra = xrd_fs(["cat", "/" + relRoot], "alice")
    return rca, outa


def _rt21_deny_bob_non_staff_cat_must(rca, find_in_body, outa, body_root, relRoot, TAG):
    ok(all((rca == 0, find_in_body(outa, body_root))),
       "sgi: POSITIVE alice (staff) cat of root-inherited file (rc={})".format(rca))

    # DENY: bob (non-staff) cat must fail and leak nothing.
    rcb, outb, errb = xrd_fs(["cat", "/" + relRoot], "bob")
    ok(rcb != 0,
       "sgi: DENY bob (non-staff) cat of group-staff 0640 file fails (rc={})".format(rcb))
    ok(not find_in_body(outb, body_root),
       "sgi: NO-LEAK root-file marker bytes absent from bob's denied cat (rc={})".format(rcb))

    # root:// nested subdir inherits setgid too (xrdfs mkdir).
    relRootSub = "sgiddir/{}_rootsub".format(TAG)
    return relRootSub


def _rt21_segment_06(sgiddir, TAG, relRootSub, stat_safe):
    pathRootSub = os.path.join(sgiddir, "{}_rootsub".format(TAG))
    rcm, outm, errm = xrd_fs(["mkdir", "/" + relRootSub], "carol")
    ok(rcm == 0, "sgi: carol xrdfs mkdir nested subdir in setgid dir (rc={})".format(rcm))
    stRootSub = stat_safe(pathRootSub)
    ok(stRootSub is not None, "sgi: root:// nested subdir exists on disk (rc=stat)")
    return rcm, stRootSub


def _rt21_segment_07_2(stRootSub, GID_STAFF, rcm):
    if stRootSub is not None:
        ok((stRootSub.st_mode & 0o2000) != 0,
           "sgi: PROPAGATE root:// subdir keeps SETGID bit (mode={:o})".format(stRootSub.st_mode))
        ok(stRootSub.st_gid == GID_STAFF,
           "sgi: PROPAGATE root:// subdir group == staff ({}) (rc={})".format(stRootSub.st_gid, rcm))


def _rt21_when_xrd_avail(TAG, sgiddir, stat_safe, GID_STAFF, GID_RESEARCH, UID_CAROL, find_in_body):
    path_deny, rcd = _rt21_segment_01(TAG, sgiddir)

    relRoot, pathRoot, local_src, body_root = _rt21_positive_inheritance_via_root_a_staff(rcd, path_deny, TAG, sgiddir)

    rc, stRoot = _rt21_segment_03(local_src, body_root, relRoot, stat_safe, pathRoot)

    rca, outa = _rt21_setgid_dir_forces_staff_2001_as(stRoot, GID_STAFF, GID_RESEARCH, rc, UID_CAROL, pathRoot, relRoot)

    relRootSub = _rt21_deny_bob_non_staff_cat_must(rca, find_in_body, outa, body_root, relRoot, TAG)

    rcm, stRootSub = _rt21_segment_06(sgiddir, TAG, relRootSub, stat_safe)

    _rt21_segment_07_2(stRootSub, GID_STAFF, rcm)



def _rt21_part_d_root_native_xrdfs_xrdcp(stGW2, GID_STAFF, relGW, port, t_alice, find_in_body, body_b, body_a, TAG, sgiddir, stat_safe, GID_RESEARCH, UID_CAROL):
    if stGW2 is not None:
        ok(all((stGW2.st_uid not in (UID_BOB, UID_SVC, 0), stGW2.st_gid == GID_STAFF)),
           "sgi: file owner/group unchanged after bob's denied overwrite "
           "(uid=%d gid=%d)" % (stGW2.st_uid, stGW2.st_gid))
    stgr2, bgr2 = http("GET", "/" + relGW, port, token=t_alice)
    ok(not find_in_body(bgr2, body_b),
       "sgi: NO-LEAK bob's intrusion bytes never landed in the file (HTTP {})".format(stgr2))
    ok(all((stgr2 == 200, find_in_body(bgr2, body_a))),
       "sgi: file still holds alice's legitimate content after bob denied (HTTP {})".format(stgr2))

    # =========================================================================
    # PART D — root:// (native xrdfs/xrdcp) create into the SAME setgid dir.
    # Proves inheritance is protocol-independent: dave (research, NON-staff)
    # creates a file -> kernel STILL forces group=staff from the dir, owner=dave.
    # Then bob (non-staff) is denied reading it once it's 0640; alice reads it.
    # GUARDED by xrd_avail().
    # =========================================================================
    if xrd_avail():
        # SECURITY CONTROL: dave is research(2002), NOT staff, and is NOT the dir
        # owner (alice).  sgiddir is 2770 alice:staff -> NO 'other' bits, so dave
        # has zero access to it.  His create MUST be DAC-denied by the broker
        # (setfsuid/setfsgid=dave + setgroups=[research,proj]; kernel denies the
        # write on a staff-only dir).  This is the correct, secure behaviour.
        _rt21_when_xrd_avail(TAG, sgiddir, stat_safe, GID_STAFF, GID_RESEARCH, UID_CAROL, find_in_body)
    else:
        ok(True, "sgi: root:// unavailable, skipped native-protocol setgid checks (xrd_avail=False)")


def _rt21_part_e_worker_survival_sanity_after(port, t_alice, stat_safe, sgiddir, GID_STAFF):

    # =========================================================================
    # PART E — WORKER SURVIVAL / sanity: after all the impersonated creates and
    # denied intrusions, the worker still serves a benign authenticated request.
    # A crash here would be the real security failure (broker/setfsuid misuse).
    # =========================================================================
    stsv, _ = http("PROPFIND", "/sgiddir/", port, token=t_alice,
                   hdrs={"Depth": "1"})
    ok(stsv in (200, 207, 403, 401, 404),
       "sgi: worker survives + responds after setgid suite (HTTP {})".format(stsv))
    st_final = stat_safe(sgiddir)
    ok(all((st_final is not None, st_final.st_mode & 1024 != 0)),
       "sgi: sgiddir/ STILL setgid after full suite (no broker corruption) (rc=stat)")
    ok(all((st_final is not None, st_final.st_gid == GID_STAFF)),
       "sgi: sgiddir/ group unchanged == staff after full suite (rc=stat)")


def run_setgid_inheritance(key, data, port, s3port):
    TAG, GID_STAFF, GID_RESEARCH, UID_ALICE, UID_CAROL = _rt21_setgid_directory_group_inheritance_under_per()

    sgiddir = _rt21_segment_02(data)

    find_in_body = _rt21_tolerant_search_for_marker_bytes_in()

    stat_safe = _rt21_segment_04()

    t_carol, t_alice, t_bob, st_dir = _rt21_carol_alice_are_staff_bob_dave(key, stat_safe, sgiddir)

    relA, pathA = _rt21_part_a_webdav_put_by_a(st_dir, GID_STAFF, TAG, data, sgiddir)

    bodyA, stp, stA = _rt21_segment_07(relA, port, t_carol, stat_safe, pathA)

    _rt21_positive_control_a_different_staff_member(stA, GID_STAFF, stp, UID_CAROL, pathA, relA, port, t_alice, find_in_body, bodyA)

    relSub, pathSub = _rt21_part_b_nested_subdir_inside_sgiddir(relA, port, t_bob, find_in_body, bodyA, TAG, sgiddir)

    _rt21_segment_10(relSub, port, t_carol, stat_safe, pathSub, GID_STAFF)

    pathSubF, stsf = _rt21_file_inside_the_nested_setgid_subdir(relSub, TAG, pathSub, port, t_carol)

    relSubF2, pathSubF2 = _rt21_dac_alice_is_in_staff_but(stat_safe, pathSubF, GID_STAFF, stsf, UID_CAROL, relSub, TAG, pathSub)

    relGW, pathGW = _rt21_part_c_multi_party_group_write(relSubF2, port, t_alice, stat_safe, pathSubF2, TAG, sgiddir)

    body_c = _rt21_segment_14(relGW, port, t_carol, pathGW)

    body_a, sta2 = _rt21_positive_alice_staff_member_not_owner(stat_safe, pathGW, GID_STAFF, relGW, port, t_alice)

    stgr, bgr = _rt21_confirm_alice_s_bytes_actually_landed(stat_safe, pathGW, UID_ALICE, sta2, GID_STAFF, relGW, port, t_carol, find_in_body, body_a)

    body_b, stGW2 = _rt21_deny_bob_non_staff_attempts_to(find_in_body, bgr, body_c, stgr, relGW, port, t_bob, stat_safe, pathGW)

    _rt21_part_d_root_native_xrdfs_xrdcp(stGW2, GID_STAFF, relGW, port, t_alice, find_in_body, body_b, body_a, TAG, sgiddir, stat_safe, GID_RESEARCH, UID_CAROL)

    _rt21_part_e_worker_survival_sanity_after(port, t_alice, stat_safe, sgiddir, GID_STAFF)

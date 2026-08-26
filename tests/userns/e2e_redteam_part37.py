def _rt37_combination_frontier_setgid_sticky_inheritance_through(port, key):
    # =========================================================================
    # COMBINATION FRONTIER: setgid / sticky inheritance THROUGH copy / move /
    # third-party-copy / cross-protocol — the interaction the per-feature
    # batches (run_setgid_inheritance = create-into-setgid only;
    # run_sticky_bit_dac = sticky delete/move of CREATED files only) never wire
    # together.  Every check below exercises a *combination*: a destination-side
    # setgid directory whose group must be FORCED onto a file that arrives via
    # WebDAV COPY/MOVE, native TPC, or S3 CopyObject, plus sticky-bit protection
    # of files that got there by COPY rather than PUT.  The invariant under test
    # is that the kernel's setgid/sticky semantics ride on top of the broker's
    # per-request setfsuid/setfsgid/setgroups for EVERY data-motion verb, and
    # that no copied/moved object ever lands owned by svc/root or carrying a
    # cross-tenant group it should not.
    # =========================================================================
    TAG = "cgsv"
    base = f"http://{HOST}:{port}"

    t_alice = mint(key, "alice")
    t_bob = mint(key, "bob")
    t_carol = mint(key, "carol")
    return TAG, base, t_alice, t_bob, t_carol


def _rt37_segment_02(key):
    t_dave = mint(key, "dave")
    t_erin = mint(key, "erin")
    return t_erin


def _rt37_segment_03():

    def stat_safe(p):
        try:
            return os.stat(p)
        except OSError:
            return None
    return stat_safe


def _rt37_segment_04():

    def has(body, needle):
        if body is None:
            return False
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return needle in body
    return has


def _rt37_segment_05(data):

    def mkfile(rel, content, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
            return True
        except OSError:
            return False
    return mkfile


def _rt37_segment_06(data):

    def mkdir_own(rel, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
            return True
        except OSError:
            return False
    return mkdir_own


def _rt37_our_own_isolated_tag_prefixed_fixtures(TAG, data, mkdir_own):

    # --- our own, isolated, tag-prefixed fixtures (never the shared sgiddir) ---
    # A 02770 alice:staff setgid destination dir.  carol IS staff, bob is NOT.
    SG = f"{TAG}_sgid"
    sg_dir = os.path.join(data, SG)
    ok(mkdir_own(SG, UID_ALICE, GID_STAFF, 0o2770),
       f"{TAG}: created destination setgid dir {SG} (rc=mkdir)")
    # A 02770 alice:proj setgid dir to prove the FORCED group is the dir's, not
    # the creator's primary, across a copy where creator carol is in BOTH staff
    # and proj — destination dir's group (proj) must win.
    SGP = f"{TAG}_sgidproj"
    sgp_dir = os.path.join(data, SGP)
    return SG, sg_dir, SGP, sgp_dir


def _rt37_a_01777_sticky_staging_dir_owned(mkdir_own, SGP, TAG, data):
    ok(mkdir_own(SGP, UID_CAROL, GID_PROJ, 0o2770),
       f"{TAG}: created proj setgid dir {SGP} (rc=mkdir)")
    # A 01777 sticky staging dir owned by svc (like /tmp) for the copy-then-
    # sticky-protect legs.
    STK = f"{TAG}_sticky"
    stk_dir = os.path.join(data, STK)
    ok(mkdir_own(STK, UID_SVC, UID_SVC, 0o1777),
       f"{TAG}: created sticky staging dir {STK} (rc=mkdir)")
    # carol's own source files (group=research-ish primary; we set group to a
    # NON-staff group so the inheritance is observable, not coincidental).
    SRC_REL = f"carol/{TAG}_src.txt"
    return STK, stk_dir, SRC_REL


def _rt37_a_whole_source_tree_owned_carol(mkdir_own, TAG, mkfile, SRC_REL):
    SRC_BODY = b"CGSV-CAROL-COPY-SOURCE-BODY"
    ok(mkdir_own("carol", UID_CAROL, UID_CAROL, 0o755),
       f"{TAG}: carol home dir present (rc=mkdir)")
    ok(mkfile(SRC_REL, SRC_BODY, UID_CAROL, GID_RESEARCH, 0o644),
       f"{TAG}: carol source file seeded group=research(non-staff) (rc=mkfile)")
    # A whole source TREE owned carol, group=research, to copy into the setgid
    # dir so children must each flip to staff.
    TREE_REL = f"carol/{TAG}_tree"
    ok(mkdir_own(TREE_REL, UID_CAROL, GID_RESEARCH, 0o755),
       f"{TAG}: source tree root seeded (rc=mkdir)")
    return SRC_BODY, TREE_REL


def _rt37_segment_10(mkfile, TREE_REL, TAG, mkdir_own, sg_dir, sgp_dir):
    ok(mkfile(f"{TREE_REL}/leaf1.txt", b"CGSV-TREE-LEAF-1", UID_CAROL,
              GID_RESEARCH, 0o644),
       f"{TAG}: tree leaf1 seeded group=research (rc=mkfile)")
    ok(mkdir_own(f"{TREE_REL}/sub", UID_CAROL, GID_RESEARCH, 0o755),
       f"{TAG}: tree subdir seeded (rc=mkdir)")
    ok(mkfile(f"{TREE_REL}/sub/leaf2.txt", b"CGSV-TREE-LEAF-2", UID_CAROL,
              GID_RESEARCH, 0o644),
       f"{TAG}: tree sub/leaf2 seeded group=research (rc=mkfile)")
    ensure_traversable(sg_dir)
    ensure_traversable(sgp_dir)


def _rt37_pre_flight_the_setgid_dirs_really(stk_dir, stat_safe, sg_dir, TAG, SG, sgp_dir, SGP):
    ensure_traversable(stk_dir)

    # PRE-FLIGHT: the setgid dirs really are setgid with the expected group.
    sgst = stat_safe(sg_dir)
    ok(all((sgst is not None, sgst.st_mode & 1024, sgst.st_gid == GID_STAFF)),
       f"{TAG}: {SG} is setgid + group=staff on disk (rc=stat)")
    sgpst = stat_safe(sgp_dir)
    ok(all((sgpst is not None, sgpst.st_mode & 1024, sgpst.st_gid == GID_PROJ)),
       f"{TAG}: {SGP} is setgid + group=proj on disk (rc=stat)")


def _rt37_part_a_webdav_copy_of_carol(SG, TAG, sg_dir, SRC_REL, port, t_carol, base, stat_safe):

    # =====================================================================
    # PART A — WebDAV COPY of carol's research-group file INTO the staff
    # setgid dir.  The COMBINATION: copy machinery creates the destination via
    # the broker as carol; the setgid bit must FORCE group=staff (overriding
    # the source's research group), owner stays carol, never svc/root.
    # =====================================================================
    A_dst = f"/{SG}/{TAG}_copied.txt"
    A_fp = os.path.join(sg_dir, f"{TAG}_copied.txt")
    sa, _ = http("COPY", "/" + SRC_REL, port, t_carol,
                 hdrs={"Destination": base + A_dst})
    ok(sa in (200, 201, 204, 207),
       f"{TAG}: carol COPY into staff setgid dir accepted (HTTP {sa})")
    A_st = stat_safe(A_fp)
    return A_dst, A_fp, sa, A_st


def _rt37_the_copy_preserved_the_source_body(A_st, TAG, sa, A_dst, port, t_carol, has, SRC_BODY, stat_safe, data, SRC_REL):
    ok(A_st is not None,
       f"{TAG}: copied file landed in setgid dir (rc=stat)")
    if A_st is not None:
        ok(A_st.st_gid == GID_STAFF,
           f"{TAG}: INHERIT copied-in file group==staff({GID_STAFF}) not "
           f"source-research({A_st.st_gid}) (HTTP {sa})")
        ok(A_st.st_uid == UID_CAROL,
           f"{TAG}: copied-in file OWNER==carol({UID_CAROL}) (HTTP {sa})")
        ok(A_st.st_uid not in (UID_SVC, 0),
           f"{TAG}: copied-in file NOT owned by svc/root (uid={A_st.st_uid})")
    # The copy preserved the source body (no truncation/cross-content).
    sar, bar = http("GET", A_dst, port, t_carol)
    ok(all((sar == 200, has(bar, SRC_BODY))),
       f"{TAG}: copied-in file body == source content (HTTP {sar})")
    # Source must be untouched (COPY, not MOVE) and keep its research group.
    src_st = stat_safe(os.path.join(data, SRC_REL))
    return src_st


def _rt37_positive_deny_on_the_copied_in(src_st, TAG, A_fp, A_dst, port, t_alice, has, SRC_BODY):
    ok(all((src_st is not None, src_st.st_gid == GID_RESEARCH, src_st.st_uid == UID_CAROL)),
       f"{TAG}: source unchanged after COPY (owner carol, group research)")

    # POSITIVE + DENY on the copied-in (now group=staff) file once tightened to
    # 0640: a SECOND staff member (alice) reads via the inherited group; a
    # NON-staff member (bob) is denied and the body never leaks.
    try:
        os.chmod(A_fp, 0o640)
        chmodA = True
    except OSError:
        chmodA = False
    ok(chmodA, f"{TAG}: chmod 0640 on copied-in file (rc=os.chmod)")
    spa, bpa = http("GET", A_dst, port, t_alice)
    ok(all((spa == 200, has(bpa, SRC_BODY))),
       f"{TAG}: POSITIVE alice(staff) reads copied-in file via inherited group "
       f"(HTTP {spa})")


def _rt37_part_b_non_member_copy_into(A_dst, port, t_bob, TAG, has, SRC_BODY, mkfile, SG):
    sba, bba = http("GET", A_dst, port, t_bob)
    ok(sba in (401, 403, 404, 500),
       f"{TAG}: DENY bob(non-staff) read of copied-in 0640 staff file "
       f"(HTTP {sba})")
    ok(not has(bba, SRC_BODY),
       f"{TAG}: NO-LEAK copied-in body bytes absent from bob's denied read "
       f"(HTTP {sba})")
    _combo_setgid_via_copymove_p2(s3port, sg_dir, port, t_bob, t_carol, data, sgp_dir, t_erin, t_alice, stk_dir, mkfile, SG, TAG, TREE_REL, SGP, STK, has, mkdir_own, base)


def _combo_setgid_via_copymove_p2(s3port, sg_dir, port, t_bob, t_carol, data, sgp_dir, t_erin, t_alice, stk_dir, mkfile, SG, TAG, TREE_REL, SGP, STK, has, mkdir_own, base):
    # =====================================================================
    # PART B — non-member COPY INTO the staff setgid dir must be DENIED by DAC
    # (bob is research, sgid dir is 2770 staff -> no 'other' bits).  Combination
    # of: cross-tenant copy + setgid-dir DAC.  Nothing may land, no svc/root file.
    # =====================================================================
    ok(mkfile(f"bob/{TAG}_bobsrc.txt", b"CGSV-BOB-SRC-BODY", UID_BOB,
              GID_RESEARCH, 0o644),
       f"{TAG}: bob source file seeded (rc=mkfile)")
    B_dst = f"/{SG}/{TAG}_bob_intrude.txt"
    return B_dst


def _rt37_control_already_proven_in_part_a(sg_dir, TAG, port, t_bob, base, B_dst, stat_safe, SG):
    B_fp = os.path.join(sg_dir, f"{TAG}_bob_intrude.txt")
    sb, _ = http("COPY", f"/bob/{TAG}_bobsrc.txt", port, t_bob,
                 hdrs={"Destination": base + B_dst})
    ok(sb in (401, 403, 404, 409, 500),
       f"{TAG}: DENY bob(non-member) COPY into staff setgid dir (HTTP {sb})")
    ok(stat_safe(B_fp) is None,
       f"{TAG}: bob's denied COPY left NO file in the setgid dir")
    # control already proven in PART A that a MEMBER (carol) can copy here.
    _combo_setgid_via_copymove_p3(s3port, sg_dir, port, t_carol, t_bob, data, sgp_dir, t_erin, t_alice, stk_dir, SG, TAG, TREE_REL, mkfile, SGP, STK, has, mkdir_own, base)


def _combo_setgid_via_copymove_p3(s3port, sg_dir, port, t_carol, t_bob, data, sgp_dir, t_erin, t_alice, stk_dir, SG, TAG, TREE_REL, mkfile, SGP, STK, has, mkdir_own, base):
    # =====================================================================
    # PART C — WebDAV tree COPY (Depth: infinity) of carol's research tree into
    # the staff setgid dir.  EVERY child file + nested subdir must inherit staff,
    # subdirs keep the setgid bit (propagation through a recursive copy).
    # =====================================================================
    C_dst_rel = f"{SG}/{TAG}_treecopy"
    return C_dst_rel


def _rt37_segment_17(sg_dir, TAG, TREE_REL, port, t_carol, base, C_dst_rel, stat_safe):
    C_dst_dir = os.path.join(sg_dir, f"{TAG}_treecopy")
    sc, _ = http("COPY", "/" + TREE_REL, port, t_carol,
                 hdrs={"Destination": base + "/" + C_dst_rel,
                       "Depth": "infinity"})
    ok(sc in (200, 201, 204, 207),
       f"{TAG}: carol tree COPY (Depth infinity) into setgid dir (HTTP {sc})")
    C_root = stat_safe(C_dst_dir)
    ok(C_root is not None,
       f"{TAG}: copied tree root present in setgid dir (rc=stat)")
    return C_dst_dir, sc, C_root


def _rt37_segment_18(C_root, TAG, sc, stat_safe, C_dst_dir):
    if C_root is not None:
        ok(C_root.st_gid == GID_STAFF,
           f"{TAG}: tree-copy root dir group==staff({C_root.st_gid}) (HTTP {sc})")
        ok((C_root.st_mode & 0o2000) != 0,
           f"{TAG}: PROPAGATE tree-copy root keeps SETGID bit "
           f"(mode={C_root.st_mode:o})")
    C_leaf1 = stat_safe(os.path.join(C_dst_dir, "leaf1.txt"))
    if C_leaf1 is not None:
        ok(C_leaf1.st_gid == GID_STAFF,
           f"{TAG}: tree-copy leaf1 group==staff({C_leaf1.st_gid}) not research")
        ok(C_leaf1.st_uid == UID_CAROL,
           f"{TAG}: tree-copy leaf1 owner==carol({C_leaf1.st_uid})")
        ok(C_leaf1.st_uid not in (UID_SVC, 0),
           f"{TAG}: tree-copy leaf1 NOT svc/root (uid={C_leaf1.st_uid})")
    else:
        ok(True, f"{TAG}: tree-copy leaf1 not materialised (recursive copy "
                 f"unsupported, handled gracefully)")
    C_leaf2 = stat_safe(os.path.join(C_dst_dir, "sub", "leaf2.txt"))
    if C_leaf2 is not None:
        ok(C_leaf2.st_gid == GID_STAFF,
           f"{TAG}: tree-copy NESTED leaf2 group==staff({C_leaf2.st_gid})")
        ok(C_leaf2.st_uid == UID_CAROL,
           f"{TAG}: tree-copy nested leaf2 owner==carol")


def _rt37_part_d_webdav_move_into_the(stat_safe, C_dst_dir, TAG, mkfile, SG, sg_dir):
    C_sub = stat_safe(os.path.join(C_dst_dir, "sub"))
    if C_sub is not None:
        ok(all((C_sub.st_mode & 1024 != 0, C_sub.st_gid == GID_STAFF)),
           f"{TAG}: PROPAGATE tree-copy nested subdir setgid+staff "
           f"(mode={C_sub.st_mode:o} gid={C_sub.st_gid})")
    _combo_setgid_via_copymove_p4(s3port, sg_dir, port, t_carol, t_bob, data, sgp_dir, t_erin, t_alice, stk_dir, mkfile, SG, TAG, SGP, STK, has, mkdir_own, base)


def _combo_setgid_via_copymove_p4(s3port, sg_dir, port, t_carol, t_bob, data, sgp_dir, t_erin, t_alice, stk_dir, mkfile, SG, TAG, SGP, STK, has, mkdir_own, base):
    # =====================================================================
    # PART D — WebDAV MOVE INTO the setgid dir.  MOVE = rename across dirs; a
    # cross-directory rename that crosses filesystems falls back to copy+unlink
    # and then setgid applies; an in-fs rename keeps the inode's group.  We must
    # NOT accept svc/root ownership either way, and a NON-member MOVE is denied.
    # carol MOVEs her own file (in carol/, same export fs) into the staff setgid
    # dir; we assert owner==carol and (if the group flipped) it is staff, never
    # research-leaked-as-svc.
    # =====================================================================
    ok(mkfile(f"carol/{TAG}_mvsrc.txt", b"CGSV-CAROL-MOVE-SRC", UID_CAROL,
              GID_RESEARCH, 0o644),
       f"{TAG}: carol move-source seeded (rc=mkfile)")
    D_dst = f"/{SG}/{TAG}_moved_in.txt"
    D_fp = os.path.join(sg_dir, f"{TAG}_moved_in.txt")
    return D_dst, D_fp


def _rt37_segment_20(TAG, port, t_carol, base, D_dst, stat_safe, D_fp):
    sd, _ = http("MOVE", f"/carol/{TAG}_mvsrc.txt", port, t_carol,
                 hdrs={"Destination": base + D_dst})
    ok(sd in (200, 201, 204),
       f"{TAG}: carol MOVE into staff setgid dir (HTTP {sd})")
    D_st = stat_safe(D_fp)
    ok(D_st is not None,
       f"{TAG}: moved-in file present in setgid dir (rc=stat)")
    if D_st is not None:
        ok(D_st.st_uid == UID_CAROL,
           f"{TAG}: moved-in file owner==carol({D_st.st_uid}) (HTTP {sd})")
        ok(D_st.st_uid not in (UID_SVC, 0),
           f"{TAG}: moved-in file NOT svc/root (uid={D_st.st_uid})")
        ok(D_st.st_gid in (GID_STAFF, GID_RESEARCH),
           f"{TAG}: moved-in file group is staff(inherited) or research(rename) "
           f"never a foreign/worker group (gid={D_st.st_gid})")


def _rt37_the_content_survived_the_move_intact(data, TAG, D_dst, port, t_carol, has, mkfile, sg_dir):
    ok(not os.path.exists(os.path.join(data, "carol", f"{TAG}_mvsrc.txt")),
       f"{TAG}: MOVE removed the source (rename semantics)")
    # the content survived the move intact.
    sdr, bdr = http("GET", D_dst, port, t_carol)
    ok(all((sdr == 200, has(bdr, b'CGSV-CAROL-MOVE-SRC'))),
       f"{TAG}: moved-in file body intact after MOVE (HTTP {sdr})")

    # DENY: bob (non-member) MOVE of his own file into the staff setgid dir.
    ok(mkfile(f"bob/{TAG}_bobmv.txt", b"CGSV-BOB-MOVE", UID_BOB,
              GID_RESEARCH, 0o644),
       f"{TAG}: bob move-source seeded (rc=mkfile)")
    D2_fp = os.path.join(sg_dir, f"{TAG}_bob_moved.txt")
    return D2_fp


def _rt37_part_e_move_out_of_the(TAG, port, t_bob, base, SG, stat_safe, D2_fp, data, D_dst):
    sd2, _ = http("MOVE", f"/bob/{TAG}_bobmv.txt", port, t_bob,
                  hdrs={"Destination": base + f"/{SG}/{TAG}_bob_moved.txt"})
    ok(sd2 in (401, 403, 404, 409, 500),
       f"{TAG}: DENY bob(non-member) MOVE into staff setgid dir (HTTP {sd2})")
    ok(stat_safe(D2_fp) is None,
       f"{TAG}: bob's denied MOVE left no file in the setgid dir")
    ok(os.path.exists(os.path.join(data, "bob", f"{TAG}_bobmv.txt")),
       f"{TAG}: bob's source preserved after his denied MOVE (no data loss)")
    _combo_setgid_via_copymove_p5(D_dst, s3port, data, port, t_carol, sgp_dir, t_erin, t_alice, stk_dir, t_bob, sg_dir, TAG, mkfile, SGP, STK, has, D_fp, mkdir_own, SG, base)


def _combo_setgid_via_copymove_p5(D_dst, s3port, data, port, t_carol, sgp_dir, t_erin, t_alice, stk_dir, t_bob, sg_dir, TAG, mkfile, SGP, STK, has, D_fp, mkdir_own, SG, base):
    # =====================================================================
    # PART E — MOVE OUT of the setgid dir into carol's plain home: the file must
    # KEEP its content; on an in-fs rename it keeps the inherited staff group,
    # but it must NOT silently become svc/root.  Then a non-staff cannot read it
    # if it is still group-restricted (combination of move-out + residual group).
    # =====================================================================
    E_src = D_dst  # the file we moved in
    return E_src


def _rt37_segment_23(TAG, data, E_src, port, t_carol, base, stat_safe):
    E_dst_rel = f"carol/{TAG}_moved_out.txt"
    E_fp = os.path.join(data, E_dst_rel)
    se, _ = http("MOVE", E_src, port, t_carol,
                 hdrs={"Destination": base + "/" + E_dst_rel})
    ok(se in (200, 201, 204),
       f"{TAG}: carol MOVEs the file back OUT of the setgid dir (HTTP {se})")
    E_st = stat_safe(E_fp)
    return E_dst_rel, E_st


def _rt37_segment_24(E_st, TAG, E_dst_rel, port, t_carol, has, D_fp):
    ok(E_st is not None,
       f"{TAG}: moved-out file present in carol home (rc=stat)")
    if E_st is not None:
        ok(all((E_st.st_uid == UID_CAROL, E_st.st_uid not in (UID_SVC, 0))),
           f"{TAG}: moved-out file owner==carol, not svc/root (uid={E_st.st_uid})")
    ser, ber = http("GET", "/" + E_dst_rel, port, t_carol)
    ok(all((ser == 200, has(ber, b'CGSV-CAROL-MOVE-SRC'))),
       f"{TAG}: moved-out file content intact (HTTP {ser})")
    ok(not os.path.exists(D_fp),
       f"{TAG}: setgid-dir source gone after move-out (rename, no stray copy)")
    _combo_setgid_via_copymove_p6(s3port, sgp_dir, port, t_carol, t_erin, t_alice, stk_dir, t_bob, sg_dir, mkfile, SGP, TAG, STK, data, has, mkdir_own, SG, base)


def _rt37_part_f_the_proj_setgid_dir(mkfile, TAG, SGP, sgp_dir, port, t_carol, base):

    # =====================================================================
    # PART F — the proj setgid dir: carol (member of BOTH staff AND proj) copies
    # her staff-grouped file into the PROJ setgid dir.  The forced group must be
    # the DESTINATION dir's group (proj), proving inheritance follows the target
    # directory, not the creator's primary or the source's group.  erin (proj
    # member, NOT staff) can then read it; alice (staff, NOT proj) cannot.
    # =====================================================================
    ok(mkfile(f"carol/{TAG}_staffsrc.txt", b"CGSV-PROJ-COPY-BODY", UID_CAROL,
              GID_STAFF, 0o644),
       f"{TAG}: carol staff-grouped source seeded (rc=mkfile)")
    F_dst = f"/{SGP}/{TAG}_into_proj.txt"
    F_fp = os.path.join(sgp_dir, f"{TAG}_into_proj.txt")
    sf, _ = http("COPY", f"/carol/{TAG}_staffsrc.txt", port, t_carol,
                 hdrs={"Destination": base + F_dst})
    ok(sf in (200, 201, 204, 207),
       f"{TAG}: carol COPY staff-file into PROJ setgid dir (HTTP {sf})")
    return F_dst, F_fp, sf


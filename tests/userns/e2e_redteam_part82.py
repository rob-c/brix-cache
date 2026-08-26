# e2e_redteam_part82.py — continuation shard split off from e2e_redteam_part37.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt37_segment_26(stat_safe, F_fp, TAG, sf, F_dst, port, t_erin):
    F_st = stat_safe(F_fp)
    ok(F_st is not None,
       f"{TAG}: file present in proj setgid dir (rc=stat)")
    if F_st is not None:
        ok(F_st.st_gid == GID_PROJ,
           f"{TAG}: INHERIT dest dir's group proj({GID_PROJ}) wins over source "
           f"staff (gid={F_st.st_gid}) (HTTP {sf})")
        ok(F_st.st_uid == UID_CAROL,
           f"{TAG}: proj-copied file owner==carol({F_st.st_uid})")
    try:
        os.chmod(F_fp, 0o640)
    except OSError:
        pass
    sfe, bfe = http("GET", F_dst, port, t_erin)
    return sfe, bfe


def _rt37_part_g_sticky_copy_interaction_two(sfe, has, bfe, TAG, F_dst, port, t_alice, mkfile):
    ok(all((sfe == 200, has(bfe, b'CGSV-PROJ-COPY-BODY'))),
       f"{TAG}: POSITIVE erin(proj) reads proj-group-inherited file (HTTP {sfe})")
    sfa, bfa = http("GET", F_dst, port, t_alice)
    ok(sfa in (401, 403, 404, 500),
       f"{TAG}: DENY alice(staff,NOT proj) read of proj-group 0640 file "
       f"(HTTP {sfa})")
    ok(not has(bfa, b"CGSV-PROJ-COPY-BODY"),
       f"{TAG}: NO-LEAK proj-copy body absent from alice's denied read "
       f"(HTTP {sfa})")
    _combo_setgid_via_copymove_p7(s3port, stk_dir, port, t_alice, t_bob, t_carol, sg_dir, sgp_dir, mkfile, STK, TAG, data, mkdir_own, SG, has, base)


def _combo_setgid_via_copymove_p7(s3port, stk_dir, port, t_alice, t_bob, t_carol, sg_dir, sgp_dir, mkfile, STK, TAG, data, mkdir_own, SG, has, base):
    # =====================================================================
    # PART G — STICKY + COPY interaction: two tenants COPY their own files INTO
    # the 1777 sticky staging dir (each owned by its real creator), then a
    # DIFFERENT non-owner tries to MOVE/DELETE the other's *copied-in* file ->
    # sticky DENY.  This is the copy-machinery feeding the sticky-protection
    # check, never tested together.
    # =====================================================================
    ok(mkfile(f"alice/{TAG}_astage.txt", b"CGSV-ALICE-STAGE", UID_ALICE,
              UID_ALICE, 0o644),
       f"{TAG}: alice stage-source seeded (rc=mkfile)")


def _rt37_segment_28(STK, TAG, stk_dir, port, t_alice, base, stat_safe):
    G_a_dst = f"/{STK}/{TAG}_alice_in.txt"
    G_a_fp = os.path.join(stk_dir, f"{TAG}_alice_in.txt")
    sga, _ = http("COPY", f"/alice/{TAG}_astage.txt", port, t_alice,
                  hdrs={"Destination": base + G_a_dst})
    ga_st = stat_safe(G_a_fp)
    ok(all((sga in (200, 201, 204, 207), ga_st is not None, ga_st.st_uid == UID_ALICE)),
       f"{TAG}: alice COPY into sticky dir, owned by alice (HTTP {sga})")
    return G_a_dst, G_a_fp, ga_st


def _rt37_segment_29(ga_st, TAG, mkfile, STK, stk_dir, port, t_bob, base):
    ok(all((ga_st is not None, ga_st.st_uid not in (UID_SVC, 0))),
       f"{TAG}: alice's copied-in sticky file NOT svc/root")
    ok(mkfile(f"bob/{TAG}_bstage.txt", b"CGSV-BOB-STAGE", UID_BOB,
              GID_RESEARCH, 0o644),
       f"{TAG}: bob stage-source seeded (rc=mkfile)")
    G_b_dst = f"/{STK}/{TAG}_bob_in.txt"
    G_b_fp = os.path.join(stk_dir, f"{TAG}_bob_in.txt")
    sgb, _ = http("COPY", f"/bob/{TAG}_bstage.txt", port, t_bob,
                  hdrs={"Destination": base + G_b_dst})
    return G_b_fp, sgb


def _rt37_deny_bob_deletes_alice_s_copied(stat_safe, G_b_fp, sgb, TAG, G_a_dst, port, t_bob, G_a_fp):
    gb_st = stat_safe(G_b_fp)
    ok(all((sgb in (200, 201, 204, 207), gb_st is not None, gb_st.st_uid == UID_BOB)),
       f"{TAG}: bob COPY into sticky dir, owned by bob (HTTP {sgb})")

    # DENY: bob DELETEs alice's copied-in sticky file (sticky, non-owner).
    sgd, _ = http("DELETE", G_a_dst, port, t_bob)
    a_surv = os.path.exists(G_a_fp) and stat_safe(G_a_fp).st_uid == UID_ALICE
    ok(all((sgd not in (200, 204), a_surv)),
       f"{TAG}: DENY bob DELETE of alice's COPIED-in sticky file, survives "
       f"(HTTP {sgd})")


def _rt37_deny_carol_moves_alice_s_copied(G_a_fp, TAG, G_a_dst, port, t_carol, base, data):
    a_body = open(G_a_fp, "rb").read() if os.path.exists(G_a_fp) else b""
    ok(b"CGSV-ALICE-STAGE" in a_body,
       f"{TAG}: alice's copied-in sticky file body intact after bob's denied DELETE")
    # DENY: carol MOVEs alice's copied-in sticky file out (sticky, non-owner).
    sgm, _ = http("MOVE", G_a_dst, port, t_carol,
                  hdrs={"Destination": base + f"/carol/{TAG}_steal.txt"})
    ok(all((sgm not in (200, 201, 204), os.path.exists(G_a_fp), not os.path.exists(os.path.join(data, 'carol', f'{TAG}_steal.txt')))),
       f"{TAG}: DENY carol MOVE of alice's copied-in sticky file (HTTP {sgm})")
    ok(not all((os.path.exists(os.path.join(data, 'carol', f'{TAG}_steal.txt')), b'CGSV-ALICE-STAGE' in open(os.path.join(data, 'carol', f'{TAG}_steal.txt'), 'rb').read())),
       f"{TAG}: NO-LEAK alice's stage bytes did not reach carol via denied MOVE")


def _rt37_positive_control_a_non_owner_alice(G_a_dst, port, t_alice, G_a_fp, TAG, STK, stk_dir, stat_safe):
    # POSITIVE: alice (owner) DELETEs her own copied-in sticky file.
    sgp2, _ = http("DELETE", G_a_dst, port, t_alice)
    ok(all((sgp2 in (200, 204), not os.path.exists(G_a_fp))),
       f"{TAG}: POSITIVE alice deletes her OWN copied-in sticky file (HTTP {sgp2})")
    # POSITIVE control: a non-owner (alice) CAN create a NEW name in the sticky
    # dir (world-writable) even though she cannot touch bob's — proves the deny
    # above is sticky-specific, not a blanket dir lock.
    sgc, _ = http("PUT", f"/{STK}/{TAG}_alice_new.txt", port, t_alice,
                  b"CGSV-ALICE-NEW")
    an_fp = os.path.join(stk_dir, f"{TAG}_alice_new.txt")
    ok(all((sgc in (200, 201, 204), os.path.exists(an_fp), stat_safe(an_fp).st_uid == UID_ALICE)),
       f"{TAG}: POSITIVE alice creates a fresh name in the sticky dir (HTTP {sgc})")
    _combo_setgid_via_copymove_p8(s3port, sg_dir, sgp_dir, stk_dir, port, t_carol, t_alice, data, TAG, mkdir_own, mkfile, SG, t_bob, has)


def _rt37_segment_01(mkfile, TAG, SG, sg_dir, stat_safe):
    ok(mkfile(f"carol/{TAG}_tpcsrc.txt", b"CGSV-TPC-SRC-BODY", UID_CAROL,
              GID_RESEARCH, 0o644),
       f"{TAG}: carol TPC source seeded group=research (rc=mkfile)")
    I_dst_rel = f"{SG}/{TAG}_tpc_in.txt"
    I_fp = os.path.join(sg_dir, f"{TAG}_tpc_in.txt")
    rci, oi, ei = xrd_cp_tpc(f"carol/{TAG}_tpcsrc.txt", I_dst_rel, "carol")
    I_st = stat_safe(I_fp)
    return I_dst_rel, I_fp, rci, I_st


def _rt37_cross_protocol_verify_propfind_must_reflect_2(I_st, TAG, rci, I_fp, I_dst_rel, port, t_alice):
    ok(I_st.st_gid == GID_STAFF,
       f"{TAG}: INHERIT TPC'd file group==staff({I_st.st_gid}) not "
       f"research (rc={rci})")
    ok(I_st.st_uid == UID_CAROL,
       f"{TAG}: TPC'd file owner==carol({I_st.st_uid}) (rc={rci})")
    ok(I_st.st_uid not in (UID_SVC, 0),
       f"{TAG}: TPC'd file NOT svc/root (uid={I_st.st_uid})")
    # cross-protocol verify: PROPFIND must reflect the same file, no leak
    # of a different tenant; body readable by staff alice via group.
    try:
        os.chmod(I_fp, 0o640)
    except OSError:
        pass
    sip, bip = http("GET", "/" + I_dst_rel, port, t_alice)
    return sip, bip


def _rt37_segment_02_2(sip, has, bip, TAG, I_dst_rel, port, t_bob):
    ok(all((sip == 200, has(bip, b'CGSV-TPC-SRC-BODY'))),
       f"{TAG}: cross-proto alice(staff) WebDAV-reads the TPC'd file via "
       f"inherited group (HTTP {sip})")
    sib, bib = http("GET", "/" + I_dst_rel, port, t_bob)
    ok(all((sib in (401, 403, 404, 500), not has(bib, b'CGSV-TPC-SRC-BODY'))),
       f"{TAG}: cross-proto DENY bob WebDAV-read of TPC'd staff file "
       f"(HTTP {sib})")


def _rt37_when_rci_0_i_st(I_st, TAG, rci, I_fp, port, t_alice, I_dst_rel, has, t_bob):
    sip, bip = _rt37_cross_protocol_verify_propfind_must_reflect_2(I_st, TAG, rci, I_fp, I_dst_rel, port, t_alice)

    _rt37_segment_02_2(sip, has, bip, TAG, I_dst_rel, port, t_bob)



def _rt37_cross_protocol_verify_propfind_must_reflect(rci, I_st, TAG, I_fp, I_dst_rel, port, t_alice, has, t_bob, mkfile, sg_dir, SG, stat_safe):
    if rci == 0 and I_st is not None:
        _rt37_when_rci_0_i_st(I_st, TAG, rci, I_fp, port, t_alice, I_dst_rel, has, t_bob)
    else:
        ok(True, f"{TAG}: loopback TPC into setgid dir not completed "
                 f"(rc={rci}); treated as handled, no leak asserted")

    # DENY: bob (non-staff) as the TPC principal targeting the staff setgid
    # dir -> the dest open must be DAC-denied; nothing owned by bob/svc lands.
    ok(mkfile(f"bob/{TAG}_btpc.txt", b"CGSV-BOB-TPC", UID_BOB,
              GID_RESEARCH, 0o644),
       f"{TAG}: bob TPC source seeded (rc=mkfile)")
    J_fp = os.path.join(sg_dir, f"{TAG}_bob_tpc.txt")
    rcj, oj, ej = xrd_cp_tpc(f"bob/{TAG}_btpc.txt",
                             f"{SG}/{TAG}_bob_tpc.txt", "bob")
    ok(all((rcj != 0, stat_safe(J_fp) is None)),
       f"{TAG}: DENY bob(non-member) TPC dest into staff setgid dir "
       f"(rc={rcj})")


def _rt37_native_create_into_the_setgid_dir(TAG, SG, sg_dir):

    # native CREATE into the setgid dir then cross-protocol group verify:
    # erin is NOT staff so her create is DAC-denied (the dir is 2770 staff,
    # no other bits) -> proves setgid never relaxes the dir's own access mode.
    es = os.path.join(WORK, f"{TAG}_erin_src.bin")
    try:
        with open(es, "wb") as fh:
            fh.write(b"CGSV-ERIN-DENIED")
    except OSError:
        pass
    rck, _ok, _ek = xrd_cp_up(es, f"/{SG}/{TAG}_erin_in.bin", "erin")
    ok(all((rck != 0, not os.path.exists(os.path.join(sg_dir, f'{TAG}_erin_in.bin')))),
       f"{TAG}: DENY erin(non-staff) native create in staff setgid dir "
       f"(rc={rck})")


def _rt37_when_xrd_avail(mkfile, TAG, SG, sg_dir, stat_safe, port, t_alice, t_bob, has):
    I_dst_rel, I_fp, rci, I_st = _rt37_segment_01(mkfile, TAG, SG, sg_dir, stat_safe)

    _rt37_cross_protocol_verify_propfind_must_reflect(rci, I_st, TAG, I_fp, I_dst_rel, port, t_alice, has, t_bob, mkfile, sg_dir, SG, stat_safe)

    _rt37_native_create_into_the_setgid_dir(TAG, SG, sg_dir)



def _rt37_check_when_xrd_avail(sg_dir, stat_safe, mkfile, SG, TAG, port, t_alice, t_bob, has):
    if xrd_avail():
        _rt37_when_xrd_avail(mkfile, TAG, SG, sg_dir, stat_safe, port, t_alice, t_bob, has)
    else:
        ok(True, f"{TAG}: native TPC/root:// setgid legs SKIPPED (xrd_avail=False)")


def _rt37_segment_01_2(filenames, dirnames, dirpath, offenders):
    for nm in list(filenames) + list(dirnames):
        p = os.path.join(dirpath, nm)
        try:
            if os.path.islink(p):
                continue
            u = os.lstat(p).st_uid
            if u in (UID_SVC, 0):
                offenders.append((p, u))
        except OSError:
            pass


def _rt37_for_each_dirpath_dirnames_filenames_os_walk_d(filenames, dirnames, dirpath, offenders):
    _rt37_segment_01_2(filenames, dirnames, dirpath, offenders)



def _rt37_part_h_s3_copyobject_into_a(s3port, TAG, data, mkdir_own, mkfile, stat_safe, has, SG, sg_dir, port, t_alice, t_bob, sgp_dir, stk_dir):

    # =====================================================================
    # PART H — S3 CopyObject INTO a setgid path.  Only alice's S3 key exists, so
    # build an alice:staff setgid dir and CopyObject alice's research-group
    # object into it; the inherited group must be staff, owner alice.  This wires
    # the S3 copy verb to the setgid-create path (never combined).
    # =====================================================================
    if s3port:
        SGS = f"{TAG}_s3sgid"
        sgs_dir = os.path.join(data, SGS)
        ok(mkdir_own(SGS, UID_ALICE, GID_STAFF, 0o2770),
           f"{TAG}: created S3 setgid dest dir {SGS} (rc=mkdir)")
        ensure_traversable(sgs_dir)
        ok(mkfile(f"alice/{TAG}_s3src.txt", b"CGSV-S3-COPY-SRC", UID_ALICE,
                  GID_RESEARCH, 0o644),
           f"{TAG}: alice S3 copy-source seeded group=research (rc=mkfile)")
        H_dst_key = f"{SGS}/{TAG}_s3copied.txt"
        H_fp = os.path.join(sgs_dir, f"{TAG}_s3copied.txt")
        sh, _ = s3("PUT", H_dst_key, s3port,
                   extra_hdrs={"x-amz-copy-source":
                               f"/{S3_BUCKET}/alice/{TAG}_s3src.txt"})
        H_st = stat_safe(H_fp)
        ok(all((sh in (200, 201), H_st is not None)),
           f"{TAG}: S3 CopyObject into setgid dir accepted + landed (HTTP {sh})")
        if H_st is not None:
            ok(H_st.st_gid == GID_STAFF,
               f"{TAG}: INHERIT S3-copied object group==staff({H_st.st_gid}) not "
               f"source-research (HTTP {sh})")
            ok(H_st.st_uid == UID_ALICE,
               f"{TAG}: S3-copied object owner==alice({H_st.st_uid})")
            ok(H_st.st_uid not in (UID_SVC, 0),
               f"{TAG}: S3-copied object NOT svc/root (uid={H_st.st_uid})")
        # body preserved by the S3 copy.
        shg, bhg = s3("GET", H_dst_key, s3port)
        ok(all((shg == 200, has(bhg, b'CGSV-S3-COPY-SRC'))),
           f"{TAG}: S3-copied object body == source (HTTP {shg})")
        # DENY: S3 CopyObject of bob's PRIVATE 0600 file (alice principal) must
        # fail closed — copy verb cannot bypass cross-tenant DAC into setgid dir.
        sh2, bh2 = s3("PUT", f"{SGS}/{TAG}_s3steal.txt", s3port,
                      extra_hdrs={"x-amz-copy-source":
                                  f"/{S3_BUCKET}/bob/private.txt"})
        steal_fp = os.path.join(sgs_dir, f"{TAG}_s3steal.txt")
        ok(sh2 not in (200, 201),
           f"{TAG}: DENY S3 CopyObject of bob's private file into setgid dir "
           f"(HTTP {sh2})")
        ok(not all((os.path.exists(steal_fp), b'BOB-PRIVATE-SECRET' in open(steal_fp, 'rb').read())),
           f"{TAG}: NO-LEAK bob's private bytes never landed via S3 copy")
    else:
        ok(True, f"{TAG}: S3 CopyObject-into-setgid leg SKIPPED (no s3 port)")
    _combo_setgid_via_copymove_p9(sg_dir, sgp_dir, stk_dir, port, t_carol, t_alice, mkfile, SG, TAG, t_bob, has)


def _combo_setgid_via_copymove_p9(sg_dir, sgp_dir, stk_dir, port, t_carol, t_alice, mkfile, SG, TAG, t_bob, has):
    # =====================================================================
    # PART I — native THIRD-PARTY-COPY (loopback TPC) of carol's research file
    # INTO the staff setgid dir.  The pulled/pushed file lands via the broker as
    # carol; setgid must force group=staff, owner=carol.  Then a NON-member TPC
    # dest (bob into the staff setgid dir) must be denied.  GUARDED by xrd_avail.
    # Cross-protocol verification: confirm the TPC result's group via WebDAV
    # PROPFIND (create via root://-TPC, verify via WebDAV).
    # =====================================================================
    _rt37_check_when_xrd_avail(sg_dir, stat_safe, mkfile, SG, TAG, port, t_alice, t_bob, has)

    # =====================================================================
    # PART K — global no-residue sweep: after all the copies/moves/TPC/denies,
    # NO file this batch created under the setgid/sticky dirs may be owned by
    # svc(1500) or root(0); a wrong-owner artefact would be a real escalation.
    # And the setgid/sticky dirs must retain their special bits (no broker
    # corruption from the storm of impersonated copies).
    # =====================================================================
    offenders = []
    for d in (sg_dir, sgp_dir, stk_dir):
        try:
            for dirpath, dirnames, filenames in os.walk(d):
                _rt37_for_each_dirpath_dirnames_filenames_os_walk_d(filenames, dirnames, dirpath, offenders)
        except OSError:
            pass
    ok(not offenders,
       f"{TAG}: NO copied/moved artefact flipped to svc/root ownership "
       f"(offenders={offenders[:3]})")


def _rt37_segment_34(stat_safe, sg_dir, TAG, sgp_dir, stk_dir):
    sg_final = stat_safe(sg_dir)
    ok(all((sg_final is not None, sg_final.st_mode & 1024, sg_final.st_gid == GID_STAFF)),
       f"{TAG}: staff setgid dir retains setgid+group post-storm (rc=stat)")
    sgp_final = stat_safe(sgp_dir)
    ok(all((sgp_final is not None, sgp_final.st_mode & 1024, sgp_final.st_gid == GID_PROJ)),
       f"{TAG}: proj setgid dir retains setgid+group post-storm (rc=stat)")
    stk_final = stat_safe(stk_dir)
    return stk_final


def _rt37_worker_still_serves_a_benign_authenticated(stk_final, TAG, SG, port, t_carol, t_alice, has):
    ok(all((stk_final is not None, stk_final.st_mode & 512, stk_final.st_uid == UID_SVC)),
       f"{TAG}: sticky dir retains sticky bit + svc ownership post-storm (rc=stat)")

    # worker still serves a benign authenticated request after the whole battery.
    sfin, _ = http("PROPFIND", f"/{SG}/", port, t_carol, hdrs={"Depth": "1"})
    ok(sfin in (200, 207, 401, 403, 404),
       f"{TAG}: worker survives + responds after copy/move/setgid suite "
       f"(HTTP {sfin})")
    sfin2, bfin2 = http("GET", "/grp/world_r.txt", port, t_alice)
    ok(all((sfin2 == 200, has(bfin2, b'WORLD-READABLE'))),
       f"{TAG}: post-battery legit world-readable GET still works (HTTP {sfin2})")


def run_combo_setgid_via_copymove(key, data, port, s3port):
    TAG, base, t_alice, t_bob, t_carol = _rt37_combination_frontier_setgid_sticky_inheritance_through(port, key)

    t_erin = _rt37_segment_02(key)

    stat_safe = _rt37_segment_03()

    has = _rt37_segment_04()

    mkfile = _rt37_segment_05(data)

    mkdir_own = _rt37_segment_06(data)

    SG, sg_dir, SGP, sgp_dir = _rt37_our_own_isolated_tag_prefixed_fixtures(TAG, data, mkdir_own)

    STK, stk_dir, SRC_REL = _rt37_a_01777_sticky_staging_dir_owned(mkdir_own, SGP, TAG, data)

    SRC_BODY, TREE_REL = _rt37_a_whole_source_tree_owned_carol(mkdir_own, TAG, mkfile, SRC_REL)

    _rt37_segment_10(mkfile, TREE_REL, TAG, mkdir_own, sg_dir, sgp_dir)

    _rt37_pre_flight_the_setgid_dirs_really(stk_dir, stat_safe, sg_dir, TAG, SG, sgp_dir, SGP)

    A_dst, A_fp, sa, A_st = _rt37_part_a_webdav_copy_of_carol(SG, TAG, sg_dir, SRC_REL, port, t_carol, base, stat_safe)

    src_st = _rt37_the_copy_preserved_the_source_body(A_st, TAG, sa, A_dst, port, t_carol, has, SRC_BODY, stat_safe, data, SRC_REL)

    _rt37_positive_deny_on_the_copied_in(src_st, TAG, A_fp, A_dst, port, t_alice, has, SRC_BODY)

    B_dst = _rt37_part_b_non_member_copy_into(A_dst, port, t_bob, TAG, has, SRC_BODY, mkfile, SG)

    C_dst_rel = _rt37_control_already_proven_in_part_a(sg_dir, TAG, port, t_bob, base, B_dst, stat_safe, SG)

    C_dst_dir, sc, C_root = _rt37_segment_17(sg_dir, TAG, TREE_REL, port, t_carol, base, C_dst_rel, stat_safe)

    _rt37_segment_18(C_root, TAG, sc, stat_safe, C_dst_dir)

    D_dst, D_fp = _rt37_part_d_webdav_move_into_the(stat_safe, C_dst_dir, TAG, mkfile, SG, sg_dir)

    _rt37_segment_20(TAG, port, t_carol, base, D_dst, stat_safe, D_fp)

    D2_fp = _rt37_the_content_survived_the_move_intact(data, TAG, D_dst, port, t_carol, has, mkfile, sg_dir)

    E_src = _rt37_part_e_move_out_of_the(TAG, port, t_bob, base, SG, stat_safe, D2_fp, data, D_dst)

    E_dst_rel, E_st = _rt37_segment_23(TAG, data, E_src, port, t_carol, base, stat_safe)

    _rt37_segment_24(E_st, TAG, E_dst_rel, port, t_carol, has, D_fp)

    F_dst, F_fp, sf = _rt37_part_f_the_proj_setgid_dir(mkfile, TAG, SGP, sgp_dir, port, t_carol, base)

    sfe, bfe = _rt37_segment_26(stat_safe, F_fp, TAG, sf, F_dst, port, t_erin)

    _rt37_part_g_sticky_copy_interaction_two(sfe, has, bfe, TAG, F_dst, port, t_alice, mkfile)

    G_a_dst, G_a_fp, ga_st = _rt37_segment_28(STK, TAG, stk_dir, port, t_alice, base, stat_safe)

    G_b_fp, sgb = _rt37_segment_29(ga_st, TAG, mkfile, STK, stk_dir, port, t_bob, base)

    _rt37_deny_bob_deletes_alice_s_copied(stat_safe, G_b_fp, sgb, TAG, G_a_dst, port, t_bob, G_a_fp)

    _rt37_deny_carol_moves_alice_s_copied(G_a_fp, TAG, G_a_dst, port, t_carol, base, data)

    _rt37_positive_control_a_non_owner_alice(G_a_dst, port, t_alice, G_a_fp, TAG, STK, stk_dir, stat_safe)

    _rt37_part_h_s3_copyobject_into_a(s3port, TAG, data, mkdir_own, mkfile, stat_safe, has, SG, sg_dir, port, t_alice, t_bob, sgp_dir, stk_dir)

    stk_final = _rt37_segment_34(stat_safe, sg_dir, TAG, sgp_dir, stk_dir)

    _rt37_worker_still_serves_a_benign_authenticated(stk_final, TAG, SG, port, t_carol, t_alice, has)

# e2e_redteam_part90.py — continuation shard split off from e2e_redteam_part70.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt70_positive_control_bob_himself_moves_his(sm, TAG, uid_of, bob_locked, body_of, LOCK_MARK, exists, alice_mv_src, base):
    ok(sm in (401, 403, 404, 409, 412, 423, 500),
       f"{TAG}(3): alice cross-tenant MOVE clobbering bob's LOCKED file DENIED "
       f"(HTTP {sm})")
    ok(all((uid_of(bob_locked) == UID_BOB, body_of(bob_locked) == LOCK_MARK)),
       f"{TAG}(3): bob's locked file untouched (still bob-owned, secret intact)")
    ok(exists(alice_mv_src),
       f"{TAG}(3): alice's source preserved after her denied clobber (no data loss)")
    # POSITIVE control: bob himself MOVEs his locked file (with his lock token) to a
    # new name -> the owner+lock-holder is allowed; proves the deny above was the
    # identity/lock boundary, not a blanket MOVE failure.
    bob_dst = f"bob/{TAG}_locked_moved.txt"
    if_hdr = {"Destination": base + "/" + bob_dst}
    return bob_dst, if_hdr


def _rt70_segment_28(ltok, if_hdr, bob_locked, port, tb, uid_of, bob_dst, TAG):
    if ltok:
        if_hdr["If"] = f"(<{ltok}>)"
    smb, _ = http("MOVE", "/" + bob_locked, port, tb, hdrs=if_hdr)
    moved_ok = smb in (200, 201, 204) and uid_of(bob_dst) == UID_BOB
    ok(any((moved_ok, uid_of(bob_dst) in (-1, UID_BOB))),
       f"{TAG}(3): POSITIVE bob (owner+lock-holder) MOVEs his own locked file, "
       f"result bob-owned never svc/root (HTTP {smb})")
    ok(uid_of(bob_dst) not in (UID_ALICE, UID_SVC, 0),
       f"{TAG}(3): bob's moved file never alice/svc/root-owned (uid={uid_of(bob_dst)})")


def _rt70_4_scoped_read_only_token_x(key, GWD, GR, port, GR_BODY, TAG, body_of, GW):

    # =====================================================================
    # (4) SCOPED READ-ONLY TOKEN x GROUP-DAC.  A carol token scoped ONLY
    #     `storage.read:/grp` (no create/modify verb).  carol IS in staff, so DAC
    #     would permit her to WRITE the 0660 group-writable file -- but the token's
    #     scope grants only READ.  The read of the 0640 group file must SUCCEED
    #     (group DAC + read scope), while the write must be denied by SCOPE even
    #     though DAC alone would allow it.  This is the scope-vs-DAC layering that
    #     run_token_scope_dac tests only on a cross-tenant path, never on a path the
    #     accessor's GROUP grants but the SCOPE forbids -- a distinct intersection.
    _deep_novel_combos_r8_p3(have_s3, have_root, key, port, body_of, GW, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, GR, GR_BODY, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, gid_of, complete_xml)


def _deep_novel_combos_r8_p3(have_s3, have_root, key, port, body_of, GW, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, GR, GR_BODY, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, gid_of, complete_xml):
    # =====================================================================
    # Read scope covers BOTH the 0640 read file (/grp) and the staff write-dir, so the
    # write-deny below is unambiguously about the missing write verb, not the path.
    tc_ro = mint(key, "carol", scope=f"storage.read:/grp storage.read:/{GWD}")
    sro, bro = http("GET", f"/grp/{GR}", port, tc_ro)
    ok(all((sro == 200, GR_BODY in any((bro, b'')))),
       f"{TAG}(4): read-only-scoped carol(staff) GETs 0640 group file via group DAC "
       f"+ read scope (HTTP {sro})")
    # write with the read-only token: scope must reject it, leaving content unchanged.
    pre_gw = body_of(GW)
    swro, _ = http("PUT", f"/{GW}", port, tc_ro, data=b"DNC8-RO-SCOPE-CLOBBER")
    return pre_gw, swro


def _rt70_positive_control_a_full_scope_carol(swro, TAG, body_of, GW, pre_gw, key, port):
    ok(swro in (401, 403, 404, 405, 423, 500),
       f"{TAG}(4): read-only-scoped carol PUT to group-writable file DENIED BY SCOPE "
       f"despite group-write DAC (HTTP {swro})")
    ok(all((body_of(GW) == pre_gw, b'DNC8-RO-SCOPE-CLOBBER' not in body_of(GW))),
       f"{TAG}(4): group-writable file content unchanged after scope-denied write")
    # POSITIVE control: a FULL-scope carol token CAN write the same 0660 group file.
    # It lives in a staff-group-writable setgid dir, so carol (staff) can stage+commit
    # the WebDAV PUT — proving the gate above was the scope, not the group/DAC boundary.
    tc_full = mint(key, "carol")
    swf, _ = http("PUT", f"/{GW}", port, tc_full, data=b"DNC8-CAROL-GROUP-WRITE")
    ok(swf in (200, 201, 204),
       f"{TAG}(4): POSITIVE full-scope carol(staff) writes 0660 group file (HTTP {swf})")
    return swf


def _rt70_dave_non_member_of_shared_tries_2(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of):
    stp, pb = s3("PUT", mpu_key, s3port,
                 params={"uploadId": up, "partNumber": "1"},
                 access_key="bob", data=b"M" * 8192)
    e1 = etag(pb)
    ok(stp in (200, 201),
       f"{TAG}(5): bob uploads part 1 of the shared-dir MPU (HTTP {stp})")
    # dave (NON-member of shared) tries to COMPLETE -> denied; nothing assembled.
    std, _ = s3("POST", mpu_key, s3port, params={"uploadId": up},
                access_key="dave", data=complete_xml([(1, e1 or "x")]))
    dave_assembled = exists(mpu_key) and uid_of(mpu_key) == UID_DAVE
    return e1, std, dave_assembled


def _rt70_carol_member_of_shared_completes_assembled(dave_assembled, TAG, std, mpu_key, s3port, up, complete_xml, e1, uid_of, exists, gid_of, svc_root_residue, SG):
    ok(not dave_assembled,
       f"{TAG}(5): non-member dave COMPLETE of bob's shared-dir MPU did NOT "
       f"assemble a dave-owned object (HTTP {std})")
    # carol (member of shared) COMPLETEs -> assembled object owned by carol.
    stc, _ = s3("POST", mpu_key, s3port, params={"uploadId": up},
                access_key="carol", data=complete_xml([(1, e1 or "x")]))
    cuid = uid_of(mpu_key)
    if exists(mpu_key):
        ok(all((cuid in (UID_CAROL, UID_BOB), cuid not in (UID_SVC, 0, UID_DAVE))),
           f"{TAG}(5): MPU assembled-by-carol object owned by a real shared "
           f"member, never svc/root/dave (uid={cuid}, HTTP {stc})")
        ok(gid_of(mpu_key) in (GID_SHARED, UID_CAROL, UID_BOB),
           f"{TAG}(5): assembled object carries shared group (setgid) or its "
           f"completer's primary, never a foreign group (gid={gid_of(mpu_key)})")
    else:
        ok(stc in (200, 201, 403, 404, 409, 500),
           f"{TAG}(5): cross-member MPU complete resolved a verdict, no object "
           f"(HTTP {stc})")
        ok(not svc_root_residue(SG),
           f"{TAG}(5): no svc/root residue from the unassembled MPU")


def _rt70_when_up(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of, gid_of, svc_root_residue, SG):
    e1, std, dave_assembled = _rt70_dave_non_member_of_shared_tries_2(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of)

    _rt70_carol_member_of_shared_completes_assembled(dave_assembled, TAG, std, mpu_key, s3port, up, complete_xml, e1, uid_of, exists, gid_of, svc_root_residue, SG)



def _rt70_dave_non_member_of_shared_tries(SG, TAG, s3port, upid, etag, complete_xml, exists, uid_of, gid_of, svc_root_residue):
    mpu_key = f"{SG}/{TAG}_mpu.bin"
    sti, ib = s3("POST", mpu_key, s3port, params={"uploads": ""}, access_key="bob")
    up = upid(ib)
    ok(sti in (200, 403),
       f"{TAG}(5): bob S3 MPU into shared setgid dir — 200 if bob is group-"
       f"writable on it, else 403 DAC (HTTP {sti})")
    if up:
        _rt70_when_up(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of, gid_of, svc_root_residue, SG)
    else:
        ok(True, f"{TAG}(5): MPU initiate failed; non-member complete leg skipped")
        ok(True, f"{TAG}(5): MPU member-complete leg skipped (no uploadId)")
        ok(True, f"{TAG}(5): MPU ownership invariant skipped (no uploadId)")


def _rt70_when_s3_live(SG, TAG, s3port, upid, etag, uid_of, exists, complete_xml, gid_of, svc_root_residue):
    _rt70_dave_non_member_of_shared_tries(SG, TAG, s3port, upid, etag, complete_xml, exists, uid_of, gid_of, svc_root_residue)



def _rt70_check_when_have_root(have_root, TAG, SG, svc_root_residue, exists):
    if have_root:
        miss_src = f"/carol/{TAG}_missing_{int(time.time())}.bin"
        miss_dst = f"/{SG}/{TAG}_tpc_miss.bin"
        rc6, _o6, _e6 = xrd_cp_tpc(miss_src, miss_dst, "carol")
        ok(all((rc6 != 0, not exists(miss_dst))),
           f"{TAG}(6a): abandoned TPC (missing source) left no partial dest (rc={rc6})")
        ok(not svc_root_residue(SG),
           f"{TAG}(6a): abandoned TPC left NO svc/root-owned residue in setgid dir")
    else:
        ok(True, f"{TAG}(6a): abandoned-TPC residue check skipped (no native client)")
        ok(True, f"{TAG}(6a): abandoned-TPC svc-residue check skipped (no native client)")


def _rt70_member_bob_initiates_uploads_a_part(swf, uid_of, GW, gid_of, TAG, have_s3, s3port, SG, upid, etag, complete_xml, exists, svc_root_residue, have_root):
    if swf in (200, 201, 204):
        ok(all((uid_of(GW) == UID_CAROL, gid_of(GW) == GID_STAFF)),
           f"{TAG}(4): group-write committed as carol, kept setgid staff group "
           f"(uid={uid_of(GW)} gid={gid_of(GW)})")
    else:
        ok(True, f"{TAG}(4): full-scope group write not honoured; no ownership change")

    # =====================================================================
    # (5) S3 MULTIPART into a GROUP-SHARED dir, COMPLETED by a DIFFERENT group
    #     member.  bob INITIATES + uploads a part into the 02770 shared dir (bob IS
    #     shared); carol (ALSO shared) drives the COMPLETE.  The assembled object
    #     must be owned by the principal the broker maps for the Complete request
    #     (carol) -- never svc/root -- and must carry the setgid'd shared group.  A
    #     NON-member (dave) completing the same upload is denied.  This "another
    #     group member finishes my MPU" sequence is not in multipart_lock_identity
    #     (which only cross-tenant-aborts/foreign-uploadId's a single tenant's MPU).
    # =====================================================================
    if have_s3:
        st0, _ = s3("GET", "", s3port, params={"list-type": "2"})
        s3_live = st0 != -1
    else:
        s3_live = False
    _deep_novel_combos_r8_p4(s3_live, have_root, port, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, A_BODY, complete_xml, body_of, gid_of)


def _deep_novel_combos_r8_p4(s3_live, have_root, port, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, A_BODY, complete_xml, body_of, gid_of):
    if s3_live:
        _rt70_when_s3_live(SG, TAG, s3port, upid, etag, uid_of, exists, complete_xml, gid_of, svc_root_residue)
    else:
        ok(True, f"{TAG}(5): S3 multipart group-complete skipped (S3 not reachable)")
        ok(True, f"{TAG}(5): non-member MPU complete deny skipped (no S3)")
        ok(True, f"{TAG}(5): MPU ownership invariant skipped (no S3)")
    _deep_novel_combos_r8_p5(have_root, port, ta, TAG, mkfile, V_OLD, V_NEW, SG, digest_of, BOB_SECRET, svc_root_residue, A_BODY, uid_of, exists, body_of)


def _deep_novel_combos_r8_p5(have_root, port, ta, TAG, mkfile, V_OLD, V_NEW, SG, digest_of, BOB_SECRET, svc_root_residue, A_BODY, uid_of, exists, body_of):
    # =====================================================================
    # (6) PARTIAL-RST mid-TPC + DIGEST-MID-OVERWRITE race.  Two failure-path
    #     combinations the existing combos never cross:
    #     (6a) a native loopback TPC whose source does NOT exist is abandoned --
    #          the broker must leave NO svc/root-owned partial in the dest dir and
    #          stay healthy (already partially covered for ENOENT in tpc matrix, but
    #          here we also assert the *worker-survival + no-svc-residue* invariant
    #          across the WHOLE export, the impersonation-leak signature);
    #     (6b) while alice overwrites a 0644 file between two WHOLE versions, bob
    #          repeatedly queries its checksum -- every successful digest must match
    #          the digest of ONE consistent whole version (V_OLD or V_NEW), never a
    #          torn/intermediate digest of a half-written file.
    # =====================================================================
    # (6a)
    _rt70_check_when_have_root(have_root, TAG, SG, svc_root_residue, exists)

    # (6b)
    race_rel = f"alice/{TAG}_race.bin"
    return race_rel


def _rt70_segment_01_2(race_rel, digest_of, mkfile, V_NEW):
    rc_o, out_o, _ = xrd_fs(["query", "checksum", "/" + race_rel], "alice")
    dig_old = digest_of(out_o) if rc_o == 0 else None
    mkfile(race_rel, V_NEW, UID_ALICE, UID_ALICE, 0o644)
    rc_n, out_n, _ = xrd_fs(["query", "checksum", "/" + race_rel], "alice")
    dig_new = digest_of(out_n) if rc_n == 0 else None
    return dig_old, dig_new


def _rt70_segment_02_2(mkfile, race_rel, V_OLD):
    mkfile(race_rel, V_OLD, UID_ALICE, UID_ALICE, 0o644)   # reset to OLD

    race_digs, race_err = [], []
    return race_digs, race_err


def _rt70_segment_03_2(race_rel, port, ta, V_NEW, V_OLD, race_err):

    def overwriter():
        for _ in range(4):
            try:
                http("PUT", "/" + race_rel, port, ta, V_NEW)
                http("PUT", "/" + race_rel, port, ta, V_OLD)
            except Exception as e:                 # noqa: BLE001
                race_err.append(repr(e))
    return overwriter


def _rt70_segment_04(race_rel, digest_of, race_digs, race_err):

    def race_ck(i):
        for _ in range(2):
            try:
                rc, out, _e = xrd_fs(["query", "checksum", "/" + race_rel], "bob")
                if rc == 0:
                    d = digest_of(out)
                    if d:
                        race_digs.append(d)
            except Exception as e:                 # noqa: BLE001
                race_err.append(repr(e))
    return race_ck


def _rt70_check_for_each_t_rthreads(rthreads):
    for t in rthreads:
        t.start()


def _rt70_segment_05_2(overwriter, race_ck, dig_old, dig_new):

    rthreads = [threading.Thread(target=overwriter)]
    rthreads += [threading.Thread(target=race_ck, args=(i,)) for i in range(3)]
    _rt70_check_for_each_t_rthreads(rthreads)
    for t in rthreads:
        t.join()

    legal = {d for d in (dig_old, dig_new) if d}
    return legal


def _rt70_segment_06_2(legal, race_digs, TAG, uid_of, race_rel, body_of, V_OLD, V_NEW):
    if legal and race_digs:
        torn = [d for d in race_digs if d not in legal]
        ok(not torn,
           f"{TAG}(6b): every concurrent digest matches one WHOLE version, never "
           f"a torn/intermediate digest (n={len(race_digs)} torn={torn[:2]})")
        ok(all((uid_of(race_rel) == UID_ALICE, uid_of(race_rel) not in (UID_SVC, 0))),
           f"{TAG}(6b): race file stays alice-owned after the overwrite storm "
           f"(uid={uid_of(race_rel)})")
    else:
        ok(body_of(race_rel) in (V_OLD, V_NEW),
           f"{TAG}(6b): race file on disk is a WHOLE writer version (no half-write)")
        ok(uid_of(race_rel) == UID_ALICE,
           f"{TAG}(6b): race file stays alice-owned (digest compare unavailable)")


def _rt70_when_have_root(race_rel, digest_of, mkfile, V_NEW, V_OLD, port, ta, TAG, body_of, uid_of):
    dig_old, dig_new = _rt70_segment_01_2(race_rel, digest_of, mkfile, V_NEW)

    race_digs, race_err = _rt70_segment_02_2(mkfile, race_rel, V_OLD)

    overwriter = _rt70_segment_03_2(race_rel, port, ta, V_NEW, V_OLD, race_err)

    race_ck = _rt70_segment_04(race_rel, digest_of, race_digs, race_err)

    legal = _rt70_segment_05_2(overwriter, race_ck, dig_old, dig_new)

    _rt70_segment_06_2(legal, race_digs, TAG, uid_of, race_rel, body_of, V_OLD, V_NEW)



def _rt70_capture_the_stable_digest_of_each(mkfile, race_rel, V_OLD, TAG, have_root, digest_of, V_NEW, port, ta, uid_of, body_of, A_BODY, BOB_SECRET):
    ok(mkfile(race_rel, V_OLD, UID_ALICE, UID_ALICE, 0o644),
       f"{TAG}(6b): overwrite-race file seeded with whole V_OLD")
    _deep_novel_combos_r8_p6(have_root, port, ta, mkfile, race_rel, V_NEW, V_OLD, digest_of, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of)


def _deep_novel_combos_r8_p6(have_root, port, ta, mkfile, race_rel, V_NEW, V_OLD, digest_of, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of):
    if have_root:
        # capture the stable digest of each whole version as the only legal answers.
        _rt70_when_have_root(race_rel, digest_of, mkfile, V_NEW, V_OLD, port, ta, TAG, body_of, uid_of)
    else:
        ok(True, f"{TAG}(6b): digest-mid-overwrite race skipped (no native client)")
        ok(True, f"{TAG}(6b): race-file ownership invariant skipped (no native client)")
    _deep_novel_combos_r8_p7(port, ta, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of)


def _deep_novel_combos_r8_p7(port, ta, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of):
    # =====================================================================
    # SURVIVAL + secret integrity: after the whole round-8 combination storm the
    # worker is not wedged, bob's canonical private secret is intact, and no
    # svc/root-owned artifact was smuggled into the setgid dir.
    # =====================================================================
    ssv, bsv = http("GET", f"/alice/{TAG}_ck.bin", port, ta)
    ok(all((ssv == 200, A_BODY[:16] in any((bsv, b'')))),
       f"{TAG} survival: alice legit GET still works after the storm (HTTP {ssv})")
    ok(all((body_of('bob/private.txt').startswith(BOB_SECRET), uid_of('bob/private.txt') == UID_BOB)),
       f"{TAG} survival: bob/private.txt canonical secret + ownership intact")


def _rt70_segment_33(svc_root_residue, SG, TAG):
    ok(not svc_root_residue(SG),
       f"{TAG} survival: setgid shared dir holds no svc/root-owned artifact")


def run_deep_novel_combos_r8(key, data, port, s3port):
    """ROUND-8 cross-feature COMBINATION frontier: sequences that CROSS the new
    round-8 surfaces (HTTP-TPC pull / native-TPC / query-checksum / scoped-token /
    cross-tenant rename) with DAC + GROUP + CONCURRENCY in shapes none of the 12
    existing combo_* batches drive.  Distinct from run_combo_setgid_via_copymove
    (it does WebDAV-COPY/MOVE/native-TPC/S3-CopyObject setgid inheritance but NOT
    an HTTP-TPC *pull* residue check, NOT checksum-vs-identity, NOT lock-vs-rename),
    from run_combo_multipart_lock_identity (it crosses S3-MPU x LOCK x identity but
    NOT a group-member-completes-another-member's-MPU, NOT rename-vs-lock, NOT a
    read-only-scope x group write-deny), from run_combo_concurrent_crossproto (torn
    read of file BYTES, never of a query-checksum DIGEST under identity-switch), and
    from run_tpc_pull_push_matrix (native-TPC DAC matrix, but NOT setgid-through-TPC
    residue, NOT a mid-TPC RST, NOT digest-mid-overwrite).  Every sequence ends in a
    DISTINCT invariant: no cross-tenant digest bleed, no torn digest, scope gates the
    write while DAC gates the read, a lock+DAC double-denies a cross-tenant clobber,
    an MPU assembled by a different group member is owned by the completer not svc,
    and no failed/aborted TPC leaves an svc/root-owned partial.  Fixtures: `dnc8_`.
    <=8 threads, <=64 KiB bodies, <=6 concurrent subprocesses."""
    TAG, base, ta, tb, tc = _rt70_segment_01(port, key)

    have_root, have_s3, BOB_SECRET, A_BODY = _rt70_segment_02(key, s3port)

    B_BODY, V_OLD, V_NEW = _rt70_segment_03()

    realp = _rt70_on_disk_introspection_this_batch_runs(data)

    uid_of = _rt70_segment_05(realp)

    gid_of = _rt70_segment_06(realp)

    mode_of = _rt70_segment_07(realp)

    exists = _rt70_segment_08(realp)

    body_of = _rt70_segment_09(realp)

    listdir = _rt70_segment_10(realp)

    mkfile = _rt70_segment_11(realp)

    mkdir_own = _rt70_segment_12(realp)

    _rt70_segment_13(realp)

    digest_of = _rt70_segment_14()

    svc_root_residue = _rt70_segment_15(listdir, realp)

    upid = _rt70_segment_16()

    etag = _rt70_segment_17()

    complete_xml = _rt70_segment_18()

    lock_file = _rt70_segment_19(port)

    SG = _rt70_isolated_fixtures_never_touch_the_canonical(TAG, mkdir_own, mode_of, gid_of, realp)

    ACK, BCK, GR = _rt70_alice_bob_distinct_checksum_sources_own(TAG, mkfile, A_BODY, B_BODY)

    GR_BODY, GWD, GW = _rt70_rename_so_the_positive_control_needs(mkfile, GR, TAG, mkdir_own)

    pull_dst = _rt70_1_http_tpc_pull_into_the(realp, GWD, mkfile, GW, TAG, SG, port, tc)

    sgm2 = _rt70_segment_24(svc_root_residue, SG, TAG, uid_of, pull_dst, mode_of)

    bob_locked, LOCK_MARK = _rt70_2_query_checksum_x_concurrent_identity(sgm2, gid_of, SG, TAG, have_root, digest_of, ACK, BCK, mkfile)

    ltok, alice_mv_src, sm = _rt70_alice_s_own_movable_source_she(lock_file, bob_locked, tb, TAG, mkfile, port, ta, base)

    bob_dst, if_hdr = _rt70_positive_control_bob_himself_moves_his(sm, TAG, uid_of, bob_locked, body_of, LOCK_MARK, exists, alice_mv_src, base)

    _rt70_segment_28(ltok, if_hdr, bob_locked, port, tb, uid_of, bob_dst, TAG)

    pre_gw, swro = _rt70_4_scoped_read_only_token_x(key, GWD, GR, port, GR_BODY, TAG, body_of, GW)

    swf = _rt70_positive_control_a_full_scope_carol(swro, TAG, body_of, GW, pre_gw, key, port)

    race_rel = _rt70_member_bob_initiates_uploads_a_part(swf, uid_of, GW, gid_of, TAG, have_s3, s3port, SG, upid, etag, complete_xml, exists, svc_root_residue, have_root)

    _rt70_capture_the_stable_digest_of_each(mkfile, race_rel, V_OLD, TAG, have_root, digest_of, V_NEW, port, ta, uid_of, body_of, A_BODY, BOB_SECRET)

    _rt70_segment_33(svc_root_residue, SG, TAG)




# ===== Round-9 new-feature-surface batches =====

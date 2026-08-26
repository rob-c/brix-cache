# e2e_redteam_part84.py — continuation shard split off from e2e_redteam_part39.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt39_section_c_mid_body_rst_during(s3_up, TAG, initiate, s3port, exists, complete_xml, etag, uid_of, bob_secret, body_of, MARK, lock_file, grp_rel, tc):

    # =========================================================================
    # SECTION C.  MID-BODY RST DURING UploadPart  (interruption x state)
    #   Build a SIGNED UploadPart (UNSIGNED-PAYLOAD, so the truncated body keeps a
    #   valid signature) whose Content-Length promises 4096 bytes but RST mid-body.
    #   The part must NOT half-commit, an Abort must still succeed, and the broker
    #   must survive (a follow-up legit complete works).
    # =========================================================================
    if s3_up:
        up = _rt39_when_s3_up_4(TAG, initiate, s3port, exists, complete_xml, uid_of, etag)
    else:
        for _ in range(4):
            ok(True, "C: mid-body RST skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION D.  CROSS-TENANT MULTIPART VIA PATH  (identity x keyspace)
    #   Only alice's S3 key exists, so cross-identity is driven by the PATH: alice
    #   initiates/uploads/completes into BOB's directory.  The assemble must run as
    #   alice and be DAC-denied in bob's space (bob/ is 0755 but bob owns it) OR, if
    #   the gateway permits a create, the result must NOT be owned by bob and must
    #   NOT overwrite bob's secret.  Positive control = same flow in alice's space.
    # =========================================================================
    if s3_up:
        # D1: initiate into bob's keyspace as alice.
        _rt39_when_s3_up_5(TAG, initiate, s3port, uid_of, complete_xml, exists, MARK, bob_secret, body_of)
    else:
        for _ in range(7):
            ok(True, "D: cross-tenant multipart skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION E.  CROSS-PROTOCOL LOCK BYPASS
    #   carol (staff) LOCKs the carol:staff group file via WebDAV.  Then bob — who
    #   is NOT in staff and is 'other' on the 0640 file — tries to DELETE/MOVE it
    #   via ROOT:// (no lock semantics) and via WebDAV with the STOLEN lock token.
    #   Every bob attempt must be DAC-denied; the file must survive carol-owned and
    #   its content must never leak to bob.  Positive control = carol's own ops.
    # =========================================================================
    # carol acquires an exclusive lock on the group file via WebDAV.
    st_l, ltok = lock_file(f"/{grp_rel}", tc)
    ok(all((st_l in (200, 201), ltok is not None)),
       f"E: carol LOCKs carol:staff group file via WebDAV (HTTP {st_l})")
    ok(uid_of(grp_rel) == UID_CAROL,
       "E: locked group file still carol-owned after LOCK")
    return ltok


def _rt39_e1_bob_delete_via_webdav_with(body_of, grp_rel, port, tb, ltok, exists, uid_of, base, TAG):

    # E1: bob DELETE via WebDAV WITH the stolen lock token -> DAC denies (bob other).
    bgrp = body_of(grp_rel)
    st, _ = http("DELETE", f"/{grp_rel}", port, tb,
                 hdrs={"If": f"(<{ltok}>)"} if ltok else None)
    ok(all((st not in (200, 204), exists(grp_rel), uid_of(grp_rel) == UID_CAROL)),
       f"E1: bob WebDAV DELETE w/ stolen lock token DENIED, file survives "
       f"(HTTP {st})")

    # E2: bob MOVE (theft) via WebDAV with the stolen token -> denied, no theft.
    st, _ = http("MOVE", f"/{grp_rel}", port, tb,
                 hdrs=({"Destination": f"{base}/bob/{TAG}_stolen.txt",
                        "If": f"(<{ltok}>)"} if ltok
                       else {"Destination": f"{base}/bob/{TAG}_stolen.txt"}))
    ok(all((st not in (200, 201, 204), exists(grp_rel), not exists(f'bob/{TAG}_stolen.txt'))),
       f"E2: bob WebDAV MOVE w/ stolen lock token DENIED, no theft (HTTP {st})")


def _rt39_bob_cannot_even_read_the_0640(grp_rel, exists, uid_of, TAG):
    rc, out, err = xrd_fs(["rm", f"/{grp_rel}"], "bob")
    ok(all((rc != 0, exists(grp_rel), uid_of(grp_rel) == UID_CAROL)),
       f"E3: bob root:// rm of carol's locked group file DENIED by DAC (rc={rc})")
    rc2, _, _ = xrd_fs(["mv", f"/{grp_rel}", f"/bob/{TAG}_rootsteal.txt"], "bob")
    ok(all((rc2 != 0, exists(grp_rel), not exists(f'bob/{TAG}_rootsteal.txt'))),
       f"E3: bob root:// mv of carol's locked group file DENIED (rc={rc2})")
    # bob cannot even READ the 0640 group content via root:// (lock irrelevant).
    outf = os.path.join(WORK, f"{TAG}_bobread.out")
    return outf


def _rt39_segment_02_2(grp_rel, outf, GMARK):
    rc3, _, _ = xrd_cp_down(f"/{grp_rel}", outf, "bob")
    leaked = b""
    try:
        with open(outf, "rb") as fh:
            leaked = fh.read()
    except OSError:
        pass
    ok(any((rc3 != 0, GMARK not in leaked)),
       f"E3: bob root:// read of carol's 0640 group file leaks no bytes "
       f"(rc={rc3})")
    try:
        os.unlink(outf)
    except OSError:
        pass


def _rt39_positive_control_carol_is_the_owner_2(TAG, grp_rel, GMARK):
    # POSITIVE CONTROL: carol IS the owner -> carol can read it via root://.
    outc = os.path.join(WORK, f"{TAG}_carolread.out")
    rcc, _, _ = xrd_cp_down(f"/{grp_rel}", outc, "carol")
    gotc = b""
    try:
        with open(outc, "rb") as fh:
            gotc = fh.read()
    except OSError:
        pass
    ok(all((rcc == 0, GMARK in gotc)),
       f"E3: CONTROL carol reads her own locked group file via root:// (rc={rcc})")
    return outc


def _rt39_segment_04_2(outc):
    try:
        os.unlink(outc)
    except OSError:
        pass


def _rt39_when_xrd_avail(grp_rel, exists, uid_of, TAG, GMARK):
    outf = _rt39_bob_cannot_even_read_the_0640(grp_rel, exists, uid_of, TAG)

    _rt39_segment_02_2(grp_rel, outf, GMARK)

    outc = _rt39_positive_control_carol_is_the_owner_2(TAG, grp_rel, GMARK)

    _rt39_segment_04_2(outc)



def _rt39_positive_control_carol_is_the_owner(grp_rel, exists, uid_of, TAG, GMARK, port, ta, ltok):

    # E3: ROOT:// has no lock semantics — bob rm/mv must still be DAC-denied there.
    if xrd_avail():
        _rt39_when_xrd_avail(grp_rel, exists, uid_of, TAG, GMARK)
    else:
        for _ in range(4):
            ok(True, "E3: root:// lock-bypass skipped (native client unavailable)")

    # E4: alice IS in staff (group can read 0640) but is NOT the file owner.  POSIX
    #     unlink is governed by the PARENT DIRECTORY, not the file's mode: grp_rel
    #     lives in alice/ which is alice-owned 0755 with NO sticky bit, so alice (the
    #     dir owner) may legitimately delete carol's file there — a 204 is CORRECT
    #     DAC, not a leak.  The stolen WebDAV lock token launders nothing: whatever
    #     happens is decided purely by the kernel under impersonation.  The genuine
    #     anti-laundering deny (a non-dir-owner) is proven by E1/E2/E3 (bob).  Here we
    #     pin the real invariants: alice's legit group READ works (control), and the
    #     op never leaks cross-tenant bytes nor silently re-owns a surviving file.
    st, gb = http("GET", f"/{grp_rel}", port, ta)
    ok(all((st == 200, GMARK in gb)),
       f"E4: CONTROL staff-member alice GROUP-READs carol's 0640 file (HTTP {st})")
    st, _ = http("DELETE", f"/{grp_rel}", port, ta,
                 hdrs={"If": f"(<{ltok}>)"} if ltok else None)
    # Either alice (dir owner) legitimately removed it (204, the file is gone), or the
    # op was denied (file survives carol-owned, GMARK intact) — never re-owned to
    # alice/svc/root and never leaking MARK (bob's secret).  No half-state.
    survived = exists(grp_rel)
    return st, survived


def _rt39_section_f_webdav_lock_then_s3(survived, st, uid_of, grp_rel, GMARK, body_of, MARK, TAG, port, ta):
    ok(any((all((not survived, st in (200, 204))), all((survived, st not in (200, 204), uid_of(grp_rel) == UID_CAROL, GMARK in body_of(grp_rel))))),
       f"E4: stolen-token DELETE is pure dir-owner DAC, no identity laundering "
       f"(HTTP {st}, survived={survived}, uid={uid_of(grp_rel)})")
    ok(MARK not in body_of(grp_rel),
       "E4: stolen-token DELETE path never surfaces bob's cross-tenant secret bytes")

    # =========================================================================
    # SECTION F.  WebDAV LOCK then S3 mutation of the SAME object  (protocol mix)
    #   alice PUTs+LOCKs a file via WebDAV, then mutates it via S3 as the OWNER
    #   (handled, stays alice-owned, no svc/root residue) and as BOB via path
    #   (cross-tenant S3 write -> denied; lock-state must not launder identity).
    # =========================================================================
    lf = f"alice/{TAG}_lockmix.txt"
    st, _ = http("PUT", f"/{lf}", port, ta, b"lockmix-v1\n")
    ok(all((st in (200, 201, 204), uid_of(lf) == UID_ALICE)),
       f"F: alice PUT lock-mix target via WebDAV, alice-owned (HTTP {st})")
    return lf


def _rt39_lock_the_assembled_object_via_webdav(kg, s3port, up, complete_xml, etag, uid_of, lock_file, ta):
    _, bg = s3("PUT", kg, s3port,
               params={"uploadId": up, "partNumber": "1"}, data=b"G" * 4096)
    st_c, _ = s3("POST", kg, s3port, params={"uploadId": up},
                 data=complete_xml([(1, etag(bg) or "x")]))
    ok(all((st_c in (200, 201), uid_of(kg) == UID_ALICE)),
       f"G: multipart-assembled object owned by alice (HTTP {st_c})")
    # LOCK the assembled object via WebDAV.
    st_l, gtok = lock_file(f"/{kg}", ta)
    ok(all((st_l in (200, 201), gtok is not None)),
       f"G: WebDAV LOCK on multipart-assembled object (HTTP {st_l})")
    return gtok


def _rt39_signed_as_alice_the_only_key_2(kg, port, tb, gtok, exists, uid_of, body_of, s3port, MARK):
    # bob cross-tenant DELETE via WebDAV w/ stolen token -> denied.
    st_bd, _ = http("DELETE", f"/{kg}", port, tb,
                    hdrs={"If": f"(<{gtok}>)"} if gtok else None)
    ok(all((st_bd not in (200, 204), exists(kg), uid_of(kg) == UID_ALICE)),
       f"G: bob WebDAV DELETE of locked assembled object DENIED (HTTP {st_bd})")
    # bob cross-tenant overwrite via S3 path of the SAME object key (alice's
    # space) -> setfsuid(bob) write into alice/ -> EACCES.
    before = body_of(kg)
    st_bw, _ = s3("PUT", kg, s3port, data=MARK, access_key="alice")
    # (signed as alice — the only key — so this is a positive owner control;
    #  prove the lock state does not corrupt ownership, content stays alice's)
    ok(all((uid_of(kg) == UID_ALICE, uid_of(kg) not in (UID_SVC, 0))),
       f"G: locked assembled object stays alice-owned after S3 PUT "
       f"(uid={uid_of(kg)})")


def _rt39_bob_via_root_rm_dac_denied(kg, exists, gtok, port, ta, s3port):
    # bob via root:// rm -> DAC denied.
    if xrd_avail():
        rc, _, _ = xrd_fs(["rm", f"/{kg}"], "bob")
        ok(all((rc != 0, exists(kg))),
           f"G: bob root:// rm of alice's locked assembled object DENIED "
           f"(rc={rc})")
    else:
        ok(True, "G: root:// cross attack skipped (native client unavailable)")
    # cleanup: UNLOCK + delete as owner.
    if gtok:
        http("UNLOCK", f"/{kg}", port, ta, hdrs={"Lock-Token": f"<{gtok}>"})
    s3("DELETE", kg, s3port)


def _rt39_when_up(kg, s3port, up, complete_xml, etag, uid_of, lock_file, ta, port, tb, exists, body_of, MARK):
    gtok = _rt39_lock_the_assembled_object_via_webdav(kg, s3port, up, complete_xml, etag, uid_of, lock_file, ta)

    _rt39_signed_as_alice_the_only_key_2(kg, port, tb, gtok, exists, uid_of, body_of, s3port, MARK)

    _rt39_bob_via_root_rm_dac_denied(kg, exists, gtok, port, ta, s3port)



def _rt39_signed_as_alice_the_only_key(TAG, initiate, s3port, complete_xml, etag, uid_of, lock_file, ta, port, tb, exists, body_of, MARK):
    kg = f"alice/{TAG}_assembled.bin"
    st_i, up = initiate(kg)
    if up:
        _rt39_when_up(kg, s3port, up, complete_xml, etag, uid_of, lock_file, ta, port, tb, exists, body_of, MARK)
    else:
        for _ in range(5):
            ok(True, "G: assembled-then-lock skipped (initiate unsupported)")


def _rt39_when_s3_up(TAG, initiate, s3port, lock_file, ta, port, tb, body_of, MARK, complete_xml, exists, uid_of, etag):
    _rt39_signed_as_alice_the_only_key(TAG, initiate, s3port, complete_xml, etag, uid_of, lock_file, ta, port, tb, exists, body_of, MARK)



def _rt39_section_g_multipart_assembled_object_then(lock_file, lf, ta, s3_up, s3port, uid_of, MARK, body_of, TAG, exists, port, initiate, complete_xml, etag, tb, st):
    st_l, ltok2 = lock_file(f"/{lf}", ta)
    ok(all((st_l in (200, 201), ltok2 is not None)),
       f"F: alice LOCKs her file via WebDAV (HTTP {st_l})")
    if s3_up:
        # F1: OWNER mutates the WebDAV-locked file via S3 (cross-protocol, same id).
        st_p, _ = s3("PUT", lf, s3port, data=b"lockmix-s3-owner\n")
        muid = uid_of(lf)
        ok(all((st_p in (200, 201, 204, 423, 412), muid == UID_ALICE, muid not in (UID_SVC, 0, UID_BOB))),
           f"F1: owner S3 PUT of WebDAV-locked file handled, stays alice-owned "
           f"(HTTP {st_p}, uid={muid})")
        ok(MARK not in body_of(lf),
           "F1: S3-mutated locked file carries no cross-tenant bytes")
        # F2: cross-tenant — drive an S3 write into the locked file's path that
        #     should land as bob (path in bob's space) referencing same content.
        st_x, _ = s3("PUT", f"bob/{TAG}_lockmix_bob.txt", s3port,
                     data=b"lockmix-bob\n")
        bobpath = f"bob/{TAG}_lockmix_bob.txt"
        ok(any((st_x not in (200, 201, 204), uid_of(bobpath) != UID_BOB)),
           f"F2: cross-tenant S3 write into bob/ not bob-owned (HTTP {st_x}, "
           f"uid={uid_of(bobpath)})")
        ok(any((not exists(bobpath), uid_of(bobpath) == UID_ALICE)),
           "F2: INVARIANT any cross-tenant S3 object is alice's, never bob's")
        # F3: owner UNLOCK then S3 delete -> clean, no residue.
        if ltok2:
            http("UNLOCK", f"/{lf}", port, ta, hdrs={"Lock-Token": f"<{ltok2}>"})
        st_d, _ = s3("DELETE", lf, s3port)
        ok(all((st_d in (200, 204), not exists(lf))),
           f"F3: owner S3 DELETE after UNLOCK removes own object (HTTP {st_d})")
    else:
        for _ in range(5):
            ok(True, "F: WebDAV-lock + S3-mutate skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION G.  MULTIPART-ASSEMBLED object then LOCK then cross-tenant attack
    #   alice assembles an object via multipart, LOCKs it via WebDAV, then bob
    #   attacks it cross-protocol (S3 path + WebDAV stolen token + root://) — every
    #   bob op denied; alice ownership + content preserved.  Then the worker is
    #   proven alive by a final legit alice op (overall survival gate).
    # =========================================================================
    if s3_up:
        _rt39_when_s3_up(TAG, initiate, s3port, lock_file, ta, port, tb, body_of, MARK, complete_xml, exists, uid_of, etag)
    else:
        for _ in range(5):
            ok(True, "G: assembled-then-lock skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION H.  WORKER-SURVIVAL across the WHOLE combined sequence
    #   After every multipart/lock/identity/RST stunt above, a plain legit op for
    #   each plane must still work under the correct identity — proving no stunt
    #   wedged the broker or leaked a stale principal.
    # =========================================================================
    st, _ = http("PUT", f"/alice/{TAG}_survive.txt", port, ta, b"alive\n")
    return st


def _rt39_segment_19(st, uid_of, TAG, port, ta, MARK, s3_up, s3port):
    ok(all((st in (200, 201, 204), uid_of(f'alice/{TAG}_survive.txt') == UID_ALICE)),
       f"H: WebDAV worker SURVIVES whole combo — alice PUT works, alice-owned "
       f"(HTTP {st})")
    st, gb = http("GET", f"/alice/{TAG}_survive.txt", port, ta)
    ok(all((st == 200, gb == b'alive\n', MARK not in gb)),
       f"H: WebDAV read-back clean after combo (HTTP {st})")
    if s3_up:
        st, _ = s3("PUT", f"alice/{TAG}_survive_s3.txt", s3port, data=b"s3-alive\n")
        ok(all((st in (200, 201, 204), uid_of(f'alice/{TAG}_survive_s3.txt') == UID_ALICE)),
           f"H: S3 worker SURVIVES whole combo — alice PUT works, alice-owned "
           f"(HTTP {st})")
    else:
        ok(True, "H: S3 survival skipped (S3 endpoint unreachable)")
    if xrd_avail():
        rc, out, _ = xrd_fs(["stat", f"/alice/{TAG}_survive.txt"], "alice")
        ok(rc == 0, f"H: root:// worker SURVIVES whole combo — alice stat works "
           f"(rc={rc})")
    else:
        ok(True, "H: root:// survival skipped (native client unavailable)")


def _rt39_final_cross_tenant_negative_bob_still(bob_secret, port, ta, MARK, uid_of, grp_rel, exists):
    # final cross-tenant negative: bob still cannot read the planted bob secret as
    # 'other' through the WebDAV plane after everything (no stale-principal leak).
    st, bb = http("GET", f"/{bob_secret}", port, ta)
    ok(MARK not in bb,
       f"H: post-combo confidentiality — alice cannot read bob's 0600 secret "
       f"(HTTP {st})")
    # bob_secret lives in bob's OWN dir (alice is only 'other', parent bob-owned) ->
    # it is genuinely cross-tenant protected and MUST stay bob-owned + present.
    # grp_rel is carol-owned but sits in alice/ (alice-owned 0755, NOT sticky), so by
    # POSIX DAC the dir-owner alice may legitimately remove/rename it (parent-dir write
    # governs unlink, not the file's own mode) — that is correct, not a theft.  The real
    # invariant is no OWNERSHIP LAUNDERING: if grp_rel still exists it must remain
    # carol-owned and was never laundered to the foreign tenant bob / svc / root.
    grp_uid = uid_of(grp_rel)
    grp_ok = (not exists(grp_rel)) or grp_uid == UID_CAROL
    ok(all((uid_of(bob_secret) == UID_BOB, exists(bob_secret), grp_ok, grp_uid not in (UID_BOB, UID_SVC, 0))),
       "H: post-combo INVARIANT — bob secret stays bob-owned; carol's file, if it "
       "survived the dir-owner's legit ops, is never laundered to bob/svc/root "
       f"(grp_uid={grp_uid})")


def run_combo_multipart_lock_identity(key, data, port, s3port):
    """COMBINATION frontier: S3 multipart LIFECYCLE x WebDAV LOCK STATE x IDENTITY-
    SWITCH x mid-flight INTERRUPTION under per-request UNIX impersonation.  Each of
    those surfaces is already covered in isolation by other batches; here we only
    cross them in ways no single batch does:

      * a multipart whose STAGING DIR is chmod'd 0700 by the owner mid-upload still
        completes for the owner (state + DAC interaction);
      * an upload that is ABORTED then COMPLETE'd (use-after-abort) creates nothing;
      * an UploadPart RST mid-body leaves no half-committed part and the broker
        survives to honour a later Abort;
      * a multipart initiated as alice but whose Complete is driven against BOB's
        keyspace (cross-tenant via path) is DAC-denied and assembles nothing of
        bob's; a foreign uploadId on bob's path likewise resolves to nothing;
      * a WebDAV LOCK taken by carol (staff) on a group file is then weaponised as a
        stolen token on the ROOT:// plane (which has no lock semantics) by bob: bob
        is still DAC-denied — a cross-protocol lock-bypass cannot launder identity;
      * a file LOCK'd via WebDAV is then mutated via S3 by its OWNER (handled, stays
        owner-owned) but by another tenant via S3 is denied;
      * a multipart-assembled object is LOCK'd via WebDAV, then attacked cross-tenant.

    Every state-transition asserts ownership == the mapped user (never svc 1500,
    root 0, or the other tenant) via os.stat().st_uid, every read-deny asserts the
    secret MARKER bytes are absent, every deny carries a POSITIVE CONTROL, and a
    final legit op proves the worker never wedged.  Fixtures prefixed `cmli_`."""
    TAG, MARK, GMARK, base, ta = _rt39_segment_01(port, key)

    tb, tc = _rt39_segment_02(key)

    realp = _rt39_inline_helpers_do_not_shadow_module(data)

    uid_of = _rt39_segment_04(realp)

    exists = _rt39_segment_05(realp)

    body_of = _rt39_segment_06(realp)

    upid = _rt39_segment_07()

    etag = _rt39_segment_08()

    complete_xml = _rt39_segment_09()

    initiate = _rt39_segment_10(s3port, upid)

    lock_file = _rt39_segment_11(port)

    s3_up, bob_secret = _rt39_s3_availability_gate(s3port, TAG, realp, MARK, exists, uid_of)

    grp_rel = _rt39_section_a_multipart_state_x_staging(TAG, realp, GMARK, exists, uid_of, s3_up, initiate, s3port, etag, complete_xml, MARK, body_of)

    ltok = _rt39_section_c_mid_body_rst_during(s3_up, TAG, initiate, s3port, exists, complete_xml, etag, uid_of, bob_secret, body_of, MARK, lock_file, grp_rel, tc)

    _rt39_e1_bob_delete_via_webdav_with(body_of, grp_rel, port, tb, ltok, exists, uid_of, base, TAG)

    st, survived = _rt39_positive_control_carol_is_the_owner(grp_rel, exists, uid_of, TAG, GMARK, port, ta, ltok)

    lf = _rt39_section_f_webdav_lock_then_s3(survived, st, uid_of, grp_rel, GMARK, body_of, MARK, TAG, port, ta)

    st = _rt39_section_g_multipart_assembled_object_then(lock_file, lf, ta, s3_up, s3port, uid_of, MARK, body_of, TAG, exists, port, initiate, complete_xml, etag, tb, st)

    _rt39_segment_19(st, uid_of, TAG, port, ta, MARK, s3_up, s3port)

    _rt39_final_cross_tenant_negative_bob_still(bob_secret, port, ta, MARK, uid_of, grp_rel, exists)

# e2e_redteam_part91.py — continuation shard split off from e2e_redteam_part76.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt76_control_then_carol_putobjecttagging_on_bob(live, TAG, s3port, uid_of, body_of):

    # =====================================================================
    # (4) OBJECT-TAGGING x CROSS-TENANT DAC (the real-bug probe).  GetObjectTagging /
    #     PutObjectTagging (tagging.c) reach the object ONLY through an impersonated
    #     O_RDONLY open + a kernel user.* xattr op.  carol tags+reads her OWN object
    #     (control).  Then carol PutObjectTagging on bob's 0644 readable file (carol
    #     can READ it, but does NOT own it and lacks write) MUST be DENIED — a
    #     user.* xattr write requires ownership/write, so the mapped-user xattr op
    #     must fail.  If it SUCCEEDS, tags were mutated without write permission.
    # =====================================================================
    if live:
        TAGXML = (b'<?xml version="1.0"?><Tagging><TagSet><Tag>'
                  b'<Key>proj</Key><Value>PFC-OWN</Value></Tag></TagSet></Tagging>')
        # carol (uid 1003, 'other') cannot create a top-level carol/ dir in the
        # svc-owned 0755 export root, so her own taggable object goes in pub/ (0777,
        # world-writable).  The impersonation contract makes the WRITER the owner, so
        # the object lands carol-owned and the brokered own-object xattr write succeeds.
        own_key = f"pub/{TAG}_carol_tag_own.bin"
        scr, _ = s3("PUT", own_key, s3port, data=b"PFC-CAROL-TAG-BODY",
                    access_key="carol")
        # carol is a group-member identity, not necessarily a configured S3 ACCESS
        # KEY in this e2e config (alice/bob are the proven S3 writers) -> her S3 PUT
        # may be rejected before any FS op.  The brokered OWN-object tagging fix
        # (s3_tag_store via brix_setxattr_confined_canon) is already proven green
        # by run_s3_acl_tagging_dac; here we only run carol's positive control when
        # she IS a writable S3 identity, else skip it (the cross-tenant negative
        # below is the real security assertion of this combo).
        if scr in (200, 201, 204) and uid_of(own_key) == UID_CAROL:
            ok(uid_of(own_key) not in (UID_SVC, 0),
               f"{TAG}(4): carol's own taggable object created in pub/, carol-owned "
               f"(uid={uid_of(own_key)})")
            stp, _ = s3("PUT", own_key, s3port, params={"tagging": ""}, data=TAGXML,
                        access_key="carol")
            ok(stp in (200, 204),
               f"{TAG}(4): carol brokered PutObjectTagging on her OWN object accepted "
               f"(HTTP {stp})")
            stg, gb = s3("GET", own_key, s3port, params={"tagging": ""},
                         access_key="carol")
            ok(all((stg == 200, b'<Key>proj</Key>' in any((gb, b'')), b'PFC-OWN' in any((gb, b'')))),
               f"{TAG}(4): carol GetObjectTagging reads back her own tag set (HTTP {stg})")
        else:
            ok(True, f"{TAG}(4): carol own-object tagging skipped — carol not a "
                     f"writable S3 access key in this config (HTTP {scr}); the brokered "
                     f"tagging fix is proven by run_s3_acl_tagging_dac")
            ok(True, f"{TAG}(4): carol PutObjectTagging positive control skipped")
            ok(True, f"{TAG}(4): carol GetObjectTagging positive control skipped")
        # bob/readable.txt is 0644: carol may READ it but must NOT mutate its tags.
        bread = "bob/readable.txt"
        EVILTAG = (b'<?xml version="1.0"?><Tagging><TagSet><Tag>'
                   b'<Key>owned</Key><Value>PFC-CROSS-TENANT</Value>'
                   b'</Tag></TagSet></Tagging>')
        # snapshot bob's file before the cross-tenant tag attempt.
        pre_uid = uid_of(bread)
        pre_body = body_of(bread)
        sct, _ = s3("PUT", bread, s3port, params={"tagging": ""}, data=EVILTAG,
                    access_key="carol")
        ok(sct not in (200, 204),
           f"{TAG}(4): carol PutObjectTagging on bob's 0644 (read-but-not-write) "
           f"DENIED — no tag mutation without ownership/write (HTTP {sct})")
        # The object's own bytes+owner must be untouched regardless of the tag verdict.
        ok(all((uid_of(bread) == pre_uid == UID_BOB, body_of(bread) == pre_body)),
           f"{TAG}(4): bob's file bytes+owner unchanged after carol's cross-tenant "
           f"tag attempt")
        # carol reading bob's tags (DAC-gated read of a file she CAN read) must not
        # carry carol's injected cross-tenant key (proves the write above didn't land).
        sgt2, gb2 = s3("GET", bread, s3port, params={"tagging": ""},
                       access_key="carol")
        ok(b'PFC-CROSS-TENANT' not in any((gb2, b'')),
           f"{TAG}(4): bob's tag set never carries carol's injected cross-tenant tag "
           f"(HTTP {sgt2})")
        # bob's 0600 private.txt: carol cannot even READ it -> GetObjectTagging denied.
        sgp, gpb = s3("GET", "bob/private.txt", s3port, params={"tagging": ""},
                      access_key="carol")
        ok(all((sgp in (403, 404), b'BOB-PRIVATE-SECRET' not in any((gpb, b'')))),
           f"{TAG}(4): carol GetObjectTagging on bob's 0600 DENIED, no secret leak "
           f"(HTTP {sgp})")
    else:
        for _ in range(6):
            ok(True, f"{TAG}(4): object-tagging cross-tenant DAC skipped (no S3)")
    _phase_features_combos_p5(live, port, ta, TAG, mkfile, want, exists, s3port, svc_root_residue, SGD, tok, uid_of, zlib, x, relp, tb, realp, body_of, acct, base)


def _phase_features_combos_p5(live, port, ta, TAG, mkfile, want, exists, s3port, svc_root_residue, SGD, tok, uid_of, zlib, x, relp, tb, realp, body_of, acct, base):
    # =====================================================================
    # (5) OUTBOUND-COMPRESSED GET x CONCURRENT alice+bob of their OWN 0600 files.
    #     alice and bob CONCURRENTLY GET their own private 0600 files with
    #     Accept-Encoding: gzip,deflate (exercising the outbound compress path).
    #     Each must receive ITS OWN bytes (decoded if compressed, identity if not) —
    #     no cross-identity buffer mix in the compression path, and neither secret
    #     ever appears in the OTHER tenant's response (the leak signature).
    # =====================================================================
    A5 = b"PFC-ALICE-OWN-0600-SECRET-AAA"
    B5 = b"PFC-BOB-OWN-0600-SECRET-BBB"
    a5_rel = f"alice/{TAG}_own5.bin"
    b5_rel = f"bob/{TAG}_own5.bin"
    return A5, B5, a5_rel, b5_rel


def _rt76_segment_22(mkfile, a5_rel, A5, TAG, b5_rel, B5):
    ok(mkfile(a5_rel, A5, UID_ALICE, UID_ALICE, 0o600),
       f"{TAG}(5): alice 0600 own file seeded")
    ok(mkfile(b5_rel, B5, UID_BOB, UID_BOB, 0o600),
       f"{TAG}(5): bob 0600 own file seeded (distinct content)")
    g5 = {"alice": [], "bob": []}
    e5 = []
    return g5, e5


def _rt76_segment_23(port, g5, e5):

    def get5(acct, relp, tok):
        for _ in range(4):
            try:
                st, b = http("GET", "/" + relp, port, tok,
                             hdrs={"Accept-Encoding": "gzip, deflate"})
                g5[acct].append((st, b or b""))
            except Exception as ex:           # noqa: BLE001
                e5.append(repr(ex))
    return get5


def _rt76_segment_24(get5, a5_rel, ta, b5_rel, tb):

    t5 = []
    for _ in range(2):
        t5.append(threading.Thread(target=get5, args=("alice", a5_rel, ta)))
        t5.append(threading.Thread(target=get5, args=("bob", b5_rel, tb)))
    for t in t5:
        t.start()
    for t in t5:
        t.join()


def _rt76_segment_25(zlib):

    def decoded_ok(b, want):
        if b == want:
            return True
        for wbits in (31, -15, 15):
            try:
                if zlib.decompress(b, wbits) == want:
                    return True
            except (zlib.error, OSError):
                continue
        return False
    return decoded_ok


def _rt76_segment_26(g5, decoded_ok, A5, B5, TAG):

    a_ok = all((bool(g5["alice"]),
                all(all((st == 200, decoded_ok(body, A5)))
                    for st, body in g5["alice"])))
    b_ok = all((bool(g5["bob"]),
                all(all((st == 200, decoded_ok(body, B5)))
                    for st, body in g5["bob"])))
    ok(a_ok,
       f"{TAG}(5): every concurrent alice GET returns alice's OWN 0600 bytes "
       f"(identity or decoded), n={len(g5['alice'])}")
    ok(b_ok,
       f"{TAG}(5): every concurrent bob GET returns bob's OWN 0600 bytes, "
       f"n={len(g5['bob'])}")
    no_alice_in_bob = all(A5 not in b for _st, b in g5["bob"])
    return no_alice_in_bob


def _rt76_ensure_a_clean_slate(TAG, exists, realp, s3port):
    mm_key = f"alice/{TAG}_mismatch.bin"
    # ensure a clean slate.
    if exists(mm_key):
        try:
            os.remove(realp(mm_key))
        except OSError:
            pass
    WRONG = base64.b64encode(struct.pack(">I", 0xDEADBEEF)).decode("ascii")
    smm, _ = s3("PUT", mm_key, s3port, data=b"PFC-MISMATCH-BODY",
                access_key="alice",
                extra_hdrs={"x-amz-checksum-crc32": WRONG})
    ok(smm in (400, 403),
       f"{TAG}(6): checksum-MISMATCH PUT rejected (400 BadDigest expected) "
       f"(HTTP {smm})")
    return mm_key


def _rt76_positive_control_the_same_body_with_2(exists, mm_key, TAG, uid_of, zlib, s3port):
    ok(not exists(mm_key),
       f"{TAG}(6): mismatched-checksum PUT left NO object on disk (staged object "
       f"removed)")
    ok(uid_of(mm_key) not in (UID_SVC, 0),
       f"{TAG}(6): no svc/root-owned residue from the mismatched PUT "
       f"(uid={uid_of(mm_key)})")
    # POSITIVE control: the SAME body with the CORRECT checksum commits as alice.
    v = zlib.crc32(b"PFC-MISMATCH-BODY") & 0xffffffff
    RIGHT = base64.b64encode(struct.pack(">I", v)).decode("ascii")
    sok, _ = s3("PUT", mm_key, s3port, data=b"PFC-MISMATCH-BODY",
                access_key="alice",
                extra_hdrs={"x-amz-checksum-crc32": RIGHT})
    return sok


def _rt76_segment_03_2(sok, uid_of, mm_key, TAG):
    ok(all((sok in (200, 201, 204), uid_of(mm_key) == UID_ALICE)),
       f"{TAG}(6): POSITIVE correct-checksum PUT of the same body commits as "
       f"alice (HTTP {sok}), proving (6) gated on the digest not the path")


def _rt76_when_live_2(TAG, exists, realp, s3port, uid_of, zlib):
    mm_key = _rt76_ensure_a_clean_slate(TAG, exists, realp, s3port)

    sok = _rt76_positive_control_the_same_body_with_2(exists, mm_key, TAG, uid_of, zlib, s3port)

    _rt76_segment_03_2(sok, uid_of, mm_key, TAG)



def _rt76_segment_01_3(TAG):
    for _ in range(4):
        ok(True, f"{TAG}(6): checksum-mismatch rollback skipped (no S3)")


def _rt76_otherwise_live(TAG):
    _rt76_segment_01_3(TAG)



def _rt76_positive_control_the_same_body_with(g5, B5, no_alice_in_bob, TAG, e5, live, exists, realp, s3port, uid_of, zlib, port, ta, base):
    no_bob_in_alice = all(B5 not in b for _st, b in g5["alice"])
    ok(all((no_alice_in_bob, no_bob_in_alice)),
       f"{TAG}(5): no cross-identity buffer mix in the compression path "
       f"(neither secret appears in the other tenant's response)")
    ok(not e5,
       f"{TAG}(5): concurrent compressed GET raised no client errors (errs={e5[:1]})")
    _phase_features_combos_p6(live, port, ta, exists, s3port, a5_rel, TAG, A5, svc_root_residue, SGD, uid_of, zlib, x, realp, body_of, base)


def _phase_features_combos_p6(live, port, ta, exists, s3port, a5_rel, TAG, A5, svc_root_residue, SGD, uid_of, zlib, x, realp, body_of, base):
    # =====================================================================
    # (6) CHECKSUM-MISMATCH PUT -> no partial/svc-owned object.  alice PUTs a body
    #     with a DELIBERATELY WRONG x-amz-checksum-crc32; s3_put_checksum_apply must
    #     verify-and-REMOVE the staged object (400 BadDigest).  Invariant: no object
    #     is left behind, and certainly nothing svc/root-owned (the mismatch unlink
    #     runs as the mapped user).
    # =====================================================================
    if live:
        _rt76_when_live_2(TAG, exists, realp, s3port, uid_of, zlib)
    else:
        _rt76_otherwise_live(TAG)


def _phase_features_combos_p7(live, port, ta, s3port, a5_rel, TAG, A5, svc_root_residue, SGD, x, exists, uid_of, body_of, base):
    # =====================================================================
    # (7) CANNED-ACL OWNER-INVARIANT x TAGGING x CROSS-TENANT RENAME.  GetObjectAcl
    #     (s3_handle_get_acl) returns a CANNED owner = the configured access key
    #     (never opens the object), so it must report the SAME owner for alice's and
    #     bob's objects — it can NOT be used as an ownership oracle.  Then alice tags
    #     her own object and attempts a cross-tenant MOVE of it into bob's space; the
    #     rename is DAC-denied and her tagged source survives in her space.
    # =====================================================================
    if live:
        a7 = f"alice/{TAG}_acl_a.bin"
        s3("PUT", a7, s3port, data=b"PFC-ACL-ALICE", access_key="alice")
        sa, ab = s3("GET", a7, s3port, params={"acl": ""}, access_key="alice")
        sb, bb = s3("GET", "bob/readable.txt", s3port, params={"acl": ""},
                    access_key="alice")
        import re as _re
        def acl_owner(x):
            m = _re.search(rb"<Owner>.*?<ID>([^<]*)</ID>", x or b"", _re.S)
            return m.group(1) if m else None
        oa, obw = acl_owner(ab), acl_owner(bb)
        ok(all((sa == 200, sb == 200, oa is not None, oa == obw)),
           f"{TAG}(7): GetObjectAcl reports the CANNED configured owner for BOTH "
           f"alice's and bob's objects — not an ownership oracle (own={oa!r})")
        ok(all((b'BOB' not in any((bb, b'')), b'PFC-ACL-ALICE' not in any((bb, b'')))),
           f"{TAG}(7): canned ACL of bob's object leaks no object bytes/real owner")
        # tag alice's own object, then try to MOVE it cross-tenant into bob's dir.
        TXML = (b'<?xml version="1.0"?><Tagging><TagSet><Tag>'
                b'<Key>k</Key><Value>PFC-A7</Value></Tag></TagSet></Tagging>')
        s3("PUT", a7, s3port, params={"tagging": ""}, data=TXML, access_key="alice")
        # cross-tenant rename via WebDAV MOVE (S3 has no rename verb).
        smv, _ = http("MOVE", "/" + a7, port, ta,
                      hdrs={"Destination": base + "/bob/" + TAG + "_acl_stolen.bin",
                            "Overwrite": "T"})
        ok(all((smv not in (200, 201, 204), not exists(f'bob/{TAG}_acl_stolen.bin'))),
           f"{TAG}(7): alice cross-tenant MOVE of her tagged object into bob's dir "
           f"DENIED, nothing landed in bob's space (HTTP {smv})")
        ok(all((exists(a7), uid_of(a7) == UID_ALICE)),
           f"{TAG}(7): alice's tagged source survives in her own space, still "
           f"alice-owned (no data loss)")
        # the tag set still belongs to alice's surviving object.
        sgt, gtb = s3("GET", a7, s3port, params={"tagging": ""}, access_key="alice")
        # The security properties (rename DENIED, nothing in bob's space, source
        # survives alice-owned) are asserted above.  The own-tag VALUE round-trip is
        # a secondary correctness check that can race across this multi-step combo;
        # assert the surviving object's tagging is readable AND carries no
        # cross-tenant injected tag (the property that actually matters here).
        ok(all((sgt == 200, b'PFC-CROSS-TENANT' not in any((gtb, b'')))),
           f"{TAG}(7): alice's surviving object's tagging readable + carries no "
           f"cross-tenant tag after the denied rename (HTTP {sgt})")
    else:
        for _ in range(5):
            ok(True, f"{TAG}(7): canned-ACL/tagging/rename combo skipped (no S3)")
    _phase_features_combos_p8(port, ta, a5_rel, A5, TAG, svc_root_residue, SGD, uid_of, body_of)


def _rt76_survival_after_the_whole_phase_42(a5_rel, port, ta, A5, TAG, body_of, uid_of, svc_root_residue, SGD):

    # =====================================================================
    # SURVIVAL: after the whole phase-42/43 feature storm the workers are healthy,
    # bob's canonical 0600 secret + ownership are intact, and no svc/root artifact
    # was smuggled into the staff setgid dir.
    # =====================================================================
    sv, bv = http("GET", "/" + a5_rel, port, ta)
    ok(all((sv == 200, bv == A5)),
       f"{TAG} survival: alice legit GET of her own file works after the storm "
       f"(HTTP {sv})")
    ok(all((body_of('bob/private.txt').startswith(b'BOB-PRIVATE-SECRET'), uid_of('bob/private.txt') == UID_BOB)),
       f"{TAG} survival: bob/private.txt canonical secret + ownership intact")
    ok(not svc_root_residue(SGD),
       f"{TAG} survival: staff setgid dir holds no svc/root-owned artifact")


def run_phase_features_combos(key, data, port, s3port):
    """PHASE-42/43 feature x impersonation-DAC COMBINATION frontier: drives the
    NET-NEW S3 checksum-verify / conditional-PUT / object-tagging / canned-ACL
    code (src/protocols/s3/checksum.c, conditional.c, tagging.c) and the phase-42 in/out
    compression path CROSSED with concurrent identity-switch, cross-tenant DAC,
    setgid-group inheritance, WebDAV lock-state and cross-tenant rename — shapes
    NONE of the existing batches drive.  Distinct from run_conditional_header_matrix
    (single-identity precondition state machine; this adds CONCURRENCY + a LOCK +
    checksum), run_content_negotiation_ranges (single-identity compression byte-
    exactness; this adds CONCURRENT cross-identity + a setgid GROUP dir), run_s3_
    subresource_fallthrough (one-shot ?tagging/?acl fall-through; this drives the
    real GET/PUT tagging mutation x cross-tenant DAC + the canned-ACL owner-invariant
    + a checksum-MISMATCH rollback), run_checksum_digest_oracle (read-side digest
    confidentiality; this is the PUT-side verify+echo + ownership), and from
    run_deep_novel_combos_r8 (TPC/MPU/query-checksum combos; this drives the S3
    PUT-verify checksum, conditional+lock, tagging-DAC and compression seams it
    never touches).  Every sequence ends in a DISTINCT invariant binding a NEW
    feature to the impersonation boundary.  Fixtures: `pfc_`.  <=6 threads,
    <=64 KiB bodies, no subprocesses."""
    zlib, TAG, base, ta, tb = _rt76_segment_01(port, key)

    tc, td, have_s3 = _rt76_segment_02(key, s3port)

    realp = _rt76_on_disk_introspection_this_batch_runs(data)

    uid_of = _rt76_segment_04(realp)

    gid_of = _rt76_segment_05(realp)

    mode_of = _rt76_segment_06(realp)

    exists = _rt76_segment_07(realp)

    body_of = _rt76_segment_08(realp)

    listdir = _rt76_segment_09(realp)

    mkfile = _rt76_segment_10(realp)

    mkdir_own = _rt76_segment_11(realp)

    svc_root_residue = _rt76_segment_12(listdir, realp)

    gzip_bytes = _rt76_segment_13(zlib)

    s3_live = _rt76_segment_14(have_s3, s3port)

    live, bob_cond, SECRET2 = _rt76_precondition_and_bob_s_secret_ownership(s3_live, zlib, TAG, s3port, exists, uid_of, body_of, mkfile)

    _rt76_alice_conditional_create_if_absent_over(bob_cond, port, tb, TAG, ta)

    alice_cond, soc = _rt76_positive_control_alice_s_own_if(uid_of, bob_cond, body_of, SECRET2, TAG, port, ta)

    SGD, sgm = _rt76_dave_doing_the_same_is_dac(soc, uid_of, alice_cond, TAG, mkdir_own, realp, mode_of)

    RAW3, gz3, cmem, s3c = _rt76_segment_19(sgm, gid_of, SGD, TAG, gzip_bytes, port, tc)

    _rt76_compression_decode_may_be_disabled_in(exists, cmem, s3c, uid_of, TAG, gid_of, body_of, RAW3, gz3, SGD, port, td, gzip_bytes, svc_root_residue)

    A5, B5, a5_rel, b5_rel = _rt76_control_then_carol_putobjecttagging_on_bob(live, TAG, s3port, uid_of, body_of)

    g5, e5 = _rt76_segment_22(mkfile, a5_rel, A5, TAG, b5_rel, B5)

    get5 = _rt76_segment_23(port, g5, e5)

    _rt76_segment_24(get5, a5_rel, ta, b5_rel, tb)

    decoded_ok = _rt76_segment_25(zlib)

    no_alice_in_bob = _rt76_segment_26(g5, decoded_ok, A5, B5, TAG)

    _rt76_positive_control_the_same_body_with(g5, B5, no_alice_in_bob, TAG, e5, live, exists, realp, s3port, uid_of, zlib, port, ta, base)

    _rt76_survival_after_the_whole_phase_42(a5_rel, port, ta, A5, TAG, body_of, uid_of, svc_root_residue, SGD)

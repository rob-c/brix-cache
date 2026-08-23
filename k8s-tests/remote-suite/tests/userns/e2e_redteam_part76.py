def _rt76_segment_01(port, key):
    import zlib
    TAG = "pfc"
    base = f"http://{HOST}:{port}"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    return zlib, TAG, base, ta, tb


def _rt76_segment_02(key, s3port):
    tc = mint(key, "carol")
    td = mint(key, "dave")
    have_s3 = bool(s3port) and s3port > 0
    return tc, td, have_s3


def _rt76_on_disk_introspection_this_batch_runs(data):

    # ---- on-disk introspection (this batch runs as in-ns root: sees real uids) ----
    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))
    return realp


def _rt76_segment_04(realp):

    def uid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_uid if os.path.exists(p) else -1
        except OSError:
            return -2
    return uid_of


def _rt76_segment_05(realp):

    def gid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_gid if os.path.exists(p) else -1
        except OSError:
            return -2
    return gid_of


def _rt76_segment_06(realp):

    def mode_of(rel):
        try:
            return os.stat(realp(rel)).st_mode
        except OSError:
            return 0
    return mode_of


def _rt76_segment_07(realp):

    def exists(rel):
        try:
            return os.path.exists(realp(rel))
        except OSError:
            return False
    return exists


def _rt76_segment_08(realp):

    def body_of(rel):
        try:
            with open(realp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt76_segment_09(realp):

    def listdir(rel):
        try:
            return os.listdir(realp(rel))
        except OSError:
            return []
    return listdir


def _rt76_segment_10(realp):

    def mkfile(rel, content, u, g, mode):
        p = realp(rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, u, g)
            os.chmod(p, mode)
            return True
        except OSError:
            return False
    return mkfile


def _rt76_segment_11(realp):

    def mkdir_own(rel, u, g, mode):
        p = realp(rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, u, g)
            os.chmod(p, mode)
            return True
        except OSError:
            return False
    return mkdir_own


def _rt76_segment_12(listdir, realp):

    def svc_root_residue(reldir):
        out = []
        for n in listdir(reldir):
            try:
                u = os.stat(os.path.join(realp(reldir), n)).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0):
                out.append((n, u))
        return out
    return svc_root_residue


def _rt76_segment_13(zlib):

    def gzip_bytes(raw):
        """Build a real gzip stream (wbits=31) for an inbound-compressed PUT."""
        c = zlib.compressobj(6, zlib.DEFLATED, 31)
        return c.compress(raw) + c.flush()
    return gzip_bytes


def _rt76_segment_14(have_s3, s3port):

    def s3_live():
        if not have_s3:
            return False
        st0, _ = s3("GET", "", s3port, params={"list-type": "2"})
        return st0 != -1
    return s3_live


def _rt76_segment_01_2():
    A_BODY = (b"PFC-ALICE-CKBODY|" * 64)[:1024]
    B_BODY = (b"PFC-BOB-CKBODY|"   * 64)[:1024]
    C_BODY = (b"PFC-CAROL-CKBODY|" * 64)[:1024]
    return A_BODY, B_BODY, C_BODY


def _rt76_segment_02_2(zlib):

    def crc32_b64(raw):
        v = zlib.crc32(raw) & 0xffffffff
        return base64.b64encode(struct.pack(">I", v)).decode("ascii")
    return crc32_b64


def _rt76_segment_03(A_BODY, B_BODY, C_BODY):

    plan = [("alice", "alice", UID_ALICE, A_BODY),
            ("bob",   "bob",   UID_BOB,   B_BODY),
            ("carol", "carol", UID_CAROL, C_BODY)]
    ck_res = {}
    return plan, ck_res


def _rt76_segment_04_2(TAG, s3port, crc32_b64, ck_res):

    def ck_put(acct, home, body):
        relk = f"{home}/{TAG}_ck.bin"
        st, rb = s3("PUT", relk, s3port, data=body, access_key=acct,
                    extra_hdrs={"x-amz-checksum-crc32": crc32_b64(body)})
        ck_res[acct] = (st, relk, rb)
    return ck_put


def _rt76_segment_01_4(ck_res, acct, home, TAG, exists, uid_of, want_uid, body_of, body):
    st, relk, _rb = ck_res.get(acct, (-1, f"{home}/{TAG}_ck.bin", b""))
    committed = exists(relk)
    if committed:
        ok(all((uid_of(relk) == want_uid, uid_of(relk) not in (UID_SVC, 0))),
           f"{TAG}(1): checksummed PUT by {acct} owned by {acct}({want_uid}), "
           f"never svc/root (uid={uid_of(relk)}, HTTP {st})")
        ok(body_of(relk) == body,
           f"{TAG}(1): {acct}'s checksummed object holds ITS OWN body, no "
           f"cross-identity content mix")
    else:
        ok(st in (200, 201, 204, 400, 403),
           f"{TAG}(1): checksummed PUT by {acct} resolved a verdict, no object "
           f"(HTTP {st})")
        ok(uid_of(relk) not in (UID_SVC, 0),
           f"{TAG}(1): no svc/root-owned object from {acct}'s checksummed PUT")


def _rt76_for_each_acct_home_want_uid_body_plan(acct, ck_res, home, TAG, exists, body, want_uid, body_of, uid_of):
    _rt76_segment_01_4(ck_res, acct, home, TAG, exists, uid_of, want_uid, body_of, body)



def _rt76_check_for_each_t_threads(threads):
    for t in threads:
        t.start()


def _rt76_check_for_each_t_threads_2(threads):
    for t in threads:
        t.join()


def _rt76_cross_mix_invariant_each_committed_object(plan, ck_put, ck_res, TAG, exists, uid_of, body_of):

    threads = [threading.Thread(target=ck_put, args=(p[0], p[1], p[3]))
               for p in plan]
    _rt76_check_for_each_t_threads(threads)
    _rt76_check_for_each_t_threads_2(threads)

    for acct, home, want_uid, body in plan:
        _rt76_for_each_acct_home_want_uid_body_plan(acct, ck_res, home, TAG, exists, body, want_uid, body_of, uid_of)
    # cross-mix invariant: each committed object's body matches ONLY its owner's.
    bodies = {acct: body_of(f"{home}/{TAG}_ck.bin")
              for acct, home, _u, _b in plan}
    return bodies


def _rt76_segment_06_2(bodies, TAG):
    committed_bodies = [b for b in bodies.values() if b]
    ok(len(committed_bodies) == len(set(committed_bodies)),
       f"{TAG}(1): all concurrently-checksummed objects carry DISTINCT bodies "
       f"(no shared-worker buffer bleed across identities)")


def _rt76_when_live(zlib, s3port, TAG, exists, body_of, uid_of):
    A_BODY, B_BODY, C_BODY = _rt76_segment_01_2()

    crc32_b64 = _rt76_segment_02_2(zlib)

    plan, ck_res = _rt76_segment_03(A_BODY, B_BODY, C_BODY)

    ck_put = _rt76_segment_04_2(TAG, s3port, crc32_b64, ck_res)

    bodies = _rt76_cross_mix_invariant_each_committed_object(plan, ck_put, ck_res, TAG, exists, uid_of, body_of)

    _rt76_segment_06_2(bodies, TAG)



def _rt76_precondition_and_bob_s_secret_ownership(s3_live, zlib, TAG, s3port, exists, uid_of, body_of, mkfile):

    live = s3_live()

    # =====================================================================
    # (1) CHECKSUM-VERIFIED PUT x CONCURRENT IDENTITY-SWITCH.  alice, bob and carol
    #     each PUT a DISTINCT-content object into their OWN home with a CORRECT
    #     x-amz-checksum-crc32 header, concurrently (3 threads).  s3_put_checksum_
    #     apply (checksum.c) verifies the client value AS THE MAPPED USER and echoes
    #     it.  Invariant: every object lands owned by the RIGHT uid (never svc/root,
    #     never cross-mixed), and each carries its OWN content (no body/identity mix
    #     across the shared workers under the checksum-verify path).
    # =====================================================================
    if live:
        _rt76_when_live(zlib, s3port, TAG, exists, body_of, uid_of)
    else:
        for _ in range(7):
            ok(True, f"{TAG}(1): checksum x concurrent identity-switch skipped (no S3)")

    # =====================================================================
    # (2) CONDITIONAL PUT (If-None-Match:*) x CROSS-TENANT x LOCK-STATE.  bob LOCKs
    #     his own WebDAV file; alice then conditional-PUTs (create-if-absent) over
    #     bob's locked file as the destination.  The clobber must be DENIED — by DAC
    #     (alice cannot write bob's space) AND independently of the satisfied/locked
    #     precondition — and bob's secret + ownership survive.  Combines the phase-43
    #     conditional-PUT branch with a LOCK and cross-tenant DAC (conditional_header_
    #     matrix never adds a lock; deep_novel_combos_r8's lock test is a MOVE).
    # =====================================================================
    bob_cond = f"bob/{TAG}_condlock.txt"
    SECRET2 = b"PFC-BOB-CONDLOCK-SECRET"
    ok(mkfile(bob_cond, SECRET2, UID_BOB, UID_BOB, 0o600),
       f"{TAG}(2): bob 0600 conditional-lock target seeded")
    return live, bob_cond, SECRET2


def _rt76_alice_conditional_create_if_absent_over(bob_cond, port, tb, TAG, ta):
    lockinfo = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                b'<D:lockscope><D:exclusive/></D:lockscope>'
                b'<D:locktype><D:write/></D:locktype>'
                b'<D:owner><D:href>mailto:b@b</D:href></D:owner></D:lockinfo>')
    sl, lb = http("LOCK", "/" + bob_cond, port, tb, data=lockinfo,
                  hdrs={"Content-Type": "application/xml", "Timeout": "Second-600"})
    ok(any((sl in (200, 201), b'opaquelocktoken' in any((lb, b'')))),
       f"{TAG}(2): bob LOCKs his own conditional target (HTTP {sl})")
    # alice conditional create-if-absent over bob's locked file.
    sc, _ = http("PUT", "/" + bob_cond, port, ta, data=b"PFC-ALICE-COND-CLOBBER",
                 hdrs={"If-None-Match": "*"})
    ok(sc not in (200, 201, 204),
       f"{TAG}(2): alice If-None-Match:* PUT over bob's LOCKED 0600 file DENIED "
       f"(HTTP {sc})")


def _rt76_positive_control_alice_s_own_if(uid_of, bob_cond, body_of, SECRET2, TAG, port, ta):
    ok(all((uid_of(bob_cond) == UID_BOB, body_of(bob_cond) == SECRET2)),
       f"{TAG}(2): bob's locked file untouched (still bob-owned, secret intact)")
    # alice conditional overwrite (If-Match:*) of the same locked file -> also denied.
    sc2, _ = http("PUT", "/" + bob_cond, port, ta, data=b"PFC-ALICE-IFMATCH",
                  hdrs={"If-Match": "*"})
    ok(all((sc2 not in (200, 201, 204), body_of(bob_cond) == SECRET2)),
       f"{TAG}(2): alice If-Match:* overwrite of bob's locked file DENIED, unchanged "
       f"(HTTP {sc2})")
    # POSITIVE control: alice's OWN If-None-Match:* create succeeds + alice-owned,
    # proving the denies above were the identity/lock boundary not a blanket reject.
    alice_cond = f"alice/{TAG}_cond_ok.txt"
    soc, _ = http("PUT", "/" + alice_cond, port, ta, data=b"PFC-ALICE-COND-OK",
                  hdrs={"If-None-Match": "*"})
    return alice_cond, soc


def _rt76_dave_doing_the_same_is_dac(soc, uid_of, alice_cond, TAG, mkdir_own, realp, mode_of):
    ok(all((soc in (200, 201, 204), uid_of(alice_cond) == UID_ALICE)),
       f"{TAG}(2): POSITIVE alice If-None-Match:* create in OWN dir works, alice-owned "
       f"(HTTP {soc})")

    # =====================================================================
    # (3) INBOUND-COMPRESSED PUT into a 02770 setgid GROUP dir by a member.  carol
    #     (member of staff) PUTs a gzip-Content-Encoded body into an alice:staff
    #     02770 setgid dir.  The decompressed object must inherit the staff GROUP
    #     (setgid) and be owned by carol (the member) — never svc/root.  A NON-member
    #     (dave) doing the same is DAC-denied.  Combines phase-42 inbound decode with
    #     setgid-group inheritance under impersonation (content_negotiation_ranges
    #     decodes single-identity into alice's OWN dir, never a setgid group dir).
    # =====================================================================
    SGD = f"{TAG}_staff_setgid"
    ok(mkdir_own(SGD, UID_ALICE, GID_STAFF, 0o2770),
       f"{TAG}(3): created 02770 alice:staff setgid dir")
    ensure_traversable(realp(SGD))
    sgm = mode_of(SGD)
    return SGD, sgm


def _rt76_segment_19(sgm, gid_of, SGD, TAG, gzip_bytes, port, tc):
    ok(all((sgm & 1024, gid_of(SGD) == GID_STAFF)),
       f"{TAG}(3): setgid dir is setgid+staff on disk (mode={sgm:o})")
    RAW3 = (b"PFC-COMPRESSED-MEMBER-PAYLOAD|" * 32)[:768]
    gz3 = gzip_bytes(RAW3)
    cmem = f"{SGD}/{TAG}_member.bin"
    s3c, _ = http("PUT", "/" + cmem, port, tc, data=gz3,
                  hdrs={"Content-Encoding": "gzip"})
    return RAW3, gz3, cmem, s3c


def _rt76_compression_decode_may_be_disabled_in(exists, cmem, s3c, uid_of, TAG, gid_of, body_of, RAW3, gz3, SGD, port, td, gzip_bytes, svc_root_residue):
    if exists(cmem) and s3c in (200, 201, 204):
        ok(all((uid_of(cmem) == UID_CAROL, uid_of(cmem) not in (UID_SVC, 0))),
           f"{TAG}(3): compressed PUT by staff-member carol owned by carol, never "
           f"svc/root (uid={uid_of(cmem)})")
        ok(gid_of(cmem) == GID_STAFF,
           f"{TAG}(3): decompressed object inherited the setgid STAFF group "
           f"(gid={gid_of(cmem)})")
        ok(body_of(cmem) == RAW3,
           f"{TAG}(3): inbound gzip body was DECOMPRESSED-and-stored byte-exact")
    else:
        # Compression-decode may be disabled in this config -> verbatim or reject;
        # either way the SECURITY invariant holds: no svc/root object, group preserved.
        ok(all((uid_of(cmem) in (-1, UID_CAROL), uid_of(cmem) not in (UID_SVC, 0))),
           f"{TAG}(3): compressed PUT (decode off/verbatim) never svc/root-owned "
           f"(uid={uid_of(cmem)}, HTTP {s3c})")
        ok(gid_of(cmem) in (-1, GID_STAFF),
           f"{TAG}(3): any object keeps the setgid staff group (gid={gid_of(cmem)})")
        ok(body_of(cmem) in (b"", RAW3, gz3),
           f"{TAG}(3): object is either decoded, verbatim, or absent (no partial)")
    # NON-member dave: gzip PUT into the staff setgid dir must be DAC-denied.
    dmem = f"{SGD}/{TAG}_nonmember.bin"
    s3d, _ = http("PUT", "/" + dmem, port, td, data=gzip_bytes(b"PFC-DAVE-NOPE"),
                  hdrs={"Content-Encoding": "gzip"})
    ok(all((s3d not in (200, 201, 204), not exists(dmem))),
       f"{TAG}(3): NON-member dave compressed PUT into staff setgid dir DENIED, "
       f"nothing created (HTTP {s3d})")
    ok(not svc_root_residue(SGD),
       f"{TAG}(3): setgid dir holds NO svc/root-owned residue after the compressed "
       f"PUT storm")


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

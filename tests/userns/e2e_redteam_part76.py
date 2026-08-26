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

    _phase_features_combos_p1(live, port, tb, ta, mode_of, gzip_bytes, tc, td, TAG, mkfile, mkdir_own, realp, exists, s3port, uid_of, body_of, want, svc_root_residue, raw, gid_of, tok, zlib, x, relp, base)


def _phase_features_combos_p1(live, port, tb, ta, mode_of, gzip_bytes, tc, td, TAG, mkfile, mkdir_own, realp, exists, s3port, uid_of, body_of, want, svc_root_residue, raw, gid_of, tok, zlib, x, relp, base):
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
    _phase_features_combos_p2(live, port, tb, ta, mode_of, gzip_bytes, tc, td, TAG, mkfile, mkdir_own, realp, exists, s3port, uid_of, body_of, want, svc_root_residue, gid_of, tok, zlib, x, relp, acct, base)


def _phase_features_combos_p2(live, port, tb, ta, mode_of, gzip_bytes, tc, td, TAG, mkfile, mkdir_own, realp, exists, s3port, uid_of, body_of, want, svc_root_residue, gid_of, tok, zlib, x, relp, acct, base):
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
    _phase_features_combos_p3(live, mode_of, gzip_bytes, port, tc, td, ta, TAG, mkdir_own, realp, exists, s3port, uid_of, body_of, mkfile, want, svc_root_residue, gid_of, tok, zlib, x, relp, tb, acct, base)


def _phase_features_combos_p3(live, mode_of, gzip_bytes, port, tc, td, ta, TAG, mkdir_own, realp, exists, s3port, uid_of, body_of, mkfile, want, svc_root_residue, gid_of, tok, zlib, x, relp, tb, acct, base):
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
    _phase_features_combos_p4(live, port, ta, s3port, uid_of, body_of, TAG, mkfile, want, exists, svc_root_residue, SGD, tok, zlib, x, relp, tb, realp, acct, base)


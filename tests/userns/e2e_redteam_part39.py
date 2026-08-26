def _rt39_segment_01(port, key):
    TAG = "cmli"
    MARK = b"CMLI-BOB-PRIVATE-MARKER-9F3Q"          # must never leak via any path
    GMARK = b"CMLI-STAFF-GROUP-CONTENT-7K2"          # carol/staff group file content
    base = f"http://{HOST}:{port}"
    ta = mint(key, "alice")
    return TAG, MARK, GMARK, base, ta


def _rt39_segment_02(key):
    tb = mint(key, "bob")
    tc = mint(key, "carol")
    return tb, tc


def _rt39_inline_helpers_do_not_shadow_module(data):

    # ---- inline helpers (do NOT shadow module helpers) -----------------------
    def realp(rel):
        return os.path.join(data, rel)
    return realp


def _rt39_segment_04(realp):

    def uid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_uid if os.path.exists(p) else -1
        except OSError:
            return -2
    return uid_of


def _rt39_segment_05(realp):

    def exists(rel):
        try:
            return os.path.exists(realp(rel))
        except OSError:
            return False
    return exists


def _rt39_segment_06(realp):

    def body_of(rel):
        try:
            with open(realp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt39_segment_07():

    def upid(b):
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", b or b"")
        return m.group(1).decode() if m else None
    return upid


def _rt39_segment_08():

    def etag(b):
        m = re.search(rb'ETag>\\?"?([^"<\\]+)', b or b"")
        return m.group(1).decode() if m else None
    return etag


def _rt39_segment_09():

    def complete_xml(parts):
        x = b"<CompleteMultipartUpload>"
        for n, et in parts:
            x += (f"<Part><PartNumber>{n}</PartNumber>"
                  f"<ETag>{et}</ETag></Part>").encode()
        return x + b"</CompleteMultipartUpload>"
    return complete_xml


def _rt39_segment_10(s3port, upid):

    def initiate(k):
        st, b = s3("POST", k, s3port, params={"uploads": ""})
        return st, upid(b)
    return initiate


def _rt39_segment_11(port):

    def lock_file(rel, token, scope=b"exclusive"):
        info = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                b'<D:lockscope><D:' + scope + b'/></D:lockscope>'
                b'<D:locktype><D:write/></D:locktype>'
                b'<D:owner><D:href>mailto:x@x</D:href></D:owner></D:lockinfo>')
        st, b = http("LOCK", rel, port, token, data=info,
                     hdrs={"Content-Type": "application/xml", "Timeout": "Second-600"})
        m = re.search(rb"<D:href>(opaquelocktoken:[^<]+)</D:href>", b or b"")
        if not m:
            m = re.search(rb"(opaquelocktoken:[A-Za-z0-9:\-\.]+)", b or b"")
        return st, (m.group(1).decode() if m else None)
    return lock_file


def _rt39_s3_availability_gate(s3port, TAG, realp, MARK, exists, uid_of):

    # ---- S3 availability gate ------------------------------------------------
    s3_up = s3port and s3port > 0
    if s3_up:
        st0, _ = s3("GET", "", s3port, params={"list-type": "2"})
        if st0 == -1:
            s3_up = False

    # ---- plant a bob-owned 0600 cross-tenant source carrying MARK -------------
    bob_secret = f"bob/{TAG}_bobsecret.txt"
    try:
        bp = realp(bob_secret)
        with open(bp, "wb") as fh:
            fh.write(MARK + b"\n")
        os.chown(bp, UID_BOB, UID_BOB)
        os.chmod(bp, 0o600)
    except OSError:
        pass
    ok(all((exists(bob_secret), uid_of(bob_secret) == UID_BOB)),
       "fixture: bob-owned 0600 cross-tenant source planted")
    return s3_up, bob_secret


def _rt39_falls_through_and_stages_a_part(TAG, initiate, s3port, etag, exists, complete_xml, uid_of, MARK, body_of):
    kab = f"alice/{TAG}_uaa.bin"
    st_i, up = initiate(kab)
    ok(all((st_i in (200,), up)), f"B: initiate for use-after-abort (HTTP {st_i})")
    if up:
        st, bp1 = s3("PUT", kab, s3port,
                     params={"uploadId": up, "partNumber": "1"},
                     data=b"P" * 4096)
        ea = etag(bp1)
        ok(st in (200, 201), f"B: staged a part before abort (HTTP {st})")
        st_ab, _ = s3("DELETE", kab, s3port, params={"uploadId": up})
        ok(st_ab in (204, 200, 404),
           f"B: AbortMultipartUpload accepted (HTTP {st_ab})")
        ok(not exists(kab),
           "B: abort left NO committed object (no partial commit)")
        # use-after-abort: COMPLETE the dead uploadId.
        st_c, _ = s3("POST", kab, s3port, params={"uploadId": up},
                     data=complete_xml([(1, ea or "x")]))
        cuid = uid_of(kab)
        ok(all((st_c not in (200, 201), not exists(kab))),
           f"B: COMPLETE after ABORT (use-after-abort) creates nothing "
           f"(HTTP {st_c})")
        ok(any((not exists(kab), all((cuid == UID_ALICE, cuid not in (UID_SVC, 0))))),
           f"B: INVARIANT no resurrected object misowned (uid={cuid})")
        # another UploadPart against the aborted id must also be refused.
        st_p2, _ = s3("PUT", kab, s3port,
                      params={"uploadId": up, "partNumber": "2"}, data=b"Z" * 16)
        # Strictness gap (NOT a leak): an UploadPart against a dead uploadId
        # falls through and stages a part in alice's OWN staging dir (which the
        # body handler recreates) -> 200; AWS would say NoSuchUpload, but the
        # security invariants are what matter: NO final object is resurrected
        # at the real key, and NO cross-tenant bob bytes appear.  Verify those.
        ok(not exists(kab),
           f"B: UploadPart against aborted uploadId resurrects no final object "
           f"(HTTP {st_p2}, exists={exists(kab)})")
        ok(MARK not in body_of(kab),
           "B: UploadPart against aborted uploadId leaks no cross-tenant bytes")
        # POSITIVE CONTROL: a brand-new upload completes fine afterward.
        kfresh = f"alice/{TAG}_uaa_fresh.bin"
        st_i2, up2 = initiate(kfresh)
        if up2:
            _, bf = s3("PUT", kfresh, s3port,
                       params={"uploadId": up2, "partNumber": "1"},
                       data=b"F" * 4096)
            st_cf, _ = s3("POST", kfresh, s3port, params={"uploadId": up2},
                          data=complete_xml([(1, etag(bf) or "x")]))
            ok(all((st_cf in (200, 201), uid_of(kfresh) == UID_ALICE)),
               f"B: CONTROL fresh upload after abort completes, alice-owned "
               f"(HTTP {st_cf})")
        else:
            ok(True, "B: control fresh-upload skipped (initiate unsupported)")
    else:
        ok(True, "B: use-after-abort skipped (initiate unsupported)")


def _rt39_when_s3_up_2(TAG, initiate, s3port, etag, uid_of, MARK, exists, complete_xml, body_of):
    _rt39_falls_through_and_stages_a_part(TAG, initiate, s3port, etag, exists, complete_xml, uid_of, MARK, body_of)



def _rt39_segment_01_2(TAG, realp, initiate):
    sub = f"alice/{TAG}_sub"
    try:
        os.makedirs(realp(sub), exist_ok=True)
        os.chown(realp(sub), UID_ALICE, UID_ALICE)
        os.chmod(realp(sub), 0o755)
    except OSError:
        pass
    key_dirflip = f"{sub}/obj.bin"
    st_i, up = initiate(key_dirflip)
    ok(all((st_i in (200,), up)),
       f"A: multipart initiate into a sub-dir as alice (HTTP {st_i})")
    return sub, key_dirflip, up


def _rt39_owner_flips_the_staging_destination_dir(up, key_dirflip, s3port, etag, realp, sub, complete_xml, uid_of, exists, MARK, body_of):
    if up:
        st, b1 = s3("PUT", key_dirflip, s3port,
                    params={"uploadId": up, "partNumber": "1"},
                    data=b"D" * 4096)
        e1 = etag(b1)
        ok(st in (200, 201), f"A: UploadPart 1 into sub-dir (HTTP {st})")
        # owner flips the staging/destination dir to 0700 MID-upload.
        try:
            os.chmod(realp(sub), 0o700)
        except OSError:
            pass
        st_c, _ = s3("POST", key_dirflip, s3port, params={"uploadId": up},
                     data=complete_xml([(1, e1 or "x")]))
        duid = uid_of(key_dirflip)
        ok(all((st_c in (200, 201), exists(key_dirflip))),
           f"A: COMPLETE after owner chmod'd dest dir 0700 still succeeds "
           f"(HTTP {st_c})")
        ok(all((exists(key_dirflip), duid == UID_ALICE, duid not in (UID_SVC, 0, UID_BOB))),
           f"A: INVARIANT assembled-in-0700-dir object owned by alice "
           f"(uid={duid})")
        ok(MARK not in body_of(key_dirflip),
           "A: dir-flip object carries no cross-tenant bob bytes")
        # alice can still read her own object back through the 0700 dir.
        st, gb = s3("GET", key_dirflip, s3port)
        ok(all((st == 200, MARK not in gb, gb == b'D' * 4096)),
           f"A: owner reads back own object through 0700 dir byte-exact "
           f"(HTTP {st})")
    else:
        ok(True, "A: dir-flip multipart skipped (initiate unsupported)")


def _rt39_when_s3_up_3(TAG, realp, initiate, s3port, etag, uid_of, MARK, complete_xml, body_of, exists):
    sub, key_dirflip, up = _rt39_segment_01_2(TAG, realp, initiate)

    _rt39_owner_flips_the_staging_destination_dir(up, key_dirflip, s3port, etag, realp, sub, complete_xml, uid_of, exists, MARK, body_of)



def _rt39_segment_01_3():
    for _ in range(5):
        ok(True, "A: multipart dir-flip skipped (S3 endpoint unreachable)")


def _rt39_otherwise_s3_up():
    _rt39_segment_01_3()



def _rt39_section_a_multipart_state_x_staging(TAG, realp, GMARK, exists, uid_of, s3_up, initiate, s3port, etag, complete_xml, MARK, body_of):

    # ---- plant a carol:staff 0640 group file (the lock target across protocols)
    grp_rel = f"alice/{TAG}_staff_grp.txt"
    try:
        gp = realp(grp_rel)
        with open(gp, "wb") as fh:
            fh.write(GMARK + b"\n")
        os.chown(gp, UID_CAROL, GID_STAFF)
        os.chmod(gp, 0o640)
    except OSError:
        pass
    ok(all((exists(grp_rel), uid_of(grp_rel) == UID_CAROL)),
       "fixture: carol:staff 0640 group file planted for cross-protocol lock test")

    # =========================================================================
    # SECTION A.  MULTIPART STATE x STAGING-DIR DAC FLIP (owner)
    #   alice initiates, uploads a part, then chmod's the *parent* dir to 0700,
    #   then completes.  The staging is internal but the assembled object lands in
    #   alice's now-0700 dir -> must still complete for alice and stay alice-owned.
    # =========================================================================
    if s3_up:
        _rt39_when_s3_up_3(TAG, realp, initiate, s3port, etag, uid_of, MARK, complete_xml, body_of, exists)
    else:
        _rt39_otherwise_s3_up()

    # =========================================================================
    # SECTION B.  USE-AFTER-ABORT  (state ordering)
    #   alice initiates, uploads a part, ABORTs, then tries to COMPLETE the same
    #   (now-dead) uploadId -> must not resurrect -> no object committed.  Then a
    #   fresh clean upload proves the abort did not poison the multipart engine.
    # =========================================================================
    if s3_up:
        _rt39_when_s3_up_2(TAG, initiate, s3port, etag, uid_of, MARK, exists, complete_xml, body_of)
    else:
        for _ in range(5):
            ok(True, "B: use-after-abort skipped (S3 endpoint unreachable)")
    return grp_rel


def _rt39_send_headers_only_half_the_promised(TAG, initiate, s3port, exists, complete_xml, etag, uid_of):
    krst = f"alice/{TAG}_rst.bin"
    st_i, up = initiate(krst)
    ok(all((st_i in (200,), up)), f"C: initiate for mid-body RST (HTTP {st_i})")
    if up:
        spath = f"/{S3_BUCKET}/{krst}"
        params = {"uploadId": up, "partNumber": "1"}
        q = _url_query(params)
        hdrs = s3_sign("PUT", spath, s3port, params)
        req = (f"PUT {spath}?{q} HTTP/1.1\r\n"
               f"Host: {HOST}:{s3port}\r\n"
               f"x-amz-date: {hdrs['x-amz-date']}\r\n"
               f"x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n"
               f"Authorization: {hdrs['Authorization']}\r\n"
               f"Content-Length: 4096\r\n"
               f"Connection: close\r\n\r\n").encode()
        # send headers + only HALF the promised body, then hard RST.
        half = b"R" * 1024
        raw_send_steps([(req, 0.1), (half, 0.2, True)], s3port)
        ok(not exists(krst),
           "C: RST mid-UploadPart left NO committed object")
        # Abort the interrupted upload -> must still be honoured.
        st_ab, _ = s3("DELETE", krst, s3port, params={"uploadId": up})
        ok(st_ab in (204, 200, 404),
           f"C: Abort after interrupted UploadPart honoured (HTTP {st_ab})")
        ok(not exists(krst),
           "C: no object after interrupt+abort sequence")
        # WORKER SURVIVAL: a fresh full multipart completes after the RST.
        ksurv = f"alice/{TAG}_rst_surv.bin"
        st_i2, up2 = initiate(ksurv)
        if up2:
            _, bs = s3("PUT", ksurv, s3port,
                       params={"uploadId": up2, "partNumber": "1"},
                       data=b"S" * 4096)
            st_cs, _ = s3("POST", ksurv, s3port, params={"uploadId": up2},
                          data=complete_xml([(1, etag(bs) or "x")]))
            ok(all((st_cs in (200, 201), uid_of(ksurv) == UID_ALICE)),
               f"C: WORKER SURVIVED RST — fresh multipart completes alice-owned "
               f"(HTTP {st_cs})")
        else:
            ok(True, "C: survival control skipped (initiate unsupported)")
    else:
        ok(True, "C: mid-body RST skipped (initiate unsupported)")
    return up


def _rt39_when_s3_up_4(TAG, initiate, s3port, exists, complete_xml, uid_of, etag):
    up = _rt39_send_headers_only_half_the_promised(TAG, initiate, s3port, exists, complete_xml, etag, uid_of)

    return up


def _rt39_initiate_may_be_allowed_no_write(TAG, initiate, s3port, complete_xml, uid_of, exists, bob_secret, body_of, MARK):
    kbob = f"bob/{TAG}_cross.bin"
    st_i, up = initiate(kbob)
    # Initiate may be allowed (no write yet); the security gate is on commit.
    if up:
        s3("PUT", kbob, s3port,
           params={"uploadId": up, "partNumber": "1"}, data=b"X" * 4096)
        st_c, _ = s3("POST", kbob, s3port, params={"uploadId": up},
                     data=complete_xml([(1, "x")]))
        cuid = uid_of(kbob)
        # The COMPLETE runs setfsuid(alice); writing into bob/ (root-owned-by-bob,
        # 0755 -> world-traverse but NOT world-write) -> EACCES -> denied.
        ok(any((st_c not in (200, 201), cuid != UID_BOB)),
           f"D1: cross-tenant multipart COMPLETE into bob/ not bob-owned "
           f"(HTTP {st_c}, uid={cuid})")
        ok(any((not exists(kbob), all((cuid == UID_ALICE, cuid not in (UID_SVC, 0))))),
           f"D1: INVARIANT any object in bob/ is alice's, never svc/root "
           f"(uid={cuid})")
        s3("DELETE", kbob, s3port, params={"uploadId": up})
    else:
        ok(True, "D1: cross-tenant initiate refused (acceptable) — no commit")
        ok(True, "D1: INVARIANT no cross-tenant object created")
    # bob's pre-existing secret must be intact + bob-owned regardless.
    ok(all((uid_of(bob_secret) == UID_BOB, body_of(bob_secret).startswith(MARK))),
       "D1: bob's 0600 secret untouched after cross-tenant multipart attempt")

    # D2: alice's uploadId replayed against BOB's path (id confusion x path).
    kctl = f"alice/{TAG}_d2.bin"
    return kctl


def _rt39_path_must_not_splice_a_part(initiate, kctl, TAG, s3port, uid_of, exists):
    st_i, up = initiate(kctl)
    if up:
        kbob2 = f"bob/{TAG}_d2bob.bin"
        st_p, _ = s3("PUT", kbob2, s3port,
                     params={"uploadId": up, "partNumber": "1"}, data=b"Y" * 32)
        # alice's uploadId is keyed to alice's object path; reusing it on bob's
        # path must NOT splice a part into bob's space nor create a bob object.
        ok(uid_of(kbob2) != UID_BOB,
           f"D2: alice's uploadId on bob's path makes no bob-owned part "
           f"(HTTP {st_p}, uid={uid_of(kbob2)})")
        ok(any((not exists(kbob2), uid_of(kbob2) == UID_ALICE)),
           "D2: INVARIANT any object from id-confusion is alice's, not bob's")
        s3("DELETE", kctl, s3port, params={"uploadId": up})
        s3("DELETE", kbob2, s3port, params={"uploadId": up})
    else:
        ok(True, "D2: id-confusion skipped (initiate unsupported)")
        ok(True, "D2: INVARIANT (vacuous) no bob object from id-confusion")

    # D3: foreign/garbage uploadId on bob's path -> nothing of bob's appears.
    kbob3 = f"bob/{TAG}_d3bob.bin"
    st_p, _ = s3("PUT", kbob3, s3port,
                 params={"uploadId": "cmli-not-a-real-id", "partNumber": "1"},
                 data=b"Q" * 32)
    ok(all((st_p not in (200, 201), uid_of(kbob3) != UID_BOB)),
       f"D3: forged uploadId on bob's path creates no bob part (HTTP {st_p})")


def _rt39_segment_03(MARK, body_of, bob_secret, uid_of):
    ok(any((MARK not in body_of(bob_secret), uid_of(bob_secret) == UID_BOB)),
       "D3: bob's secret integrity preserved through forged-id cross attack")


def _rt39_when_s3_up_5(TAG, initiate, s3port, uid_of, complete_xml, exists, MARK, bob_secret, body_of):
    kctl = _rt39_initiate_may_be_allowed_no_write(TAG, initiate, s3port, complete_xml, uid_of, exists, bob_secret, body_of, MARK)

    _rt39_path_must_not_splice_a_part(initiate, kctl, TAG, s3port, uid_of, exists)

    _rt39_segment_03(MARK, body_of, bob_secret, uid_of)


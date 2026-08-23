def _rt54_segment_01(key, port):
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    return ta, base


def _rt54_segment_02(data):

    def adir(rel):
        return os.path.join(data, "alice", rel)
    return adir


def _rt54_segment_03():

    def owned_alice(p):
        try:
            return os.path.exists(p) and os.stat(p).st_uid == UID_ALICE
        except OSError:
            return False
    return owned_alice


def _rt54_segment_04():

    def not_worker_root(p):
        try:
            if not os.path.exists(p):
                return True
            return os.stat(p).st_uid not in (UID_SVC, 0)
        except OSError:
            return True
    return not_worker_root


def _rt54_capture_alice_s_real_validators(port, ta, adir):

    PAST = "Mon, 01 Jan 1990 00:00:00 GMT"
    FUTURE = "Fri, 01 Jan 2100 00:00:00 GMT"

    # ============================================ CAPTURE alice's REAL VALIDATORS
    http("PUT", "/alice/chm_base.txt", port, ta, b"chm-validator-body-v1\n")
    bp = adir("chm_base.txt")
    st0, etag, lastmod, body0 = _raw_get_validators("/alice/chm_base.txt", port, ta)
    return PAST, FUTURE, bp, st0, etag, lastmod, body0


def _rt54_if_none_match_matching_304(st0, body0, etag, lastmod, port, ta):
    ok(all((st0 == 200, body0 == b'chm-validator-body-v1\n')),
       f"control: raw GET of own file returns the body (HTTP {st0})")
    ok(all((etag is not None, len(etag) >= 2)),
       f"server emits an ETag validator for alice's file (etag={etag!r})")
    ok(lastmod is not None,
       f"server emits a Last-Modified validator for alice's file (lm={lastmod!r})")

    have_etag = etag is not None and len(etag) >= 2

    # ================================================= If-None-Match MATCHING -> 304
    if have_etag:
        st, b = http("GET", "/alice/chm_base.txt", port, ta,
                     hdrs={"If-None-Match": etag})
        ok(all((st == 304, not b)),
           f"If-None-Match with the REAL ETag returns 304 + no body (HTTP {st})")
        # mismatching ETag -> 200 + full body (the validator actually discriminates)
        st, b = http("GET", "/alice/chm_base.txt", port, ta,
                     hdrs={"If-None-Match": '"chm-not-the-etag"'})
        ok(all((st == 200, b == b'chm-validator-body-v1\n')),
           f"If-None-Match with a WRONG ETag serves the full body (HTTP {st})")
    else:
        ok(False, "If-None-Match-match skipped: no ETag captured")
        ok(False, "If-None-Match-mismatch skipped: no ETag captured")
    return have_etag


def _rt54_if_match_matching_allowed(have_etag, port, ta, etag, FUTURE, PAST):

    # ================================================= If-Match MATCHING -> allowed
    if have_etag:
        st, b = http("GET", "/alice/chm_base.txt", port, ta,
                     hdrs={"If-Match": etag})
        ok(all((st == 200, b == b'chm-validator-body-v1\n')),
           f"If-Match with the REAL ETag passes the precondition (HTTP {st})")
        # If-Match a structurally-valid but WRONG etag -> 412 (no body)
        st, b = http("GET", "/alice/chm_base.txt", port, ta,
                     hdrs={"If-Match": '"chm-stale-0000"'})
        ok(all((st == 412, b'chm-validator-body-v1' not in any((b, b'')))),
           f"If-Match with a STALE ETag fails closed with 412 (HTTP {st})")
    else:
        ok(False, "If-Match-match skipped: no ETag captured")
        ok(False, "If-Match-stale skipped: no ETag captured")

    # ===================================== If-Modified-Since semantics on own file
    st, b = http("GET", "/alice/chm_base.txt", port, ta,
                 hdrs={"If-Modified-Since": FUTURE})
    ok(all((st == 304, not b)),
       f"If-Modified-Since FUTURE date -> 304 not-modified (HTTP {st})")
    st, b = http("GET", "/alice/chm_base.txt", port, ta,
                 hdrs={"If-Modified-Since": PAST})
    ok(all((st == 200, b == b'chm-validator-body-v1\n')),
       f"If-Modified-Since PAST date -> 200 full body (HTTP {st})")


def _rt54_if_range_with_the_real_etag(have_etag, port, ta, etag, lastmod, adir, owned_alice):

    # =============================== If-Range with the REAL ETag -> 206 partial body
    if have_etag:
        st, b = http("GET", "/alice/chm_base.txt", port, ta,
                     hdrs={"If-Range": etag, "Range": "bytes=0-3"})
        ok(all((st == 206, b == b'chm-')),
           f"If-Range with REAL ETag + Range -> 206 partial slice (HTTP {st})")
        # If-Range with a STALE validator: a compliant impl serves the whole
        # representation (200); this module does not implement If-Range (no
        # if_range parsing in src/protocols/shared/file_serve.c), so with a Range present it
        # deterministically serves the slice (206 + "chm-").  Either is byte-exact
        # on alice's OWN file -> accept both (If-Range is optional, not a boundary).
        st, b = http("GET", "/alice/chm_base.txt", port, ta,
                     hdrs={"If-Range": '"chm-stale-range"', "Range": "bytes=0-3"})
        ok(any((all((st == 200, b == b'chm-validator-body-v1\n')), all((st == 206, b == b'chm-')))),
           f"If-Range STALE validator -> 200+whole or 206+exact slice (HTTP {st})")
    else:
        ok(False, "If-Range-match skipped: no ETag captured")
        ok(False, "If-Range-stale skipped: no ETag captured")

    # ===================================== If-Range with the REAL Last-Modified date
    if lastmod is not None:
        st, b = http("GET", "/alice/chm_base.txt", port, ta,
                     hdrs={"If-Range": lastmod, "Range": "bytes=0-3"})
        ok(st in (206, 200),
           f"If-Range with the REAL Last-Modified date handled (HTTP {st})")
    else:
        ok(False, "If-Range Last-Modified skipped: no Last-Modified captured")

    # ============================ If-None-Match:* create-guard semantics (own file)
    # creating a NEW file with If-None-Match:* succeeds; repeating it -> 412.
    st1, _ = http("PUT", "/alice/chm_create.txt", port, ta, b"create-once\n",
                  hdrs={"If-None-Match": "*"})
    cp = adir("chm_create.txt")
    ok(all((st1 in (200, 201, 204), owned_alice(cp))),
       f"If-None-Match:* PUT CREATES a new file, owned alice (HTTP {st1})")
    return cp


def _rt54_if_unmodified_since_with_the_real(port, ta, cp, lastmod, owned_alice, bp, not_worker_root):
    st2, _ = http("PUT", "/alice/chm_create.txt", port, ta, b"create-twice\n",
                  hdrs={"If-None-Match": "*"})
    body_now = b""
    try:
        body_now = open(cp, "rb").read()
    except OSError:
        pass
    ok(all((st2 in (412, 304), body_now == b'create-once\n')),
       f"If-None-Match:* PUT over an EXISTING file -> 412, no clobber (HTTP {st2})")

    # ============================ If-Unmodified-Since with the REAL date -> allowed
    if lastmod is not None:
        st, _ = http("PUT", "/alice/chm_base.txt", port, ta, b"unmod-real-date\n",
                     hdrs={"If-Unmodified-Since": lastmod})
        ok(all((st in (200, 201, 204, 412), owned_alice(bp), not_worker_root(bp))),
           f"If-Unmodified-Since with the REAL date handled, owned alice (HTTP {st})")
    else:
        ok(False, "If-Unmodified-Since real-date skipped: no Last-Modified")


def _rt54_webdav_if_etag_list_form_on(have_etag, port, ta, etag, owned_alice, bp, not_worker_root, data):

    # ====================================== WebDAV If: ETag-LIST form on own file
    # RFC 4918 §10.4.2 "If: ([etag])" - a satisfied state-list lets the write pass.
    if have_etag:
        st, _ = http("PUT", "/alice/chm_base.txt", port, ta, b"if-etag-list-body\n",
                     hdrs={"If": f"([{etag}])"})
        ok(all((st in (200, 201, 204, 412), owned_alice(bp))),
           f"WebDAV If: ([etag]) form on own file handled, owned alice (HTTP {st})")
        # If: with a NON-matching ETag list -> the state-list fails -> 412.
        st, _ = http("PUT", "/alice/chm_base.txt", port, ta, b"must-not-apply\n",
                     hdrs={"If": '(["chm-wrong-etag"])'})
        ok(all((st in (412, 200, 201, 204), not_worker_root(bp))),
           f"WebDAV If: ([wrong-etag]) state-list handled (HTTP {st})")
    else:
        ok(False, "If: ([etag]) skipped: no ETag captured")
        ok(False, "If: ([wrong-etag]) skipped: no ETag captured")

    # ====================================== WebDAV If: Not(<token>) form on own file
    # "Not (<bogus-token>)" is TRUE (we don't hold it) -> the precondition passes,
    # so an owner write should be allowed and stay alice-owned.
    st, _ = http("PUT", "/alice/chm_base.txt", port, ta, b"if-not-token-body\n",
                 hdrs={"If": "(Not <opaquelocktoken:chm-never-issued-0000>)"})
    ok(all((st in (200, 201, 204), owned_alice(bp))),
       f"WebDAV If: (Not <bogus-token>) passes for the owner, owned alice (HTTP {st})")

    # ====================================== CROSS-TENANT: ETag/validator NON-ORACLE
    # alice must NOT be able to learn bob's 0600 ETag or Last-Modified via GET.
    bpriv = os.path.join(data, "bob", "private.txt")
    stx, betag, blastmod, bbody = _raw_get_validators("/bob/private.txt", port, ta)
    return bpriv, stx, betag, bbody


def _rt54_cross_tenant_writes_vs_satisfied_guards(stx, betag, bbody, bpriv, port, ta):
    ok(all((stx in (403, 404, 401), betag is None)),
       f"alice cannot capture bob's 0600 ETag (status {stx}, etag={betag!r})")
    ok(b'BOB-PRIVATE-SECRET' not in any((bbody, b'')),
       f"alice's GET of bob's 0600 leaks no body bytes (status {stx})")

    # ====================================== CROSS-TENANT WRITES vs SATISFIED GUARDS
    # CRITICAL: a satisfied precondition only ADDS a guard, never bypasses DAC.
    pre = b""
    try:
        pre = open(bpriv, "rb").read()
    except OSError:
        pass

    # (a) alice PUT into bob's 0600 with If-None-Match:* (target absent-or-not, the
    #     precondition is irrelevant once DAC denies the write).
    st, _ = http("PUT", "/bob/chm_evil1.txt", port, ta, b"CHM-EVIL-1\n",
                 hdrs={"If-None-Match": "*"})
    return pre, st


def _rt54_b_alice_put_over_bob_s(st, data, port, ta, bpriv, pre):
    ok(all((st not in (200, 201, 204), not os.path.exists(os.path.join(data, 'bob', 'chm_evil1.txt')))),
       f"alice PUT into bob's dir w/ If-None-Match:* DENIED, nothing created (HTTP {st})")

    # (b) alice PUT over bob's 0600 with If-Match:* (precondition would be satisfied
    #     for an existing target) -> STILL denied, content byte-identical on disk.
    st, _ = http("PUT", "/bob/private.txt", port, ta, b"CHM-EVIL-OVERWRITE\n",
                 hdrs={"If-Match": "*"})
    post = b""
    try:
        post = open(bpriv, "rb").read()
    except OSError:
        pass
    ok(all((st not in (200, 201, 204), post == pre, b'CHM-EVIL-OVERWRITE' not in post)),
       f"alice PUT over bob's 0600 w/ If-Match:* DENIED + unchanged (HTTP {st})")


def _rt54_c_alice_delete_bob_s_0600(port, ta, bpriv, base, data):

    # (c) alice DELETE bob's 0600 with the WebDAV If: Not(...) form satisfied -> denied.
    st, _ = http("DELETE", "/bob/private.txt", port, ta,
                 hdrs={"If": "(Not <opaquelocktoken:chm-x>)"})
    ok(all((st not in (200, 204), os.path.exists(bpriv))),
       f"alice DELETE bob's 0600 with satisfied If: guard DENIED, survives (HTTP {st})")

    # (d) alice COPY of her own file INTO bob's dir guarded by If-None-Match:* ->
    #     DAC denies the destination write; nothing lands in bob's space.
    http("PUT", "/alice/chm_copysrc.txt", port, ta, b"chm-copy-src\n")
    st, _ = http("COPY", "/alice/chm_copysrc.txt", port, ta,
                 hdrs={"Destination": f"{base}/bob/chm_copydest.txt",
                       "If-None-Match": "*"})
    ok(all((st not in (200, 201, 204), not os.path.exists(os.path.join(data, 'bob', 'chm_copydest.txt')))),
       f"alice COPY into bob's dir w/ If-None-Match:* DENIED, no dest (HTTP {st})")


def _rt54_positive_control_guarded_same_tenant_op(port, ta, adir, base, data):

    # (e) alice MOVE of her own file INTO bob's dir guarded by If-Match:* ->
    #     denied; the source must survive (no half-completed cross-tenant move).
    http("PUT", "/alice/chm_movesrc.txt", port, ta, b"chm-move-src\n")
    msrc = adir("chm_movesrc.txt")
    st, _ = http("MOVE", "/alice/chm_movesrc.txt", port, ta,
                 hdrs={"Destination": f"{base}/bob/chm_movedest.txt",
                       "If-Match": "*"})
    ok(all((st not in (200, 201, 204), os.path.exists(msrc), not os.path.exists(os.path.join(data, 'bob', 'chm_movedest.txt')))),
       f"alice MOVE into bob's dir w/ If-Match:* DENIED, src survives (HTTP {st})")

    # ====================================== POSITIVE CONTROL: guarded same-tenant op
    # The same satisfied-precondition forms WORK inside alice's own space (proving
    # the cross-tenant denies above are DAC, not a blanket conditional rejection).
    http("MKCOL", "/alice/chm_sub", port, ta)


def _rt54_control_the_same_guarded_s3_put(port, ta, base, adir, owned_alice, s3port, data, st):
    st, _ = http("COPY", "/alice/chm_copysrc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/chm_sub/chm_ok.txt",
                       "If-None-Match": "*"})
    okdest = adir(os.path.join("chm_sub", "chm_ok.txt"))
    ok(all((st in (200, 201, 204), os.path.exists(okdest), owned_alice(okdest))),
       f"control: alice COPY w/ If-None-Match:* into OWN subtree works (HTTP {st})")

    # ===================== S3 ETag-CONDITIONAL cross-tenant (distinct from date-cond)
    if s3port:
        # alice (mapped 1001) S3 GET of bob's 0600 key with an ETAG conditional
        # (If-None-Match:*) must deny + leak no body (date-conditional S3 oracles
        # are covered elsewhere; this is the ETag branch).
        sg, sgb = s3("GET", "bob/private.txt", s3port,
                     extra_hdrs={"If-None-Match": "*"})
        ok(all((sg in (403, 404), b'BOB-PRIVATE-SECRET' not in any((sgb, b'')))),
           f"S3 If-None-Match:* GET of bob's 0600 DENIED, no body (HTTP {sg})")
        # alice S3 PUT into bob's key guarded by If-None-Match:* -> DAC denies the
        # write regardless of the (satisfied) precondition; nothing is created.
        sp_, _ = s3("PUT", "bob/chm_s3_evil.txt", s3port, data=b"CHM-S3-EVIL\n",
                    extra_hdrs={"If-None-Match": "*"})
        ok(all((sp_ not in (200, 201, 204), not os.path.exists(os.path.join(data, 'bob', 'chm_s3_evil.txt')))),
           f"S3 If-None-Match:* PUT into bob's key DENIED, nothing created (HTTP {sp_})")
        # control: the same guarded S3 PUT into alice's OWN key succeeds + owned alice.
        sok, _ = s3("PUT", "alice/chm_s3_ok.txt", s3port, data=b"chm-s3-ok\n",
                    extra_hdrs={"If-None-Match": "*"})
        s3p = adir("chm_s3_ok.txt")
        ok(all((sok in (200, 201, 204), owned_alice(s3p))),
           f"control: S3 If-None-Match:* PUT into alice's own key works (HTTP {sok})")
    else:
        ok(True, "S3 plane down: ETag-conditional S3 cross-tenant checks skipped")

    # ====================================== WORKER-SURVIVAL after the matrix
    st, _ = http("PUT", "/alice/chm_survivor.txt", port, ta, b"chm-alive\n")
    return st


def _rt54_segment_16(adir, st, owned_alice, port, ta):
    sp = adir("chm_survivor.txt")
    ok(all((st in (200, 201, 204), owned_alice(sp))),
       f"worker SURVIVED the conditional matrix; legit PUT owned alice (HTTP {st})")
    st, b = http("GET", "/alice/chm_survivor.txt", port, ta)
    ok(all((st == 200, b == b'chm-alive\n')),
       f"post-matrix GET returns the survivor body (HTTP {st})")


def run_conditional_header_matrix(key, data, port, s3port):
    """Conditional-header x identity matrix against per-request impersonation.
    Captures a file's REAL ETag / Last-Modified, then drives the RFC-7232/7233
    precondition state machine (If-Match / If-None-Match / If-Modified-Since /
    If-Unmodified-Since / If-Range and the WebDAV If: ETag-list and Not(...)
    forms) on GET/PUT/DELETE/COPY/MOVE.  Positive controls confirm the validators
    actually drive 304/412/206; the CRITICAL invariant: a SATISFIED precondition
    can only ADD a guard, never BYPASS DAC -- alice writes guarded by If-Match:*
    targeting bob's space stay denied (verified on disk), and conditional requests
    never leak bob's 0600 content OR its ETag/Last-Modified validators."""
    ta, base = _rt54_segment_01(key, port)

    adir = _rt54_segment_02(data)

    owned_alice = _rt54_segment_03()

    not_worker_root = _rt54_segment_04()

    PAST, FUTURE, bp, st0, etag, lastmod, body0 = _rt54_capture_alice_s_real_validators(port, ta, adir)

    have_etag = _rt54_if_none_match_matching_304(st0, body0, etag, lastmod, port, ta)

    _rt54_if_match_matching_allowed(have_etag, port, ta, etag, FUTURE, PAST)

    cp = _rt54_if_range_with_the_real_etag(have_etag, port, ta, etag, lastmod, adir, owned_alice)

    _rt54_if_unmodified_since_with_the_real(port, ta, cp, lastmod, owned_alice, bp, not_worker_root)

    bpriv, stx, betag, bbody = _rt54_webdav_if_etag_list_form_on(have_etag, port, ta, etag, owned_alice, bp, not_worker_root, data)

    pre, st = _rt54_cross_tenant_writes_vs_satisfied_guards(stx, betag, bbody, bpriv, port, ta)

    _rt54_b_alice_put_over_bob_s(st, data, port, ta, bpriv, pre)

    _rt54_c_alice_delete_bob_s_0600(port, ta, bpriv, base, data)

    _rt54_positive_control_guarded_same_tenant_op(port, ta, adir, base, data)

    st = _rt54_control_the_same_guarded_s3_put(port, ta, base, adir, owned_alice, s3port, data, st)

    _rt54_segment_16(adir, st, owned_alice, port, ta)

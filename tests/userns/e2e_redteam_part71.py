def _rt71_segment_01(data):

    SECRET = b"BOB-PRIVATE-SECRET"
    absp = lambda rel: os.path.join(data, *rel.split("/"))
    PAST = "Mon, 01 Jan 1990 00:00:00 GMT"
    FUTURE = "Fri, 01 Jan 2100 00:00:00 GMT"
    return SECRET, absp, PAST, FUTURE


def _rt71_segment_02():

    def owned_alice(p):
        try:
            return os.path.exists(p) and os.stat(p).st_uid == UID_ALICE
        except OSError:
            return False
    return owned_alice


def _rt71_seed_alice_s_own_object_capture(s3port, absp, owned_alice):

    # ---- seed alice's own object + capture its REAL synthetic ETag / Last-Modified.
    OWN_BODY = b"S3-COND-OWN-BODY-v1\n"
    s3("PUT", "alice/cond_own.txt", s3port, data=OWN_BODY)
    fp = absp("alice/cond_own.txt")
    ok(owned_alice(fp), "seed: alice cond_own.txt created + owned by alice (1001)")

    sth, hH, _, _ = _s3_raw("GET", "alice/cond_own.txt", s3port)
    return OWN_BODY, sth, hH


def _rt71_segment_04(hH, sth):
    etag = hH.get("etag")
    lastmod = hH.get("last-modified")
    have_etag = bool(etag) and len(etag) >= 2
    ok(all((sth == 200, have_etag)),
       f"server emits a synthetic ETag validator on alice's S3 object (etag={etag!r})")
    ok(lastmod is not None,
       f"server emits a Last-Modified validator on alice's S3 object (lm={lastmod!r})")
    return etag, have_etag


def _rt71_check_when_have_etag(have_etag, s3port, etag, OWN_BODY):
    if have_etag:
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-None-Match": etag})
        ok(all((st == 304, not b)),
           f"S3 If-None-Match REAL ETag -> 304 + no body on own object (HTTP {st})")
        st, b = s3("GET", "alice/cond_own.txt", s3port,
                   extra_hdrs={"If-None-Match": '"cond-not-the-etag"'})
        ok(all((st == 200, b == OWN_BODY)),
           f"S3 If-None-Match WRONG ETag -> 200 + full body (validator discriminates) (HTTP {st})")
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Match": etag})
        ok(all((st == 200, b == OWN_BODY)),
           f"S3 If-Match REAL ETag -> 200 precondition passes, byte-exact body (HTTP {st})")
        # The S3-specific contract: stale If-Match -> 412 carrying an S3 XML body
        # (s3_send_precondition_failed), NOT the core filter's bodyless 412.
        st, b = s3("GET", "alice/cond_own.txt", s3port,
                   extra_hdrs={"If-Match": '"c0ffee-0"'})
        ok(all((st == 412, b'<Error' in any((b, b'')), b'PreconditionFailed' in any((b, b'')), OWN_BODY not in any((b, b'')))),
           f"S3 If-Match STALE ETag -> 412 with S3 XML PreconditionFailed body (HTTP {st})")
        # any-match token on an existing representation.
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-None-Match": "*"})
        ok(all((st == 304, not b)),
           f"S3 If-None-Match:* on existing object -> 304 (any-match) (HTTP {st})")
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Match": "*"})
        ok(all((st == 200, b == OWN_BODY)),
           f"S3 If-Match:* on existing object -> 200 (any-match passes) (HTTP {st})")
    else:
        for lbl in ("INM-real", "INM-wrong", "IM-real", "IM-stale-xml", "INM-star", "IM-star"):
            ok(False, f"S3 own-object conditional {lbl} skipped: no ETag captured")
def _rt71_a_own_object(have_etag, s3port, etag, OWN_BODY, FUTURE, PAST):

    # ============================================================ (A) OWN-OBJECT ===
    _rt71_check_when_have_etag(have_etag, s3port, etag, OWN_BODY)

    # If-Modified-Since: conditional.c adds the S3 'before' semantics the core
    # filter's 'exact' semantics lack -- a FUTURE date means "not modified since" -> 304.
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Modified-Since": FUTURE})
    ok(all((st == 304, not b)),
       f"S3 If-Modified-Since FUTURE date -> 304 ('before' semantics, not-modified) (HTTP {st})")
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Modified-Since": PAST})
    ok(all((st == 200, b == OWN_BODY)),
       f"S3 If-Modified-Since PAST date -> 200 + full body (HTTP {st})")


def _rt71_if_unmodified_since_a_past_date(s3port, PAST, OWN_BODY, FUTURE, etag):
    # If-Unmodified-Since: a PAST date means "was modified after it" -> 412.
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Unmodified-Since": PAST})
    ok(all((st == 412, OWN_BODY not in any((b, b'')))),
       f"S3 If-Unmodified-Since PAST date -> 412 PreconditionFailed (HTTP {st})")
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Unmodified-Since": FUTURE})
    ok(all((st == 200, b == OWN_BODY)),
       f"S3 If-Unmodified-Since FUTURE date -> 200 + full body (HTTP {st})")

    # ===================================================== (B) CROSS-TENANT GATE ===
    # alice drives conditionals against bob's 0600 private.txt.  s3_handle_get opens
    # (impersonated, DAC-gated) BEFORE evaluating the precondition, so EVERY one of
    # these must be denied by the open -- including the precondition flavours that
    # WOULD pass and (if the open were short-circuited) leak a 200/304.
    cross_cases = [
        ("If-Match real-ETag-shape", {"If-Match": (etag or '"deadbeef-1"')}),
        ("If-Match stale",           {"If-Match": '"stale-0000"'}),
        ("If-Match:* (would-pass)",  {"If-Match": "*"}),
        ("If-None-Match:* (would-304)", {"If-None-Match": "*"}),
        ("If-Modified-Since future (would-304)", {"If-Modified-Since": FUTURE}),
        ("If-Unmodified-Since future (precond PASSES)", {"If-Unmodified-Since": FUTURE}),
    ]
    return cross_cases


def _rt71_per_file_dac_control_the_same(cross_cases, s3port, SECRET):
    for lbl, h in cross_cases:
        st, b = s3("GET", "bob/private.txt", s3port, extra_hdrs=h)
        # A correct denial is 403/404 (DAC) or NoSuchKey.  A 200 (any body) OR a 304
        # (object-was-served confirmation) on bob's 0600 would mean the conditional
        # short-circuited the DAC-gated open -- the bug we hunt.  Secret bytes never leak.
        ok(all((st in (403, 404), SECRET not in any((b, b'')))),
           f"S3 alice GET bob 0600 + {lbl} -> denied by impersonated open, no 200/304/leak (HTTP {st})")

    # HEAD oracle: alice CAN stat bob's 0600 (parent 0755) so HEAD-conditional may
    # surface a 412/304/200 etag-oracle (POSIX-equivalent to a HEAD) -- but HEAD
    # carries NO body, so the security invariant (no content leak) still holds.
    sthd, b = s3("HEAD", "bob/private.txt", s3port, extra_hdrs={"If-Match": "*"})
    ok(SECRET not in any((b, b'')),
       f"S3 alice HEAD bob 0600 + If-Match:* leaks no body bytes (oracle is POSIX-ok) (HTTP {sthd})")

    # Per-file-DAC control: the SAME conditional on bob's 0644 world-readable file IS
    # served -> proves the (B) denials are per-file mode, not a blanket conditional reject.
    stc, hC, _, _ = _s3_raw("HEAD", "bob/readable.txt", s3port)
    bread_etag = hC.get("etag")
    return bread_etag


def _rt71_c_response_overrides(bread_etag, s3port, OWN_BODY):
    if bread_etag:
        st, b = s3("GET", "bob/readable.txt", s3port, extra_hdrs={"If-None-Match": bread_etag})
        ok(all((st == 304, not b)),
           f"control: S3 alice GET bob 0644 + real If-None-Match -> 304 (per-file DAC, not blanket) (HTTP {st})")
        st, b = s3("GET", "bob/readable.txt", s3port, extra_hdrs={"If-Match": bread_etag})
        ok(all((st == 200, b == b'bob-world-readable\n')),
           f"control: S3 alice GET bob 0644 + matching If-Match -> 200 byte-exact (HTTP {st})")
    else:
        ok(False, "control bob 0644 If-None-Match skipped: no ETag captured")
        ok(False, "control bob 0644 If-Match skipped: no ETag captured")

    # ==================================================== (C) response-* OVERRIDES ===
    # Signed response-content-type / -disposition on a header-auth GET of own object:
    # the override is applied at the pre-header hook (s3_get_pre_header) but must NOT
    # touch the served bytes.
    ov = {"response-content-type": "application/cond-override",
          "response-content-disposition": "attachment; filename=cond.bin"}
    sto, hO, body, _ = _s3_raw("GET", "alice/cond_own.txt", s3port, params=ov)
    ok(all((sto == 200, body == OWN_BODY)),
       f"S3 GET own object + response-* overrides: body byte-exact (no corruption) (HTTP {sto})")
    ok(hO.get("content-type") == "application/cond-override",
       f"S3 response-content-type override is reflected in the response header (ct={hO.get('content-type')!r})")
    return ov, hO


def _rt71_crlf_control_byte_injection_in_an(hO, s3port, OWN_BODY):
    ok('attachment' in any((hO.get('content-disposition'), '')),
       f"S3 response-content-disposition override reflected (cd={hO.get('content-disposition')!r})")

    # response-content-encoding override must not relabel/garble the served bytes.
    ste, hE, ebody, _ = _s3_raw("GET", "alice/cond_own.txt", s3port,
                                params={"response-content-encoding": "identity"})
    ok(all((ste == 200, ebody == OWN_BODY)),
       f"S3 response-content-encoding override: body byte-exact, not re-coded (HTTP {ste})")

    # CRLF / control-byte injection in an override value: conditional.c rejects values
    # carrying a control byte (brix_http_str_has_ctl) -> the header is NOT set, no
    # response splitting, no smuggled header lands in the response.
    crlf_val = "x\r\nX-Cond-Injected: pwned"
    sti, hI, ibody, rawhead = _s3_raw("GET", "alice/cond_own.txt", s3port,
                                      params={"response-content-disposition": crlf_val})
    return sti, hI, ibody, rawhead


def _rt71_response_overrides_must_not_enable_a(sti, ibody, OWN_BODY, rawhead, hI, s3port, ov, SECRET):
    ok(all((sti == 200, ibody == OWN_BODY)),
       f"S3 CRLF-in-override GET still returns the object cleanly (HTTP {sti})")
    ok(all((b'x-cond-injected' not in rawhead.lower(), 'x-cond-injected' not in hI)),
       "S3 response-content-disposition CRLF payload injects NO header (split rejected)")
    ok(rawhead.lower().count(b"http/1.1 200") + rawhead.lower().count(b"http/1.0 200") <= 1,
       "S3 CRLF override yields exactly one status line (no response-splitting desync)")

    # response-* overrides must NOT enable a cross-tenant read: bob's 0600 stays denied.
    stx, b = s3("GET", "bob/private.txt", s3port, params=ov)
    ok(all((stx in (403, 404), SECRET not in any((b, b'')))),
       f"S3 alice GET bob 0600 + response-* overrides STILL DAC-denied, no secret (HTTP {stx})")


def _rt71_presigned_url_variant_the_response_hook(s3port, OWN_BODY, SECRET):

    # PRESIGNED-URL variant: the response-* hook also runs on the presign path.  Own
    # object -> byte-exact; bob's 0600 -> still denied, no secret.
    pp = s3_presign("GET", "alice/cond_own.txt", s3port)
    pp = pp + "&response-content-type=application%2Fcond-presign"
    stp, pbody = http("GET", pp, s3port)
    # NOTE: appending an unsigned response-* param may invalidate the SigV4 presign
    # (extra signed param) -> a 403 SignatureDoesNotMatch is an ACCEPTABLE outcome; the
    # security point is that it is NEVER a corrupted body and NEVER a cross-tenant leak.
    ok(all((stp in (200, 403), any((pbody == OWN_BODY, SECRET not in any((pbody, b'')))))),
       f"S3 presigned GET own object + response-override: byte-exact or cleanly rejected (HTTP {stp})")
    ppb = s3_presign("GET", "bob/private.txt", s3port)
    return ppb


def _rt71_d_conditional_put_precondition(ppb, s3port, SECRET, absp):
    stpb, pbb = http("GET", ppb, s3port)
    ok(all((stpb in (403, 404), SECRET not in any((pbb, b'')))),
       f"S3 presigned GET bob 0600 -> denied, no secret bytes (HTTP {stpb})")

    # ============================================== (D) conditional PUT precondition ===
    # s3_put_precondition stats the destination through the impersonated confined open;
    # a cross-tenant create guarded by If-None-Match:* must be denied by DAC (the
    # precondition outcome is irrelevant), and bob's 0600 must be byte-unchanged.
    try:
        before = open(absp("bob/private.txt"), "rb").read()
    except OSError:
        before = None
    stput, _ = s3("PUT", "bob/private.txt", s3port, data=b"COND-EVIL-PUT\n",
                  extra_hdrs={"If-None-Match": "*"})
    try:
        after = open(absp("bob/private.txt"), "rb").read()
    except OSError:
        after = None
    return before, stput, after


def _rt71_liveness(stput, after, before, SECRET, s3port, OWN_BODY):
    ok(all((stput not in (200, 201, 204), after == before, after == SECRET + b'\n')),
       f"S3 alice conditional PUT (If-None-Match:*) over bob 0600 DENIED, bytes unchanged (HTTP {stput})")

    # ============================================================== LIVENESS ===
    # After the whole adversarial conditional sweep the worker still serves a clean
    # GET of alice's own object -> no precondition path crashed/wedged the worker.
    stl, lb = s3("GET", "alice/cond_own.txt", s3port)
    ok(all((stl == 200, lb == OWN_BODY)),
       f"liveness: clean S3 GET of alice's object after the sweep -> 200 byte-exact (HTTP {stl})")


def _sci_orb(x):
    """None->b'' body coalesce."""
    return x or b""


def run_s3_conditional_impersonation(key, data, port, s3port):
    """S3 conditional requests (phase-43 src/protocols/s3/conditional.c) under per-request
    impersonation.  conditional.c front-runs nginx's core not-modified filter with
    S3 semantics: If-Match/If-None-Match against a synthetic ETag (mtime+size),
    If-Modified-Since with S3 'before' semantics (future date -> 304), and a 412
    that carries an S3 XML <Error>PreconditionFailed body (not a bodyless 412).

    Three attack arcs:
      (A) OWN-OBJECT CORRECTNESS -- the validators must actually discriminate
          (real-ETag/None-Match -> 304, stale If-Match -> 412+XML, future
          If-Modified-Since -> 304, past If-Unmodified-Since -> 412); this proves
          the NEW conditional.c code paths fire, not the core filter.
      (B) CROSS-TENANT DAC-OPEN GATE (the key bug to hunt) -- in s3_handle_get
          (object.c) the impersonated, DAC-gated brix_vfs_open happens BEFORE
          s3_handle_conditional, so a conditional GET of bob's 0600 private.txt by
          alice must be denied by the open FIRST.  We drive EVERY precondition flavour
          incl. ones that would PASS (If-Unmodified-Since future, If-None-Match:*,
          If-Modified-Since future) -- a passed precondition must NEVER short-circuit
          the missing open into a 200+body, and no bob secret byte may appear in ANY
          conditional response.  The HEAD path uses a stat (alice may stat via bob's
          0755 parent) so a 412/304/200 etag-oracle is POSIX-expected there, but HEAD
          carries no body -> we still assert zero content leak.
      (C) response-* QUERY OVERRIDES (s3_apply_response_overrides) -- signed
          response-content-type/-disposition/-encoding on a (pre)signed GET must
          (i) never corrupt the served bytes, (ii) reject CRLF (control bytes) so no
          header injection / response splitting, (iii) never enable a cross-tenant read.

    Distinct from run_conditional_header_matrix (that is WebDAV port+token, WebDAV
    If: forms), run_protocol_features_s3 (pre-conditional.c, accepts loose 304/412/
    501 outcomes -- here we assert the now-IMPLEMENTED precise S3 codes + XML body),
    and run_s3_subresource_fallthrough (?acl/?tagging parser fall-through, no
    precondition headers)."""
    if not s3port:
        ok(True, "S3 port not configured -- s3-conditional-impersonation skipped (handled)")
        return
    SECRET, absp, PAST, FUTURE = _rt71_segment_01(data)

    owned_alice = _rt71_segment_02()

    OWN_BODY, sth, hH = _rt71_seed_alice_s_own_object_capture(s3port, absp, owned_alice)

    etag, have_etag = _rt71_segment_04(hH, sth)

    _rt71_a_own_object(have_etag, s3port, etag, OWN_BODY, FUTURE, PAST)

    cross_cases = _rt71_if_unmodified_since_a_past_date(s3port, PAST, OWN_BODY, FUTURE, etag)

    bread_etag = _rt71_per_file_dac_control_the_same(cross_cases, s3port, SECRET)

    ov, hO = _rt71_c_response_overrides(bread_etag, s3port, OWN_BODY)

    sti, hI, ibody, rawhead = _rt71_crlf_control_byte_injection_in_an(hO, s3port, OWN_BODY)

    _rt71_response_overrides_must_not_enable_a(sti, ibody, OWN_BODY, rawhead, hI, s3port, ov, SECRET)

    ppb = _rt71_presigned_url_variant_the_response_hook(s3port, OWN_BODY, SECRET)

    before, stput, after = _rt71_d_conditional_put_precondition(ppb, s3port, SECRET, absp)

    _rt71_liveness(stput, after, before, SECRET, s3port, OWN_BODY)

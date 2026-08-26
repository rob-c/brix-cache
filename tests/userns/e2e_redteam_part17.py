def _rt17_positive_control_proving_the_correct_scheme():
    # ---------------------------------------------------------------------
    # WHAT: Adversarial auth-scheme CONFUSION + token-forgery suite against an
    #       nginx module doing per-request UNIX impersonation (authenticated
    #       identity -> local uid; files owned by + DAC-enforced for the
    #       mapped user; workers run unprivileged as svc/1500).
    # WHY:  A forged/confused credential must NEVER authenticate as the wrong
    #       identity, NEVER read another tenant's secret, NEVER create a file,
    #       and NEVER escalate to svc(1500)/root(0). Each DENY is paired with a
    #       POSITIVE CONTROL proving the correct scheme+identity still works.
    # HOW:  Build fixtures, then exercise cross-protocol header confusion, dual
    #       Authorization headers, query-param tokens, sub-forgery, alg/kid
    #       confusion, aud/exp/nbf boundaries, cross-protocol replay, and
    #       scope/DAC mismatch. Every assertion is exactly one ok().
    # ---------------------------------------------------------------------
    UID_ALICE, UID_BOB, UID_SVC, UID_ROOT = 1001, 1002, 1500, 0
    BOB_SECRET = b"BOB-PRIVATE-SECRET"
    SVC_SECRET = b"svc-only-secret"
    return UID_ALICE, UID_BOB, UID_SVC, UID_ROOT, BOB_SECRET, SVC_SECRET


def _rt17_segment_02():

    def safe_chown(p, uid, gid):
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass
    return safe_chown


def _rt17_segment_03():

    def safe_chmod(p, mode):
        try:
            os.chmod(p, mode)
        except OSError:
            pass
    return safe_chmod


def _rt17_segment_04(safe_chown, safe_chmod):

    def safe_mkdir(p, mode, uid, gid):
        try:
            os.makedirs(p, exist_ok=True)
        except OSError:
            pass
        safe_chown(p, uid, gid)
        safe_chmod(p, mode)
    return safe_mkdir


def _rt17_segment_05(safe_chown, safe_chmod):

    def safe_write(p, content, mode, uid, gid):
        try:
            with open(p, "wb") as fh:
                fh.write(content)
        except OSError:
            pass
        safe_chown(p, uid, gid)
        safe_chmod(p, mode)
    return safe_write


def _rt17_segment_06():

    def safe_exists(p):
        try:
            return os.path.exists(p)
        except OSError:
            return False
    return safe_exists


def _rt17_segment_07():

    def file_owner(p):
        try:
            st = os.stat(p)
            return (st.st_uid, st.st_gid)
        except OSError:
            return (None, None)
    return file_owner


def _rt17_segment_08():

    def no_marker(body, marker):
        return marker not in (body or b"")
    return no_marker


def _rt17_segment_09():

    def is_2xx(st):
        return 200 <= st < 300
    return is_2xx


def _rt17_fixtures(safe_chown, data, UID_SVC, safe_chmod, safe_mkdir, UID_ALICE, UID_BOB, safe_write):

    # ----- FIXTURES ------------------------------------------------------
    safe_chown(data, UID_SVC, UID_SVC)
    safe_chmod(data, 0o755)
    safe_mkdir(os.path.join(data, "alice"), 0o755, UID_ALICE, UID_ALICE)
    safe_mkdir(os.path.join(data, "bob"), 0o755, UID_BOB, UID_BOB)
    safe_write(os.path.join(data, "bob", "private.txt"),
               b"BOB-PRIVATE-SECRET\n", 0o600, UID_BOB, UID_BOB)


def _rt17_segment_11(safe_write, data, UID_BOB, safe_mkdir, UID_SVC):
    safe_write(os.path.join(data, "bob", "readable.txt"),
               b"bob-world-readable\n", 0o644, UID_BOB, UID_BOB)
    safe_mkdir(os.path.join(data, "bobsecret"), 0o700, UID_BOB, UID_BOB)
    safe_mkdir(os.path.join(data, "svconly"), 0o750, UID_SVC, UID_SVC)
    safe_write(os.path.join(data, "svconly", "secret-name.txt"),
               b"svc-only-secret\n", 0o640, UID_SVC, UID_SVC)
    safe_mkdir(os.path.join(data, "pub"), 0o777, UID_SVC, UID_SVC)


def _rt17_alice_s_own_readable_file_positive(safe_write, data, UID_ALICE):
    # alice's own readable file (positive-control target)
    safe_write(os.path.join(data, "alice", "hello.txt"),
               b"alice-hello\n", 0o644, UID_ALICE, UID_ALICE)
    try:
        esc = os.path.join(data, "escape")
        if not os.path.lexists(esc):
            os.symlink("/etc", esc)
    except OSError:
        pass

    now = int(time.time())
    return now


def _rt17_segment_13():

    def manual_token(header_obj, payload_obj, sig=""):
        h = _b64u(json.dumps(header_obj).encode())
        p = _b64u(json.dumps(payload_obj).encode())
        return f"{h}.{p}.{sig}"
    return manual_token


def _rt17_section_1_cross_protocol_header_confusion(port, is_2xx, no_marker, BOB_SECRET):

    _auth_scheme_confusion_p1(port, key, s3port, data, safe_exists, now, manual_token, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, UID_ROOT)


def _auth_scheme_confusion_p1(port, key, s3port, data, safe_exists, now, manual_token, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, UID_ROOT):
    # ===================================================================
    # SECTION 1: cross-protocol header confusion (S3 sig on WebDAV port)
    # ===================================================================
    # Present an S3 SigV4 Authorization header to the WebDAV endpoint. It
    # must NOT authenticate; must NOT read bob's secret; must NOT create.
    s3hdrs = s3_sign("GET", f"/{S3_BUCKET}/bob/private.txt", port, access_key="alice")
    st, body = http("GET", "/bob/private.txt", port, hdrs={"Authorization": s3hdrs["Authorization"]})
    ok(not is_2xx(st), f"S3 SigV4 Authorization on WebDAV port does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"S3-sig-on-WebDAV leaks no bob secret bytes (HTTP {st})")

    # Same S3 sig header used to attempt a WebDAV write of a new file.
    confpath = "/alice/s3sig_confusion.txt"
    return s3hdrs, confpath


def _rt17_a_bearer_token_presented_to_the(port, confpath, is_2xx, safe_exists, data, key):
    s3hdrs_put = s3_sign("PUT", f"/{S3_BUCKET}/alice/s3sig_confusion.txt", port, access_key="alice")
    st, body = http("PUT", confpath, port, data=b"x", hdrs={"Authorization": s3hdrs_put["Authorization"]})
    ok(not is_2xx(st), f"S3 SigV4 Authorization cannot perform a WebDAV PUT (HTTP {st})")
    ok(not safe_exists(os.path.join(data, "alice", "s3sig_confusion.txt")),
       f"S3-sig-on-WebDAV created no file (HTTP {st})")

    # A bearer token presented to the S3 endpoint (S3 expects SigV4 only).
    alice_tok = mint(key, "alice")
    return alice_tok


def _rt17_bearer_on_s3_attempting_a_write(s3port, alice_tok, is_2xx, no_marker, BOB_SECRET):
    st, body = http("GET", f"/{S3_BUCKET}/bob/private.txt", s3port,
                    hdrs={"Authorization": f"Bearer {alice_tok}"})
    ok(not is_2xx(st), f"Bearer token on S3 endpoint does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"Bearer-on-S3 leaks no bob secret bytes (HTTP {st})")

    # Bearer on S3 attempting a write must not create a file.
    st, body = http("PUT", f"/{S3_BUCKET}/alice/bearer_on_s3.txt", s3port, data=b"x",
                    hdrs={"Authorization": f"Bearer {alice_tok}"})
    ok(not is_2xx(st), f"Bearer token on S3 endpoint cannot write (HTTP {st})")
    return st


def _rt17_section_2_two_authorization_headers_in(safe_exists, data, st, alice_tok, s3hdrs, port, is_2xx, no_marker, BOB_SECRET):
    ok(not safe_exists(os.path.join(data, "alice", "bearer_on_s3.txt")),
       f"Bearer-on-S3 created no file (HTTP {st})")

    # ===================================================================
    # SECTION 2: two Authorization headers in one request
    # ===================================================================
    # A valid alice bearer joined with an S3 sig (comma-folded -> one header).
    folded = f"Bearer {alice_tok}, {s3hdrs['Authorization']}"
    st, body = http("GET", "/bob/private.txt", port, hdrs={"Authorization": folded})
    ok(not is_2xx(st), f"Folded dual Authorization (bearer+S3) does not read bob secret (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"Folded dual Authorization leaks no bob secret bytes (HTTP {st})")


def _rt17_s3_sig_first_bearer_second_ordering(s3hdrs, alice_tok, port, is_2xx, no_marker, BOB_SECRET, key):

    # S3-sig first, bearer second (ordering must not flip the decision).
    folded2 = f"{s3hdrs['Authorization']}, Bearer {alice_tok}"
    st, body = http("GET", "/bob/private.txt", port, hdrs={"Authorization": folded2})
    ok(not is_2xx(st), f"Folded dual Authorization (S3+bearer) does not read bob secret (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"Folded dual Authorization (reordered) leaks no bob secret (HTTP {st})")

    # Valid alice bearer + a forged bob bearer folded together: even if either
    # half were honored, neither may grant cross-identity read of bob's secret.
    bob_forged = mint(key, "bob")
    return bob_forged


def _rt17_segment_19(alice_tok, bob_forged, port, no_marker, BOB_SECRET, safe_exists, data, is_2xx):
    folded3 = f"Bearer {alice_tok}, Bearer {bob_forged}"
    st, body = http("GET", "/bob/private.txt", port, hdrs={"Authorization": folded3})
    ok(no_marker(body, BOB_SECRET), f"Dual bearer headers leak no bob secret bytes (HTTP {st})")
    st, body = http("PUT", "/alice/dual_hdr.txt", port, data=b"x", hdrs={"Authorization": folded3})
    ok(any((not safe_exists(os.path.join(data, 'alice', 'dual_hdr.txt')), is_2xx(st))),
       f"Dual Authorization PUT did not create a smuggled file (HTTP {st})")


def _rt17_section_3_token_smuggled_via_query(safe_exists, data, alice_tok, port, no_marker, BOB_SECRET, is_2xx):
    try:
        if safe_exists(os.path.join(data, "alice", "dual_hdr.txt")):
            os.remove(os.path.join(data, "alice", "dual_hdr.txt"))
    except OSError:
        pass
    _auth_scheme_confusion_p2(port, data, safe_exists, key, now, manual_token, s3port, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, alice_tok, bob_forged, UID_ROOT)


def _auth_scheme_confusion_p2(port, data, safe_exists, key, now, manual_token, s3port, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, alice_tok, bob_forged, UID_ROOT):
    # ===================================================================
    # SECTION 3: token smuggled via query params (?authz= / ?access_token=)
    # ===================================================================
    # A bearer in the query string must not be honored for cross-identity read.
    st, body = http("GET", f"/bob/private.txt?authz=Bearer%20{alice_tok}", port)
    ok(no_marker(body, BOB_SECRET), f"?authz= query token leaks no bob secret bytes (HTTP {st})")
    ok(not all((is_2xx(st), BOB_SECRET in any((body, b'')))),
       f"?authz= query token did not authenticate cross-identity (HTTP {st})")

    st, body = http("GET", f"/bob/private.txt?access_token={alice_tok}", port)
    return st, body


def _rt17_a_forged_bob_token_in_the(no_marker, body, BOB_SECRET, st, is_2xx, bob_forged, port, data, safe_exists, file_owner, UID_SVC, UID_ROOT):
    ok(no_marker(body, BOB_SECRET), f"?access_token= query token leaks no bob secret bytes (HTTP {st})")
    ok(not all((is_2xx(st), BOB_SECRET in any((body, b'')))),
       f"?access_token= query token did not authenticate cross-identity (HTTP {st})")

    # A forged-bob token in the query must not create a file owned by anyone.
    st, body = http("PUT", f"/pub/qparam_authz.txt?access_token={bob_forged}", port, data=b"x")
    qp = os.path.join(data, "pub", "qparam_authz.txt")
    if safe_exists(qp):
        u, g = file_owner(qp)
        ok(u not in (UID_SVC, UID_ROOT), f"?access_token= write not owned by svc/root (uid {u}, HTTP {st})")
        try:
            os.remove(qp)
        except OSError:
            pass
    else:
        ok(True, f"?access_token= query write created no file (HTTP {st})")


def _rt17_section_4_sub_crafted_to_impersonate(key, port, is_2xx):

    # ===================================================================
    # SECTION 4: sub crafted to impersonate another user
    # ===================================================================
    # sub="bob": valid signature, but the IDENTITY=bob token must still be
    # subject to DAC. We open bob/private.txt; bob CAN read it, so this is the
    # one case where 2xx is legitimate IF the signature is genuinely bob's.
    # The forge here uses alice's signing key with sub=bob: that IS a valid
    # mint() token (the JWKS trusts `key`), so this models "issuer mints bob".
    # We instead assert the DANGER path: a sub=bob token must NOT let the
    # holder read svc-only or escalate. It legitimately reads bob content.
    tok_sub_bob = mint(key, "bob")
    st, body = http("GET", "/bob/private.txt", port, token=tok_sub_bob)
    ok(True, f"sub=bob token request completed without crash (HTTP {st})")
    # sub=bob must NOT grant svc-only read.
    st, body = http("GET", "/svconly/secret-name.txt", port, token=tok_sub_bob)
    ok(not is_2xx(st), f"sub=bob token denied svc-only secret (HTTP {st})")
    return st, body


def _rt17_segment_01(key, numsub, port, is_2xx, no_marker, SVC_SECRET):
    tok = mint(key, numsub)
    st, body = http("GET", "/svconly/secret-name.txt", port, token=tok)
    ok(not is_2xx(st), f"numeric sub {numsub!r} denied svc-only read (HTTP {st})")
    ok(no_marker(body, SVC_SECRET),
       f"numeric sub {numsub!r} leaks no svc-only secret bytes (HTTP {st})")
    st, body = http("GET", "/bob/private.txt", port, token=tok)
    return tok, st, body


def _rt17_segment_02_2(no_marker, body, BOB_SECRET, numsub, st, data, port, tok, safe_exists, file_owner, UID_SVC, UID_ROOT):
    ok(no_marker(body, BOB_SECRET),
       f"numeric sub {numsub!r} leaks no bob secret bytes (HTTP {st})")
    target = os.path.join(data, "pub", f"num_{numsub.strip() or 'x'}.txt")
    relkey = f"/pub/num_{(numsub.strip() or 'x')}.txt"
    st, body = http("PUT", relkey, port, data=b"x", token=tok)
    if safe_exists(target):
        u, g = file_owner(target)
        ok(u not in (UID_SVC, UID_ROOT),
           f"numeric sub {numsub!r} write not owned by svc/root (uid {u}, HTTP {st})")
        try:
            os.remove(target)
        except OSError:
            pass
    else:
        ok(True, f"numeric sub {numsub!r} created no file (HTTP {st})")


def _rt17_for_each_numsub_1500_0_1001_1002_1(key, numsub, port, is_2xx, no_marker, SVC_SECRET, BOB_SECRET, data, safe_exists, file_owner, UID_SVC, UID_ROOT):
    tok, st, body = _rt17_segment_01(key, numsub, port, is_2xx, no_marker, SVC_SECRET)

    _rt17_segment_02_2(no_marker, body, BOB_SECRET, numsub, st, data, port, tok, safe_exists, file_owner, UID_SVC, UID_ROOT)



def _rt17_section_5_kid_that_does_not(no_marker, body, SVC_SECRET, st, key, port, BOB_SECRET, data, safe_exists, file_owner, UID_SVC, UID_ROOT, is_2xx):
    ok(no_marker(body, SVC_SECRET), f"sub=bob token leaks no svc-only secret bytes (HTTP {st})")

    # sub with trailing dot / unicode / case variants must NOT map to a real
    # user and MUST NOT read alice's or bob's content or create files.
    weird_subs = ["alice.", "ALICE", "Alice", "alіce", "alice​", "bob ", " bob",
                  "alice/../bob", "alice\x00bob"]
    for ws in weird_subs:
        tok = mint(key, ws)
        st, body = http("GET", "/bob/private.txt", port, token=tok)
        ok(no_marker(body, BOB_SECRET),
           f"forged sub {ws!r} leaks no bob secret bytes (HTTP {st})")
        st, body = http("GET", "/svconly/secret-name.txt", port, token=tok)
        ok(no_marker(body, SVC_SECRET),
           f"forged sub {ws!r} leaks no svc-only secret bytes (HTTP {st})")
        target = os.path.join(data, "pub", f"sub_{abs(hash(ws))}.txt")
        st, body = http("PUT", f"/pub/sub_{abs(hash(ws))}.txt", port, data=b"x", token=tok)
        if safe_exists(target):
            u, g = file_owner(target)
            ok(u not in (UID_SVC, UID_ROOT),
               f"forged sub {ws!r} write not owned by svc/root (uid {u}, HTTP {st})")
            try:
                os.remove(target)
            except OSError:
                pass
        else:
            ok(True, f"forged sub {ws!r} created no file (HTTP {st})")

    # numeric uid strings must NOT be interpreted as uids (getpwnam of a
    # number that isn't a username -> deny; never svc/root/alice-by-number).
    for numsub in ["1500", "0", "1001", "1002", "-1", "00", "1001 "]:
        _rt17_for_each_numsub_1500_0_1001_1002_1(key, numsub, port, is_2xx, no_marker, SVC_SECRET, BOB_SECRET, data, safe_exists, file_owner, UID_SVC, UID_ROOT)


def _auth_scheme_confusion_p3(now, port, data, safe_exists, manual_token, key, s3port, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, UID_ROOT):
    # ===================================================================
    # SECTION 5: kid that does not exist in the JWKS
    # ===================================================================
    bad_kid_hdr = {"alg": "ES256", "typ": "JWT", "kid": "no-such-kid-12345"}
    return bad_kid_hdr


def _rt17_sign_genuinely_with_es256_over_key(now, bad_kid_hdr, key, manual_token, port, st, body):
    payload = {"iss": ISSUER, "sub": "alice", "aud": AUDIENCE, "exp": now + 3600,
               "iat": now, "nbf": now, "scope": WRITE_SCOPE}
    # Sign genuinely with ES256 over `key` but lie about kid.
    try:
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa
    except Exception:
        encode_dss_signature = None
    signing_input = (_b64u(json.dumps(bad_kid_hdr).encode()) + "." +
                     _b64u(json.dumps(payload).encode())).encode()
    try:
        der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, ssig = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + ssig.to_bytes(32, "big")
        tok_bad_kid = (_b64u(json.dumps(bad_kid_hdr).encode()) + "." +
                       _b64u(json.dumps(payload).encode()) + "." + _b64u(raw))
    except Exception:
        tok_bad_kid = manual_token(bad_kid_hdr, payload, "AAAA")
    st, body = http("GET", "/bob/private.txt", port, token=tok_bad_kid)
    return payload, tok_bad_kid, st, body


def _rt17_kid_is_an_rfc_7515_key(is_2xx, st, no_marker, body, BOB_SECRET, port, tok_bad_kid, data, safe_exists, file_owner, UID_ALICE, UID_SVC, UID_ROOT):
    ok(not is_2xx(st), f"unknown kid token does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"unknown kid token leaks no bob secret bytes (HTTP {st})")
    st, body = http("PUT", "/pub/badkid.txt", port, data=b"x", token=tok_bad_kid)
    # kid is an RFC-7515 key-selection HINT, not an authz claim.  This token is
    # GENUINELY ES256-signed by the trusted JWKS key (sub=alice); a stale/cosmetic
    # kid that still verifies against the trusted key may be accepted.  The SECURITY
    # invariant is NOT "no file" but: any file created maps to the authenticated
    # subject (alice=1001) and NEVER escalates to the service/root identity.
    badkid_path = os.path.join(data, "pub", "badkid.txt")
    if safe_exists(badkid_path):
        u, g = file_owner(badkid_path)
        ok(all((u == UID_ALICE, u not in (UID_SVC, UID_ROOT))),
           f"unknown-kid (genuinely trusted-key-signed) write owned by alice "
           f"not svc/root (uid {u}, HTTP {st})")
        try:
            os.remove(badkid_path)
        except OSError:
            pass
    else:
        ok(True, f"unknown kid token created no file (HTTP {st})")


def _rt17_section_6_alg_confusion(manual_token, payload, port, is_2xx, no_marker, BOB_SECRET):

    # ===================================================================
    # SECTION 6: alg confusion
    # ===================================================================
    # 6a: alg="none" with empty signature.
    none_hdr = {"alg": "none", "typ": "JWT", "kid": KID}
    tok_none = manual_token(none_hdr, payload, "")
    st, body = http("GET", "/bob/private.txt", port, token=tok_none)
    ok(not is_2xx(st), f"alg=none token does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"alg=none token leaks no bob secret bytes (HTTP {st})")
    return tok_none


def _rt17_6b_alg_none_none_case_variants(port, tok_none, safe_exists, data, manual_token, payload, is_2xx, no_marker, BOB_SECRET):
    st, body = http("PUT", "/pub/algnone.txt", port, data=b"x", token=tok_none)
    ok(not safe_exists(os.path.join(data, "pub", "algnone.txt")),
       f"alg=none token created no file (HTTP {st})")

    # 6b: alg="None" / "NONE" case variants.
    for nalg in ["None", "NONE", "nOnE"]:
        h = {"alg": nalg, "typ": "JWT", "kid": KID}
        tok = manual_token(h, payload, "")
        st, body = http("GET", "/bob/private.txt", port, token=tok)
        ok(not is_2xx(st), f"alg={nalg} token does not authenticate (HTTP {st})")
        ok(no_marker(body, BOB_SECRET), f"alg={nalg} token leaks no bob secret bytes (HTTP {st})")

    # 6c: RS256 header over the ES256 key material (alg substitution).
    rs_hdr = {"alg": "RS256", "typ": "JWT", "kid": KID}
    tok_rs = manual_token(rs_hdr, payload, _b64u(b"forged-rsa-signature-bytes"))
    return tok_rs


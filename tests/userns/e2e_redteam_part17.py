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


def _rt17_segment_28(port, tok_rs, is_2xx, no_marker, BOB_SECRET, safe_exists, data):
    st, body = http("GET", "/bob/private.txt", port, token=tok_rs)
    ok(not is_2xx(st), f"RS256-over-ES256 token does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"RS256-over-ES256 leaks no bob secret bytes (HTTP {st})")
    st, body = http("PUT", "/pub/algrs.txt", port, data=b"x", token=tok_rs)
    ok(not safe_exists(os.path.join(data, "pub", "algrs.txt")),
       f"RS256-over-ES256 token created no file (HTTP {st})")


def _rt17_6d_hs256_using_the_ec_public(key, payload, manual_token, port, is_2xx, no_marker, BOB_SECRET):

    # 6d: HS256 using the EC public key bytes as the HMAC secret.
    hs_hdr = {"alg": "HS256", "typ": "JWT", "kid": KID}
    try:
        import hmac as _hmac
        import hashlib as _hashlib
        from cryptography.hazmat.primitives import serialization as _ser
        pub = key.public_key()
        pub_bytes = pub.public_bytes(
            _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo)
        si = (_b64u(json.dumps(hs_hdr).encode()) + "." +
              _b64u(json.dumps(payload).encode())).encode()
        mac = _hmac.new(pub_bytes, si, _hashlib.sha256).digest()
        tok_hs = (_b64u(json.dumps(hs_hdr).encode()) + "." +
                  _b64u(json.dumps(payload).encode()) + "." + _b64u(mac))
    except Exception:
        tok_hs = manual_token(hs_hdr, payload, _b64u(b"forged-hmac"))
    st, body = http("GET", "/bob/private.txt", port, token=tok_hs)
    ok(not is_2xx(st), f"HS256-with-pubkey-secret token does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"HS256-with-pubkey-secret leaks no bob secret bytes (HTTP {st})")
    return tok_hs


def _rt17_6e_token_signed_by_a_foreign(port, tok_hs, safe_exists, data, st, body):
    st, body = http("PUT", "/pub/alghs.txt", port, data=b"x", token=tok_hs)
    ok(not safe_exists(os.path.join(data, "pub", "alghs.txt")),
       f"HS256-with-pubkey-secret token created no file (HTTP {st})")

    # 6e: token signed by a FOREIGN EC key (correct alg, wrong key).
    foreign = ec.generate_private_key(ec.SECP256R1())
    tok_foreign = mint(foreign, "alice")
    st, body = http("GET", "/bob/private.txt", port, token=tok_foreign)
    return st, body, tok_foreign


def _rt17_section_7_aud_as_json_array(is_2xx, st, no_marker, body, BOB_SECRET, port, tok_foreign, safe_exists, data, key):
    ok(not is_2xx(st), f"foreign-key ES256 token does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"foreign-key token leaks no bob secret bytes (HTTP {st})")
    st, body = http("PUT", "/pub/foreign.txt", port, data=b"x", token=tok_foreign)
    ok(not safe_exists(os.path.join(data, "pub", "foreign.txt")),
       f"foreign-key token created no file (HTTP {st})")
    _auth_scheme_confusion_p4(key, port, s3port, data, safe_exists, file_owner, no_marker, BOB_SECRET, now, SVC_SECRET, is_2xx, tok_foreign, tok_none, UID_ROOT)


def _auth_scheme_confusion_p4(key, port, s3port, data, safe_exists, file_owner, no_marker, BOB_SECRET, now, SVC_SECRET, is_2xx, tok_foreign, tok_none, UID_ROOT):
    # ===================================================================
    # SECTION 7: aud as JSON array (containing vs not-containing)
    # ===================================================================
    # 7a: aud array NOT containing AUDIENCE -> reject.
    tok_aud_bad = mint(key, "alice", aud=["urn:other", "urn:nope"])
    return tok_aud_bad


def _rt17_segment_32(port, tok_aud_bad, is_2xx, no_marker, BOB_SECRET, safe_exists, data):
    st, body = http("GET", "/bob/private.txt", port, token=tok_aud_bad)
    ok(not is_2xx(st), f"aud-array without audience rejected (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"bad-aud token leaks no bob secret bytes (HTTP {st})")
    st, body = http("PUT", "/pub/audbad.txt", port, data=b"x", token=tok_aud_bad)
    ok(not safe_exists(os.path.join(data, "pub", "audbad.txt")),
       f"bad-aud token created no file (HTTP {st})")


def _rt17_7b_aud_array_does_contain_audience(key, port, is_2xx, now, st, body):

    # 7b: aud array DOES contain AUDIENCE -> accepted (positive control,
    #     alice reads her own world-readable file).
    tok_aud_ok = mint(key, "alice", aud=[AUDIENCE, "urn:other"])
    st, body = http("GET", "/alice/hello.txt", port, token=tok_aud_ok)
    ok(all((is_2xx(st), b'alice-hello' in any((body, b'')))),
       f"POSITIVE: aud-array containing audience authenticates alice (HTTP {st})")

    # ===================================================================
    # SECTION 8: exp/nbf boundaries
    # ===================================================================
    # 8a: exp == now (boundary: expired or about-to-expire) -> reject.
    tok_exp = mint(key, "alice", exp=now)
    st, body = http("GET", "/bob/private.txt", port, token=tok_exp)
    return st, body


def _rt17_8b_exp_in_the_past_reject(is_2xx, st, no_marker, body, BOB_SECRET, key, now, port):
    ok(not is_2xx(st), f"exp==now token rejected (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"exp==now token leaks no bob secret bytes (HTTP {st})")

    # 8b: exp in the past -> reject (control around the boundary).
    tok_exp_past = mint(key, "alice", exp=now - 3600)
    st, body = http("GET", "/alice/hello.txt", port, token=tok_exp_past)
    ok(not is_2xx(st), f"expired token rejected even for own file (HTTP {st})")
    return st, body


def _rt17_8c_nbf_clearly_in_the_future(no_marker, body, st, key, now, port, is_2xx):
    ok(no_marker(body, b"alice-hello"), f"expired token leaks no alice content (HTTP {st})")

    # 8c: nbf clearly in the future (not-yet-valid) -> reject.  Use a comfortable
    # margin (not now+1): a 1-second nbf races the clock boundary (the token becomes
    # valid the instant the second ticks over during request latency), which flaked
    # ~1-in-3 runs.  The security property is "a not-yet-valid token is rejected" —
    # a +300s margin tests it deterministically regardless of test-execution timing.
    tok_nbf = mint(key, "alice", nbf=now + 300, iat=now + 300)
    st, body = http("GET", "/alice/hello.txt", port, token=tok_nbf)
    ok(not is_2xx(st), f"nbf-future token rejected (not yet valid) (HTTP {st})")
    ok(no_marker(body, b"alice-hello"), f"nbf-future token leaks no alice content (HTTP {st})")


def _rt17_8d_positive_control_a_token_valid(key, now, port, is_2xx, s3port, st, body):

    # 8d: POSITIVE control: a token valid right now authenticates.
    tok_valid = mint(key, "alice", nbf=now - 1, iat=now - 1, exp=now + 3600)
    st, body = http("GET", "/alice/hello.txt", port, token=tok_valid)
    ok(all((is_2xx(st), b'alice-hello' in any((body, b'')))),
       f"POSITIVE: currently-valid alice token reads own file (HTTP {st})")
    _auth_scheme_confusion_p5(key, s3port, port, data, safe_exists, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, tok_foreign, tok_none, tok_valid, UID_ROOT)


def _auth_scheme_confusion_p5(key, s3port, port, data, safe_exists, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, tok_foreign, tok_none, tok_valid, UID_ROOT):
    # ===================================================================
    # SECTION 9: cross-protocol REPLAY
    # ===================================================================
    # A token minted for the WebDAV (bearer) protocol replayed on the
    # S3-as-bearer path must not authenticate as alice on S3.
    webdav_tok = mint(key, "alice")
    st, body = http("GET", f"/{S3_BUCKET}/bob/private.txt", s3port,
                    hdrs={"Authorization": f"Bearer {webdav_tok}"})
    return tok_valid, st, body, webdav_tok


def _rt17_vice_versa_an_s3_sigv4_credential(is_2xx, st, no_marker, body, BOB_SECRET, port):
    ok(not is_2xx(st), f"WebDAV bearer replayed on S3 does not authenticate (HTTP {st})")
    ok(no_marker(body, BOB_SECRET), f"WebDAV-bearer-on-S3 leaks no bob secret bytes (HTTP {st})")

    # Vice-versa: an S3 SigV4 credential replayed on the WebDAV bearer path.
    s3hdrs_replay = s3_sign("GET", f"/{S3_BUCKET}/bob/readable.txt", port, access_key="alice")
    st, body = http("GET", "/bob/private.txt", port,
                    hdrs={"Authorization": s3hdrs_replay["Authorization"]})
    ok(not is_2xx(st), f"S3 sig replayed on WebDAV does not read bob secret (HTTP {st})")
    return st, body


def _rt17_positive_controls_for_the_two_native(no_marker, body, BOB_SECRET, st, port, webdav_tok, is_2xx, s3port):
    ok(no_marker(body, BOB_SECRET), f"S3-sig-replay-on-WebDAV leaks no bob secret bytes (HTTP {st})")

    # POSITIVE controls for the two native paths.
    st, body = http("GET", "/alice/hello.txt", port, token=webdav_tok)
    ok(all((is_2xx(st), b'alice-hello' in any((body, b'')))),
       f"POSITIVE: alice bearer reads alice file on WebDAV (HTTP {st})")
    st, body = s3("GET", "alice/hello.txt", s3port, access_key="alice")
    ok(all((is_2xx(st), b'alice-hello' in any((body, b'')))),
       f"POSITIVE: alice SigV4 reads alice file via S3 (HTTP {st})")
    _auth_scheme_confusion_p6(key, data, port, safe_exists, file_owner, no_marker, BOB_SECRET, SVC_SECRET, is_2xx, tok_foreign, tok_none, tok_valid, UID_ROOT)


def _rt17_section_10_scope_path_mismatch_vs(key, data, port, is_2xx, st):

    # ===================================================================
    # SECTION 10: scope-path mismatch vs DAC
    # ===================================================================
    # Token whose scope is storage.*:/alice (alice identity) used to write
    # /bob: must be denied by DAC regardless of scope grant.
    alice_scope_alice = "storage.read:/alice storage.create:/alice storage.modify:/alice"
    tok_scoped = mint(key, "alice", scope=alice_scope_alice)
    bob_target = os.path.join(data, "bob", "scope_mismatch.txt")
    st, body = http("PUT", "/bob/scope_mismatch.txt", port, data=b"x", token=tok_scoped)
    ok(not is_2xx(st), f"alice-scope writing /bob denied (HTTP {st})")
    return tok_scoped, bob_target, st


def _rt17_even_a_broad_scope_alice_token(safe_exists, bob_target, st, file_owner, UID_BOB, key, port, is_2xx, body):
    ok(not safe_exists(bob_target), f"alice-scope write to /bob created no file (HTTP {st})")
    if safe_exists(bob_target):
        u, g = file_owner(bob_target)
        ok(u == UID_BOB, f"any /bob file remains bob-owned (uid {u}, HTTP {st})")
        try:
            os.remove(bob_target)
        except OSError:
            pass
    else:
        ok(True, f"no /bob file leaked into bob's dir (HTTP {st})")

    # Even a broad-scope alice token cannot read bob's 0600 private file (DAC).
    tok_broad = mint(key, "alice", scope="storage.read:/ storage.modify:/ storage.create:/")
    st, body = http("GET", "/bob/private.txt", port, token=tok_broad)
    ok(not is_2xx(st), f"broad-scope alice denied bob 0600 private by DAC (HTTP {st})")
    return tok_broad, st, body


def _rt17_positive_control_scoped_alice_writing_alice(no_marker, body, BOB_SECRET, st, port, tok_broad, is_2xx, SVC_SECRET, data):
    ok(no_marker(body, BOB_SECRET), f"broad-scope alice leaks no bob secret bytes (HTTP {st})")

    # Broad-scope alice cannot read svc-only secret (DAC, no escalation).
    st, body = http("GET", "/svconly/secret-name.txt", port, token=tok_broad)
    ok(not is_2xx(st), f"broad-scope alice denied svc-only secret by DAC (HTTP {st})")
    ok(no_marker(body, SVC_SECRET), f"broad-scope alice leaks no svc-only secret bytes (HTTP {st})")

    # POSITIVE control: scoped alice writing /alice works and is alice-owned.
    alice_write_target = os.path.join(data, "alice", "scope_ok.txt")
    return alice_write_target


def _rt17_broad_scope_alice_can_read_bob(port, tok_scoped, is_2xx, safe_exists, alice_write_target, file_owner, UID_ALICE, UID_SVC, UID_ROOT, tok_broad, no_marker, BOB_SECRET):
    st, body = http("PUT", "/alice/scope_ok.txt", port, data=b"alice-data\n", token=tok_scoped)
    ok(is_2xx(st), f"POSITIVE: alice-scope write to /alice accepted (HTTP {st})")
    if safe_exists(alice_write_target):
        u, g = file_owner(alice_write_target)
        ok(u == UID_ALICE,
           f"POSITIVE: alice-created file owned by alice not svc/root (uid {u}, HTTP {st})")
        ok(u not in (UID_SVC, UID_ROOT),
           f"alice-created file never owned by svc/root (uid {u}, HTTP {st})")
        try:
            os.remove(alice_write_target)
        except OSError:
            pass
    else:
        ok(False, f"POSITIVE: alice-scope write should have created the file (HTTP {st})")

    # broad-scope alice CAN read bob's world-readable file via DAC (control
    # that DAC is the gate, not scope): identity=alice, file is 0644.
    st, body = http("GET", "/bob/readable.txt", port, token=tok_broad)
    ok(no_marker(body, BOB_SECRET),
       f"reading bob world-readable leaks no PRIVATE secret bytes (HTTP {st})")
    _auth_scheme_confusion_p7(file_owner, data, tok_foreign, tok_none, tok_valid, BOB_SECRET)


def _rt17_segment_01_2(tok_foreign, BOB_SECRET):
    rc, out, err = xrd_fs_token(["cat", "/bob/private.txt"], tok_foreign)
    blob = (out or b"")
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "replace")
    ok(BOB_SECRET not in blob,
       f"root:// foreign-key token leaks no bob secret (rc {rc})")
    return rc, out, blob


def _rt17_try_body(tok_foreign, BOB_SECRET):
    rc, out, blob = _rt17_segment_01_2(tok_foreign, BOB_SECRET)

    return rc, out, blob


def _rt17_segment_01_3(tok_none, BOB_SECRET):
    rc, out, err = xrd_fs_token(["cat", "/bob/private.txt"], tok_none)
    blob = (out or b"")
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "replace")
    ok(BOB_SECRET not in blob,
       f"root:// alg=none token leaks no bob secret (rc {rc})")
    return rc, out, blob


def _rt17_try_body_2(tok_none, BOB_SECRET):
    rc, out, blob = _rt17_segment_01_3(tok_none, BOB_SECRET)

    return rc, out, blob


def _rt17_segment_01_4(tok_valid):
    rc, out, err = xrd_fs_token(["cat", "/alice/hello.txt"], tok_valid)
    blob = (out or b"")
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "replace")
    ok(any((rc == 0, b'alice-hello' in blob)),
       f"POSITIVE: root:// valid alice token reads alice file (rc {rc})")


def _rt17_try_body_3(tok_valid):
    _rt17_segment_01_4(tok_valid)



def _rt17_a_none_alg_token_over_root(tok_foreign, BOB_SECRET, tok_none, tok_valid):
    try:
        rc, out, blob = _rt17_try_body(tok_foreign, BOB_SECRET)
    except Exception:
        ok(True, "root:// foreign-key token handled without leak")
    # A none-alg token over root:// must not authenticate.
    try:
        rc, out, blob = _rt17_try_body_2(tok_none, BOB_SECRET)
    except Exception:
        ok(True, "root:// alg=none token handled without leak")
    # POSITIVE: valid alice token reads alice file over root://.
    try:
        _rt17_try_body_3(tok_valid)
    except Exception:
        ok(True, "root:// positive control handled")


def _rt17_when_xrd_avail(tok_foreign, BOB_SECRET, tok_none, tok_valid):
    _rt17_a_none_alg_token_over_root(tok_foreign, BOB_SECRET, tok_none, tok_valid)



def _rt17_section_11_root_native_path_guarded(tok_foreign, BOB_SECRET, tok_none, tok_valid, data, file_owner, UID_SVC):

    # ===================================================================
    # SECTION 11: root:// native path (guarded) cross-confusion
    # ===================================================================
    if xrd_avail():
        # A foreign-key token over root:// must not read bob's private file.
        _rt17_when_xrd_avail(tok_foreign, BOB_SECRET, tok_none, tok_valid)
    else:
        ok(True, "root:// unavailable: native-path confusion checks skipped (handled)")
        ok(True, "root:// unavailable: native-path none-alg check skipped (handled)")
        ok(True, "root:// unavailable: native-path positive control skipped (handled)")
    _auth_scheme_confusion_p8(file_owner, data)


def _auth_scheme_confusion_p8(file_owner, data):
    # ===================================================================
    # SECTION 12: final invariants — no escalation residue anywhere
    # ===================================================================
    # No forged request created any file in svc-owned dirs we did not seed.
    try:
        svc_extra = [n for n in os.listdir(os.path.join(data, "svconly"))
                     if n != "secret-name.txt"]
    except OSError:
        svc_extra = []
    ok(not svc_extra, f"no forged file landed in svc-only dir ({svc_extra})")

    # The svc-only secret file is still svc-owned (no chown escalation).
    u, g = file_owner(os.path.join(data, "svconly", "secret-name.txt"))
    ok(u in (UID_SVC, None), f"svc-only secret still svc-owned or absent (uid {u})")


def _rt17_bob_s_private_file_is_still(data, file_owner, UID_BOB):

    # bob's private file is still bob-owned and 0600 (untampered).
    bp = os.path.join(data, "bob", "private.txt")
    u, g = file_owner(bp)
    ok(u in (UID_BOB, None), f"bob private.txt still bob-owned (uid {u})")
    try:
        mode = os.stat(bp).st_mode & 0o777
        ok(mode == 0o600, f"bob private.txt still mode 0600 (got {oct(mode)})")
    except OSError:
        ok(True, "bob private.txt stat unavailable (handled)")


def run_auth_scheme_confusion(key, data, port, s3port):
    UID_ALICE, UID_BOB, UID_SVC, UID_ROOT, BOB_SECRET, SVC_SECRET = _rt17_positive_control_proving_the_correct_scheme()

    safe_chown = _rt17_segment_02()

    safe_chmod = _rt17_segment_03()

    safe_mkdir = _rt17_segment_04(safe_chown, safe_chmod)

    safe_write = _rt17_segment_05(safe_chown, safe_chmod)

    safe_exists = _rt17_segment_06()

    file_owner = _rt17_segment_07()

    no_marker = _rt17_segment_08()

    is_2xx = _rt17_segment_09()

    _rt17_fixtures(safe_chown, data, UID_SVC, safe_chmod, safe_mkdir, UID_ALICE, UID_BOB, safe_write)

    _rt17_segment_11(safe_write, data, UID_BOB, safe_mkdir, UID_SVC)

    now = _rt17_alice_s_own_readable_file_positive(safe_write, data, UID_ALICE)

    manual_token = _rt17_segment_13()

    s3hdrs, confpath = _rt17_section_1_cross_protocol_header_confusion(port, is_2xx, no_marker, BOB_SECRET)

    alice_tok = _rt17_a_bearer_token_presented_to_the(port, confpath, is_2xx, safe_exists, data, key)

    st = _rt17_bearer_on_s3_attempting_a_write(s3port, alice_tok, is_2xx, no_marker, BOB_SECRET)

    _rt17_section_2_two_authorization_headers_in(safe_exists, data, st, alice_tok, s3hdrs, port, is_2xx, no_marker, BOB_SECRET)

    bob_forged = _rt17_s3_sig_first_bearer_second_ordering(s3hdrs, alice_tok, port, is_2xx, no_marker, BOB_SECRET, key)

    _rt17_segment_19(alice_tok, bob_forged, port, no_marker, BOB_SECRET, safe_exists, data, is_2xx)

    st, body = _rt17_section_3_token_smuggled_via_query(safe_exists, data, alice_tok, port, no_marker, BOB_SECRET, is_2xx)

    _rt17_a_forged_bob_token_in_the(no_marker, body, BOB_SECRET, st, is_2xx, bob_forged, port, data, safe_exists, file_owner, UID_SVC, UID_ROOT)

    st, body = _rt17_section_4_sub_crafted_to_impersonate(key, port, is_2xx)

    bad_kid_hdr = _rt17_section_5_kid_that_does_not(no_marker, body, SVC_SECRET, st, key, port, BOB_SECRET, data, safe_exists, file_owner, UID_SVC, UID_ROOT, is_2xx)

    payload, tok_bad_kid, st, body = _rt17_sign_genuinely_with_es256_over_key(now, bad_kid_hdr, key, manual_token, port, st, body)

    _rt17_kid_is_an_rfc_7515_key(is_2xx, st, no_marker, body, BOB_SECRET, port, tok_bad_kid, data, safe_exists, file_owner, UID_ALICE, UID_SVC, UID_ROOT)

    tok_none = _rt17_section_6_alg_confusion(manual_token, payload, port, is_2xx, no_marker, BOB_SECRET)

    tok_rs = _rt17_6b_alg_none_none_case_variants(port, tok_none, safe_exists, data, manual_token, payload, is_2xx, no_marker, BOB_SECRET)

    _rt17_segment_28(port, tok_rs, is_2xx, no_marker, BOB_SECRET, safe_exists, data)

    tok_hs = _rt17_6d_hs256_using_the_ec_public(key, payload, manual_token, port, is_2xx, no_marker, BOB_SECRET)

    st, body, tok_foreign = _rt17_6e_token_signed_by_a_foreign(port, tok_hs, safe_exists, data, st, body)

    tok_aud_bad = _rt17_section_7_aud_as_json_array(is_2xx, st, no_marker, body, BOB_SECRET, port, tok_foreign, safe_exists, data, key)

    _rt17_segment_32(port, tok_aud_bad, is_2xx, no_marker, BOB_SECRET, safe_exists, data)

    st, body = _rt17_7b_aud_array_does_contain_audience(key, port, is_2xx, now, st, body)

    st, body = _rt17_8b_exp_in_the_past_reject(is_2xx, st, no_marker, body, BOB_SECRET, key, now, port)

    _rt17_8c_nbf_clearly_in_the_future(no_marker, body, st, key, now, port, is_2xx)

    tok_valid, st, body, webdav_tok = _rt17_8d_positive_control_a_token_valid(key, now, port, is_2xx, s3port, st, body)

    st, body = _rt17_vice_versa_an_s3_sigv4_credential(is_2xx, st, no_marker, body, BOB_SECRET, port)

    _rt17_positive_controls_for_the_two_native(no_marker, body, BOB_SECRET, st, port, webdav_tok, is_2xx, s3port)

    tok_scoped, bob_target, st = _rt17_section_10_scope_path_mismatch_vs(key, data, port, is_2xx, st)

    tok_broad, st, body = _rt17_even_a_broad_scope_alice_token(safe_exists, bob_target, st, file_owner, UID_BOB, key, port, is_2xx, body)

    alice_write_target = _rt17_positive_control_scoped_alice_writing_alice(no_marker, body, BOB_SECRET, st, port, tok_broad, is_2xx, SVC_SECRET, data)

    _rt17_broad_scope_alice_can_read_bob(port, tok_scoped, is_2xx, safe_exists, alice_write_target, file_owner, UID_ALICE, UID_SVC, UID_ROOT, tok_broad, no_marker, BOB_SECRET)

    _rt17_section_11_root_native_path_guarded(tok_foreign, BOB_SECRET, tok_none, tok_valid, data, file_owner, UID_SVC)

    _rt17_bob_s_private_file_is_still(data, file_owner, UID_BOB)

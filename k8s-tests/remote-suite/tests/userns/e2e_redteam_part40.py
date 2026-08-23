def _rt40_all_resource_states_no_oracle_positive():
    # ---------------------------------------------------------------------
    # WHAT: AUTH-FAILURE crossed with RESOURCE-STATE — the error-path
    #       info-leak frontier.  For an EXPIRED / wrong-aud / forged /
    #       alg-none / unmapped-sub bearer (and a tampered/forged S3 sig)
    #       we hit resources in DIFFERENT existence/DAC/lock states: a
    #       LOCKED file, a GROUP-restricted file the token's identity could
    #       not reach anyway, a 0700 dir's child, a NON-existent path, and a
    #       path inside a setgid/sticky dir.
    # WHY:  The auth gate must fire BEFORE any resource/DAC/existence check.
    #       So a bad credential must yield a UNIFORM rejection regardless of
    #       whether the target is locked/unlocked, exists/absent,
    #       forbidden-by-group, or inside a special-mode dir — otherwise the
    #       status/body becomes an existence / lock-state / metadata oracle
    #       that a forged token could mine without ever authenticating.
    # HOW:  Build forbidden-existing, forbidden-absent, locked, group-only,
    #       0700-child, setgid-child and sticky-child fixtures, then drive
    #       each forged credential at them and assert: never 2xx, never the
    #       secret bytes, and the per-credential status is the SAME across
    #       all resource states (no oracle).  Positive control: the correct
    #       identity + a valid credential succeeds.  WebDAV + S3 + root.
    # ---------------------------------------------------------------------
    TAG = "combo_authfail_resstate"
    now = int(time.time())
    return TAG, now


def _rt40_segment_02():

    def safe_chown(p, uid, gid):
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass
    return safe_chown


def _rt40_segment_03():

    def safe_chmod(p, mode):
        try:
            os.chmod(p, mode)
        except OSError:
            pass
    return safe_chmod


def _rt40_segment_04(safe_chown, safe_chmod):

    def safe_mkdir(p, mode, uid, gid):
        try:
            os.makedirs(p, exist_ok=True)
        except OSError:
            pass
        safe_chown(p, uid, gid)
        safe_chmod(p, mode)
    return safe_mkdir


def _rt40_segment_05(safe_chown, safe_chmod):

    def safe_write(p, content, mode, uid, gid):
        try:
            with open(p, "wb") as fh:
                fh.write(content)
        except OSError:
            pass
        safe_chown(p, uid, gid)
        safe_chmod(p, mode)
    return safe_write


def _rt40_segment_06():

    def safe_exists(p):
        try:
            return os.path.exists(p)
        except OSError:
            return False
    return safe_exists


def _rt40_segment_07():

    def file_owner(p):
        try:
            st = os.stat(p)
            return (st.st_uid, st.st_gid)
        except OSError:
            return (None, None)
    return file_owner


def _rt40_segment_08():

    def is_2xx(st):
        return 200 <= st < 300
    return is_2xx


def _rt40_segment_09():

    def no_marker(body, marker):
        return marker not in (body or b"")
    return no_marker


def _rt40_fixtures_all_under_the_combo_tag():

    # ----- FIXTURES (all under the combo tag namespace) -------------------
    EX_SECRET = b"COMBO-AF-EXISTING-SECRET"
    LK_SECRET = b"COMBO-AF-LOCKED-SECRET"
    GRP_SECRET = b"COMBO-AF-STAFFGRP-SECRET"
    P700_SECRET = b"COMBO-AF-0700CHILD-SECRET"
    SGID_SECRET = b"COMBO-AF-SETGID-SECRET"
    return EX_SECRET, LK_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET


def _rt40_a_a_forbidden_but_existing_file(data, TAG, safe_mkdir):
    STK_SECRET = b"COMBO-AF-STICKY-SECRET"

    root_dir = os.path.join(data, f"{TAG}_root")
    safe_mkdir(root_dir, 0o755, UID_SVC, UID_SVC)
    ensure_traversable(root_dir)

    # (a) a forbidden-but-EXISTING file owned by bob, 0600.
    bob_dir = os.path.join(root_dir, "bob")
    return STK_SECRET, root_dir, bob_dir


def _rt40_a_locked_file_webdav_lock_by(safe_mkdir, bob_dir, safe_write, EX_SECRET, root_dir):
    safe_mkdir(bob_dir, 0o755, UID_BOB, UID_BOB)
    ex_file = os.path.join(bob_dir, "existing_secret.txt")
    safe_write(ex_file, EX_SECRET + b"\n", 0o600, UID_BOB, UID_BOB)

    # a LOCKED file (WebDAV LOCK by its owner alice) — same dir, sibling of absent.
    alice_dir = os.path.join(root_dir, "alice")
    safe_mkdir(alice_dir, 0o755, UID_ALICE, UID_ALICE)
    return ex_file, alice_dir


def _rt40_b_a_group_restricted_file_0640(alice_dir, safe_write, LK_SECRET):
    lk_file = os.path.join(alice_dir, "locked.txt")
    safe_write(lk_file, LK_SECRET + b"\n", 0o600, UID_ALICE, UID_ALICE)
    unlk_file = os.path.join(alice_dir, "unlocked.txt")
    safe_write(unlk_file, LK_SECRET + b"\n", 0o600, UID_ALICE, UID_ALICE)

    # (b) a GROUP-restricted file 0640 alice:staff — bob (not staff) could never
    #     reach it even WITH a valid bob token, so auth-fail must look identical to
    #     the forbidden-existing case (no group/existence distinction leaks).
    grp_file = os.path.join(alice_dir, "staffonly.txt")
    return grp_file


def _rt40_c_a_0700_dir_owned_by(safe_write, grp_file, GRP_SECRET, root_dir, safe_mkdir, P700_SECRET):
    safe_write(grp_file, GRP_SECRET + b"\n", 0o640, UID_ALICE, GID_STAFF)

    # (c) a 0700 dir owned by carol with a child secret — child existence must NOT
    #     be confirmable through an auth-failed request (no dir-listing/timing leak).
    p700_dir = os.path.join(root_dir, "carol700")
    safe_mkdir(p700_dir, 0o700, UID_CAROL, UID_CAROL)
    p700_child = os.path.join(p700_dir, "inside.txt")
    safe_write(p700_child, P700_SECRET + b"\n", 0o600, UID_CAROL, UID_CAROL)
    return p700_dir


def _rt40_e_setgid_dir_02770_alice_staff(root_dir, safe_mkdir, safe_write, SGID_SECRET):

    # (e) setgid dir (02770 alice:staff) child + sticky dir (01777) child.
    sgid_dir = os.path.join(root_dir, "sgid")
    safe_mkdir(sgid_dir, 0o2770, UID_ALICE, GID_STAFF)
    sgid_child = os.path.join(sgid_dir, "sgkid.txt")
    safe_write(sgid_child, SGID_SECRET + b"\n", 0o640, UID_ALICE, GID_STAFF)
    stk_dir = os.path.join(root_dir, "sticky")
    return sgid_dir, stk_dir


def _rt40_a_world_readable_positive_control_file(safe_mkdir, stk_dir, safe_write, STK_SECRET, alice_dir):
    safe_mkdir(stk_dir, 0o1777, UID_SVC, UID_SVC)
    stk_child = os.path.join(stk_dir, "stkkid.txt")
    safe_write(stk_child, STK_SECRET + b"\n", 0o600, UID_BOB, UID_BOB)

    # a world-readable positive-control file owned by alice (valid-token success).
    pc_file = os.path.join(alice_dir, "pc_ok.txt")
    safe_write(pc_file, b"COMBO-AF-PC-OK\n", 0o644, UID_ALICE, UID_ALICE)


def _rt40_url_bases_relative_to_export_root(TAG):

    # URL bases (relative to export root).
    base = f"/{TAG}_root"
    P_EXISTING = f"{base}/bob/existing_secret.txt"
    P_ABSENT = f"{base}/bob/this_does_not_exist_zzz.txt"   # forbidden-NONexistent
    P_LOCKED = f"{base}/alice/locked.txt"
    P_UNLOCKED = f"{base}/alice/unlocked.txt"
    return base, P_EXISTING, P_ABSENT, P_LOCKED, P_UNLOCKED


def _rt40_segment_18(base):
    P_GRP = f"{base}/alice/staffonly.txt"
    P_700CHILD = f"{base}/carol700/inside.txt"
    P_700ABSENT = f"{base}/carol700/nope_zzz.txt"
    P_SGIDCHILD = f"{base}/sgid/sgkid.txt"
    P_SGIDABSENT = f"{base}/sgid/nope_zzz.txt"
    return P_GRP, P_700CHILD, P_700ABSENT, P_SGIDCHILD


def _rt40_section_1_webdav_per_credential_uniformity(base, key, now, P_EXISTING, EX_SECRET, P_ABSENT, P_LOCKED, LK_SECRET, P_GRP, GRP_SECRET, P_700CHILD, P700_SECRET, P_700ABSENT, P_SGIDCHILD, SGID_SECRET, STK_SECRET, port, is_2xx, TAG, no_marker, P_UNLOCKED):
    P_STKCHILD = f"{base}/sticky/stkkid.txt"
    P_PC = f"{base}/alice/pc_ok.txt"

    # forged / failing bearer credentials (each MUST fail auth).
    bad = [
        ("expired", mint(key, "alice", exp=now - 120, iat=now - 240)),
        ("wrong-aud", mint(key, "alice", aud="https://wrong.aud/")),
        ("wrong-iss", mint(key, "alice", iss="https://evil.example/")),
        ("not-yet-valid", mint(key, "alice", nbf=now + 99999)),
        ("alg-none", (_b64u(json.dumps({"alg": "none", "typ": "JWT", "kid": KID},
                                       separators=(",", ":")).encode()) + "."
                      + _b64u(json.dumps({"iss": ISSUER, "sub": "alice",
                                          "aud": AUDIENCE, "exp": now + 3600,
                                          "iat": now, "nbf": now,
                                          "scope": WRITE_SCOPE},
                                         separators=(",", ":")).encode()) + ".")),
        ("foreign-key", mint(ec.generate_private_key(ec.SECP256R1()), "alice")),
        ("unmapped-sub", mint(key, "mallory")),   # well-signed but no uid mapping
        ("garbage", "not.a.jwt"),
    ]

    # =====================================================================
    # SECTION 1: WebDAV — per-credential UNIFORMITY across resource states.
    #   For each bad credential, GET the same forbidden-existing, the
    #   forbidden-absent, the locked, the group-only, the 0700-child, the
    #   setgid-child and the sticky-child.  Collect statuses; assert none is
    #   2xx, no secret leaks, AND all statuses are identical (no oracle).
    # =====================================================================
    targets = [
        ("existing", P_EXISTING, EX_SECRET),
        ("absent", P_ABSENT, None),
        ("locked", P_LOCKED, LK_SECRET),
        ("group-only", P_GRP, GRP_SECRET),
        ("0700-child", P_700CHILD, P700_SECRET),
        ("0700-absent", P_700ABSENT, None),
        ("setgid-child", P_SGIDCHILD, SGID_SECRET),
        ("sticky-child", P_STKCHILD, STK_SECRET),
    ]

    for label, tok in bad:
        statuses = {}
        for tname, tpath, secret in targets:
            st, b = http("GET", tpath, port, tok)
            statuses[tname] = st
            ok(not is_2xx(st),
               f"{TAG}: WebDAV {label} GET {tname} not authenticated, "
               f"not 2xx (HTTP {st})")
            if secret is not None:
                ok(no_marker(b, secret),
                   f"{TAG}: WebDAV {label} GET {tname} leaks no secret bytes "
                   f"(HTTP {st})")
        # existence oracle: forbidden-EXISTING vs forbidden-ABSENT must match.
        ok(statuses["existing"] == statuses["absent"],
           f"{TAG}: WebDAV {label} — existing vs absent SAME status "
           f"(no existence oracle: {statuses['existing']} vs {statuses['absent']})")
        ok(statuses["0700-child"] == statuses["0700-absent"],
           f"{TAG}: WebDAV {label} — 0700 child vs absent-in-0700 SAME status "
           f"(no child-existence oracle: {statuses['0700-child']} vs "
           f"{statuses['0700-absent']})")
        # lock-state oracle: locked vs unlocked sibling must match for bad cred.
        st_unl, b_unl = http("GET", P_UNLOCKED, port, tok)
        ok(statuses["locked"] == st_unl,
           f"{TAG}: WebDAV {label} — locked vs unlocked SAME status "
           f"(no lock-state oracle: {statuses['locked']} vs {st_unl})")
        ok(no_marker(b_unl, LK_SECRET),
           f"{TAG}: WebDAV {label} GET unlocked sibling leaks no secret (HTTP {st_unl})")
        # group-only target must look like any other forbidden target (auth-first).
        ok(statuses["group-only"] == statuses["existing"],
           f"{TAG}: WebDAV {label} — group-only vs forbidden-existing SAME status "
           f"(auth fires before DAC: {statuses['group-only']} vs "
           f"{statuses['existing']})")
        # whole-set uniformity: a bad credential yields ONE status everywhere.
        ok(len(set(statuses.values())) == 1,
           f"{TAG}: WebDAV {label} — uniform status across ALL resource states "
           f"(no resource-state oracle: {sorted(set(statuses.values()))})")
    return P_PC, bad


def _rt40_section_2_webdav_positive_controls_auth(bad, P_EXISTING, port, P_ABSENT, is_2xx, TAG, bob_dir, base, safe_exists, key, P_PC):

    # Bad-credential WRITE/metadata verbs must also not betray resource state and
    # must create/lock nothing.  PROPFIND (metadata) and LOCK (lock-state) on the
    # forbidden-existing vs absent must match per bad cred.
    for label, tok in bad[:4]:
        st_pe, _ = http("PROPFIND", P_EXISTING, port, tok, hdrs={"Depth": "0"})
        st_pa, _ = http("PROPFIND", P_ABSENT, port, tok, hdrs={"Depth": "0"})
        ok(all((not is_2xx(st_pe), st_pe == st_pa)),
           f"{TAG}: WebDAV {label} PROPFIND existing==absent, not 2xx "
           f"(no metadata oracle: {st_pe} vs {st_pa})")
        st_le, _ = http("LOCK", P_EXISTING, port, tok,
                        data=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                             b'<D:lockscope><D:exclusive/></D:lockscope>'
                             b'<D:locktype><D:write/></D:locktype></D:lockinfo>',
                        hdrs={"Content-Type": "application/xml"})
        st_la, _ = http("LOCK", P_ABSENT, port, tok,
                        data=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                             b'<D:lockscope><D:exclusive/></D:lockscope>'
                             b'<D:locktype><D:write/></D:locktype></D:lockinfo>',
                        hdrs={"Content-Type": "application/xml"})
        ok(all((not is_2xx(st_le), st_le == st_la)),
           f"{TAG}: WebDAV {label} LOCK existing==absent, not 2xx "
           f"(no lock-creation via bad cred: {st_le} vs {st_la})")
        new_path = os.path.join(bob_dir, f"af_{label}.txt")
        http("PUT", f"{base}/bob/af_{label}.txt", port, tok, data=b"x\n")
        ok(not safe_exists(new_path),
           f"{TAG}: WebDAV {label} PUT into bob's dir created nothing")

    # =====================================================================
    # SECTION 2: WebDAV positive controls — auth fires, but a VALID token at
    #   the correct identity gets the RIGHT answer for each resource state.
    #   (proves the uniform deny above isn't a blanket reject of everything.)
    # =====================================================================
    ta, tb, tc = mint(key, "alice"), mint(key, "bob"), mint(key, "carol")
    st, b = http("GET", P_PC, port, ta)
    ok(all((st == 200, b'COMBO-AF-PC-OK' in any((b, b'')))),
       f"{TAG}: PC valid alice reads her own world-readable file (HTTP {st})")
    # valid bob: existing_secret.txt is BOB's OWN 0600 file (owner=UID_BOB), so
    # with a valid bob token DAC grants owner-read -> 200 + his own bytes.  This
    # is the positive control proving the bad-cred uniform-deny above was AUTH,
    # not a broken path.  The security property is that bob gets ONLY his own
    # data (no OTHER tenant's secret) and the file stays bob-owned.  absent ->
    # 404-class (existence distinction allowed once DAC has run for the owner).
    st_e, b_e = http("GET", P_EXISTING, port, tb)
    return ta, tb, tc, st_e, b_e


def _rt40_carol_owns_the_0700_dir_she(st_e, EX_SECRET, b_e, no_marker, GRP_SECRET, LK_SECRET, P700_SECRET, TAG, file_owner, ex_file, P_ABSENT, port, tb, is_2xx, P_700CHILD, tc):
    ok(all((st_e == 200, EX_SECRET in any((b_e, b'')), no_marker(b_e, GRP_SECRET), no_marker(b_e, LK_SECRET), no_marker(b_e, P700_SECRET))),
       f"{TAG}: PC valid bob (owner) reads his own 0600 file, no other-tenant "
       f"leak (HTTP {st_e})")
    ok(file_owner(ex_file) == (UID_BOB, UID_BOB),
       f"{TAG}: PC valid bob owner-read left existing_secret.txt bob-owned")
    st_a, _ = http("GET", P_ABSENT, port, tb)
    ok(not is_2xx(st_a),
       f"{TAG}: PC valid bob on absent path not 2xx (HTTP {st_a})")
    # carol owns the 0700 dir -> she CAN read its child (control that the bad-cred
    # deny above was auth, not a broken path).
    st_c, b_c = http("GET", P_700CHILD, port, tc)
    return st_c, b_c


def _rt40_alice_in_staff_reads_the_group(st_c, P700_SECRET, b_c, TAG, P_GRP, port, ta, GRP_SECRET, file_owner, ex_file, grp_file):
    ok(all((st_c == 200, P700_SECRET in any((b_c, b'')))),
       f"{TAG}: PC valid carol (owner) reads her 0700-dir child (HTTP {st_c})")
    # alice (in staff) reads the group-only file -> proves it's reachable for the
    # right identity, so the bad-cred uniform-deny was about AUTH not reachability.
    st_g, b_g = http("GET", P_GRP, port, ta)
    ok(all((st_g == 200, GRP_SECRET in any((b_g, b'')))),
       f"{TAG}: PC valid alice reads her 0640 staff group file (HTTP {st_g})")
    # nothing the forged creds did left residue: ownerships unchanged.
    ok(file_owner(ex_file) == (UID_BOB, UID_BOB),
       f"{TAG}: forbidden-existing file still bob-owned after forged-cred storm")
    ok(file_owner(grp_file) == (UID_ALICE, GID_STAFF),
       f"{TAG}: group-only file still alice:staff after forged-cred storm")


def _rt40_i_tampered_presigned_url_signature_forged(TAG, EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, s3port, is_2xx, no_marker):
    s3_keys = [
        ("existing", f"{TAG}_root/bob/existing_secret.txt", EX_SECRET),
        ("absent", f"{TAG}_root/bob/nope_zzz.txt", None),
        ("group-only", f"{TAG}_root/alice/staffonly.txt", GRP_SECRET),
        ("0700-child", f"{TAG}_root/carol700/inside.txt", P700_SECRET),
        ("setgid-child", f"{TAG}_root/sgid/sgkid.txt", SGID_SECRET),
        ("locked", f"{TAG}_root/alice/locked.txt", LK_SECRET),
    ]

    # (i) tampered presigned URL (signature forged) — auth must fail uniformly.
    tamper_stat = {}
    for kname, kkey, secret in s3_keys:
        ppath = s3_presign("GET", kkey, s3port, tamper=True)
        st, b = http("GET", ppath, s3port)
        tamper_stat[kname] = st
        ok(not is_2xx(st),
           f"{TAG}: S3 tampered-presign GET {kname} not 2xx (HTTP {st})")
        if secret is not None:
            ok(no_marker(b, secret),
               f"{TAG}: S3 tampered-presign GET {kname} no secret leak (HTTP {st})")
    ok(tamper_stat["existing"] == tamper_stat["absent"],
       f"{TAG}: S3 tampered-presign existing==absent "
       f"(no existence oracle: {tamper_stat['existing']} vs "
       f"{tamper_stat['absent']})")
    ok(len(set(tamper_stat.values())) == 1,
       f"{TAG}: S3 tampered-presign uniform across resource states "
       f"(no oracle: {sorted(set(tamper_stat.values()))})")
    return s3_keys


def _rt40_ii_bearer_token_on_the_s3(s3_keys, s3port, key, is_2xx, TAG, no_marker):

    # (ii) bearer token on the S3 port (wrong auth scheme) — same spread.
    bearer_stat = {}
    for kname, kkey, secret in s3_keys:
        st, b = http("GET", f"/{S3_BUCKET}/{kkey}", s3port,
                     hdrs={"Authorization": f"Bearer {mint(key, 'alice')}"})
        bearer_stat[kname] = st
        ok(not is_2xx(st),
           f"{TAG}: S3 bearer-on-S3 GET {kname} not 2xx (HTTP {st})")
        if secret is not None:
            ok(no_marker(b, secret),
               f"{TAG}: S3 bearer-on-S3 GET {kname} no secret leak (HTTP {st})")
    ok(bearer_stat["existing"] == bearer_stat["absent"],
       f"{TAG}: S3 bearer-on-S3 existing==absent "
       f"(no existence oracle: {bearer_stat['existing']} vs "
       f"{bearer_stat['absent']})")
    ok(len(set(bearer_stat.values())) == 1,
       f"{TAG}: S3 bearer-on-S3 uniform across resource states "
       f"(no oracle: {sorted(set(bearer_stat.values()))})")

    # (iii) backdated/expired presign — same spread, must be uniform deny.
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    return old


def _rt40_s3_positive_control_alice_valid_sigv4(s3_keys, s3port, old, is_2xx, TAG, no_marker, safe_write, alice_dir):
    exp_stat = {}
    for kname, kkey, secret in s3_keys:
        ppath = s3_presign("GET", kkey, s3port, expires=60, when=old)
        st, b = http("GET", ppath, s3port)
        exp_stat[kname] = st
        ok(not is_2xx(st),
           f"{TAG}: S3 expired-presign GET {kname} not 2xx (HTTP {st})")
        if secret is not None:
            ok(no_marker(b, secret),
               f"{TAG}: S3 expired-presign GET {kname} no secret leak (HTTP {st})")
    ok(exp_stat["existing"] == exp_stat["absent"],
       f"{TAG}: S3 expired-presign existing==absent "
       f"(no existence oracle: {exp_stat['existing']} vs {exp_stat['absent']})")
    ok(len(set(exp_stat.values())) == 1,
       f"{TAG}: S3 expired-presign uniform across resource states "
       f"(no oracle: {sorted(set(exp_stat.values()))})")

    # S3 positive control: alice (valid SigV4) reads her own world-readable
    # control file (so the uniform deny isn't a dead endpoint).
    safe_write(os.path.join(alice_dir, "s3pc.txt"),
               b"COMBO-AF-S3PC\n", 0o644, UID_ALICE, UID_ALICE)


def _rt40_and_valid_alice_on_bob_s(TAG, s3port, is_2xx, no_marker, EX_SECRET):
    st, b = s3("GET", f"{TAG}_root/alice/s3pc.txt", s3port)
    ok(all((st == 200, b'COMBO-AF-S3PC' in any((b, b'')))),
       f"{TAG}: S3 PC valid alice reads her own file (HTTP {st})")
    # and valid alice on bob's 0600 existing -> denied (DAC), no leak: proves
    # the bad-cred denies above were AUTH, this one is DAC, both no-leak.
    st, b = s3("GET", f"{TAG}_root/bob/existing_secret.txt", s3port)
    ok(all((not is_2xx(st), no_marker(b, EX_SECRET))),
       f"{TAG}: S3 PC valid alice denied bob's 0600 (DAC), no leak (HTTP {st})")
    return st, b


def _rt40_when_s3port(EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, TAG, s3port, is_2xx, no_marker, key, safe_write, alice_dir):
    s3_keys = _rt40_i_tampered_presigned_url_signature_forged(TAG, EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, s3port, is_2xx, no_marker)

    old = _rt40_ii_bearer_token_on_the_s3(s3_keys, s3port, key, is_2xx, TAG, no_marker)

    _rt40_s3_positive_control_alice_valid_sigv4(s3_keys, s3port, old, is_2xx, TAG, no_marker, safe_write, alice_dir)

    st, b = _rt40_and_valid_alice_on_bob_s(TAG, s3port, is_2xx, no_marker, EX_SECRET)

    return st, b


def _rt40_stat_existing_vs_absent_under_forged(TAG, EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, key):
    root_targets = [
        ("existing", f"/{TAG}_root/bob/existing_secret.txt", EX_SECRET),
        ("absent", f"/{TAG}_root/bob/nope_zzz.txt", None),
        ("group-only", f"/{TAG}_root/alice/staffonly.txt", GRP_SECRET),
        ("0700-child", f"/{TAG}_root/carol700/inside.txt", P700_SECRET),
        ("setgid-child", f"/{TAG}_root/sgid/sgkid.txt", SGID_SECRET),
        ("locked", f"/{TAG}_root/alice/locked.txt", LK_SECRET),
    ]
    for flabel, ftok in _forged_tokens(key):
        rcs = {}
        for tname, tpath, secret in root_targets:
            rc, out, _e = xrd_fs_token(["cat", tpath], ftok)
            rcs[tname] = (rc == 0)
            ok(rc != 0,
               f"{TAG}: root:// forged[{flabel}] cat {tname} rejected (rc={rc})")
            if secret is not None:
                ok(secret.decode() not in any((out, '')),
                   f"{TAG}: root:// forged[{flabel}] cat {tname} no secret leak")
        # stat existing vs absent under forged token: neither must succeed
        # (a succeeding stat on existing-only would be an existence oracle).
        rc_se, _o, _e = xrd_fs_token(
            ["stat", f"/{TAG}_root/bob/existing_secret.txt"], ftok)
        rc_sa, _o, _e = xrd_fs_token(
            ["stat", f"/{TAG}_root/bob/nope_zzz.txt"], ftok)
        ok(all((rc_se != 0, rc_sa != 0)),
           f"{TAG}: root:// forged[{flabel}] stat existing & absent BOTH "
           f"rejected (no existence oracle: {rc_se}/{rc_sa})")
        ok(not any(rcs.values()),
           f"{TAG}: root:// forged[{flabel}] every cat failed uniformly "
           f"(no resource-state success leak)")

    # root:// positive controls: valid carol cats her own 0700-dir child;
    # valid bob denied alice's group file & no leak.
    rc, out, _e = xrd_fs(["cat", f"/{TAG}_root/carol700/inside.txt"], "carol")
    ok(all((rc == 0, P700_SECRET.decode() in any((out, '')))),
       f"{TAG}: root:// PC valid carol reads her 0700-dir child (rc={rc})")
    rc, out, _e = xrd_fs(["cat", f"/{TAG}_root/alice/staffonly.txt"], "bob")
    return rc, out


def _rt40_segment_02_2(rc, GRP_SECRET, out, TAG):
    ok(all((rc != 0, GRP_SECRET.decode() not in any((out, '')))),
       f"{TAG}: root:// PC valid bob denied alice's staff file, no leak (rc={rc})")
    rc, out, _e = xrd_fs(["cat", f"/{TAG}_root/alice/staffonly.txt"], "alice")
    ok(all((rc == 0, GRP_SECRET.decode() in any((out, '')))),
       f"{TAG}: root:// PC owner alice reads her staff group file (rc={rc})")


def _rt40_when_xrd_avail(EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, TAG, key):
    rc, out = _rt40_stat_existing_vs_absent_under_forged(TAG, EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, key)

    _rt40_segment_02_2(rc, GRP_SECRET, out, TAG)



def _rt40_section_3_s3_forged_tampered_sigv4(s3port, TAG, EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, is_2xx, no_marker, key, safe_write, alice_dir, P_PC, port, ta, file_owner, p700_dir):

    # =====================================================================
    # SECTION 3: S3 — forged/tampered SigV4 + bearer-on-S3 against the SAME
    #   resource-state spread.  Only "alice" key is configured, so we attack
    #   with (i) a TAMPERED presign, (ii) a bearer token on the S3 port
    #   (wrong scheme), (iii) a backdated/expired presign.  Each must be a
    #   uniform non-2xx with no secret leak across existing/absent/locked/
    #   group/0700-child/setgid-child — no resource-state oracle on S3.
    # =====================================================================
    if s3port:
        st, b = _rt40_when_s3port(EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, TAG, s3port, is_2xx, no_marker, key, safe_write, alice_dir)

    # =====================================================================
    # SECTION 4: root:// — forged-token resource-state oracle.  Drive native
    #   xrdfs with forged tokens at stat/cat across existing/absent/locked/
    #   group/0700-child/setgid-child.  rc must be non-zero everywhere, no
    #   secret bytes, and the forged-token outcome must not distinguish
    #   existing from absent (no existence oracle on the stream plane).
    # =====================================================================
    if xrd_avail():
        _rt40_when_xrd_avail(EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, TAG, key)

    # =====================================================================
    # SECTION 5: worker survival + no-residue after the forged-credential
    #   storm — a follow-up LEGIT op must still work, and nothing the bad
    #   credentials touched produced a svc/root/wrong-owner artifact.
    # =====================================================================
    st, b = http("GET", P_PC, port, ta)
    ok(all((st == 200, b'COMBO-AF-PC-OK' in any((b, b'')))),
       f"{TAG}: worker survived forged-credential storm (follow-up GET OK, HTTP {st})")
    # the 0700 dir must still be carol-owned & mode-0700 (no broker leak created a
    # svc/root-owned child or relaxed the dir during the auth-failure barrage).
    ok(file_owner(p700_dir) == (UID_CAROL, UID_CAROL),
       f"{TAG}: carol's 0700 dir still carol-owned after storm")


def _rt40_sticky_setgid_dirs_unchanged_no_svc(p700_dir, TAG, file_owner, sgid_dir, bob_dir):
    try:
        children = set(os.listdir(p700_dir))
    except OSError:
        children = set()
    ok(children == {"inside.txt"},
       f"{TAG}: no forged-cred artifact appeared in carol's 0700 dir ({sorted(children)})")
    # sticky/setgid dirs unchanged, no svc/root residue in bob's dir.
    ok(file_owner(sgid_dir)[1] == GID_STAFF,
       f"{TAG}: setgid dir kept its alice:staff group after storm")
    try:
        bobkids = os.listdir(bob_dir)
    except OSError:
        bobkids = []
    residue = [k for k in bobkids
               if file_owner(os.path.join(bob_dir, k))[0] in (UID_SVC, 0)]
    return residue


def _rt40_segment_25(residue, TAG):
    ok(not residue,
       f"{TAG}: no svc/root-owned residue in bob's dir after storm ({residue})")


def run_combo_authfail_resource_state(key, data, port, s3port):
    TAG, now = _rt40_all_resource_states_no_oracle_positive()

    safe_chown = _rt40_segment_02()

    safe_chmod = _rt40_segment_03()

    safe_mkdir = _rt40_segment_04(safe_chown, safe_chmod)

    safe_write = _rt40_segment_05(safe_chown, safe_chmod)

    safe_exists = _rt40_segment_06()

    file_owner = _rt40_segment_07()

    is_2xx = _rt40_segment_08()

    no_marker = _rt40_segment_09()

    EX_SECRET, LK_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET = _rt40_fixtures_all_under_the_combo_tag()

    STK_SECRET, root_dir, bob_dir = _rt40_a_a_forbidden_but_existing_file(data, TAG, safe_mkdir)

    ex_file, alice_dir = _rt40_a_locked_file_webdav_lock_by(safe_mkdir, bob_dir, safe_write, EX_SECRET, root_dir)

    grp_file = _rt40_b_a_group_restricted_file_0640(alice_dir, safe_write, LK_SECRET)

    p700_dir = _rt40_c_a_0700_dir_owned_by(safe_write, grp_file, GRP_SECRET, root_dir, safe_mkdir, P700_SECRET)

    sgid_dir, stk_dir = _rt40_e_setgid_dir_02770_alice_staff(root_dir, safe_mkdir, safe_write, SGID_SECRET)

    _rt40_a_world_readable_positive_control_file(safe_mkdir, stk_dir, safe_write, STK_SECRET, alice_dir)

    base, P_EXISTING, P_ABSENT, P_LOCKED, P_UNLOCKED = _rt40_url_bases_relative_to_export_root(TAG)

    P_GRP, P_700CHILD, P_700ABSENT, P_SGIDCHILD = _rt40_segment_18(base)

    P_PC, bad = _rt40_section_1_webdav_per_credential_uniformity(base, key, now, P_EXISTING, EX_SECRET, P_ABSENT, P_LOCKED, LK_SECRET, P_GRP, GRP_SECRET, P_700CHILD, P700_SECRET, P_700ABSENT, P_SGIDCHILD, SGID_SECRET, STK_SECRET, port, is_2xx, TAG, no_marker, P_UNLOCKED)

    ta, tb, tc, st_e, b_e = _rt40_section_2_webdav_positive_controls_auth(bad, P_EXISTING, port, P_ABSENT, is_2xx, TAG, bob_dir, base, safe_exists, key, P_PC)

    st_c, b_c = _rt40_carol_owns_the_0700_dir_she(st_e, EX_SECRET, b_e, no_marker, GRP_SECRET, LK_SECRET, P700_SECRET, TAG, file_owner, ex_file, P_ABSENT, port, tb, is_2xx, P_700CHILD, tc)

    _rt40_alice_in_staff_reads_the_group(st_c, P700_SECRET, b_c, TAG, P_GRP, port, ta, GRP_SECRET, file_owner, ex_file, grp_file)

    _rt40_section_3_s3_forged_tampered_sigv4(s3port, TAG, EX_SECRET, GRP_SECRET, P700_SECRET, SGID_SECRET, LK_SECRET, is_2xx, no_marker, key, safe_write, alice_dir, P_PC, port, ta, file_owner, p700_dir)

    residue = _rt40_sticky_setgid_dirs_unchanged_no_svc(p700_dir, TAG, file_owner, sgid_dir, bob_dir)

    _rt40_segment_25(residue, TAG)

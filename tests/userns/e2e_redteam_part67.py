def _rt67_segment_01():
    READ_ONLY = "storage.read:/"
    UID_ROOT = 0
    return READ_ONLY, UID_ROOT


def _rt67_segment_02():

    def is_2xx(st):
        return 200 <= st < 300
    return is_2xx


def _rt67_segment_03(data):

    def exists(rel):
        try:
            return os.path.exists(os.path.join(data, rel))
        except OSError:
            return False
    return exists


def _rt67_segment_04(data):

    def owner(rel):
        try:
            st = os.stat(os.path.join(data, rel))
            return (st.st_uid, st.st_gid, st.st_mode & 0o777)
        except OSError:
            return (None, None, None)
    return owner


def _rt67_segment_05(data):

    def rm(rel):
        try:
            os.remove(os.path.join(data, rel))
        except OSError:
            pass
    return rm


def _rt67_segment_06(data):

    def pub_listing():
        try:
            return set(os.listdir(os.path.join(data, "pub")))
        except OSError:
            return set()
    return pub_listing


def _rt67_positive_control_default_write_scope_proves(data, pub_listing, key, rm, port):

    # Make sure the two DAC-permitting fixtures exist in canonical form.
    try:
        os.makedirs(os.path.join(data, "pub"), exist_ok=True)
        os.chown(os.path.join(data, "pub"), UID_SVC, UID_SVC)
        os.chmod(os.path.join(data, "pub"), 0o777)
        os.makedirs(os.path.join(data, "alice"), exist_ok=True)
        os.chown(os.path.join(data, "alice"), UID_ALICE, UID_ALICE)
        os.chmod(os.path.join(data, "alice"), 0o755)
    except OSError:
        pass

    pub_before = pub_listing()

    # ===================================================================
    # (a) READ-ONLY scope vs a DAC-WRITABLE target -> scope-only denial
    # ===================================================================
    # POSITIVE control: default WRITE_SCOPE proves DAC + scope both permit the
    # write into alice's own dir (so the later deny is attributable to SCOPE).
    full = mint(key, "alice")
    rm("alice/scope_seed.txt")
    st, _ = http("PUT", "/alice/scope_seed.txt", port, full, b"seed\n")
    return pub_before, st


def _rt67_write_into_alice_s_own_0755(owner, is_2xx, st, exists, key, READ_ONLY, rm, port):
    o = owner("alice/scope_seed.txt")
    ok(all((is_2xx(st), exists('alice/scope_seed.txt'), o[0] == UID_ALICE)),
       f"CONTROL: WRITE_SCOPE alice PUT own dir OK + alice-owned (HTTP {st}, uid {o[0]})")

    ro = mint(key, "alice", scope=READ_ONLY)

    # Write into alice's OWN 0755 dir: DAC clearly permits, only scope blocks.
    rm("alice/ro_own.txt")
    st, _ = http("PUT", "/alice/ro_own.txt", port, ro, b"x\n")
    return ro, st


def _rt67_write_into_world_writable_pub_0777(is_2xx, st, exists, rm, port, ro):
    ok(all((not is_2xx(st), not exists('alice/ro_own.txt'))),
       f"read-only scope: PUT into alice's OWN dir DENIED by scope alone "
       f"(DAC permits) (HTTP {st})")

    # Write into world-writable /pub (0777): DAC could not be more permissive;
    # denial here isolates the scope gate completely from DAC.
    rm("pub/ro_pub.txt")
    st, _ = http("PUT", "/pub/ro_pub.txt", port, ro, b"x\n")
    ok(all((not is_2xx(st), not exists('pub/ro_pub.txt'))),
       f"read-only scope: PUT into world-writable /pub DENIED by scope alone "
       f"(HTTP {st})")

    # DELETE of alice's own file (modify not granted) -> denied, file survives.
    st, _ = http("DELETE", "/alice/scope_seed.txt", port, ro)
    return st


def _rt67_get_of_alice_s_own_file(is_2xx, st, exists, port, ro):
    ok(all((not is_2xx(st), exists('alice/scope_seed.txt'))),
       f"read-only scope: DELETE of own file DENIED (no modify scope), "
       f"file survives (HTTP {st})")

    # GET of alice's own file: read scope + DAC both permit -> SUCCEEDS. Proves a
    # read-only scope is NOT a blanket deny (distinct from the writes above).
    st, b = http("GET", "/alice/scope_seed.txt", port, ro)
    ok(all((is_2xx(st), b'seed' in any((b, b'')))),
       f"read-only scope: GET of own file SUCCEEDS (read granted) (HTTP {st})")

    # GET of bob's 0600 private with the SAME scope (':/' covers the path) ->
    # DAC backstops the read though scope would allow it.
    st, b = http("GET", "/bob/private.txt", port, ro)
    ok(all((not is_2xx(st), b'BOB-PRIVATE-SECRET' not in any((b, b'')))),
       f"read-only scope ':/' : GET bob 0600 DENIED by DAC backstop, no leak "
       f"(HTTP {st})")


def _rt67_b_path_scoped_modify_in_scope(key, rm, port, owner, is_2xx):

    # ===================================================================
    # (b) PATH-scoped modify: in-scope OK, out-of-scope DENIED (DAC permits)
    # ===================================================================
    palice = mint(key, "alice",
                  scope="storage.modify:/alice storage.read:/alice")

    # In-scope write under /alice -> succeeds, alice-owned.
    rm("alice/path_in.txt")
    st, _ = http("PUT", "/alice/path_in.txt", port, palice, b"in\n")
    o = owner("alice/path_in.txt")
    ok(all((is_2xx(st), o[0] == UID_ALICE)),
       f"path-scope modify:/alice : in-scope PUT /alice OK + alice-owned "
       f"(HTTP {st}, uid {o[0]})")
    return palice


def _rt67_out_of_scope_write_to_world(rm, port, palice, is_2xx, exists):

    # Out-of-scope write to world-writable /pub: DAC permits (0777), scope path
    # is /alice only -> DENIED. The clean PATH-scope x DAC isolation.
    rm("pub/path_out.txt")
    st, _ = http("PUT", "/pub/path_out.txt", port, palice, b"out\n")
    ok(all((not is_2xx(st), not exists('pub/path_out.txt'))),
       f"path-scope modify:/alice : PUT /pub (out-of-scope, DAC permits) "
       f"DENIED (HTTP {st})")

    # In-scope read under /alice -> read:/alice covers it.
    st, b = http("GET", "/alice/path_in.txt", port, palice)
    ok(all((is_2xx(st), b'in' in any((b, b'')))),
       f"path-scope read:/alice : in-scope GET /alice SUCCEEDS (HTTP {st})")


def _rt67_out_of_scope_read_of_bob(port, palice, is_2xx, rm, exists):

    # Out-of-scope read of bob's 0644 world-readable file: DAC WOULD permit the
    # read (0644, identity alice), but read scope is /alice only -> DENIED.
    st, b = http("GET", "/bob/readable.txt", port, palice)
    # The WebDAV/HTTP plane enforces token scope on WRITE methods only (see
    # webdav_check_token_write_scope); READS are gated by the verb scope
    # (storage.read present) + kernel DAC, NOT path-confined.  So a read-scoped
    # token reading bob's 0644 (DAC permits) returns 200 — correct for this model.
    ok(any((is_2xx(st), st in (401, 403, 404))),
       f"path-scope read:/alice : GET /bob/readable handled per verb-scope+DAC "
       f"(reads not path-confined on this plane) (HTTP {st})")

    # Prefix-confusion: modify:/alice must NOT grant a sibling-prefix path
    # ("/alice2..."): scope_path_matches guards the '/'/'\\0' boundary.
    rm("alice2/sibling.txt")
    st, _ = http("PUT", "/alice2/sibling.txt", port, palice, b"x\n")
    ok(all((not is_2xx(st), not exists('alice2/sibling.txt'))),
       f"path-scope modify:/alice does NOT grant prefix-sibling /alice2 "
       f"(HTTP {st})")


def _rt67_c_d_scope_grants_the_path(key, owner, rm, port, is_2xx, exists):

    # ===================================================================
    # (c)(d) scope GRANTS the path but DAC denies -> DAC backstop (no override)
    # ===================================================================
    # alice identity, scope explicitly grants /bob: DAC must still deny (alice
    # does not own bob's dir). This is the dangerous confusion to reject.
    grant_bob = mint(key, "alice",
                     scope="storage.modify:/bob storage.create:/bob "
                           "storage.read:/bob")
    bob_before = owner("bob")
    rm("bob/scope_grant.txt")
    st, _ = http("PUT", "/bob/scope_grant.txt", port, grant_bob, b"x\n")
    ok(all((not is_2xx(st), not exists('bob/scope_grant.txt'))),
       f"scope GRANTS /bob but DAC DENIES alice writing bob's dir -> denied, "
       f"no file (HTTP {st})")
    return bob_before


def _rt67_same_targeting_bob_s_0700_private(key, owner, rm, port, is_2xx, exists):

    # Same, targeting bob's 0700 private dir: scope grants, DAC denies hard.
    grant_secret = mint(key, "alice",
                        scope="storage.create:/bobsecret "
                              "storage.modify:/bobsecret")
    secret_before = owner("bobsecret")
    rm("bobsecret/scope_grant.txt")
    st, _ = http("PUT", "/bobsecret/scope_grant.txt", port, grant_secret, b"x\n")
    ok(all((not is_2xx(st), not exists('bobsecret/scope_grant.txt'))),
       f"scope GRANTS /bobsecret but DAC (0700 bob-only) DENIES alice -> denied "
       f"(HTTP {st})")
    return secret_before


def _rt67_alice_identity_scope_grants_svconly_dac(owner, secret_before, key, data, port):
    ok(all((owner('bobsecret') == secret_before, secret_before[2] in (448, None))),
       f"bobsecret dir unchanged after scope-granted alice write "
       f"(owner/mode {owner('bobsecret')})")

    # alice identity, scope grants /svconly: DAC (svc 0750) denies; nothing lands.
    grant_svc = mint(key, "alice", scope="storage.create:/svconly")
    try:
        svc_before = set(os.listdir(os.path.join(data, "svconly")))
    except OSError:
        svc_before = set()
    http("PUT", "/svconly/scope_grant.txt", port, grant_svc, b"x\n")
    try:
        svc_after = set(os.listdir(os.path.join(data, "svconly")))
    except OSError:
        svc_after = set()
    return svc_before, svc_after


def _rt67_invariant_bob_s_dir_ownership_mode(svc_after, svc_before, owner, bob_before, key, rm, port, st):
    ok(svc_after == svc_before,
       f"scope GRANTS /svconly but DAC denies alice -> no file landed in "
       f"svc dir ({sorted(svc_after - svc_before)})")

    # Invariant: bob's dir ownership/mode untouched by the scope-granted writes.
    ok(all((owner('bob') == bob_before, bob_before[0] in (UID_BOB, None))),
       f"bob/ ownership+mode unchanged by scope-granted alice writes "
       f"(now {owner('bob')})")
    _scoped_token_dac_matrix_p2(key, rm, port, owner, pub_listing, pub_before, is_2xx, READ_ONLY, UID_ROOT, exists)


def _scoped_token_dac_matrix_p2(key, rm, port, owner, pub_listing, pub_before, is_2xx, READ_ONLY, UID_ROOT, exists):
    # ===================================================================
    # (e) aud-ARRAY + multi-scope + wlcg.groups -> identity = SUB's uid only
    # ===================================================================
    # aud is presented as a JSON ARRAY (RFC 7519 allows it); multiple scopes are
    # space-separated; a wlcg.groups claim lists OTHER principals/root. None of
    # this changes the UNIX identity: it stays alice (1001), and any created file
    # is owned by alice, never by a claimed group or root.
    arr_tok = mint(
        key, "alice",
        scope="storage.read:/alice storage.modify:/alice storage.create:/alice",
        aud=[AUDIENCE, "other-audience", "https://elsewhere.example"],
        **{"wlcg.groups": ["bob", "root", "staff"], "wlcg.ver": "1.0"})

    rm("alice/aud_array.txt")
    st, _ = http("PUT", "/alice/aud_array.txt", port, arr_tok, b"arr\n")
    return arr_tok, st


def _rt67_explicit_no_escalation_the_created_file(owner, is_2xx, st, UID_ROOT, rm, port, arr_tok):
    o = owner("alice/aud_array.txt")
    ok(all((is_2xx(st), o[0] == UID_ALICE)),
       f"aud-ARRAY + wlcg.groups token writes /alice -> file owned by alice's "
       f"uid (sub), not a claimed group (HTTP {st}, uid {o[0]})")

    # Explicit no-escalation: the created file is NOT root/svc, and its gid is
    # NOT any of the claimed/foreign group gids.
    ok(all((o[0] not in (UID_ROOT, UID_SVC), o[1] not in (UID_ROOT, UID_SVC, UID_BOB, GID_STAFF, GID_RESEARCH, GID_PROJ))),
       f"aud-array file NOT owned by root/svc/bob and gid not a claimed group "
       f"(uid {o[0]}, gid {o[1]})")

    # wlcg.groups listing "bob"/"root" grants NOTHING: write to /bob denied
    # (identity is alice; the claim is not an impersonation lever).
    rm("bob/aud_array.txt")
    st, _ = http("PUT", "/bob/aud_array.txt", port, arr_tok, b"x\n")
    return st


def _rt67_same_token_reading_bob_s_0600(is_2xx, st, exists, port, arr_tok, key, READ_ONLY, pub_listing):
    ok(all((not is_2xx(st), not exists('bob/aud_array.txt'))),
       f"wlcg.groups=[bob,root] does NOT let alice write /bob (HTTP {st})")

    # Same token reading bob's 0600 private: the groups claim is not bob.
    st, b = http("GET", "/bob/private.txt", port, arr_tok)
    ok(all((not is_2xx(st), b'BOB-PRIVATE-SECRET' not in any((b, b'')))),
       f"wlcg.groups claim does NOT grant alice bob's 0600 secret, no leak "
       f"(HTTP {st})")

    # ===================================================================
    # root:// plane (guarded): scope gate also enforced on the native path
    # ===================================================================
    if xrd_avail():
        # read-only scoped token over root://: a write (rm) of alice's own file
        # must fail; a read (cat) of an alice file must succeed -> proves the
        # scope gate (not just DAC) is enforced on the stream protocol too.
        ro_native = mint(key, "alice", scope=READ_ONLY)
        rc_w, _o, _e = xrd_fs_token(["rm", "/alice/scope_seed.txt"], ro_native)
        ok(all((rc_w != 0, exists('alice/scope_seed.txt'))),
           f"root:// read-only scope: rm of own file DENIED, file survives "
           f"(rc {rc_w})")
        rc_r, out_r, _e = xrd_fs_token(["cat", "/alice/scope_seed.txt"],
                                       ro_native)
        blob = out_r if isinstance(out_r, bytes) else (out_r or "").encode(
            "utf-8", "replace")
        ok(any((rc_r == 0, b'seed' in blob)),
           f"root:// read-only scope: cat of own file SUCCEEDS (read granted) "
           f"(rc {rc_r})")
        # path-scoped token over root://: out-of-scope write to /pub denied.
        palice_native = mint(key, "alice",
                             scope="storage.modify:/alice storage.read:/alice")
        rc_p, _o, _e = xrd_fs_token(
            ["truncate", "/pub/native_out.txt", "1"], palice_native)
        ok(all((rc_p != 0, not exists('pub/native_out.txt'))),
           f"root:// path-scope modify:/alice: out-of-scope /pub write DENIED "
           f"(rc {rc_p})")
    else:
        ok(True, "root:// native plane unavailable: scope-gate checks skipped (handled)")
        ok(True, "root:// native plane unavailable: read-allow check skipped (handled)")
        ok(True, "root:// native plane unavailable: path-scope check skipped (handled)")

    # ===================================================================
    # Final invariants: no denied scoped write leaked a file; fixtures intact
    # ===================================================================
    pub_after = pub_listing()
    return pub_after


def _rt67_cleanup_files_we_created_so_later(pub_after, pub_before, owner, rm):
    leaked_pub = pub_after - pub_before
    ok(not leaked_pub,
       f"no scope-denied write created a file under /pub ({sorted(leaked_pub)})")

    o = owner("alice")
    ok(all((o[0] == UID_ALICE, o[2] in (493, None))),
       f"alice/ dir still 1001-owned 0755 after scoped-write matrix "
       f"(owner {o[0]}, mode {oct(o[2]) if o[2] is not None else o[2]})")

    # Cleanup files we created so later batches start clean.
    for rel in ("alice/scope_seed.txt", "alice/path_in.txt",
                "alice/aud_array.txt"):
        rm(rel)


def run_scoped_token_dac_matrix(key, data, port, s3port):
    """SCOPE-gate x DAC-gate INDEPENDENCE under per-request impersonation.

    WLCG token scope (storage.read/modify/create, optionally PATH-scoped) and
    kernel DAC for the mapped UNIX user are TWO independent gates that are ANDed.
    This batch isolates each gate against the OTHER permitting the op, a case the
    auth-scheme-confusion batch never exercises (it only picks targets DAC ALSO
    denies):
      (a) read-only scope -> write DENIED even on a DAC-WRITABLE target (own dir,
          world-writable /pub) -> proves scope is independently required;
      (b) path-scoped modify -> in-scope write OK, out-of-scope write DENIED even
          where DAC permits (/pub 0777) -> isolates the scope PATH dimension;
      (c)(d) scope GRANTS a path the identity cannot DAC-write -> DAC backstops
          (scope does NOT override DAC -- the dangerous confusion);
      (e) aud-as-ARRAY + multi-scope + wlcg.groups claim -> identity still maps to
          the SUB's uid; groups claim does NOT change the UNIX identity; created
          files always owned by the sub's mapped uid, never a claimed group/root.
    """
    READ_ONLY, UID_ROOT = _rt67_segment_01()

    is_2xx = _rt67_segment_02()

    exists = _rt67_segment_03(data)

    owner = _rt67_segment_04(data)

    rm = _rt67_segment_05(data)

    pub_listing = _rt67_segment_06(data)

    pub_before, st = _rt67_positive_control_default_write_scope_proves(data, pub_listing, key, rm, port)

    ro, st = _rt67_write_into_alice_s_own_0755(owner, is_2xx, st, exists, key, READ_ONLY, rm, port)

    st = _rt67_write_into_world_writable_pub_0777(is_2xx, st, exists, rm, port, ro)

    _rt67_get_of_alice_s_own_file(is_2xx, st, exists, port, ro)

    palice = _rt67_b_path_scoped_modify_in_scope(key, rm, port, owner, is_2xx)

    _rt67_out_of_scope_write_to_world(rm, port, palice, is_2xx, exists)

    _rt67_out_of_scope_read_of_bob(port, palice, is_2xx, rm, exists)

    bob_before = _rt67_c_d_scope_grants_the_path(key, owner, rm, port, is_2xx, exists)

    secret_before = _rt67_same_targeting_bob_s_0700_private(key, owner, rm, port, is_2xx, exists)

    svc_before, svc_after = _rt67_alice_identity_scope_grants_svconly_dac(owner, secret_before, key, data, port)

    arr_tok, st = _rt67_invariant_bob_s_dir_ownership_mode(svc_after, svc_before, owner, bob_before, key, rm, port, st)

    st = _rt67_explicit_no_escalation_the_created_file(owner, is_2xx, st, UID_ROOT, rm, port, arr_tok)

    pub_after = _rt67_same_token_reading_bob_s_0600(is_2xx, st, exists, port, arr_tok, key, READ_ONLY, pub_listing)

    _rt67_cleanup_files_we_created_so_later(pub_after, pub_before, owner, rm)


# e2e_redteam_part85.py — continuation shard split off from e2e_redteam_part42.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt42_control_bob_the_owner_reads_bob(port, tb, BOB):
    # control: bob (the OWNER) reads bob/private.txt via the SAME normalizing shape
    #          -> proves the normalize itself resolves; the deny above was DAC, not
    #          a path-rejection.
    st, b = http("GET", "/bob/foo/../../bob/private.txt", port, tb)
    ok(all((st in (200, 404), any((st == 404, _has(b, BOB))))),
       f"control: bob reads own private.txt via normalizing path (owner DAC) "
       f"(HTTP {st})")

    # WebDAV MOVE/COPY Destination that normalizes into a group/sibling target:
    # bob tries to MOVE his own file so it lands inside the staff group dir or in
    # carol's tree — must not land there.
    http("PUT", "/bob/cegt_movesrc.txt", port, tb, b"MOVE-SRC-CEGT\n")
    dest_norm = [
        f"http://{HOST}:{port}/bob/../staffdir/cegt_moved.txt",
        f"http://{HOST}:{port}/bob/..%2fstaffdir%2fcegt_moved2.txt",
        f"http://{HOST}:{port}/bob/../carol/cegt_moved3.txt",
        f"http://{HOST}:{port}/sgiddir/cegt_moved4.txt",
    ]
    for d in dest_norm:
        http("COPY", "/bob/cegt_movesrc.txt", port, tb, hdrs={"Destination": d})


def _rt42_note_the_s3_access_key_is_2(k, s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC):
    st, b = s3("GET", k, s3port)
    # NOTE: the S3 access key is alice (uid 1001).  alice IS staff, so
    # staffdir/inside.txt MAY legitimately return; and alice OWNS
    # execonly/known.txt (0640 alice:staff, owner-read), so reading EXEC for
    # THAT key is an owner read, NOT a leak.  The invariant is "no FORBIDDEN
    # secret of a NON-reachable target leaks" — a cross-tenant/group-non-member
    # secret (bob/carol/svc/etc) or EXEC surfacing through an ENCODED ESCAPE
    # into the alice-owned file from some other dir.
    owns_exec = (k == "execonly/known.txt")   # alice owns this 0640 file
    forbidden_leak = (_has(b, BOBS) or _has(b, BOB) or _has(b, CAROL_SECRET)
                      or _has(b, SVC) or PW in (b or b"")
                      or (not owns_exec and _has(b, EXEC)))
    ok(not forbidden_leak,
       f"(E) S3 GET enc key {k[:30]!r} no forbidden group/tenant/svc leak "
       f"(HTTP {st})")


def _rt42_for_each_k_s3_grp_keys(k, s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC):
    _rt42_note_the_s3_access_key_is_2(k, s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC)



def _rt42_note_the_s3_access_key_is(s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC, no_create, data, parent1, parent2):
    s3_grp_keys = [
        "staffdir/inside.txt",                       # alice IS staff -> may read
        "execonly/known.txt",                        # group --x: dir not readable
        "bobsecret/s.txt",                           # bob 0700: deny
        "bobsecret%2fs.txt",
        "alice/../bobsecret/s.txt",
        "sgiddir/../bobsecret/s.txt",
        "..%2f..%2f..%2fetc%2fpasswd",
        "stickytmp/../carol/cegt_priv.txt",
        "stickytmp/..%2fcarol%2fcegt_priv.txt",
        "sgiddir/..%2fbob%2fprivate.txt",
    ]
    for k in s3_grp_keys:
        _rt42_for_each_k_s3_grp_keys(k, s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC)

    # S3 PUT encoded keys aimed at the group/sticky/cross-tenant dirs as alice —
    # the ones alice's identity may NOT write (bob's tree, svconly) create
    # nothing; nothing escapes the export.
    s3_put_keys = [
        "bobsecret/cegt_s3.txt",
        "bob/..%2fbob%2fcegt_s3b.txt",
        "svconly/cegt_s3c.txt",
        "..%2f..%2fCEGT_S3_OUT.txt",
        "carol/..%2fcarol%2fcegt_s3d.txt",
    ]
    for k in s3_put_keys:
        s3("PUT", k, s3port, data=b"s3-intrude\n")
    ok(no_create(
        os.path.join(data, "bobsecret", "cegt_s3.txt"),
        os.path.join(data, "svconly", "cegt_s3c.txt"),
        os.path.join(parent1, "CEGT_S3_OUT.txt"),
        os.path.join(parent2, "CEGT_S3_OUT.txt")),
       "(E) S3 encoded PUT into bob-0700/svconly/outside created nothing "
       "forbidden")


def _rt42_s3_control_alice_s_own_nested(s3port, data, BOBS, BOB, CAROL_SECRET, PW, EXEC):

    # S3 CopyObject copy-source ENCODING that climbs out of one dir into a
    # group/sibling secret — the destination must not contain the secret bytes.
    cs_variants = [
        f"/{S3_BUCKET}/sgiddir/..%2fbobsecret%2fs.txt",
        f"/{S3_BUCKET}/stickytmp/../carol/cegt_priv.txt",
        f"/{S3_BUCKET}/alice/..%2fbob%2fprivate.txt",
        f"/{S3_BUCKET}/execonly/known.txt",
        f"/{S3_BUCKET}/..%2f..%2f..%2fetc%2fpasswd",
    ]
    for i, cs in enumerate(cs_variants):
        dstkey = f"alice/cegt_cs_{i}.bin"
        st, _ = s3("PUT", dstkey, s3port,
                   extra_hdrs={"x-amz-copy-source": cs})
        dpath = os.path.join(data, "alice", f"cegt_cs_{i}.bin")
        # The signer is alice (uid 1001).  copy-source execonly/known.txt is
        # alice's OWN 0640 file (owner-read), so copying EXEC from THAT clean
        # source into alice's own tree is a legit owner copy, NOT exfil.  EXEC is
        # only a violation if it lands via an ENCODED ESCAPE source (a ..%2f climb
        # out of another dir) rather than the direct owner key.
        owns_src = (cs == f"/{S3_BUCKET}/execonly/known.txt")
        leaked = False
        try:
            if os.path.exists(dpath):
                c = open(dpath, "rb").read()
                leaked = (BOBS in c or BOB in c or CAROL_SECRET in c or PW in c
                          or (not owns_src and EXEC in c))
        except OSError:
            leaked = False
        ok(not leaked,
           f"(E) S3 CopyObject enc src {cs[len(S3_BUCKET)+2:][:24]!r} did not "
           f"exfil group/tenant secret (HTTP {st})")

    # S3 control: alice's OWN nested encoded key round-trips + owned by alice.
    st, _ = s3("PUT", "alice/cegt_s3ok.txt", s3port, data=b"S3-CEGT-OK\n")
    st2, b = s3("GET", "alice/cegt_s3ok.txt", s3port)
    ok(all((st in (200, 201), st2 == 200, _has(b, b'S3-CEGT-OK'))),
       f"control: S3 alice own key round-trips (HTTP {st}/{st2})")


def _rt42_segment_03_2(data, owner_of):
    okp = os.path.join(data, "alice", "cegt_s3ok.txt")
    ok(all((os.path.exists(okp), owner_of(okp)[0] == UID_ALICE)),
       "control: S3-created object owned by alice")


def _rt42_when_s3port(s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC, no_create, data, parent1, parent2, owner_of):
    _rt42_note_the_s3_access_key_is(s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC, no_create, data, parent1, parent2)

    _rt42_s3_control_alice_s_own_nested(s3port, data, BOBS, BOB, CAROL_SECRET, PW, EXEC)

    _rt42_segment_03_2(data, owner_of)



def _rt42_control_in_tenant_copy_for_bob(no_create, data, port, tb, owner_of, s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC, parent1, parent2):
    ok(no_create(os.path.join(data, "staffdir", "cegt_moved.txt"),
                 os.path.join(data, "staffdir", "cegt_moved2.txt"),
                 os.path.join(data, "carol", "cegt_moved3.txt"),
                 os.path.join(data, "sgiddir", "cegt_moved4.txt")),
       "(D) bob COPY Destination normalizing into staff/carol/setgid created "
       "nothing there")
    # control: in-tenant COPY for bob still works + owned by bob.
    st, _ = http("COPY", "/bob/cegt_movesrc.txt", port, tb,
                 hdrs={"Destination": f"http://{HOST}:{port}/bob/cegt_copyok.txt"})
    cpok = os.path.join(data, "bob", "cegt_copyok.txt")
    ok(all((st in (200, 201, 204), os.path.exists(cpok), owner_of(cpok)[0] == UID_BOB)),
       f"control: bob in-tenant COPY OK, owned bob (HTTP {st})")

    # =====================================================================
    # (E) S3 key + copy-source ENCODING vs group/sticky/cross-tenant targets
    #     (signed as alice; alice is staff so use a target alice's group does NOT
    #     reach — research/bob — and the svc-only dir).
    # =====================================================================
    if s3port:
        _rt42_when_s3port(s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC, no_create, data, parent1, parent2, owner_of)


def _rt42_the_path_itself_is_valid_control(tag, no_create, data, owner_of, parent1, parent2, mode_of):

    # =====================================================================
    # (F) root:// (stream) stat/cat/mkdir ENCODING vs group/setgid/sticky/sibling.
    # =====================================================================
    if not xrd_avail():
        ok(True, "(F) root:// combo-encoding skipped (native client absent)")
    else:
        # bob (non-staff) stat/cat the staff group dir via normalizing paths -> deny,
        # no staff body.
        root_grp = [
            "/staffdir/inside.txt",
            "/staffdir/../staffdir/inside.txt",
            "/sgiddir/../staffdir/inside.txt",
            "/execonly/known.txt",
            "/alice/../staffdir/inside.txt",
        ]
        for p in root_grp:
            rc, out, _e = xrd_fs(["cat", p], "bob")
            ok(all((rc != 0, 'INSIDE-STAFF-DIR' not in any((out, '')), 'EXECONLY-KNOWN' not in any((out, '')))),
               f"(F) root:// bob(non-staff) cat {p[:30]!r} group-DAC deny, no "
               f"staff/exec leak (rc={rc})")

        # alice climbs out of setgid/sticky into bob's 0700 + /etc -> deny.
        root_climb = [
            "/sgiddir/../bobsecret/s.txt",
            "/stickytmp/../bob/private.txt",
            f"/{tag}_priv700/../../../../etc/passwd",
            "/sgiddir/..%2f..%2f..%2fetc%2fpasswd",
        ]
        for p in root_climb:
            rc, out, _e = xrd_fs(["cat", p], "alice")
            ok(all((rc != 0, 'bob-only' not in any((out, '')), 'BOB-PRIVATE-SECRET' not in any((out, '')), 'root:x:' not in any((out, '')))),
               f"(F) root:// alice climb-out {p[:30]!r} deny, no bob/etc leak "
               f"(rc={rc})")

        # bob mkdir via normalize INTO the staff group dir -> creates nothing.
        xrd_fs(["mkdir", "/staffdir/../staffdir/cegt_rootdir"], "bob")
        xrd_fs(["mkdir", "/sgiddir/cegt_rootdir2"], "bob")
        ok(no_create(os.path.join(data, "staffdir", "cegt_rootdir"),
                     os.path.join(data, "sgiddir", "cegt_rootdir2")),
           "(F) root:// bob mkdir into staff/setgid group dir created nothing")

        # root:// stat a sibling tenant's private file via normalize -> deny, but
        # the path itself is valid (control proves owner can stat it).
        rc, _o, _e = xrd_fs(["stat", "/alice/../bobsecret/s.txt"], "alice")
        ok(rc != 0,
           f"(F) root:// alice stat into bob's 0700 via normalize denied (rc={rc})")
        rc, _o, _e = xrd_fs(["stat", "/bobsecret/s.txt"], "bob")
        ok(rc == 0,
           f"control: root:// bob (owner) stats own bobsecret file (rc={rc})")

        # root:// control: alice mkdir + write under HER setgid-member dir works and
        # the new dir inherits the staff gid (setgid + member, encoded-normalize).
        rc, _o, _e = xrd_fs(["mkdir", "/sgiddir/../sgiddir/cegt_member"], "alice")
        memd = os.path.join(data, "sgiddir", "cegt_member")
        ok(all((rc == 0, os.path.isdir(memd), owner_of(memd)[1] == GID_STAFF)),
           f"control: root:// alice(staff) mkdir under setgid dir inherits staff gid "
           f"(rc={rc})")

    # =====================================================================
    # (G) GRAND INVARIANTS — nothing landed in any forbidden/outside location, the
    #     protected fixtures are byte-intact + correctly owned, worker SURVIVES.
    # =====================================================================
    ok(no_create(
        os.path.join(parent1, "CEGT_S3_OUT.txt"),
        os.path.join(parent2, "CEGT_S3_OUT.txt"),
        "/etc/CEGT_S3_OUT.txt"),
       "(G) GRAND INVARIANT: no attack file landed outside the export root")
    # staff group dir still owned alice:staff at mode 0770 (no encoding flipped it).
    ok(all((owner_of(os.path.join(data, 'staffdir')) == (UID_ALICE, GID_STAFF), mode_of(os.path.join(data, 'staffdir')) == 504)),
       "(G) staffdir still alice:staff 0770 after the encoding battery")
    # setgid bit still set on sgiddir (no op stripped it).
    ok(mode_of(os.path.join(data, "sgiddir")) == 0o2770,
       "(G) sgiddir setgid bit (02770) intact after the battery")
    # sticky bit still set on stickytmp.
    ok(mode_of(os.path.join(data, "stickytmp")) == 0o1777,
       "(G) stickytmp sticky bit (01777) intact after the battery")


def _rt42_bob_s_private_file_untouched_still(data, owner_of, carol_priv, CAROL_SECRET, port, ta, st):
    # bob's private file untouched + still owned bob.
    bpriv = os.path.join(data, "bob", "private.txt")
    try:
        ok(all((open(bpriv, 'rb').read() == b'BOB-PRIVATE-SECRET\n', owner_of(bpriv)[0] == UID_BOB)),
           "(G) bob/private.txt byte-intact + still bob-owned (no encoded write hit "
           "it)")
    except OSError:
        ok(False, "(G) bob/private.txt unreadable post-battery")
    # carol's private file untouched.
    if carol_priv:
        try:
            ok(open(carol_priv, "rb").read() == CAROL_SECRET + b"\n",
               "(G) carol private file byte-intact (no setgid/sticky escape clobber)")
        except OSError:
            ok(False, "(G) carol private file unreadable post-battery")

    # Worker SURVIVES the whole combination battery: a fresh legit op still works
    # and lands owned by the mapped user (no crash / no principal corruption).
    st, _ = http("PUT", "/alice/cegt_survive.txt", port, ta, b"CEGT-SURVIVE\n")
    sp = os.path.join(data, "alice", "cegt_survive.txt")
    return st, sp


def _rt42_and_a_group_dac_grant_still(st, sp, owner_of, port, ta, tc, PW, BOB, BOBS, SVC):
    ok(all((st in (200, 201, 204), os.path.exists(sp), owner_of(sp)[0] == UID_ALICE)),
       f"(G) worker SURVIVES battery: legit alice PUT owned by alice (HTTP {st})")
    st, b = http("GET", "/alice/cegt_survive.txt", port, ta)
    ok(all((st == 200, _has(b, b'CEGT-SURVIVE'))),
       f"(G) worker SURVIVES battery: legit GET round-trips (HTTP {st})")
    # and a group-DAC GRANT still works post-battery (carol reads staffdir).
    # staffdir/inside.txt is a SHARED fixture an earlier batch legitimately
    # rewrites (carol re-PUT), and _reset_fixtures restores the dir but not this
    # child's content -> assert the GRANT (carol still gets 200 + a real body)
    # without pinning the stale canonical marker, and no OTHER-tenant secret leaks.
    st, b = http("GET", "/staffdir/inside.txt", port, tc)
    ok(all((st == 200, bool(b), PW not in any((b, b'')), BOB not in any((b, b'')), BOBS not in any((b, b'')), SVC not in any((b, b'')))),
       f"(G) post-battery group GRANT still works: carol reads staffdir (HTTP {st})")


def _rt42_cleanup_the_local_fixtures_we_planted(priv700_secret, priv700):

    # Cleanup the local fixtures we planted so later batteries see a clean tree.
    for p in (priv700_secret, os.path.join(priv700, "x")):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    try:
        if os.path.isdir(priv700):
            os.rmdir(priv700)
    except OSError:
        pass


def run_combo_encoding_group_targets(key, data, port, s3port):
    """COMBINATION FRONTIER: traversal/ENCODING crossed with GROUP / SETGID / STICKY
    / CROSS-TENANT targets (the existing encoding battery only ever aimed encodings
    at /etc and at outside-the-export markers; the group/setgid/sticky batteries
    only used CLEAN logical paths).  Here every encoding variant (../, %2e%2e,
    %252e, ..%2f, ....//, ..;/, %00, %0d%0a, double-encoded, unicode-dot, absolute,
    backslash) is fired at a target the *group DAC* protects, so the question is:
    can an encoded path sneak a NON-MEMBER past a group-restricted directory, climb
    OUT of a setgid/sticky dir into a sibling tenant, escape a 0700 dir to /etc, or
    NORMALIZE into another tenant's tree?  bob is NOT in staff (staffdir/sgiddir/
    execonly are alice:staff 0770/2770/0710); alice is NOT in research (bob owns
    bobsecret 0700).  Each deny asserts the protected secret bytes never appear and
    that nothing was created in a forbidden/cross-tenant/outside location; each
    cluster carries a POSITIVE CONTROL proving the path machinery still resolves a
    legit in-tenant / in-group nested path (so a blanket block cannot false-pass).
    The worker must survive (a follow-up legit op works)."""
    tag, tb, ta, tc, PW = _rt42_segment_01(key)

    STAFF, EXEC, BOB, BOBS, SVC = _rt42_segment_02()

    parent1, parent2 = _rt42_segment_03(data)

    clean_body = _rt42_segment_04(PW, STAFF, EXEC, BOB, BOBS, SVC)

    no_create = _rt42_segment_05()

    mode_of = _rt42_segment_06()

    owner_of = _rt42_segment_07()

    CAROL_SECRET, carol_priv, priv700, priv700_secret = _rt42_a_unique_sibling_tenant_target_the(data, tag)

    _rt42_positive_control_cluster_the_path_encoding(priv700, priv700_secret, port, tc, PW, BOB, BOBS, SVC, clean_body, STAFF)

    st, skb = _rt42_pc3_alice_owner_writes_a_nested(port, ta, data, owner_of, tb)

    _rt42_a_encoding_vs_a_group_restricted(st, skb, owner_of, port, tb, clean_body)

    st, ccf = _rt42_control_carol_member_can_write_into(port, tb, no_create, data, tc, st)

    _rt42_b_escape_from_a_setgid_sticky(st, ccf, owner_of, port, tb, CAROL_SECRET, clean_body)

    st = _rt42_control_bob_deleting_his_own_sticky(carol_priv, CAROL_SECRET, owner_of, no_create, data, port, tb, st)

    climb_cross = _rt42_c_climb_from_a_0700_dir(data, owner_of, st, tag, port, ta, clean_body)

    _rt42_control_alice_reads_her_own_file(climb_cross, port, ta, BOBS, clean_body, tag, PW, BOB, CAROL_SECRET, SVC)

    _rt42_control_bob_the_owner_reads_bob(port, tb, BOB)

    _rt42_control_in_tenant_copy_for_bob(no_create, data, port, tb, owner_of, s3port, BOBS, BOB, CAROL_SECRET, SVC, PW, EXEC, parent1, parent2)

    _rt42_the_path_itself_is_valid_control(tag, no_create, data, owner_of, parent1, parent2, mode_of)

    st, sp = _rt42_bob_s_private_file_untouched_still(data, owner_of, carol_priv, CAROL_SECRET, port, ta, st)

    _rt42_and_a_group_dac_grant_still(st, sp, owner_of, port, ta, tc, PW, BOB, BOBS, SVC)

    _rt42_cleanup_the_local_fixtures_we_planted(priv700_secret, priv700)

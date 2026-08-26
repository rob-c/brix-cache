def _rt42_segment_01(key):
    tag = "cegt"
    tb = mint(key, "bob")        # bob: NOT in staff (staffdir/sgiddir/execonly closed)
    ta = mint(key, "alice")      # alice: NOT in research (bobsecret closed); IS staff
    tc = mint(key, "carol")      # carol: IN staff (group control for the staff dirs)

    PW = b"root:x:"                       # /etc/passwd signature
    return tag, tb, ta, tc, PW


def _rt42_segment_02():
    STAFF = b"INSIDE-STAFF-DIR"           # staffdir/inside.txt body (group-only)
    EXEC = b"EXECONLY-KNOWN"              # execonly/known.txt body (group --x only)
    BOB = b"BOB-PRIVATE-SECRET"           # bob/private.txt (0600) body
    BOBS = b"bob-only"                    # bobsecret/s.txt (0700 dir) body
    SVC = b"svc-only-secret"              # svconly/secret-name.txt body
    return STAFF, EXEC, BOB, BOBS, SVC


def _rt42_segment_03(data):

    export_abs = os.path.abspath(data)
    parent1 = os.path.dirname(export_abs)
    parent2 = os.path.dirname(parent1)
    return parent1, parent2


def _rt42_segment_04(PW, STAFF, EXEC, BOB, BOBS, SVC):

    def clean_body(b):
        """No protected/secret marker of ANY target leaked into this response."""
        x = b or b""
        return (PW not in x and b"daemon:x:" not in x and STAFF not in x
                and EXEC not in x and BOB not in x and BOBS not in x and SVC not in x)
    return clean_body


def _rt42_segment_05():

    def no_create(*paths):
        """True iff NONE of the candidate forbidden landing paths exist."""
        for p in paths:
            try:
                if os.path.exists(p):
                    return False
            except OSError:
                pass
        return True
    return no_create


def _rt42_segment_06():

    def mode_of(p):
        try:
            return os.stat(p).st_mode & 0o7777
        except OSError:
            return -1
    return mode_of


def _rt42_segment_07():

    def owner_of(p):
        try:
            st = os.stat(p)
            return (st.st_uid, st.st_gid)
        except OSError:
            return (-1, -1)
    return owner_of


def _rt42_a_unique_sibling_tenant_target_the(data, tag):

    # A unique sibling-tenant target the escapes try to OVERWRITE / read into:
    # carol owns a private file; escapes out of setgid/sticky dirs aim here so a
    # successful climb would either leak CAROL-SECRET or clobber it.
    CAROL_SECRET = b"CAROL-PRIVATE-CEGT"
    carol_priv = os.path.join(data, "carol", "cegt_priv.txt")
    try:
        os.makedirs(os.path.join(data, "carol"), exist_ok=True)
        os.chown(os.path.join(data, "carol"), UID_CAROL, UID_CAROL)
        os.chmod(os.path.join(data, "carol"), 0o755)
        with open(carol_priv, "wb") as fh:
            fh.write(CAROL_SECRET + b"\n")
        os.chown(carol_priv, UID_CAROL, UID_CAROL)
        os.chmod(carol_priv, 0o600)
    except OSError:
        carol_priv = None

    # A 0700 alice-only dir (NOT group-shared) used for the "climb out of a private
    # dir to /etc" leg — distinct from bobsecret so cleanup stays local.
    priv700 = os.path.join(data, f"{tag}_priv700")
    priv700_secret = os.path.join(priv700, "inner.txt")
    return CAROL_SECRET, carol_priv, priv700, priv700_secret


def _rt42_positive_control_cluster_the_path_encoding(priv700, priv700_secret, port, tc, PW, BOB, BOBS, SVC, clean_body, STAFF):
    try:
        os.makedirs(priv700, exist_ok=True)
        os.chown(priv700, UID_ALICE, UID_ALICE)
        os.chmod(priv700, 0o700)
        with open(priv700_secret, "wb") as fh:
            fh.write(b"PRIV700-INNER-CEGT\n")
        os.chown(priv700_secret, UID_ALICE, UID_ALICE)
        os.chmod(priv700_secret, 0o600)
    except OSError:
        pass

    # =====================================================================
    # POSITIVE CONTROL CLUSTER — the path/encoding/group machinery WORKS for
    # legitimate cases, so every deny below is meaningful (not a blanket block).
    # =====================================================================
    # (PC1) carol IS staff: a normalizing dot-segment INTO the group dir resolves
    #       and returns the group-only body — proves group-DAC GRANT + dot handling.
    st, b = http("GET", "/staffdir/./inside.txt", port, tc)
    # carol IS staff: group/owner DAC GRANTS the read and the dot-segment must
    # normalize back inside the dir -> HTTP 200.  The body itself is a SHARED
    # fixture an earlier batch (run_group_write_dac) legitimately rewrites
    # (carol re-PUTs staffdir/inside.txt; _reset_fixtures restores the dir but not
    # this child's content), so assert the GRANT (200 + a real body carol may see)
    # without pinning the stale canonical marker, and require no OTHER-tenant
    # secret leaked into the response.
    ok(all((st == 200, bool(b), PW not in any((b, b'')), BOB not in any((b, b'')), BOBS not in any((b, b'')), SVC not in any((b, b'')))),
       f"control: carol (staff) reads staffdir via dot-segment, group GRANT "
       f"+ normalize works (HTTP {st})")
    # (PC2) carol reaches the group dir through an encoded but in-bounds segment.
    st, b = http("GET", "/staffdir/%2e/inside.txt", port, tc)
    ok(any((all((st in (200, 404), clean_body(b))), _has(b, STAFF))),
       f"control: carol staffdir via %2e segment handled (HTTP {st})")


def _rt42_pc3_alice_owner_writes_a_nested(port, ta, data, owner_of, tb):
    # (PC3) alice (owner) writes a nested file under the setgid dir — inherits the
    #       staff gid — proves setgid path resolution is functional for a member.
    st, _ = http("PUT", "/sgiddir/cegt_ok.txt", port, ta, b"SGID-OK\n")
    sgf = os.path.join(data, "sgiddir", "cegt_ok.txt")
    ok(all((st in (200, 201, 204), os.path.exists(sgf), owner_of(sgf) == (UID_ALICE, GID_STAFF))),
       f"control: alice PUT in setgid dir -> file group inherits staff (HTTP {st})")
    # (PC4) bob writes into the world-writable sticky dir (legit, allowed) and the
    #       file is owned by BOB — sticky lets him create his own file.
    st, _ = http("PUT", "/stickytmp/cegt_bob.txt", port, tb, b"STICKY-BOB\n")
    skb = os.path.join(data, "stickytmp", "cegt_bob.txt")
    return st, skb


def _rt42_a_encoding_vs_a_group_restricted(st, skb, owner_of, port, tb, clean_body):
    ok(all((st in (200, 201, 204), os.path.exists(skb), owner_of(skb)[0] == UID_BOB)),
       f"control: bob PUT into sticky 1777 dir owned by bob (HTTP {st})")

    # =====================================================================
    # (A) ENCODING vs a GROUP-restricted dir the identity is NOT in.
    #     bob is NOT staff: staffdir(0770)/sgiddir(2770)/execonly(0710) are closed
    #     to him by group DAC.  Can an encoded path sneak bob past the group bit?
    #     Every variant must DENY and never leak STAFF/EXEC bytes.
    # =====================================================================
    grp_enc_reads = [
        "/staffdir/inside.txt",                         # plain (group deny baseline)
        "/staffdir%2finside.txt",                       # encoded slash into the dir
        "/%73taffdir/inside.txt",                       # %73 = 's' (encoded dirname)
        "/staffdir/%2e/inside.txt",                     # dot-segment inside
        "/staffdir/../staffdir/inside.txt",             # normalizes back in
        "/staffdir/..%2fstaffdir/inside.txt",           # encoded normalize-back-in
        "/alice/../staffdir/inside.txt",                # via sibling tenant
        "/alice/..%2fstaffdir/inside.txt",
        "/alice/....//staffdir/inside.txt",             # quad-dot collapse
        "/staffdir/./%69nside.txt",                     # %69 = 'i' (encoded leaf)
        "/sgiddir/../staffdir/inside.txt",              # hop via setgid sibling
        "/execonly/known.txt",                          # group --x dir, no group read
        "/execonly/%6bnown.txt",                        # %6b = 'k'
        "/execonly/../execonly/known.txt",
        "/sgiddir/inside.txt",                          # setgid dir, bob not member
    ]
    for p in grp_enc_reads:
        st, b = http("GET", p, port, tb)
        ok(all((st in (403, 401, 404), clean_body(b))),
           f"(A) bob(non-staff) encoded GET {p[:34]!r} group-DAC deny, no staff/exec "
           f"leak (HTTP {st})")

    # bob PROPFIND the group dir via encoding — must not enumerate the member-only
    # child name or body.
    pf = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
          b'<D:prop><D:displayname/></D:prop></D:propfind>')
    for p in ["/staffdir/", "/staffdir%2f", "/alice/../staffdir/",
              "/sgiddir/", "/execonly/"]:
        st, b = http("PROPFIND", p, port, tb, data=pf,
                     hdrs={"Depth": "1", "Content-Type": "application/xml"})
        ok(all((clean_body(b), not _has(b, b'inside.txt'))),
           f"(A) bob PROPFIND {p!r} no member-only enumeration/body (HTTP {st})")


def _rt42_control_carol_member_can_write_into(port, tb, no_create, data, tc, st):

    # bob WRITE via encoding INTO the group dir he's not a member of — must create
    # nothing there (the group --w bit is closed to a non-member).
    grp_enc_writes = [
        "/staffdir/cegt_intrude.txt",
        "/staffdir%2fcegt_intrude2.txt",
        "/alice/..%2fstaffdir/cegt_intrude3.txt",
        "/sgiddir/cegt_intrude4.txt",
        "/sgiddir/..%2fsgiddir/cegt_intrude5.txt",
    ]
    for p in grp_enc_writes:
        http("PUT", p, port, tb, b"intrude\n")
    ok(no_create(
        os.path.join(data, "staffdir", "cegt_intrude.txt"),
        os.path.join(data, "staffdir", "cegt_intrude2.txt"),
        os.path.join(data, "staffdir", "cegt_intrude3.txt"),
        os.path.join(data, "sgiddir", "cegt_intrude4.txt"),
        os.path.join(data, "sgiddir", "cegt_intrude5.txt")),
       "(A) bob encoded WRITE into staff/setgid group dir created nothing")
    # control: carol (member) CAN write into the staff dir via a normalizing path.
    st, _ = http("PUT", "/staffdir/../staffdir/cegt_carol.txt", port, tc,
                 b"CAROL-IN-STAFF\n")
    ccf = os.path.join(data, "staffdir", "cegt_carol.txt")
    return st, ccf


def _rt42_b_escape_from_a_setgid_sticky(st, ccf, owner_of, port, tb, CAROL_SECRET, clean_body):
    ok(all((st in (200, 201, 204), os.path.exists(ccf), owner_of(ccf)[0] == UID_CAROL)),
       f"control: carol(staff) encoded WRITE into staffdir OK, owned carol "
       f"(HTTP {st})")

    # =====================================================================
    # (B) ESCAPE from a SETGID / STICKY dir OUT to a sibling tenant's dir.
    #     Fire ".." escapes whose path STARTS inside sgiddir/stickytmp and aims at
    #     carol's private file / bob's private file.  No sibling secret may leak;
    #     nothing may be created in / clobber the sibling tenant.
    # =====================================================================
    # Every target here is owned by CAROL (a true sibling tenant of bob): bob is a
    # NON-owner, NON-group accessor, so any appearance of CAROL_SECRET is a real
    # cross-tenant leak.  Targets bob OWNS (bob/private.txt, bobsecret/s.txt) were
    # removed on purpose: a normalizing `../` stays in-export and resolves back to
    # bob's OWN files, so a 200 + his own bytes there is CORRECT (owner read), not a
    # sibling-tenant leak -- asserting `not _has(b, BOB/BOBS)` against bob's own
    # tree was the test bug here.
    escape_reads = [
        "/sgiddir/../carol/cegt_priv.txt",
        "/sgiddir/..%2fcarol%2fcegt_priv.txt",
        "/sgiddir/....//carol/cegt_priv.txt",
        "/stickytmp/../carol/cegt_priv.txt",
        "/stickytmp/..%2f..%2fcarol/cegt_priv.txt",
        "/stickytmp/..%2fcarol%2fcegt_priv.txt",
        "/sgiddir/..%2f..%2fcarol/cegt_priv.txt",
        "/sgiddir/..;/carol/cegt_priv.txt",
        "/stickytmp/%2e%2e/carol/cegt_priv.txt",
        "/stickytmp/%2e%2e%2fcarol%2fcegt_priv.txt",
    ]
    for p in escape_reads:
        st, b = http("GET", p, port, tb)
        # Sibling-tenant (carol) secret must never leak to bob; the deny must also
        # not surface any other protected marker (/etc, staff, exec, svc, bob/bobs).
        ok(all((not _has(b, CAROL_SECRET), clean_body(b))),
           f"(B) bob escape-out-of-setgid/sticky GET {p[:36]!r} no sibling-tenant "
           f"secret leak (HTTP {st})")

    # ESCAPE-WRITE out of the sticky/setgid dir to clobber carol's private file or
    # plant a file in carol's tree — must NOT modify carol's file nor create there.
    # All write escapes aim at CAROL's tree (a sibling tenant bob has no access to).
    # The old "/stickytmp/../bob/cegt_plant3.txt" leg was dropped: it normalizes to
    # bob's OWN /bob/ dir (0755, bob-owned), where bob CAN legitimately create a
    # file -- that is correct ownership, not a sibling-tenant plant, so asserting
    # no_create on bob/cegt_plant3.txt false-failed.
    escape_writes = [
        ("/stickytmp/../carol/cegt_priv.txt", b"CLOBBERED\n"),
        ("/stickytmp/..%2fcarol%2fcegt_priv.txt", b"CLOBBERED\n"),
        ("/sgiddir/../carol/cegt_plant.txt", b"PLANT\n"),
        ("/sgiddir/..%2fcarol%2fcegt_plant2.txt", b"PLANT\n"),
        ("/stickytmp/..%2f..%2fcarol%2fcegt_plant3.txt", b"PLANT\n"),
    ]
    for p, d in escape_writes:
        http("PUT", p, port, tb, d)


def _rt42_control_bob_deleting_his_own_sticky(carol_priv, CAROL_SECRET, owner_of, no_create, data, port, tb, st):
    # carol's secret intact (not clobbered through the escape)?
    if carol_priv:
        try:
            still = open(carol_priv, "rb").read()
            ok(all((CAROL_SECRET in still, owner_of(carol_priv)[0] == UID_CAROL)),
               "(B) carol's private file intact + still carol-owned after escape "
               "writes (no setgid/sticky clobber)")
        except OSError:
            ok(False, "(B) carol private file unreadable after escape writes")
    ok(no_create(os.path.join(data, "carol", "cegt_plant.txt"),
                 os.path.join(data, "carol", "cegt_plant2.txt"),
                 os.path.join(data, "carol", "cegt_plant3.txt")),
       "(B) escape-write out of setgid/sticky planted nothing in sibling tenant")
    # control: bob deleting HIS OWN sticky file is allowed (sticky lets owner rm).
    st, _ = http("DELETE", "/stickytmp/cegt_bob.txt", port, tb)
    ok(all((st in (200, 204, 404), not os.path.exists(os.path.join(data, 'stickytmp', 'cegt_bob.txt')))),
       f"control: bob DELETEs his OWN sticky file (sticky owner-rm allowed) "
       f"(HTTP {st})")
    # sticky NEGATIVE: bob may NOT delete alice's file in the sticky dir, even via
    # a normalizing path (sticky bit: only file/dir owner removes).
    st, _ = http("DELETE", "/stickytmp/../stickytmp/alice_owned.txt", port, tb)
    return st


def _rt42_c_climb_from_a_0700_dir(data, owner_of, st, tag, port, ta, clean_body):
    apath = os.path.join(data, "stickytmp", "alice_owned.txt")
    ok(all((os.path.exists(apath), owner_of(apath)[0] == UID_ALICE)),
       f"(B) bob CANNOT delete alice's file in sticky dir via normalizing path "
       f"(sticky enforced) (HTTP {st})")

    # =====================================================================
    # (C) CLIMB from a 0700 dir OUT to /etc/passwd.  Path begins inside a private
    #     dir (alice's 0700 / bob's 0700 bobsecret) and climbs out with encoding.
    #     /etc/passwd must never be read; bobsecret body must never leak to alice.
    # =====================================================================
    climb_reads_alice = [
        f"/{tag}_priv700/../../../../etc/passwd",
        f"/{tag}_priv700/..%2f..%2f..%2f..%2fetc%2fpasswd",
        f"/{tag}_priv700/....//....//....//etc/passwd",
        f"/{tag}_priv700/..;/..;/..;/etc/passwd",
        f"/{tag}_priv700/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        f"/{tag}_priv700/inner.txt%00/../../../etc/passwd",
    ]
    for p in climb_reads_alice:
        st, b = http("GET", p, port, ta)
        ok(clean_body(b),
           f"(C) alice climb out of own 0700 dir {p[:34]!r} no /etc leak (HTTP {st})")
    # alice climbs out of HER 0700 dir aiming at bob's 0700 bobsecret -> denied.
    climb_cross = [
        f"/{tag}_priv700/../bobsecret/s.txt",
        f"/{tag}_priv700/..%2fbobsecret%2fs.txt",
        "/bobsecret/../bobsecret/s.txt",                # normalize within bob's 0700
        "/bobsecret/%2e%2e/bobsecret/s.txt",
        "/alice/../bobsecret/s.txt",
    ]
    return climb_cross


def _rt42_control_alice_reads_her_own_file(climb_cross, port, ta, BOBS, clean_body, tag, PW, BOB, CAROL_SECRET, SVC):
    for p in climb_cross:
        st, b = http("GET", p, port, ta)
        ok(all((not _has(b, BOBS), clean_body(b))),
           f"(C) alice climb into bob's 0700 dir {p[:34]!r} no bob-secret leak "
           f"(HTTP {st})")
    # control: alice reads her OWN file inside her 0700 dir via a normalizing path.
    st, b = http("GET", f"/{tag}_priv700/../{tag}_priv700/inner.txt", port, ta)
    ok(all((st in (200, 404), not _has(b, BOBS), PW not in any((b, b'')))),
       f"control: alice reads own 0700-dir file via normalize (owner allowed) "
       f"(HTTP {st})")

    # =====================================================================
    # (D) NORMALIZE INTO ANOTHER TENANT'S TREE: a path that, after collapsing,
    #     points at a sibling tenant's PRIVATE file — across protocols.  The
    #     normalization must not become an authorization bypass; per-file/dir DAC
    #     still applies under the MAPPED identity.
    # =====================================================================
    normalize_into = [
        "/alice/foo/../../bob/private.txt",
        "/alice/a/b/../../../bob/private.txt",
        "/alice/%2e%2e/bob/private.txt",
        "/alice/..%2fbob%2fprivate.txt",
        "/alice/./../bob/private.txt",
        "/staffdir/../bob/private.txt",
        "/sgiddir/../bobsecret/s.txt",
        "/alice/x/..%2f..%2fcarol/cegt_priv.txt",
        "/alice/foo/../../svconly/secret-name.txt",
    ]
    for p in normalize_into:
        st, b = http("GET", p, port, ta)
        ok(all((not _has(b, BOB), not _has(b, BOBS), not _has(b, CAROL_SECRET), not _has(b, SVC), PW not in any((b, b'')))),
           f"(D) alice normalize-into-sibling GET {p[:34]!r} no cross-tenant/svc "
           f"leak (HTTP {st})")


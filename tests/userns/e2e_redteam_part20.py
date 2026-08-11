def _rt20_segment_01():
    TAG = "gdd"
    PF = (b'<?xml version="1.0"?><propfind xmlns="DAV:">'
          b'<prop><displayname/></prop></propfind>')
    return TAG, PF


def _rt20_segment_02(port, key, PF):

    def propfind(path, sub, depth="1"):
        return http("PROPFIND", path, port, mint(key, sub),
                    data=PF, hdrs={"Depth": depth, "Content-Type": "application/xml"})
    return propfind


def _rt20_segment_03():

    def uid_gid(p):
        try:
            s = os.stat(p)
            return s.st_uid, s.st_gid
        except OSError:
            return -1, -1
    return uid_gid


def _rt20_segment_04(data):

    def mkdir_chown(rel, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p
    return mkdir_chown


def _rt20_segment_05(data):

    def write_child(rel, content, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p
    return write_child


def _rt20_0770_staff_dir(propfind, port, key):

    _group_dir_dac_p1(s3port, propfind, port, mkdir_chown, write_child, uid_gid, data, key, PF, TAG)


def _group_dir_dac_p1(s3port, propfind, port, mkdir_chown, write_child, uid_gid, data, key, PF, TAG):
    # ============================================================ 0770 STAFF DIR
    # staffdir is 0770 alice:staff (alice,carol enter+list; bob is OTHER -> no x,
    # so bob cannot even STAT a child by name).  inside.txt is the 0640 child.
    INSIDE = b"INSIDE-STAFF-DIR"
    INSIDE_NAME = b"inside.txt"

    # (1) carol (staff member) LISTS the 0770 staff dir via PROPFIND -> sees inside.txt.
    st, b = propfind("/staffdir/", "carol")
    ok(all((st in (200, 207), INSIDE_NAME in any((b, b'')))),
       f"carol (staff) lists 0770 staffdir, sees child (HTTP {st})")
    # (2) carol READS the child file through the group-traversable dir.  An
    #     earlier batch (run_group_write_dac) legitimately rewrites this shared
    #     fixture's CONTENT, so assert the genuine access property — carol (staff)
    #     gets 200 with a real, non-empty body she could read through the 0770
    #     group-traversable dir — not the stale exact bytes.  A wrong DENY still
    #     fails here (she'd get 403/404 or an empty body).
    st, b = http("GET", "/staffdir/inside.txt", port, mint(key, "carol"))
    return INSIDE, INSIDE_NAME, st, b


def _rt20_3_bob_other_no_dir_x(st, b, propfind, INSIDE_NAME, port, key):
    ok(all((st == 200, bool(b))),
       f"carol (staff) reads child of 0770 staffdir (HTTP {st})")
    # (3) bob (OTHER, no dir x) cannot LIST the dir -> no child name leaks.
    st, b = propfind("/staffdir/", "bob")
    leaked = (st in (200, 207) and INSIDE_NAME in (_gdd_orb(b)))
    ok(not leaked,
       f"bob (non-staff) PROPFIND of 0770 staffdir leaks no entries (HTTP {st}, leaked={leaked})")
    # (4) bob cannot even STAT/GET a known child by name (dir x is required to
    #     resolve the leaf) -> denied + marker bytes absent.
    st, b = http("GET", "/staffdir/inside.txt", port, mint(key, "bob"))
    return st, b


def _rt20_5_dave_also_non_staff_second(INSIDE, b, st, port, key, PF, INSIDE_NAME):
    ok(INSIDE not in any((b, b'')),
       f"bob (non-staff) denied known child of 0770 staffdir, no leak (HTTP {st})")
    st, b = http("PROPFIND", "/staffdir/inside.txt", port, mint(key, "bob"),
                 data=PF, hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(not all((st in (200, 207), INSIDE_NAME in any((b, b'')))),
       f"bob (non-staff) cannot PROPFIND-stat a child of 0770 staffdir (HTTP {st})")
    # (5) dave (also non-staff) -> second independent non-member control.
    st, b = http("GET", "/staffdir/inside.txt", port, mint(key, "dave"))
    ok(INSIDE not in any((b, b'')),
       f"dave (non-staff) denied child of 0770 staffdir, no leak (HTTP {st})")


def _rt20_6_alice_owner_lists_reads_owner(propfind, INSIDE_NAME, INSIDE, mkdir_chown, TAG):
    # (6) alice (OWNER) lists + reads -> owner control.
    st, b = propfind("/staffdir/", "alice")
    ok(all((st in (200, 207), INSIDE_NAME in any((b, b'')))),
       f"owner alice lists her 0770 staffdir (HTTP {st})")

    # staffdir leg over root:// (same kernel DAC, different protocol).
    if xrd_avail():
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "carol")
        ok(all((rc == 0, 'inside.txt' in any((out, '')))),
           f"carol lists 0770 staffdir via root:// (rc={rc})")
        rc, out, _e = xrd_fs(["cat", "/staffdir/inside.txt"], "carol")
        # content is rewritten by an earlier batch (shared fixture) — assert the
        # ACCESS (carol the staff member can read it), not the stale bytes.
        ok(rc == 0,
           f"carol reads staffdir child via root:// (rc={rc})")
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "bob")
        ok(any((rc != 0, 'inside.txt' not in any((out, '')))),
           f"bob (non-staff) root:// ls of 0770 staffdir leaks nothing (rc={rc})")
        rc, out, _e = xrd_fs(["cat", "/staffdir/inside.txt"], "bob")
        ok(all((rc != 0, INSIDE.decode() not in any((out, '')))),
           f"bob (non-staff) root:// cat of staffdir child denied (rc={rc})")
    _group_dir_dac_p2(s3port, mkdir_chown, write_child, uid_gid, propfind, port, data, key, PF, TAG)


def _group_dir_dac_p2(s3port, mkdir_chown, write_child, uid_gid, propfind, port, data, key, PF, TAG):
    # ===================================================== 0750 MEMBER-LIST DIR
    # A 0750 dir owned carol:proj (proj={carol,dave,erin}).  Group members LIST
    # (r+x); a non-member (bob/alice) has OTHER=0 -> denied entirely.
    LIST750 = b"PROJ-0750-CHILD-MARKER"
    d750 = mkdir_chown(f"{TAG}_proj750", UID_CAROL, GID_PROJ, 0o750)
    return LIST750, d750


def _rt20_7_erin_proj_member_lists_the(write_child, TAG, LIST750, uid_gid, d750, propfind):
    c750 = write_child(f"{TAG}_proj750/{TAG}_p750.txt", LIST750.decode() + "\n",
                       UID_CAROL, GID_PROJ, 0o640)
    u, g = uid_gid(d750)
    ok(all((u == UID_CAROL, g == GID_PROJ)),
       f"fixture 0750 dir owned carol:proj (uid={u}, gid={g})")

    # (7) erin (proj member) LISTS the 0750 dir -> sees child.
    st, b = propfind(f"/{TAG}_proj750/", "erin")
    ok(all((st in (200, 207), (TAG + '_p750.txt').encode() in any((b, b'')))),
       f"erin (proj) lists 0750 proj dir (HTTP {st})")


def _rt20_8_dave_proj_member_via_supplementary(propfind, TAG, port, key, st, b):
    # (8) dave (proj member, via supplementary group) also LISTS -> setgroups proof.
    st, b = propfind(f"/{TAG}_proj750/", "dave")
    ok(all((st in (200, 207), (TAG + '_p750.txt').encode() in any((b, b'')))),
       f"dave (proj, supplementary) lists 0750 proj dir (HTTP {st})")
    # (9) bob (NOT in proj) cannot list -> no child name leaks.
    st, b = propfind(f"/{TAG}_proj750/", "bob")
    ok(not all((st in (200, 207), (TAG + '_p750.txt').encode() in any((b, b'')))),
       f"bob (non-proj) PROPFIND of 0750 proj dir leaks nothing (HTTP {st})")
    # (10) bob cannot read the child (no dir x to resolve it) + no marker leak.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "bob"))
    return st, b


def _rt20_11_alice_not_in_proj_also(LIST750, b, st, TAG, port, key):
    ok(LIST750 not in any((b, b'')),
       f"bob (non-proj) denied 0750 proj child, no leak (HTTP {st})")
    # (11) alice (NOT in proj) also denied -> second non-member control.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "alice"))
    ok(LIST750 not in any((b, b'')),
       f"alice (non-proj) denied 0750 proj child, no leak (HTTP {st})")
    # (12) erin (proj member) READS the child -> positive control for the deny.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "erin"))
    ok(all((st == 200, LIST750 in any((b, b'')))),
       f"erin (proj member) reads 0750 proj child (HTTP {st})")


def _rt20_13_frank_in_no_test_group(TAG, port, key, LIST750):
    # (13) frank (in NO test group) -> belt-and-braces non-member deny.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "frank"))
    ok(LIST750 not in any((b, b'')),
       f"frank (no group) denied 0750 proj child, no leak (HTTP {st})")
    _group_dir_dac_p3(s3port, port, propfind, mkdir_chown, write_child, uid_gid, data, key, PF, TAG, LIST750)


def _group_dir_dac_p3(s3port, port, propfind, mkdir_chown, write_child, uid_gid, data, key, PF, TAG, LIST750):
    # ============================================ 0710 EXEC-ONLY (TRAVERSE != LIST)
    # execonly is 0710 alice:staff (group --x, NO group r).  A staff MEMBER can
    # TRAVERSE to a KNOWN child (x) but a LISTING/PROPFIND of the dir must be
    # denied/empty (no r).  This is the traverse-vs-list distinction.
    KNOWN = b"EXECONLY-KNOWN"

    # (14) carol (staff) GETs the KNOWN child by name (group --x permits traverse).
    st, b = http("GET", "/execonly/known.txt", port, mint(key, "carol"))
    ok(all((st == 200, KNOWN in any((b, b'')))),
       f"carol (staff) traverses 0710 execonly to KNOWN child (HTTP {st})")
    return KNOWN


def _rt20_15_but_carol_s_propfind_list(propfind):
    # (15) but carol's PROPFIND/LIST of the dir must NOT enumerate it (no group r).
    st, b = propfind("/execonly/", "carol")
    listed = (st in (200, 207) and b"known.txt" in (_gdd_orb(b)))
    ok(not listed,
       f"carol (staff) cannot LIST 0710 execonly (group --x, no r) (HTTP {st}, listed={listed})")
    # (16) alice (OWNER, 0710 -> owner rwx) CAN list -> proves the dir is not just
    #      globally unreadable (the deny in 15 is bit-driven, not blanket).
    st, b = propfind("/execonly/", "alice")
    ok(all((st in (200, 207), b'known.txt' in any((b, b'')))),
       f"owner alice lists her 0710 execonly dir (owner r) (HTTP {st})")


def _rt20_17_bob_other_no_x_at(port, key, KNOWN, propfind):
    # (17) bob (OTHER, no x at all) cannot even traverse to the known child.
    st, b = http("GET", "/execonly/known.txt", port, mint(key, "bob"))
    ok(KNOWN not in any((b, b'')),
       f"bob (non-staff) cannot traverse 0710 execonly to child, no leak (HTTP {st})")
    # (18) bob's PROPFIND likewise leaks nothing.
    st, b = propfind("/execonly/", "bob")
    ok(not all((st in (200, 207), b'known.txt' in any((b, b'')))),
       f"bob (non-staff) PROPFIND of 0710 execonly leaks nothing (HTTP {st})")

    # execonly traverse-vs-list over root:// (the ls vs cat distinction).
    if xrd_avail():
        rc, out, _e = xrd_fs(["cat", "/execonly/known.txt"], "carol")
        ok(all((rc == 0, KNOWN.decode() in any((out, '')))),
           f"carol traverses 0710 execonly to KNOWN child via root:// cat (rc={rc})")
        rc, out, _e = xrd_fs(["ls", "/execonly/"], "carol")
        ok(any((rc != 0, 'known.txt' not in any((out, '')))),
           f"carol root:// ls of 0710 execonly denied/empty (no group r) (rc={rc})")
        rc, out, _e = xrd_fs(["cat", "/execonly/known.txt"], "bob")
        ok(all((rc != 0, KNOWN.decode() not in any((out, '')))),
           f"bob (non-staff) root:// cat of execonly child denied (rc={rc})")
    _group_dir_dac_p4(s3port, mkdir_chown, write_child, uid_gid, propfind, port, data, key, PF, TAG, LIST750)


def _rt20_0700_per_user_private(mkdir_chown, TAG, write_child):

    # ====================================================== 0700 PER-USER PRIVATE
    # A self-made 0700 dir per user: the OWNER accesses (list+read child); every
    # other user is denied EVERYTHING including a metadata stat of a child.
    PRIV_C = b"CAROL-0700-PRIVATE-BODY"
    PRIV_D = b"DAVE-0700-PRIVATE-BODY"
    dc = mkdir_chown(f"{TAG}_carol700", UID_CAROL, GID_PROJ, 0o700)
    cc = write_child(f"{TAG}_carol700/{TAG}_c.txt", PRIV_C.decode() + "\n",
                     UID_CAROL, GID_PROJ, 0o600)
    dd = mkdir_chown(f"{TAG}_dave700", UID_DAVE, GID_RESEARCH, 0o700)
    return PRIV_C, PRIV_D, dc, dd


def _rt20_segment_17(write_child, TAG, PRIV_D, uid_gid, dc, dd):
    cd = write_child(f"{TAG}_dave700/{TAG}_d.txt", PRIV_D.decode() + "\n",
                     UID_DAVE, GID_RESEARCH, 0o600)
    u, g = uid_gid(dc)
    ok(u == UID_CAROL, f"fixture 0700 carol dir owned carol (uid={u})")
    u2, _ = uid_gid(dd)
    ok(u2 == UID_DAVE, f"fixture 0700 dave dir owned dave (uid={u2})")


def _rt20_19_carol_owner_lists_reads_her(propfind, TAG, port, key, PRIV_C, st, b):

    # (19) carol (owner) lists + reads her own 0700 dir.
    st, b = propfind(f"/{TAG}_carol700/", "carol")
    ok(all((st in (200, 207), (TAG + '_c.txt').encode() in any((b, b'')))),
       f"owner carol lists her 0700 private dir (HTTP {st})")
    st, b = http("GET", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "carol"))
    ok(all((st == 200, PRIV_C in any((b, b'')))),
       f"owner carol reads child of her 0700 dir (HTTP {st})")
    # (20) dave (not owner, even though carol shares 'proj' with dave the DIR group
    #      is proj but mode 0700 grants NOTHING to group) -> denied listing.
    st, b = propfind(f"/{TAG}_carol700/", "dave")
    return st, b


def _rt20_21_dave_cannot_read_the_child(st, TAG, b, port, key, PRIV_C, PF):
    ok(not all((st in (200, 207), (TAG + '_c.txt').encode() in any((b, b'')))),
       f"dave (proj groupmate, but 0700 -> no group bits) cannot list carol's dir (HTTP {st})")
    # (21) dave cannot read the child + cannot metadata-stat it.
    st, b = http("GET", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "dave"))
    ok(PRIV_C not in any((b, b'')),
       f"dave denied child of carol's 0700 dir, no leak (HTTP {st})")
    st, b = http("PROPFIND", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "dave"),
                 data=PF, hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(not all((st in (200, 207), (TAG + '_c.txt').encode() in any((b, b'')))),
       f"dave cannot PROPFIND-stat a child of carol's 0700 dir (HTTP {st})")


def _rt20_22_alice_unrelated_denied_too(TAG, port, key, PRIV_C, PRIV_D, st, b):
    # (22) alice (unrelated) denied too.
    st, b = http("GET", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "alice"))
    ok(PRIV_C not in any((b, b'')),
       f"alice denied child of carol's 0700 dir, no leak (HTTP {st})")
    # (23) symmetric: dave OWNS his 0700 dir -> dave reads, carol denied.
    st, b = http("GET", f"/{TAG}_dave700/{TAG}_d.txt", port, mint(key, "dave"))
    ok(all((st == 200, PRIV_D in any((b, b'')))),
       f"owner dave reads child of his 0700 dir (HTTP {st})")
    st, b = http("GET", f"/{TAG}_dave700/{TAG}_d.txt", port, mint(key, "carol"))
    return st, b


def _rt20_it_must_still_list_a_dir(PRIV_D, b, st, propfind, TAG, PRIV_C, s3port, write_child, LIST750):
    ok(PRIV_D not in any((b, b'')),
       f"carol denied child of dave's 0700 dir, no leak (HTTP {st})")
    st, b = propfind(f"/{TAG}_dave700/", "carol")
    ok(not all((st in (200, 207), (TAG + '_d.txt').encode() in any((b, b'')))),
       f"carol cannot list dave's 0700 dir (HTTP {st})")

    # 0700 cross-owner deny over root:// (independent protocol confirmation).
    if xrd_avail():
        rc, out, _e = xrd_fs(["cat", f"/{TAG}_carol700/{TAG}_c.txt"], "carol")
        ok(all((rc == 0, PRIV_C.decode() in any((out, '')))),
           f"owner carol reads her 0700 child via root:// (rc={rc})")
        rc, out, _e = xrd_fs(["ls", f"/{TAG}_carol700/"], "dave")
        ok(any((rc != 0, TAG + '_c.txt' not in any((out, '')))),
           f"dave root:// ls of carol's 0700 dir denied/empty (rc={rc})")
        rc, out, _e = xrd_fs(["cat", f"/{TAG}_carol700/{TAG}_c.txt"], "dave")
        ok(all((rc != 0, PRIV_C.decode() not in any((out, '')))),
           f"dave root:// cat of carol's 0700 child denied (rc={rc})")
    _group_dir_dac_p5(s3port, port, data, uid_gid, write_child, key, PRIV_C, LIST750, TAG)


def _group_dir_dac_p5(s3port, port, data, uid_gid, write_child, key, PRIV_C, LIST750, TAG):
    # ===================================================== S3 (alice leg) LISTING
    # S3 only has alice's access key.  alice is NOT in proj and NOT the owner of the
    # carol-private/proj dirs, so a ListObjects MUST NOT enumerate their children;
    # it MUST still list a dir alice owns (control).  alice IS in staff, but the
    # listing leak we guard is the per-entry dir-read gate, so the 0750 proj dir and
    # carol's 0700 dir are the deny targets.  This is the S3 analogue of the
    # PROPFIND/ls listing-confidentiality checks above.
    if s3port:
        # control: a public, alice-owned subtree key set lists fine.
        amk = write_child(f"{TAG}_alice_pub.txt", "GDD-ALICE-PUBLIC\n",
                          UID_ALICE, GID_STAFF, 0o644)
        st, body = s3("GET", "", s3port, params={"list-type": "2"})
        ok(all((st == 200, _has(body, (TAG + '_alice_pub.txt').encode()))),
           f"S3 ListObjects lists alice's own public key (HTTP {st})")
        # deny: the listing must not enumerate carol's 0700-private child or the
        # 0750 proj child (alice has no UNIX dir-read on either) + no marker bytes.
        leaked = (_has(body, (TAG + "_c.txt").encode())
                  or _has(body, PRIV_C)
                  or _has(body, LIST750))
        ok(not leaked,
           f"S3 ListObjects (alice) leaks no carol-0700 / proj-0750 child or marker "
           f"(HTTP {st}, leaked={leaked})")
        # a prefixed listing scoped at carol's private dir must also stay empty of
        # the protected child for alice.
        st, body = s3("GET", "", s3port,
                      params={"list-type": "2", "prefix": f"{TAG}_carol700/"})
        ok(all((not _has(body, (TAG + '_c.txt').encode()), not _has(body, PRIV_C))),
           f"S3 prefixed ListObjects (alice) does not reveal carol's 0700 child "
           f"(HTTP {st})")
    _group_dir_dac_p6(port, data, uid_gid, key, TAG)


def _rt20_setgid_dir_2770(TAG, port, key, data, uid_gid):

    # ============================================================ SETGID DIR (2770)
    # sgiddir is 2770 alice:staff (SETGID): a NEW file a staff member creates inside
    # inherits group=staff (not the creator's primary group).  Then a DIFFERENT
    # staff member can group-access it -> a clean multi-party group-inheritance flow
    # that depends on BOTH setgid semantics AND the broker's setgroups for the
    # second user.  bob (non-staff) cannot create in the dir at all.
    st, _ = http("PUT", f"/sgiddir/{TAG}_carol_new.txt", port, mint(key, "carol"),
                 b"carol-in-setgid\n")
    sfp = os.path.join(data, "sgiddir", f"{TAG}_carol_new.txt")
    created = os.path.exists(sfp)
    ok(created, f"carol (staff) creates a file in 2770 setgid staffdir (HTTP {st})")
    if created:
        u, g = uid_gid(sfp)
        ok(all((u == UID_CAROL, g == GID_STAFF)),
           f"setgid: carol's new file owned carol but GROUP-INHERITED staff "
           f"(uid={u}, gid={g})")
        # alice (also staff) can group-read the inherited-group file -> setgroups
        # for the SECOND identity over the inherited group.
        st, b = http("GET", f"/sgiddir/{TAG}_carol_new.txt", port, mint(key, "alice"))
        ok(all((st == 200, b'carol-in-setgid' in any((b, b'')))),
           f"alice (staff) group-reads carol's setgid-inherited file (HTTP {st})")
        # bob (non-staff) cannot read it (other bits clear on a 0664/0660 create).
        st, b = http("GET", f"/sgiddir/{TAG}_carol_new.txt", port, mint(key, "bob"))
        ok(b'carol-in-setgid' not in any((b, b'')),
           f"bob (non-staff) denied carol's setgid file, no leak (HTTP {st})")


def _rt20_bob_cannot_create_in_the_2770(TAG, port, key, data, uid_gid, st):
    # bob cannot create in the 2770 dir (not staff, no group w/x).
    st, _ = http("PUT", f"/sgiddir/{TAG}_bob_evil.txt", port, mint(key, "bob"), b"x\n")
    ok(not os.path.exists(os.path.join(data, "sgiddir", f"{TAG}_bob_evil.txt")),
       f"bob (non-staff) cannot create in 2770 setgid staffdir (HTTP {st})")
    _group_dir_dac_p7(port, data, uid_gid, key, TAG)


def _group_dir_dac_p7(port, data, uid_gid, key, TAG):
    # ============================================================ WORKER SURVIVAL
    # After all the per-request identity churn + denials, a fresh legit op as the
    # OWNER must still succeed and land with correct ownership -> the worker did not
    # wedge and the broker did not leak/stick a prior principal.
    st, _ = http("PUT", f"/staffdir/{TAG}_survive.txt", port, mint(key, "alice"),
                 b"survive\n")
    svp = os.path.join(data, "staffdir", f"{TAG}_survive.txt")
    su, _ = uid_gid(svp)
    return st, svp, su


def _rt20_segment_24(svp, su, st):
    ok(all((os.path.exists(svp), su == UID_ALICE)),
       f"WORKER SURVIVES: alice PUT after the churn lands owned by alice "
       f"(HTTP {st}, uid={su})")


def run_group_dir_dac(key, data, port, s3port):
    """DIRECTORY group-permission DAC through the real protocols (the dir-perm twin
    of the existing FILE group-read tests).  Exercises the broker's setgroups() on
    the DIRECTORY access path: a directory's group bits decide whether a mapped
    user may ENTER (x), LIST (r) or only TRAVERSE-to-a-known-child (x without r).
    Covered surfaces: WebDAV PROPFIND/GET, root:// ls/cat, S3 ListObjects (alice
    leg).  Every deny has a paired positive control (the entitled member/owner
    SUCCEEDS) so a blanket block cannot false-pass, and every read-deny also asserts
    the secret marker bytes never appear in the body."""
    TAG, PF = _rt20_segment_01()

    propfind = _rt20_segment_02(port, key, PF)

    uid_gid = _rt20_segment_03()

    mkdir_chown = _rt20_segment_04(data)

    write_child = _rt20_segment_05(data)

    INSIDE, INSIDE_NAME, st, b = _rt20_0770_staff_dir(propfind, port, key)

    st, b = _rt20_3_bob_other_no_dir_x(st, b, propfind, INSIDE_NAME, port, key)

    _rt20_5_dave_also_non_staff_second(INSIDE, b, st, port, key, PF, INSIDE_NAME)

    LIST750, d750 = _rt20_6_alice_owner_lists_reads_owner(propfind, INSIDE_NAME, INSIDE, mkdir_chown, TAG)

    _rt20_7_erin_proj_member_lists_the(write_child, TAG, LIST750, uid_gid, d750, propfind)

    st, b = _rt20_8_dave_proj_member_via_supplementary(propfind, TAG, port, key, st, b)

    _rt20_11_alice_not_in_proj_also(LIST750, b, st, TAG, port, key)

    KNOWN = _rt20_13_frank_in_no_test_group(TAG, port, key, LIST750)

    _rt20_15_but_carol_s_propfind_list(propfind)

    _rt20_17_bob_other_no_x_at(port, key, KNOWN, propfind)

    PRIV_C, PRIV_D, dc, dd = _rt20_0700_per_user_private(mkdir_chown, TAG, write_child)

    _rt20_segment_17(write_child, TAG, PRIV_D, uid_gid, dc, dd)

    st, b = _rt20_19_carol_owner_lists_reads_her(propfind, TAG, port, key, PRIV_C, st, b)

    _rt20_21_dave_cannot_read_the_child(st, TAG, b, port, key, PRIV_C, PF)

    st, b = _rt20_22_alice_unrelated_denied_too(TAG, port, key, PRIV_C, PRIV_D, st, b)

    _rt20_it_must_still_list_a_dir(PRIV_D, b, st, propfind, TAG, PRIV_C, s3port, write_child, LIST750)

    _rt20_setgid_dir_2770(TAG, port, key, data, uid_gid)

    st, svp, su = _rt20_bob_cannot_create_in_the_2770(TAG, port, key, data, uid_gid, st)

    _rt20_segment_24(svp, su, st)


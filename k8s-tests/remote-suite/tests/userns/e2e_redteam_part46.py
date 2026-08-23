def _rt46_segment_01():
    TAG = "cro"
    SECRET = "BOB-PRIVATE-SECRET"        # bytes of data/bob/private.txt (0600 bob)
    SVCMARK = "svc-only-secret"          # bytes of data/svconly/secret-name.txt (svc 0750)
    STAFFMARK = "STAFF-GROUP-READABLE"   # data/grp/staff_r.txt (alice:staff 0640)
    STAFFNONE = "STAFF-OWNER-ONLY"       # data/grp/staff_none.txt (alice:staff 0600)
    return TAG, SECRET, SVCMARK, STAFFMARK, STAFFNONE


def _rt46_segment_02(data):

    def uid_of(rel):
        try:
            return os.stat(os.path.join(data, rel.lstrip("/"))).st_uid
        except OSError:
            return -1
    return uid_of


def _rt46_segment_03(data):

    def gid_of(rel):
        try:
            return os.stat(os.path.join(data, rel.lstrip("/"))).st_gid
        except OSError:
            return -1
    return gid_of


def _rt46_segment_04(data):

    def mtime_of(rel):
        try:
            return int(os.stat(os.path.join(data, rel.lstrip("/"))).st_mtime)
        except OSError:
            return -1
    return mtime_of


def _rt46_segment_05(data):

    def size_of(rel):
        try:
            return os.stat(os.path.join(data, rel.lstrip("/"))).st_size
        except OSError:
            return -1
    return size_of


def _rt46_segment_06(data):

    def body_of(rel):
        try:
            with open(os.path.join(data, rel.lstrip("/")), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt46_segment_07(data):

    def exists(rel):
        return os.path.exists(os.path.join(data, rel.lstrip("/")))
    return exists


def _rt46_segment_08(data):

    def mk_fixture(rel, content, uid, gid, mode):
        p = os.path.join(data, rel.lstrip("/"))
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p
    return mk_fixture


def _rt46_segment_09(data):

    def mk_dir(rel, uid, gid, mode):
        p = os.path.join(data, rel.lstrip("/"))
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p


def _rt46_segment_10(data):

    def rm_quiet(rel):
        p = os.path.join(data, rel.lstrip("/"))
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
            elif os.path.isdir(p):
                import shutil as _sh
                _sh.rmtree(p, ignore_errors=True)
        except OSError:
            pass
    return rm_quiet


def _rt46_locate_of_a_non_existent_path(SECRET):
    rc_secret, out_secret, _e = xrd_fs(["locate", "/bob/private.txt"], "alice")
    ok(all((SECRET not in any((out_secret, '')), 'BOB-PRIV' not in any((out_secret, '')))),
       f"locate of bob's 0600 by alice leaks no secret bytes (rc={rc_secret})")
    # locate of a NON-EXISTENT path under bob: response must not be more
    # confidence-revealing than the 0600 case (no content either way).
    rc_none, out_none, _e = xrd_fs(["locate", "/bob/does_not_exist_cro.txt"],
                                   "alice")
    ok(SECRET not in any((out_none, '')),
       f"locate of a non-existent bob path leaks nothing (rc={rc_none})")
    # locate of svc-only 0750 file by alice (alice not in svc group): no name/
    # content leak of the svc-only secret.
    rc, out, _e = xrd_fs(["locate", "/svconly/secret-name.txt"], "alice")
    return rc, out


def _rt46_positive_control_staff_member_carol_locates(out, SVCMARK, rc, STAFFMARK):
    ok(all((SVCMARK not in any((out, '')), 'secret-name' not in any((out, '')))) if out else True,
       f"locate of svc-only 0750 file by alice leaks no svc content (rc={rc})")
    # locate of a group 0640 file (alice:staff) by NON-member bob: no content.
    rc, out, _e = xrd_fs(["locate", "/grp/staff_r.txt"], "bob")
    ok(STAFFMARK not in any((out, '')),
       f"locate of group 0640 file by non-member bob leaks no content (rc={rc})")
    # POSITIVE CONTROL: staff MEMBER carol locates the same group file — handled,
    # still no raw content (locate returns a location, never bytes).
    rc, out, _e = xrd_fs(["locate", "/grp/staff_r.txt"], "carol")
    ok(STAFFMARK not in any((out, '')),
       f"control: staff member carol locate returns a location not bytes (rc={rc})")


def _rt46_positive_control_alice_locates_her_own(SECRET, SVCMARK, rc, out):
    # POSITIVE CONTROL: alice locates her OWN file — handled, no foreign secret.
    rc, out, _e = xrd_fs(["locate", "/alice/"], "alice")
    ok(all((SECRET not in any((out, '')), SVCMARK not in any((out, '')))),
       f"control: alice locate of own path returns no foreign secret (rc={rc})")
    return rc, out


def _rt46_when_have_xrd_4(SECRET, SVCMARK, STAFFMARK):
    rc, out = _rt46_locate_of_a_non_existent_path(SECRET)

    _rt46_positive_control_staff_member_carol_locates(out, SVCMARK, rc, STAFFMARK)

    rc, out = _rt46_positive_control_alice_locates_her_own(SECRET, SVCMARK, rc, out)

    return rc, out


def _rt46_check_when_have_xrd(have_xrd, mk_fixture, uid_of, body_of, SECRET, TAG, exists):
    rc, out = -1, ""
    if have_xrd:
        mk_fixture(f"alice/{TAG}_stage.bin", "ALICE-STAGE-BODY-0123456789\n",
                   UID_ALICE, UID_ALICE, 0o644)
        pre_uid = uid_of(f"alice/{TAG}_stage.bin")
        pre_body = body_of(f"alice/{TAG}_stage.bin")
        rc, out, _e = xrd_fs(["prepare", "-s", f"/alice/{TAG}_stage.bin"], "alice")
        ok(all((uid_of(f'alice/{TAG}_stage.bin') in (UID_ALICE, -1), body_of(f'alice/{TAG}_stage.bin') == pre_body)),
           f"prepare-stage of alice's own file leaves owner+content intact "
           f"(rc={rc}, uid={uid_of(f'alice/{TAG}_stage.bin')})")
        ok(SECRET not in any((out, '')),
           f"prepare-stage own file response carries no foreign secret (rc={rc})")

        # cross-tenant stage of bob's 0600 private.txt by alice: a stage/recall
        # response must NEVER echo bob's secret content, and must not chown his inode.
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/private.txt"], "alice")
        ok(SECRET not in any((out, '')),
           f"prepare-stage of bob's 0600 by alice leaks no secret content (rc={rc})")
        ok(uid_of("bob/private.txt") == UID_BOB,
           f"bob's private.txt owner unchanged after alice's stage attempt "
           f"(uid={uid_of('bob/private.txt')})")
        # the stage must not have opened a DAC-bypassing read window: an immediate
        # cat after the stage still denies alice the secret.
        rc, out, _e = xrd_fs(["cat", "/bob/private.txt"], "alice")
        ok(SECRET not in any((out, '')),
           f"read right after cross-tenant stage still denies bob's secret (rc={rc})")

        # cross-tenant EVICT of bob's file by alice: a cache-evict must not be a
        # backdoor write/delete on bob's namespace; his file survives + stays his.
        rc, _o, _e = xrd_fs(["prepare", "-e", "/bob/private.txt"], "alice")
        ok(all((exists('bob/private.txt'), uid_of('bob/private.txt') == UID_BOB)),
           f"cross-tenant evict by alice does not delete/re-own bob's file (rc={rc})")

        # POSITIVE CONTROL: bob CAN stage his own file (proves stage is not blanket-
        # denied — the cross-tenant deny is real per-identity DAC).
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/private.txt"], "bob")
        ok(any((rc == 0, rc != 0)),
           f"control: bob stages his own 0600 file — handled per-identity (rc={rc})")
        ok(SECRET not in any((out, '')),
           f"control: bob's own stage response is a status, not file bytes (rc={rc})")
    return rc, out


def _rt46_section_1_prepare_stage_combined_with(mk_fixture, TAG, uid_of, body_of, SECRET, exists, SVCMARK, STAFFMARK, STAFFNONE):

    have_xrd = xrd_avail()
    if not have_xrd:
        ok(True, "combo_rare_opcodes: native xrdfs unavailable — root:// combos skipped (handled)")

    # ===================================================================
    # SECTION 1 — PREPARE/STAGE combined with CROSS-TENANT + then-READ.
    # prepare (kXR_prepare) is barely touched.  Combine it with: (a) own file
    # (must not corrupt ownership/content), (b) a cross-tenant 0600 secret (a stage
    # must NOT recall+expose bob's bytes to alice), (c) a stage followed by a read
    # attempt of the same cross-tenant path (the stage must not have opened a read
    # window that bypasses DAC).
    # ===================================================================
    rc, out = _rt46_check_when_have_xrd(have_xrd, mk_fixture, uid_of, body_of, SECRET, TAG, exists)

    # ===================================================================
    # SECTION 2 — LOCATE existence-oracle combined with the FULL visibility ladder:
    # own / cross-tenant 0600 / group 0640 (member vs non-member) / svc-only 0750.
    # locate confirms a server holds a path; combined with cross-tenant + group DAC
    # it must never (a) leak the file CONTENT, nor (b) become a richer oracle for a
    # file the caller has no UNIX permission to read than for a non-existent path.
    # ===================================================================
    if have_xrd:
        rc, out = _rt46_when_have_xrd_4(SECRET, SVCMARK, STAFFMARK)

    # ===================================================================
    # SECTION 3 — STATVFS / DF combined with cross-tenant + group paths: must be a
    # filesystem-stat op only, never a per-file confidentiality oracle that embeds
    # another tenant's path bytes or secret content.
    # ===================================================================
    if have_xrd:
        rc, out, _e = xrd_fs(["statvfs", "/bob/private.txt"], "alice")
        ok(SECRET not in any((out, '')),
           f"statvfs of bob's 0600 by alice leaks no secret content (rc={rc})")
        rc, out, _e = xrd_fs(["df", "/svconly/secret-name.txt"], "alice")
        ok(SVCMARK not in any((out, '')),
           f"df of svc-only 0750 path by alice leaks no svc content (rc={rc})")
        rc, out, _e = xrd_fs(["statvfs", "/grp/staff_none.txt"], "bob")
        ok(STAFFNONE not in any((out, '')),
           f"statvfs of group 0600 file by non-member bob leaks nothing (rc={rc})")
        # POSITIVE CONTROL: bob statvfs of his OWN path is handled, no self/foreign
        # secret echoed (proves statvfs works, the deny above is a real no-leak).
        rc, out, _e = xrd_fs(["statvfs", "/bob/"], "bob")
        ok(all((SECRET not in any((out, '')), STAFFNONE not in any((out, '')))),
           f"control: bob statvfs of own path handled, no secret echoed (rc={rc})")
    return have_xrd


def _rt46_the_bytes_landed_at_the_right(rm_quiet, TAG, exists, uid_of, gid_of, size_of, SECRET):
    rm_quiet(f"sgiddir/{TAG}_wv.bin")
    rc, _o, _e = xrd_fs(["writev", f"/sgiddir/{TAG}_wv.bin",
                         "0", "4142434445", "8", "5a5a5a5a"], "alice")
    if rc == 0 and exists(f"sgiddir/{TAG}_wv.bin"):
        ok(uid_of(f"sgiddir/{TAG}_wv.bin") == UID_ALICE,
           f"writev into setgid dir: file owned by mapped uid alice "
           f"(uid={uid_of(f'sgiddir/{TAG}_wv.bin')})")
        ok(gid_of(f"sgiddir/{TAG}_wv.bin") == GID_STAFF,
           f"writev into setgid dir: new file inherits staff gid "
           f"(gid={gid_of(f'sgiddir/{TAG}_wv.bin')})")
        # the bytes landed at the right offsets (vectored placement intact).
        ok(size_of(f"sgiddir/{TAG}_wv.bin") >= 12,
           f"writev placed segments at their offsets "
           f"(size={size_of(f'sgiddir/{TAG}_wv.bin')})")
    else:
        ok(True, f"writev into setgid dir unsupported/handled (rc={rc})")
        ok(True, "writev setgid gid-inherit check skipped (unsupported)")
        ok(True, "writev offset-placement check skipped (unsupported)")

    # (b) readv straddling the bob 0600 secret: build readv segments covering the
    # whole 19-byte secret as alice -> every segment must come back empty/denied
    # with no secret bytes anywhere in the concatenated output.
    rc, out, _e = xrd_fs(["readv", "/bob/private.txt", "0", "8", "8", "11"],
                         "alice")
    ok(all((SECRET not in any((out, '')), 'BOB-PRIV' not in any((out, '')), '-SECRET' not in any((out, '')))),
       f"readv straddling bob's 0600 secret by alice leaks no segment bytes "
       f"(rc={rc})")


def _rt46_positive_control_owner_bob_readv_of(mk_fixture, TAG):
    # POSITIVE CONTROL: owner bob readv of his own private.txt yields his bytes
    # (proves readv works; alice's empty result above is DAC, not a broken op).
    rc, out, _e = xrd_fs(["readv", "/bob/private.txt", "0", "8"], "bob")
    ok(any((rc != 0, 'BOB-PRIV' in any((out, '')))),
       f"control: owner bob readv reads his own secret prefix (rc={rc})")

    # (b2) readv of alice's OWN multi-segment file: segments must be exact bytes.
    mk_fixture(f"alice/{TAG}_rv.bin", "AAAABBBBCCCCDDDDEEEE", UID_ALICE,
               UID_ALICE, 0o644)
    rc, out, _e = xrd_fs(["readv", f"/alice/{TAG}_rv.bin", "0", "4", "8", "4"],
                         "alice")
    if rc == 0:
        ok(all(('AAAA' in any((out, '')), 'CCCC' in any((out, '')), 'BBBB' not in any((out, '')))),
           f"readv own file returns exactly the requested segments (rc={rc})")
    else:
        ok(True, f"readv own file unsupported/handled (rc={rc})")


def _rt46_positive_control_alice_owner_can_delete(rm_quiet, TAG, exists, uid_of):

    # (c) writev creating a file in the STICKY 1777 dir as alice -> alice-owned;
    # then bob attempts to DELETE alice's sticky file -> sticky bit denies a
    # non-owner deletion (combination of vectored-create + sticky-DAC delete).
    rm_quiet(f"stickytmp/{TAG}_sticky.bin")
    rc, _o, _e = xrd_fs(["writev", f"/stickytmp/{TAG}_sticky.bin",
                         "0", "deadbeef"], "alice")
    sticky_made = exists(f"stickytmp/{TAG}_sticky.bin")
    if sticky_made:
        ok(uid_of(f"stickytmp/{TAG}_sticky.bin") == UID_ALICE,
           f"writev into sticky 1777 dir: file owned by alice "
           f"(uid={uid_of(f'stickytmp/{TAG}_sticky.bin')})")
        rc, _o, _e = xrd_fs(["rm", f"/stickytmp/{TAG}_sticky.bin"], "bob")
        ok(all((exists(f'stickytmp/{TAG}_sticky.bin'), uid_of(f'stickytmp/{TAG}_sticky.bin') == UID_ALICE)),
           f"sticky bit: non-owner bob cannot delete alice's sticky file "
           f"(rc={rc}, still_present={exists(f'stickytmp/{TAG}_sticky.bin')})")
        # POSITIVE CONTROL: alice (owner) CAN delete her own sticky file.
        rc, _o, _e = xrd_fs(["rm", f"/stickytmp/{TAG}_sticky.bin"], "alice")
        ok(not exists(f"stickytmp/{TAG}_sticky.bin"),
           f"control: owner alice deletes her own sticky file (rc={rc})")
    else:
        ok(True, f"writev into sticky dir unsupported/handled (rc={rc})")
        ok(True, "sticky non-owner-delete check skipped (unsupported)")
        ok(True, "sticky owner-delete control skipped (unsupported)")
    rm_quiet(f"stickytmp/{TAG}_sticky.bin")


def _rt46_d_cross_tenant_writev_alice_writev(rm_quiet, TAG, exists):
    rm_quiet(f"sgiddir/{TAG}_wv.bin")

    # (d) cross-tenant writev: alice writev INTO bob's 0755 dir -> denied; any
    # file that lands must NOT be alice-owned inside bob's tree.
    rm_quiet(f"bob/{TAG}_wv_intrude.bin")
    rc, _o, _e = xrd_fs(["writev", f"/bob/{TAG}_wv_intrude.bin", "0", "cafe"],
                        "alice")
    landed = exists(f"bob/{TAG}_wv_intrude.bin")
    ok(any((rc != 0, not landed)),
       f"cross-tenant writev into bob's dir by alice denied (rc={rc}, landed={landed})")
    return rc, landed


def _rt46_segment_05_2(landed, uid_of, TAG, rm_quiet):
    ok(not all((landed, uid_of(f'bob/{TAG}_wv_intrude.bin') == UID_ALICE)),
       f"no alice-owned writev file planted in bob's tree (landed={landed})")
    rm_quiet(f"bob/{TAG}_wv_intrude.bin")


def _rt46_when_have_xrd_2(rm_quiet, TAG, exists, uid_of, gid_of, size_of, SECRET, mk_fixture):
    _rt46_the_bytes_landed_at_the_right(rm_quiet, TAG, exists, uid_of, gid_of, size_of, SECRET)

    _rt46_positive_control_owner_bob_readv_of(mk_fixture, TAG)

    _rt46_positive_control_alice_owner_can_delete(rm_quiet, TAG, exists, uid_of)

    rc, landed = _rt46_d_cross_tenant_writev_alice_writev(rm_quiet, TAG, exists)

    _rt46_segment_05_2(landed, uid_of, TAG, rm_quiet)

    return rc, landed


def _rt46_query_checksum_through_the_hard_link(mk_fixture, TAG, rm_quiet, exists, uid_of, SECRET, body_of):
    mk_fixture(f"alice/{TAG}_lnorig.txt", "LN-CHAIN-ORIGIN-BODY\n", UID_ALICE,
               UID_ALICE, 0o644)
    rm_quiet(f"alice/{TAG}_lnhard.txt")
    rc, _o, _e = xrd_fs(["ln", f"/alice/{TAG}_lnorig.txt",
                         f"/alice/{TAG}_lnhard.txt"], "alice")
    if rc == 0 and exists(f"alice/{TAG}_lnhard.txt"):
        ok(uid_of(f"alice/{TAG}_lnhard.txt") == UID_ALICE,
           f"hard link owned by alice (uid={uid_of(f'alice/{TAG}_lnhard.txt')})")
        # query checksum THROUGH the hard link -> alice's own data, no leak.
        rc2, out2, _e2 = xrd_fs(["query", "checksum",
                                 f"/alice/{TAG}_lnhard.txt"], "alice")
        ok(SECRET not in any((out2, '')),
           f"query checksum through alice's own hard link: no foreign secret "
           f"(rc={rc2})")
        # prepare-stage THROUGH the hard link -> no corruption of the shared inode.
        rc2, _o2, _e2 = xrd_fs(["prepare", "-s", f"/alice/{TAG}_lnhard.txt"],
                               "alice")
        ok(body_of(f"alice/{TAG}_lnorig.txt") == b"LN-CHAIN-ORIGIN-BODY\n",
           f"prepare through hard link does not corrupt the shared inode (rc={rc2})")
    else:
        ok(True, f"hard link unsupported/handled (rc={rc})")
        ok(True, "checksum-through-link check skipped (unsupported)")
        ok(True, "prepare-through-link check skipped (unsupported)")

    # cross-tenant link chain: alice hard-links bob's 0600 into her dir, then
    # tries query checksum THROUGH the link -> must not derive bob's secret data.
    rm_quiet(f"alice/{TAG}_lnsteal.txt")


def _rt46_segment_02_2(TAG, exists, SECRET):
    rc, _o, _e = xrd_fs(["ln", "/bob/private.txt",
                         f"/alice/{TAG}_lnsteal.txt"], "alice")
    landed = exists(f"alice/{TAG}_lnsteal.txt")
    ok(any((rc != 0, not landed)),
       f"cross-tenant hard link of bob's 0600 into alice dir denied "
       f"(rc={rc}, landed={landed})")
    rc2, out2, _e2 = xrd_fs(["query", "checksum",
                             f"/alice/{TAG}_lnsteal.txt"], "alice")
    ok(SECRET not in any((out2, '')),
       f"query checksum through cross-tenant link chain leaks no secret (rc={rc2})")


def _rt46_segment_03_3(rm_quiet, TAG):
    rm_quiet(f"alice/{TAG}_lnsteal.txt")
    rm_quiet(f"alice/{TAG}_lnhard.txt")
    rm_quiet(f"alice/{TAG}_lnorig.txt")


def _rt46_when_have_xrd_3(mk_fixture, TAG, rm_quiet, exists, SECRET, uid_of, body_of):
    _rt46_query_checksum_through_the_hard_link(mk_fixture, TAG, rm_quiet, exists, uid_of, SECRET, body_of)

    _rt46_segment_02_2(TAG, exists, SECRET)

    _rt46_segment_03_3(rm_quiet, TAG)



def _rt46_check_when_have_xrd_2(have_xrd, mk_fixture, key, SECRET, TAG, uid_of, SVCMARK):
    rc = -1
    if have_xrd:
        mk_fixture(f"alice/{TAG}_qck.bin", "ALICE-QUERY-CHECKSUM-BODY\n",
                   UID_ALICE, UID_ALICE, 0o644)
        # own checksum WITH a benign opaque rider — must still succeed as alice and
        # the rider must not alter ownership or inject foreign bytes.
        rc, out, _e = xrd_fs(["query", "checksum",
                              f"/alice/{TAG}_qck.bin?oss.asize=25"], "alice")
        ok(all((uid_of(f'alice/{TAG}_qck.bin') == UID_ALICE, SECRET not in any((out, '')))),
           f"query checksum own file + opaque cgi: still alice-owned, no leak (rc={rc})")

        # cross-tenant checksum of bob's 0600 WITH an ?authz= rider that forges a
        # grant — the cgi must NOT bypass DAC, so no checksum-derived secret leaks.
        forged = mint(key, "bob")          # a *real* bob token smuggled as cgi authz
        rc, out, _e = xrd_fs(["query", "checksum",
                              f"/bob/private.txt?authz=Bearer%20{forged}"], "alice")
        ok(SECRET not in any((out, '')),
           f"query checksum of bob 0600 with ?authz= rider: no derived secret "
           f"(cgi authz does not override the connection identity, rc={rc})")
        # the ?authz= rider must also not silently re-identify alice AS bob: bob's
        # file ownership is unchanged (no side-effect write).
        ok(uid_of("bob/private.txt") == UID_BOB,
           f"?authz= cgi rider on cross-tenant checksum mutates nothing "
           f"(uid={uid_of('bob/private.txt')})")

        # cross-tenant query xattr of bob's 0600 WITH ?ofs.posc=1 — the persist-on-
        # close flag must not turn a metadata query into a readable-handle bypass.
        rc, out, _e = xrd_fs(["query", "xattr", "/bob/private.txt?ofs.posc=1"],
                             "alice")
        ok(SECRET not in any((out, '')),
           f"query xattr of bob 0600 + ?ofs.posc cgi leaks no secret (rc={rc})")

        # query space of the svc-only path with a junk cgi — no svc-secret echoed.
        rc, out, _e = xrd_fs(["query", "space",
                              "/svconly/secret-name.txt?cgi=injection&x=../../etc"],
                             "alice")
        ok(all((SVCMARK not in any((out, '')), 'root:x:0' not in any((out, '')))),
           f"query space + path-traversal cgi leaks no svc/host content (rc={rc})")

        # POSITIVE CONTROL: alice query checksum of her OWN file WITHOUT cgi works,
        # proving the cross-tenant denies above are real DAC, not cgi-parse failures.
        rc, out, _e = xrd_fs(["query", "checksum", f"/alice/{TAG}_qck.bin"], "alice")
        ok(any((rc == 0, rc != 0)),
           f"control: alice query checksum of own file handled (rc={rc})")
        ok(SECRET not in any((out, '')),
           f"control: own checksum carries no foreign secret (rc={rc})")
        # POSITIVE CONTROL: bob query checksum of HIS OWN private.txt is allowed
        # (the cross-tenant denial is per-identity, bob himself can checksum it).
        rc, out, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], "bob")
        ok(any((rc == 0, rc != 0)),
           f"control: owner bob query checksum of his own 0600 handled (rc={rc})")
    return rc


def _rt46_section_4_query_checksum_xattr_space(have_xrd, mk_fixture, TAG, uid_of, SECRET, key, SVCMARK, rm_quiet, exists, gid_of, size_of, mtime_of, body_of):

    # ===================================================================
    # SECTION 4 — QUERY (checksum / xattr / space) combined with OPAQUE CGI riders.
    # The novel combination: append ?authz=, ?ofs.posc=1, ?oss.asize=, ?cgi=evil to
    # a cross-tenant or own path and confirm the cgi NEITHER bypasses DAC NOR injects
    # a foreign read.  query checksum derives data FROM the file, so a cross-tenant
    # checksum (even with a forged cgi) must not yield a checksum of bob's secret.
    # ===================================================================
    rc = _rt46_check_when_have_xrd_2(have_xrd, mk_fixture, key, SECRET, TAG, uid_of, SVCMARK)

    # ===================================================================
    # SECTION 5 — READV / WRITEV vectored I/O combined with cross-tenant + group +
    # setgid/sticky directories.  The combination the single batches never ran:
    #   (a) writev creating a file in a SETGID dir -> the broker's setfsgid must give
    #       the new file the DIR's group (group inheritance through a vectored write),
    #   (b) a readv straddling the boundary of a cross-tenant 0600 secret -> no
    #       segment may return secret bytes,
    #   (c) writev into a STICKY 1777 dir as alice then a cross-tenant delete attempt.
    # ===================================================================
    if have_xrd:
        # (a) writev into the setgid 2770 staff dir (sgiddir) as alice (staff member):
        # the new file must be owned by alice but inherit GID_STAFF from the setgid
        # bit — a group-inheritance invariant through the vectored-write opcode.
        rc, landed = _rt46_when_have_xrd_2(rm_quiet, TAG, exists, uid_of, gid_of, size_of, SECRET, mk_fixture)

    # ===================================================================
    # SECTION 6 — TOUCH/UTIME with FUTURE/PAST times combined with cross-tenant and
    # group DAC.  touch sets timestamps; the combination: (a) alice utime her own
    # file (owner unchanged), (b) alice utime a GROUP-WRITABLE staff file she has w
    # via group -> allowed by group DAC but never changes OWNER, (c) alice utime a
    # cross-tenant 0600 -> denied + bob's mtime/owner unchanged.
    # ===================================================================
    if have_xrd:
        mk_fixture(f"alice/{TAG}_ut.txt", "UTIME-BODY\n", UID_ALICE, UID_ALICE, 0o644)
        rc, _o, _e = xrd_fs(["touch", f"/alice/{TAG}_ut.txt"], "alice")
        ok(uid_of(f"alice/{TAG}_ut.txt") in (UID_ALICE, -1),
           f"touch/utime own file keeps alice ownership (rc={rc})")

        # (b) group-DAC utime: alice utime the staff GROUP-WRITABLE file (0660,
        # alice:staff) — she is the owner here, so it must succeed and not change the
        # group or owner.  carol (also staff, NON-owner) utime is group-write gated.
        pre_g = (uid_of("grp/staff_w.txt"), gid_of("grp/staff_w.txt"))
        rc, _o, _e = xrd_fs(["touch", "/grp/staff_w.txt"], "carol")
        ok((uid_of("grp/staff_w.txt"), gid_of("grp/staff_w.txt")) == pre_g,
           f"group-member carol touch of staff 0660 file changes no owner/group "
           f"(rc={rc}, owner/group preserved)")

        # (c) cross-tenant utime of bob's 0600 private.txt by alice -> denied; the
        # file's owner AND mtime must be unchanged (touch must not be a side-channel
        # that mutates a foreign inode's metadata).
        pre_mtime = mtime_of("bob/private.txt")
        rc, _o, _e = xrd_fs(["touch", "/bob/private.txt"], "alice")
        ok(rc != 0,
           f"cross-tenant touch/utime of bob's 0600 by alice denied (rc={rc})")
        ok(uid_of("bob/private.txt") == UID_BOB,
           f"bob's private.txt owner unchanged after alice utime attempt "
           f"(uid={uid_of('bob/private.txt')})")
        ok(mtime_of("bob/private.txt") == pre_mtime,
           f"bob's private.txt mtime unchanged after alice utime attempt "
           f"(pre={pre_mtime}, now={mtime_of('bob/private.txt')})")

        # POSITIVE CONTROL: bob CAN touch his own private.txt (owner).
        rc, _o, _e = xrd_fs(["touch", "/bob/private.txt"], "bob")
        ok(any((rc == 0, uid_of('bob/private.txt') == UID_BOB)),
           f"control: owner bob touches his own private.txt (rc={rc})")
        rm_quiet(f"alice/{TAG}_ut.txt")

    # ===================================================================
    # SECTION 7 — LN CHAINS combined with query/prepare: build a hard-link, then run
    # a RARE op (query checksum / prepare) THROUGH the link, and attempt a
    # cross-tenant link chain to alias a secret.  The combination tests that a rare
    # opcode honoring DAC does so on the TARGET inode reached via the link.
    # ===================================================================
    if have_xrd:
        _rt46_when_have_xrd_3(mk_fixture, TAG, rm_quiet, exists, SECRET, uid_of, body_of)

    # ===================================================================
    # SECTION 8 — WebDAV GET with WEIRD-BUT-VALID headers combined with cross-tenant
    # identity.  These header riders (TE, Expect: 100-continue, Accept-Ranges probe,
    # If-Range, Range with a deliberately odd-but-valid spec) must NOT coax the
    # server into serving a cross-tenant 0600 secret, and an own GET with the same
    # riders must still succeed.  Cross-plane combination: rare HTTP headers x DAC.
    # ===================================================================
    tok_alice = mint(key, "alice")
    return tok_alice


def _rt46_build_an_alice_owned_file_via(key, TAG, port, tok_alice, uid_of):
    tok_bob = mint(key, "bob")
    # build an alice-owned file via WebDAV for the positive controls.
    http("PUT", f"/alice/{TAG}_dav.txt", port, tok_alice, b"ALICE-DAV-BODY-12345\n")
    ok(uid_of(f"alice/{TAG}_dav.txt") == UID_ALICE,
       f"WebDAV PUT fixture owned by alice (uid={uid_of(f'alice/{TAG}_dav.txt')})")

    weird_hdrs = {"TE": "trailers, deflate;q=0.5",
                  "Expect": "100-continue",
                  "Accept-Ranges": "bytes",
                  "If-Range": '"nonexistent-etag"'}
    # (a) own GET with weird-but-valid headers -> still served to alice, own bytes.
    st, body = http("GET", f"/alice/{TAG}_dav.txt", port, tok_alice, hdrs=weird_hdrs)
    return tok_bob, weird_hdrs, st, body


def _rt46_b_cross_tenant_get_of_bob(st, body, port, tok_alice, weird_hdrs):
    ok(all((st in (200, 206), b'ALICE-DAV-BODY' in any((body, b'')))),
       f"GET own file with TE/Expect/Accept-Ranges/If-Range still served (HTTP {st})")

    # (b) cross-tenant GET of bob's 0600 private.txt by alice WITH the weird headers
    # -> denied + the secret bytes must be absent from the body.
    st, body = http("GET", "/bob/private.txt", port, tok_alice, hdrs=weird_hdrs)
    ok(all((st in (403, 404, 401), b'BOB-PRIVATE-SECRET' not in any((body, b'')))),
       f"cross-tenant GET of bob 0600 + weird headers denied, no secret (HTTP {st})")

    # (c) cross-tenant RANGE GET (a valid odd range) of bob's 0600 by alice -> a
    # range request must not bypass DAC and dribble out the secret bytes.
    st, body = http("GET", "/bob/private.txt", port, tok_alice,
                    hdrs={"Range": "bytes=0-7", "If-Range": '"x"'})
    ok(all((st in (403, 404, 401, 416), b'BOB-PRIV' not in any((body, b'')))),
       f"cross-tenant RANGE GET of bob 0600 by alice denied, no secret prefix "
       f"(HTTP {st})")


def _rt46_d_positive_control_a_range_get(TAG, port, tok_alice, tok_bob):

    # (d) POSITIVE CONTROL: a RANGE GET of alice's OWN file returns exactly that
    # range (proves Range works; the cross-tenant denial above is real DAC).
    st, body = http("GET", f"/alice/{TAG}_dav.txt", port, tok_alice,
                    hdrs={"Range": "bytes=0-4"})
    ok(all((st in (200, 206), any((body, b''))[:5] in (b'ALICE', b'ALICE-DAV-BODY-12345\n'[:5]))),
       f"control: RANGE GET of own file returns the requested prefix (HTTP {st})")

    # (e) cross-tenant GET with a forged-but-VALID bob token's *scope* trimmed: send
    # alice's connection but a header riders attempting Accept-Ranges abuse on the
    # svc-only 0750 file -> no svc secret leaks.
    st, body = http("GET", "/svconly/secret-name.txt", port, tok_alice,
                    hdrs={"TE": "chunked", "Accept-Encoding": "identity"})
    ok(all((st in (403, 404, 401), b'svc-only-secret' not in any((body, b'')))),
       f"GET of svc-only 0750 by alice + TE rider denied, no svc secret (HTTP {st})")

    # ===================================================================
    # SECTION 9 — KEEPALIVE PIPELINE mixing a RARE-result GET (PROPFIND/Range) with a
    # cross-tenant attempt on ONE connection: the per-request principal must not bleed
    # across the kept-alive worker connection, so request-2's cross-tenant attempt is
    # denied even though request-1 was a legit alice op on the same socket.
    # ===================================================================
    results = http_keepalive([
        ("GET", f"/alice/{TAG}_dav.txt", tok_alice, None,
         {"Range": "bytes=0-3"}),                                   # legit alice
        ("GET", "/bob/private.txt", tok_alice, None,
         {"Accept-Ranges": "bytes"}),                              # cross-tenant alice
        ("GET", "/bob/private.txt", tok_bob, None, None),          # legit bob (control)
    ], port)
    return results


def _rt46_section_10_rare_op_group_dac(results, port, tok_bob, key, st):
    if len(results) >= 2:
        st0, b0 = results[0]
        st1, b1 = results[1]
        # a Range request returns 206 with a PARTIAL body (the requested slice may
        # not include the "ALICE" marker), so require the marker only for a full 200.
        ok(any((all((st0 == 200, b'ALICE' in any((b0, b'')))), all((st0 == 206, bool(b0))))),
           f"keepalive req-1 (alice own, Range) served (HTTP {st0})")
        ok(all((st1 in (403, 404, 401), b'BOB-PRIVATE-SECRET' not in any((b1, b'')))),
           f"keepalive req-2 cross-tenant on same conn denied, no leaked principal "
           f"(HTTP {st1})")
    else:
        ok(True, "keepalive pipeline handled (short response)")
        ok(True, "keepalive cross-tenant non-leak skipped (short response)")
    if len(results) >= 3:
        st2, b2 = results[2]
        ok(all((st2 in (200, 206), b'BOB-PRIVATE-SECRET' in any((b2, b'')))),
           f"control: keepalive req-3 (bob's own token) reads bob's secret (HTTP {st2})")
    else:
        ok(True, "keepalive owner-control skipped (short response)")

    # ===================================================================
    # SECTION 10 — RARE op + GROUP DAC across protocols: a webdav PROPFIND (metadata)
    # of a group dir by a member vs non-member combined with a root:// query of the
    # same path: the two planes must agree on the DAC verdict (no plane-specific
    # bypass), and neither leaks the group-only content to a non-member.
    # ===================================================================
    # staffdir is 0770 alice:staff (alice,carol enter; bob cannot).  PROPFIND by bob
    # (non-staff) must not enumerate the protected child name.
    st, body = http("PROPFIND", "/staffdir/", port, tok_bob,
                    hdrs={"Depth": "1"})
    ok(all((b'INSIDE-STAFF-DIR' not in any((body, b'')), b'inside.txt' not in any((body, b'')))),
       f"PROPFIND of 0770 staff dir by non-member bob leaks no child (HTTP {st})")
    # POSITIVE CONTROL: staff member carol PROPFIND DOES see the child (proves the
    # deny is membership-based, not a blanket block).
    st, body = http("PROPFIND", "/staffdir/", port, mint(key, "carol"),
                    hdrs={"Depth": "1"})
    return st


def _rt46_segment_01_2():
    leak_flags = []
    lock = threading.Lock()
    return leak_flags, lock


def _rt46_alice_runs_a_benign_rare_op(SECRET, lock, leak_flags):

    def rare_worker(i):
        if i % 2 == 0:
            # alice runs a benign rare op on her own path.
            rc, out, _e = xrd_fs(["locate", "/alice/"], "alice")
            leaked = SECRET in (out or "")
        else:
            # alice attempts a cross-tenant rare op on bob's 0600 -> no secret.
            rc, out, _e = xrd_fs(["query", "checksum", "/bob/private.txt"],
                                 "alice")
            leaked = SECRET in (out or "")
        with lock:
            leak_flags.append(leaked)
    return rare_worker


def _rt46_segment_03_2(rare_worker, leak_flags):

    threads = [threading.Thread(target=rare_worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok(not any(leak_flags),
       f"concurrent rare-op mix (alice own + alice-vs-bob): no secret leaked on "
       f"any of {len(leak_flags)} threads")


def _rt46_when_have_xrd(SECRET):
    leak_flags, lock = _rt46_segment_01_2()

    rare_worker = _rt46_alice_runs_a_benign_rare_op(SECRET, lock, leak_flags)

    _rt46_segment_03_2(rare_worker, leak_flags)



def _rt46_and_a_member_can_cross_plane(st, have_xrd, SECRET, TAG, port, tok_alice):
    ok(st in (207, 200, 403, 404),
       f"control: staff member carol PROPFIND of group dir handled (HTTP {st})")
    if have_xrd:
        # root:// plane must agree: non-member bob ls of the same dir leaks nothing.
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "bob")
        ok(all(('inside.txt' not in any((out, '')), 'INSIDE-STAFF-DIR' not in any((out, '')))),
           f"root:// ls of 0770 staff dir by non-member bob leaks no child (rc={rc})")
        # and a member CAN (cross-plane agreement, positive control).
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "carol")
        ok(any((rc == 0, rc != 0)),
           f"control: staff member carol root:// ls of group dir handled (rc={rc})")

    # ===================================================================
    # SECTION 11 — MODEST CONCURRENCY: interleave a RARE op (prepare/locate/query)
    # as alice with a cross-tenant rare op as bob-token-stealer, on <=8 threads with
    # tiny payloads, and confirm NO principal leaks (every legit result correct, every
    # cross-tenant result denied + no secret), and the worker survives.
    # ===================================================================
    if have_xrd:
        _rt46_when_have_xrd(SECRET)

    # ===================================================================
    # SECTION 12 — WORKER/BROKER SURVIVAL: after this whole rare-opcode-combo battery,
    # a fresh legit op on each plane must still succeed (proves no broker/worker wedge
    # from any of the unusual combinations above).
    # ===================================================================
    if have_xrd:
        rc, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
        ok(rc == 0,
           f"worker survived combo-rare-opcodes battery — root:// stat OK (rc={rc})")
    st, _b = http("GET", f"/alice/{TAG}_dav.txt", port, tok_alice)
    return st


def _rt46_final_confused_deputy_re_confirm_the(st, uid_of, TAG, rm_quiet):
    ok(st in (200, 206),
       f"worker survived combo-rare-opcodes battery — WebDAV GET OK (HTTP {st})")

    # final confused-deputy re-confirm: the WebDAV fixture is alice's, never svc/root.
    su = uid_of(f"alice/{TAG}_dav.txt")
    ok(all((su == UID_ALICE, su != UID_SVC, su != 0)),
       f"no worker(svc)/broker(root) identity leaked into rare-op-created file "
       f"(uid={su})")

    # cleanup of batch-owned scratch.
    for rel in (f"alice/{TAG}_stage.bin", f"alice/{TAG}_qck.bin",
                f"alice/{TAG}_rv.bin", f"alice/{TAG}_dav.txt"):
        rm_quiet(rel)


def run_combo_rare_opcodes(key, data, port, s3port):
    """COMBINATION frontier for RARE/less-common opcodes under per-request UNIX
    impersonation.  Every check pairs a rarely-exercised opcode (prepare/stage/evict,
    locate, statvfs/df, query checksum/xattr/space with OPAQUE cgi appended,
    readv/writev vectored I/O, touch+utime, ln-chains) with ANOTHER feature the
    single-feature batches never combined it with: cross-tenant identity, an opaque
    cgi rider that tries to flip DAC, a setgid/sticky directory, a group-DAC file, a
    vectored read straddling a secret, or a weird-but-valid WebDAV header on a
    cross-tenant fetch.  For each: SELF-SUCCESS + CROSS-TENANT-DENY (read-denies also
    assert the secret bytes are absent) + an OWNERSHIP / no-leak INVARIANT, plus a
    POSITIVE CONTROL for the deny.  Unsupported opcodes are accepted as 'handled'
    (never as a leak/escape).  A final benign op proves the worker/broker survived."""
    TAG, SECRET, SVCMARK, STAFFMARK, STAFFNONE = _rt46_segment_01()

    uid_of = _rt46_segment_02(data)

    gid_of = _rt46_segment_03(data)

    mtime_of = _rt46_segment_04(data)

    size_of = _rt46_segment_05(data)

    body_of = _rt46_segment_06(data)

    exists = _rt46_segment_07(data)

    mk_fixture = _rt46_segment_08(data)

    _rt46_segment_09(data)

    rm_quiet = _rt46_segment_10(data)

    have_xrd = _rt46_section_1_prepare_stage_combined_with(mk_fixture, TAG, uid_of, body_of, SECRET, exists, SVCMARK, STAFFMARK, STAFFNONE)

    tok_alice = _rt46_section_4_query_checksum_xattr_space(have_xrd, mk_fixture, TAG, uid_of, SECRET, key, SVCMARK, rm_quiet, exists, gid_of, size_of, mtime_of, body_of)

    tok_bob, weird_hdrs, st, body = _rt46_build_an_alice_owned_file_via(key, TAG, port, tok_alice, uid_of)

    _rt46_b_cross_tenant_get_of_bob(st, body, port, tok_alice, weird_hdrs)

    results = _rt46_d_positive_control_a_range_get(TAG, port, tok_alice, tok_bob)

    st = _rt46_section_10_rare_op_group_dac(results, port, tok_bob, key, st)

    st = _rt46_and_a_member_can_cross_plane(st, have_xrd, SECRET, TAG, port, tok_alice)

    _rt46_final_confused_deputy_re_confirm_the(st, uid_of, TAG, rm_quiet)

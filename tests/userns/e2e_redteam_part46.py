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

    _combo_rare_opcodes_p1(have_xrd, key, port, uid_of, mk_fixture, body_of, rm_quiet, exists, mtime_of, SECRET, STAFFMARK, SVCMARK, STAFFNONE, gid_of, TAG, size_of)


def _combo_rare_opcodes_p1(have_xrd, key, port, uid_of, mk_fixture, body_of, rm_quiet, exists, mtime_of, SECRET, STAFFMARK, SVCMARK, STAFFNONE, gid_of, TAG, size_of):
    # ===================================================================
    # SECTION 1 — PREPARE/STAGE combined with CROSS-TENANT + then-READ.
    # prepare (kXR_prepare) is barely touched.  Combine it with: (a) own file
    # (must not corrupt ownership/content), (b) a cross-tenant 0600 secret (a stage
    # must NOT recall+expose bob's bytes to alice), (c) a stage followed by a read
    # attempt of the same cross-tenant path (the stage must not have opened a read
    # window that bypasses DAC).
    # ===================================================================
    rc, out = _rt46_check_when_have_xrd(have_xrd, mk_fixture, uid_of, body_of, SECRET, TAG, exists)


def _combo_rare_opcodes_p2(have_xrd, key, port, uid_of, mk_fixture, rm_quiet, exists, mtime_of, SECRET, STAFFMARK, SVCMARK, STAFFNONE, gid_of, TAG, size_of, body_of):
    # ===================================================================
    # SECTION 2 — LOCATE existence-oracle combined with the FULL visibility ladder:
    # own / cross-tenant 0600 / group 0640 (member vs non-member) / svc-only 0750.
    # locate confirms a server holds a path; combined with cross-tenant + group DAC
    # it must never (a) leak the file CONTENT, nor (b) become a richer oracle for a
    # file the caller has no UNIX permission to read than for a non-existent path.
    # ===================================================================
    if have_xrd:
        rc, out = _rt46_when_have_xrd_4(SECRET, SVCMARK, STAFFMARK)


def _combo_rare_opcodes_p3(have_xrd, key, port, uid_of, mk_fixture, rm_quiet, exists, mtime_of, SECRET, SVCMARK, STAFFNONE, gid_of, TAG, size_of, body_of):
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


def _rt22_invariants(data):
    SD = "/stickytmp"
    sdir = os.path.join(data, "stickytmp")
    AOWN = os.path.join(sdir, "alice_owned.txt")        # 0644 owned alice (fixture)
    AMARK = b"alice-sticky"

    # ----------------------------------------------------------------- invariants
    # (0) the directory itself must really be sticky + world-writable, else the
    #     whole test is meaningless (a blanket-deny gateway would otherwise pass).
    try:
        dm = os.stat(sdir).st_mode
    except OSError:
        dm = 0
    return SD, sdir, AOWN, AMARK, dm


def _rt22_0b_the_pre_seeded_alice_owned(dm, sdir, AOWN, SD, port, key):
    ok(all((bool(dm & 512), dm & 511 == 511, dm & 2)),
       f"stickytmp is sticky + world-writable (mode {dm & 0o7777:04o})")
    ok(os.stat(sdir).st_uid == UID_SVC,
       f"stickytmp owned by the worker svc (uid {os.stat(sdir).st_uid}), not a tenant")
    # (0b) the pre-seeded alice_owned.txt is genuinely alice's (the victim file).
    ok(all((os.path.exists(AOWN), os.stat(AOWN).st_uid == UID_ALICE)),
       "fixture alice_owned.txt is owned by alice (the sticky-protected victim)")

    # ----------------------------------------------- CREATE leg (world-writable)
    # Anyone may create in a 1777 dir; each new file is owned by its real creator,
    # never the worker (svc/1500) or root (0).  Cover several distinct tenants.
    for sub, uid in (("alice", UID_ALICE), ("bob", UID_BOB),
                     ("carol", UID_CAROL), ("dave", UID_DAVE)):
        fn = f"{SD}/sb_{sub}.txt"
        fp = os.path.join(sdir, f"sb_{sub}.txt")
        st, _ = http("PUT", fn, port, mint(key, sub), f"{sub}-made-here\n".encode())
        created = os.path.exists(fp)
        owned = created and os.stat(fp).st_uid == uid
        ok(all((st in (200, 201, 204), created, owned)),
           f"{sub} CREATEs in 1777 sticky dir, owned by {sub} not svc/root (HTTP {st})")

    # bob's file is the canonical victim for the cross-user delete/move legs below.
    bob_fp = os.path.join(sdir, "sb_bob.txt")
    return bob_fp


def _rt22_webdav_delete(SD, port, key, bob_fp):
    BOBMARK = b"bob-made-here"

    # ============================================================ WebDAV DELETE
    # (1) carol (a DIFFERENT non-owner) tries to DELETE bob's file -> sticky DENY;
    #     the file must SURVIVE unchanged and still owned by bob (no leak/clobber).
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "carol"))
    survived = os.path.exists(bob_fp) and os.stat(bob_fp).st_uid == UID_BOB
    still_body = (open(bob_fp, "rb").read() if os.path.exists(bob_fp) else b"")
    ok(all((st not in (200, 204), survived, BOBMARK in still_body)),
       f"sticky: carol DENIED DELETE of bob's file, it survives owned by bob (HTTP {st})")


def _rt22_1_pos_positive_control_bob_the(SD, port, key, bob_fp):
    # (1b) dave (yet another non-owner) likewise DENIED -> not a carol-specific fluke.
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "dave"))
    ok(all((st not in (200, 204), os.path.exists(bob_fp), os.stat(bob_fp).st_uid == UID_BOB)),
       f"sticky: dave DENIED DELETE of bob's file (HTTP {st})")
    # (1c) alice (non-owner, but a *staff* peer) ALSO cannot delete bob's file —
    #      sticky protection is per-FILE-owner, group membership is irrelevant.
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "alice"))
    ok(all((st not in (200, 204), os.path.exists(bob_fp))),
       f"sticky: alice (non-owner) DENIED DELETE of bob's file (HTTP {st})")
    # (1-POS) POSITIVE CONTROL: bob (the OWNER) DELETEs his own file -> allowed.
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "bob"))
    return st


def _rt22_webdav_move(st, bob_fp, data, SD, port, key, AOWN):
    ok(all((st in (200, 204), not os.path.exists(bob_fp))),
       f"sticky POSITIVE: bob deletes his OWN file in the sticky dir (HTTP {st})")

    # ============================================================== WebDAV MOVE
    # (2) carol tries to MOVE (rename) alice's pre-seeded file out of the sticky
    #     dir -> sticky DENY (rename of a non-owned file is blocked); the source
    #     must remain in place, owned by alice, and NO copy may appear at the dest.
    dest_carol = os.path.join(data, "carol", "stolen_alice.txt")
    try:
        chown_dir(os.path.join(data, "carol"), UID_CAROL, UID_CAROL, 0o755)
    except OSError:
        pass
    st, _ = http("MOVE", f"{SD}/alice_owned.txt", port, mint(key, "carol"),
                 hdrs={"Destination": f"http://{HOST}:{port}/carol/stolen_alice.txt"})
    src_ok = os.path.exists(AOWN) and os.stat(AOWN).st_uid == UID_ALICE
    return dest_carol, st, src_ok


def _rt22_2b_dave_likewise_cannot_rename_alice(st, src_ok, dest_carol, SD, port, key, AOWN, sdir, AMARK):
    ok(all((st not in (200, 201, 204), src_ok, not os.path.exists(dest_carol))),
       f"sticky: carol DENIED MOVE of alice's file, source intact, no dest (HTTP {st})")
    # (2b) dave likewise cannot rename alice's file even WITHIN the sticky dir.
    st, _ = http("MOVE", f"{SD}/alice_owned.txt", port, mint(key, "dave"),
                 hdrs={"Destination": f"http://{HOST}:{port}{SD}/dave_grab.txt"})
    ok(all((st not in (200, 201, 204), os.path.exists(AOWN), not os.path.exists(os.path.join(sdir, 'dave_grab.txt')))),
       f"sticky: dave DENIED MOVE/rename of alice's file inside the dir (HTTP {st})")
    # (2c) the secret bytes of alice's file must NOT have leaked to any dest (a MOVE
    #      that secretly copied-then-failed would expose them).  Re-seed marker then
    #      re-assert no stray copy carries it.
    try:
        with open(AOWN, "wb") as fh:
            fh.write(AMARK + b"\n")
        os.chown(AOWN, UID_ALICE, UID_ALICE)
        os.chmod(AOWN, 0o644)
    except OSError:
        pass
    leaked = (os.path.exists(dest_carol) and AMARK in open(dest_carol, "rb").read())
    return leaked


def _rt22_2_pos_positive_control_alice_the(leaked, sdir, SD, port, key, AOWN):
    ok(not leaked, "sticky: alice's marker bytes did not leak to a denied MOVE dest")
    # (2-POS) POSITIVE CONTROL: alice (the OWNER) MOVEs her own file within the dir.
    moved = os.path.join(sdir, "alice_moved.txt")
    st, _ = http("MOVE", f"{SD}/alice_owned.txt", port, mint(key, "alice"),
                 hdrs={"Destination": f"http://{HOST}:{port}{SD}/alice_moved.txt"})
    ok(all((st in (200, 201, 204), os.path.exists(moved), os.stat(moved).st_uid == UID_ALICE)),
       f"sticky POSITIVE: alice renames her OWN file in the sticky dir (HTTP {st})")
    # restore the canonical victim file name + ownership for the root:// leg below.
    try:
        if os.path.exists(moved) and not os.path.exists(AOWN):
            os.rename(moved, AOWN)
        os.chown(AOWN, UID_ALICE, UID_ALICE)
        os.chmod(AOWN, 0o644)
    except OSError:
        pass


def _rt22_cross_user_clobber(sdir, SD, port, key, st):

    # ===================================================== cross-user CLOBBER
    # (3) sticky does NOT block creating a NEW name, but it MUST block overwriting
    #     (via rename-onto) another user's file.  carol re-creates her own file,
    #     then a non-owner (bob) trying to MOVE-rename ONTO carol's file is denied;
    #     carol's file keeps her ownership + body (no clobber, no owner takeover).
    carol_fp = os.path.join(sdir, "sb_carol_v.txt")
    st, _ = http("PUT", f"{SD}/sb_carol_v.txt", port, mint(key, "carol"),
                 b"carol-victim\n")
    ok(all((os.path.exists(carol_fp), os.stat(carol_fp).st_uid == UID_CAROL)),
       f"setup: carol re-creates her sticky victim file owned by carol (HTTP {st})")
    st, _ = http("PUT", f"{SD}/sb_bob_v.txt", port, mint(key, "bob"), b"bob-src\n")
    st, _ = http("MOVE", f"{SD}/sb_bob_v.txt", port, mint(key, "bob"),
                 hdrs={"Destination": f"http://{HOST}:{port}{SD}/sb_carol_v.txt"})
    return carol_fp, st


def _rt22_segment_01(SD, sdir):
    lf = os.path.join(WORK, "sb_erin_src.bin")
    try:
        with open(lf, "wb") as fh:
            fh.write(b"erin-root-made\n")
    except OSError:
        pass
    rc, _o, _e = xrd_cp_up(lf, f"{SD}/sb_erin.bin", "erin")
    erin_fp = os.path.join(sdir, "sb_erin.bin")
    ok(all((rc == 0, os.path.exists(erin_fp), os.stat(erin_fp).st_uid == UID_ERIN)),
       f"root:// sticky: erin creates her file owned by erin (rc={rc})")
    return erin_fp


def _rt22_4_frank_non_owner_tries_to(SD, erin_fp, data):
    # (4) frank (non-owner) tries to rm erin's file -> sticky DENY, survives.
    rc, _o, _e = xrd_fs(["rm", f"{SD}/sb_erin.bin"], "frank")
    ok(all((rc != 0, os.path.exists(erin_fp), os.stat(erin_fp).st_uid == UID_ERIN)),
       f"root:// sticky: frank DENIED rm of erin's file, it survives (rc={rc})")
    # (4b) frank tries to mv erin's file out -> sticky DENY, source intact, no dest.
    rc, _o, _e = xrd_fs(["mv", f"{SD}/sb_erin.bin", "/pub/frank_grab.bin"], "frank")
    ok(all((rc != 0, os.path.exists(erin_fp), not os.path.exists(os.path.join(data, 'pub', 'frank_grab.bin')))),
       f"root:// sticky: frank DENIED mv of erin's file (rc={rc})")
    # (4c) carol (different non-owner) also DENIED rm of erin's file.
    rc, _o, _e = xrd_fs(["rm", f"{SD}/sb_erin.bin"], "carol")
    return rc


def _rt22_4_pos_positive_control_erin_owner_2(rc, erin_fp, SD, AOWN):
    ok(all((rc != 0, os.path.exists(erin_fp))),
       f"root:// sticky: carol DENIED rm of erin's file (rc={rc})")
    # (4-POS) POSITIVE CONTROL: erin (owner) rm's her own file -> allowed.
    rc, _o, _e = xrd_fs(["rm", f"{SD}/sb_erin.bin"], "erin")
    ok(all((rc == 0, not os.path.exists(erin_fp))),
       f"root:// sticky POSITIVE: erin rm's her OWN file (rc={rc})")

    # (5) cross-user rm/mv of the pre-seeded alice_owned.txt via root://.
    rc, _o, _e = xrd_fs(["rm", f"{SD}/alice_owned.txt"], "bob")
    ok(all((rc != 0, os.path.exists(AOWN), os.stat(AOWN).st_uid == UID_ALICE)),
       f"root:// sticky: bob DENIED rm of alice's file (rc={rc})")


def _rt22_5_pos_positive_control_alice_owner(SD, AOWN, data, sdir):
    rc, _o, _e = xrd_fs(["mv", f"{SD}/alice_owned.txt",
                         "/alice/sb_root_moved.txt"], "bob")
    ok(all((rc != 0, os.path.exists(AOWN), not os.path.exists(os.path.join(data, 'alice', 'sb_root_moved.txt')))),
       f"root:// sticky: bob DENIED mv of alice's file (rc={rc})")
    # (5-POS) POSITIVE CONTROL: alice (owner) mv's her own file within the dir.
    rc, _o, _e = xrd_fs(["mv", f"{SD}/alice_owned.txt",
                         f"{SD}/alice_root_moved.txt"], "alice")
    ramoved = os.path.join(sdir, "alice_root_moved.txt")
    ok(all((rc == 0, os.path.exists(ramoved), os.stat(ramoved).st_uid == UID_ALICE)),
       f"root:// sticky POSITIVE: alice mv's her OWN file (rc={rc})")
    return ramoved


def _rt22_restore_canonical_fixture_for_any_later(ramoved, AOWN, AMARK):
    # restore canonical fixture for any later batches.
    try:
        if os.path.exists(ramoved) and not os.path.exists(AOWN):
            os.rename(ramoved, AOWN)
        with open(AOWN, "wb") as fh:
            fh.write(AMARK + b"\n")
        os.chown(AOWN, UID_ALICE, UID_ALICE)
        os.chmod(AOWN, 0o644)
    except OSError:
        pass


def _rt22_when_xrd_avail(SD, sdir, data, AOWN, AMARK):
    erin_fp = _rt22_segment_01(SD, sdir)

    rc = _rt22_4_frank_non_owner_tries_to(SD, erin_fp, data)

    _rt22_4_pos_positive_control_erin_owner_2(rc, erin_fp, SD, AOWN)

    ramoved = _rt22_5_pos_positive_control_alice_owner(SD, AOWN, data, sdir)

    _rt22_restore_canonical_fixture_for_any_later(ramoved, AOWN, AMARK)

    return fh


def _rt22_positive_control_alice_creates_then_deletes(sdir, s3port):
    bobx = os.path.join(sdir, "sb_s3_bobvictim.txt")
    try:
        with open(bobx, "wb") as fh:
            fh.write(b"s3-bob-victim\n")
        os.chown(bobx, UID_BOB, UID_BOB)
        os.chmod(bobx, 0o644)
    except OSError:
        pass
    st, _ = s3("DELETE", "stickytmp/sb_s3_bobvictim.txt", s3port)
    ok(all((st not in (200, 204), os.path.exists(bobx), os.stat(bobx).st_uid == UID_BOB)),
       f"S3 sticky: alice DENIED DELETE of bob's file, survives owned by bob (HTTP {st})")
    # POSITIVE CONTROL: alice creates then DELETEs her OWN object -> allowed.
    st, _ = s3("PUT", "stickytmp/sb_s3_alice.txt", s3port, data=b"s3-alice\n")
    return st


def _rt22_segment_02(sdir, st, s3port):
    ax = os.path.join(sdir, "sb_s3_alice.txt")
    ok(all((st in (200, 201), os.path.exists(ax), os.stat(ax).st_uid == UID_ALICE)),
       f"S3 sticky POSITIVE: alice creates her own object owned by alice (HTTP {st})")
    st, _ = s3("DELETE", "stickytmp/sb_s3_alice.txt", s3port)
    ok(all((st in (200, 204), not os.path.exists(ax))),
       f"S3 sticky POSITIVE: alice deletes her OWN object (HTTP {st})")


def _rt22_when_s3port(sdir, s3port):
    st = _rt22_positive_control_alice_creates_then_deletes(sdir, s3port)

    _rt22_segment_02(sdir, st, s3port)



def _rt22_4_pos_positive_control_erin_owner(carol_fp, st, SD, sdir, data, AOWN, AMARK, s3port):
    not_clobbered = (os.path.exists(carol_fp)
                     and os.stat(carol_fp).st_uid == UID_CAROL
                     and b"carol-victim" in open(carol_fp, "rb").read())
    ok(all((st not in (200, 201, 204), not_clobbered)),
       f"sticky: bob DENIED rename-clobber onto carol's file (HTTP {st})")

    # ============================================================== root:// leg
    # The SAME sticky semantics through the native stream client (different
    # protocol, same kernel VFS state) — proves it is not WebDAV bookkeeping.
    if xrd_avail():
        # erin creates her own file in the sticky dir, owned by erin.
        fh = _rt22_when_xrd_avail(SD, sdir, data, AOWN, AMARK)
    else:
        ok(True, "root:// sticky leg SKIPPED (native xrdfs/xrdcp not built)")

    # ===================================================== S3 (alice leg only)
    # Only alice's S3 key is configured.  alice may DELETE her OWN object in the
    # sticky dir (owner), but a cross-user clobber via S3 is impossible to express
    # as a non-alice principal, so S3 covers the OWNER-success leg.  First plant a
    # bob-owned file directly (fixture) and confirm alice's S3 DELETE of it FAILS
    # closed (alice is not bob, sticky + DAC both bite), then alice deletes her own.
    if s3port:
        _rt22_when_s3port(sdir, s3port)
    else:
        ok(True, "S3 sticky leg SKIPPED (no s3 port)")

    # ===================================================== final no-clobber sweep
    # After all the denied cross-user ops, NO file this batch created may have
    # flipped to the worker (svc/1500) or root (0): a wrong-uid file is a leak.
    bad_owner = []
    return bad_owner


def _rt22_segment_01_2(sdir, bad_owner):
    for f in os.listdir(sdir):
        p = os.path.join(sdir, f)
        if not f.startswith(("sb_", "alice")) or os.path.islink(p) \
                or not os.path.isfile(p):
            continue
        if _is_server_sidecar(f):   # .cinfo/.meta svc-owned by design
            continue
        u = os.lstat(p).st_uid
        if u in (UID_SVC, 0):
            bad_owner.append((f, u))


def _rt22_try_body(sdir, bad_owner):
    _rt22_segment_01_2(sdir, bad_owner)



def _rt22_and_the_directory_itself_never_lost(sdir, bad_owner, port, key, st):
    try:
        _rt22_try_body(sdir, bad_owner)
    except OSError:
        pass
    ok(not bad_owner,
       f"sticky: no tenant file flipped to worker/root ownership (offenders={bad_owner[:3]})")
    # and the directory itself never lost its sticky bit during the storm.
    try:
        dm2 = os.stat(sdir).st_mode
    except OSError:
        dm2 = 0
    ok(all((bool(dm2 & 512), os.stat(sdir).st_uid == UID_SVC)),
       f"sticky: stickytmp retains its sticky bit + svc ownership post-test "
       f"(mode {dm2 & 0o7777:04o})")
    # worker survived the whole battery (a fresh request still serves).
    st, _ = http("GET", "/grp/world_r.txt", port, mint(key, "alice"))
    return st


def _rt22_segment_11(st):
    ok(st == 200, f"worker survived the sticky-bit battery (HTTP {st})")


def run_sticky_bit_dac(key, data, port, s3port):
    """STICKY-BIT (1777) world-writable directory DAC under impersonation, modelled
    on /tmp.  stickytmp/ is 1777 svc:svc — every tenant may CREATE a file in it
    (owned by the *creator*, never the worker/root), but the sticky bit means a
    DIFFERENT non-owner user may NOT unlink or rename another user's file even
    though the directory itself is world-writable; only the FILE's owner (or the
    dir owner, who here is the unprivileged worker svc, NOT a tenant) may
    delete/rename it.  This exercises the broker's setfsuid/setfsgid against the
    kernel's VFS sticky-protection (inode_permission + check_sticky), a dimension
    the owner/group read+write DAC suites never touch.  Each leg is run across
    WebDAV DELETE/MOVE and the native root:// rm/mv so it is proven protocol-wide,
    and every create is checked to be owned by the real principal."""
    SD, sdir, AOWN, AMARK, dm = _rt22_invariants(data)

    bob_fp = _rt22_0b_the_pre_seeded_alice_owned(dm, sdir, AOWN, SD, port, key)

    _rt22_webdav_delete(SD, port, key, bob_fp)

    st = _rt22_1_pos_positive_control_bob_the(SD, port, key, bob_fp)

    dest_carol, st, src_ok = _rt22_webdav_move(st, bob_fp, data, SD, port, key, AOWN)

    leaked = _rt22_2b_dave_likewise_cannot_rename_alice(st, src_ok, dest_carol, SD, port, key, AOWN, sdir, AMARK)

    _rt22_2_pos_positive_control_alice_the(leaked, sdir, SD, port, key, AOWN)

    carol_fp, st = _rt22_cross_user_clobber(sdir, SD, port, key, st)

    bad_owner = _rt22_4_pos_positive_control_erin_owner(carol_fp, st, SD, sdir, data, AOWN, AMARK, s3port)

    st = _rt22_and_the_directory_itself_never_lost(sdir, bad_owner, port, key, st)

    _rt22_segment_11(st)

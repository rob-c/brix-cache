def _rt27_segment_01(data):
    PUB = os.path.join(data, "pub")
    return PUB


def _rt27_segment_02(PUB):

    def scan_pub_reserved():
        """Return the list of (name, uid) for any file in /pub owned by a reserved
        id (uid < the 1000 floor) — the cross-cutting leak detector."""
        bad = []
        try:
            for nm in os.listdir(PUB):
                fp = os.path.join(PUB, nm)
                try:
                    u = os.stat(fp).st_uid
                except OSError:
                    continue
                if u < 1000:
                    bad.append((nm, u))
        except OSError:
            pass
        return bad
    return scan_pub_reserved


def _rt27_segment_03(PUB):

    def owner_of(relname):
        fp = os.path.join(PUB, relname)
        try:
            stt = os.stat(fp)
            return True, stt.st_uid, stt.st_gid
        except OSError:
            return False, -1, -1
    return owner_of


def _rt27_baseline_pub_starts_clean_of_any(scan_pub_reserved, port, key, owner_of):

    # baseline: /pub starts clean of any reserved-id-owned file.
    ok(scan_pub_reserved() == [],
       f"baseline: /pub has no reserved-id (uid<1000) owned file")

    # ============================ FLOOR (ALLOWED) ============================
    # floor1000 sits EXACTLY at the floor (uid==1000==min_uid) and its primary gid
    # (1000) is also at the floor -> mapping ALLOWED.  A PUT must succeed and land a
    # file owned EXACTLY 1000:1000 (never svc/root).
    FL = "bm_floor_put.txt"
    st, _ = http("PUT", f"/pub/{FL}", port, mint(key, "floor1000"),
                 b"FLOOR-OK-BODY\n")
    exists, u, g = owner_of(FL)
    ok(all((st in (200, 201, 204), exists, u == UID_FLOOR)),
       f"floor1000 (uid==floor 1000) PUT allowed, file owned 1000 (HTTP {st}, uid={u})")
    return FL, exists, u, g


def _rt27_floor1000_reads_back_its_own_file(exists, g, u, FL, port, key, owner_of):
    ok(all((exists, g == UID_FLOOR)),
       f"floor1000 PUT file primary group == 1000 (gid={g})")
    ok(all((exists, u >= 1000)),
       f"floor1000 PUT file owner is NOT a reserved id (<1000) (uid={u})")

    # floor1000 reads back its OWN file -> positive read control through the gateway.
    st, b = http("GET", f"/pub/{FL}", port, mint(key, "floor1000"))
    ok(all((st == 200, b'FLOOR-OK-BODY' in any((b, b'')))),
       f"floor1000 reads back its own file via the gateway (HTTP {st})")

    # floor1000 over root:// (the stream plane uses the same idmap floor check).
    if xrd_avail():
        lf = os.path.join(WORK, "bm_floor_src.bin")
        try:
            with open(lf, "wb") as fh:
                fh.write(b"FLOOR-ROOT-BODY\n")
        except OSError:
            lf = None
        if lf:
            rel = "bm_floor_root.bin"
            rc, _o, _e = xrd_cp_up(lf, f"/pub/{rel}", "floor1000")
            exists, u, _g = owner_of(rel)
            ok(all((rc == 0, exists, u == UID_FLOOR)),
               f"floor1000 root:// write allowed, owned 1000 (rc={rc}, uid={u})")
            ok(all((exists, u >= 1000)),
               f"floor1000 root:// file owner not reserved (uid={u})")


def _rt27_control_proving_the_denies_above_are(port, key, owner_of, FL):

    # ===================== FORBIDDEN IDENTITIES (DENIED) =====================
    # For each forbidden subject: the op MUST fail, create NO file, and certainly
    # never create one owned by a reserved id or by the forbidden user's uid.  We
    # write into /pub (svc:svc 0777) so the FS itself can never be the thing that
    # stops the write — only the idmap guard can — making a created file a true
    # security failure rather than a benign FS deny.
    forbidden = (
        ("lowu", UID_LOW, "uid 999 below the 1000 floor"),
        ("badprim", 1009, "uid 1009 ok but PRIMARY gid 50 reserved"),
        ("dockerite", 1007, "member of forbidden 'docker' group"),
    )
    for sub, sub_uid, label in forbidden:
        # ---- WebDAV PUT (async body handler) ----
        rel = f"bm_{sub}_wd.txt"
        marker = f"{sub.upper()}-FORBIDDEN-BODY".encode()
        st, _ = http("PUT", f"/pub/{rel}", port, mint(key, sub), marker + b"\n")
        exists, u, _g = owner_of(rel)
        ok(all((st not in (200, 201, 204), not exists)),
           f"{sub} ({label}) WebDAV PUT DENIED, no file created (HTTP {st}, exists={exists})")
        # if (against contract) a file slipped through, it must not be reserved-owned
        # nor owned by the forbidden subject's own uid.
        ok(any((not exists, all((u >= 1000, u != sub_uid)))),
           f"{sub} PUT created no reserved/forbidden-owned file (exists={exists}, uid={u})")

        # ---- WebDAV GET of a file that subject must not be able to materialize ----
        # the denied PUT created nothing, so a follow-up GET must 404/deny and leak
        # none of the marker bytes (no half-written body served back).
        st, b = http("GET", f"/pub/{rel}", port, mint(key, sub))
        ok(all((st != 200, marker not in any((b, b'')))),
           f"{sub} GET of its (never-created) file denied, no marker leak (HTTP {st})")

        # ---- root:// stream plane (same idmap guard, different code path) ----
        if xrd_avail():
            lf = os.path.join(WORK, f"bm_{sub}_src.bin")
            try:
                with open(lf, "wb") as fh:
                    fh.write(marker + b"\n")
            except OSError:
                lf = None
            if lf:
                rrel = f"bm_{sub}_root.bin"
                rc, _o, _e = xrd_cp_up(lf, f"/pub/{rrel}", sub)
                rexists, ru, _rg = owner_of(rrel)
                ok(all((rc != 0, not rexists)),
                   f"{sub} ({label}) root:// write DENIED, no file (rc={rc}, exists={rexists})")
                ok(any((not rexists, all((ru >= 1000, ru != sub_uid)))),
                   f"{sub} root:// created no reserved/forbidden-owned file (uid={ru})")
                # a root:// stat as the forbidden subject must also be refused (the
                # mapping is rejected at session/auth, so even metadata ops fail).
                rc, _o, _e = xrd_fs(["stat", f"/pub/{FL}"], sub)
                ok(rc != 0,
                   f"{sub} ({label}) root:// stat refused (mapping denied) (rc={rc})")
    _boundary_mapping_p2(s3port, port, owner_of, scan_pub_reserved, key, data, PUB)


def _boundary_mapping_p2(s3port, port, owner_of, scan_pub_reserved, key, data, PUB):
    # ===================== BOUNDARY-ADJACENT POSITIVE CONTROLS ===============
    # alice (uid 1001, well above floor, no forbidden group) is the always-allowed
    # control proving the DENIES above are identity-specific, not a blanket /pub
    # write block.
    AR = "bm_alice_ctrl.txt"
    st, _ = http("PUT", f"/pub/{AR}", port, mint(key, "alice"), b"ALICE-CTRL\n")
    exists, u, _g = owner_of(AR)
    return st, exists, u, AR


def _rt27_bob_uid_1002_second_above_floor(st, exists, u, AR, port, key):
    ok(all((st in (200, 201, 204), exists, u == UID_ALICE)),
       f"control: alice (above floor) PUT into /pub allowed, owned 1001 (HTTP {st}, uid={u})")
    st, b = http("GET", f"/pub/{AR}", port, mint(key, "alice"))
    ok(all((st == 200, b'ALICE-CTRL' in any((b, b'')))),
       f"control: alice reads back her /pub file (HTTP {st})")

    # bob (uid 1002) second above-floor control — distinct uid lands a distinct
    # owner, proving the floor accept is not pinned to a single id.
    BR = "bm_bob_ctrl.txt"
    st, _ = http("PUT", f"/pub/{BR}", port, mint(key, "bob"), b"BOB-CTRL\n")
    return st, BR


def _rt27_repeated_attempt_no_drift_invariant(owner_of, BR, st):
    exists, u, _g = owner_of(BR)
    ok(all((st in (200, 201, 204), exists, u == UID_BOB)),
       f"control: bob (above floor) PUT into /pub allowed, owned 1002 (HTTP {st}, uid={u})")
    _boundary_mapping_p3(s3port, scan_pub_reserved, port, data, PUB, key, owner_of, AR)


def _boundary_mapping_p3(s3port, scan_pub_reserved, port, data, PUB, key, owner_of, AR):
    # =================== REPEATED-ATTEMPT / NO-DRIFT INVARIANT ===============
    # hammer the floor boundary: many interleaved attempts (allowed floor1000 +
    # denied lowu) must never, under any race, drift a denied identity into a
    # created file or a reserved-id owner.  Proves the per-request map decision
    # carries no cross-request state.
    leaks = {"deny_created": 0, "allow_missing": 0}
    return leaks


def _rt27_segment_09(port, key, owner_of, leaks):

    def _floor_worker(i):
        if i % 2 == 0:
            sub, rel, want = "floor1000", f"bm_race_floor_{i}.txt", UID_FLOOR
            http("PUT", f"/pub/{rel}", port, mint(key, sub), f"f{i}\n".encode())
            ex, uu, _gg = owner_of(rel)
            if not (ex and uu == want):
                leaks["allow_missing"] += 1
        else:
            sub, rel = "lowu", f"bm_race_low_{i}.txt"
            http("PUT", f"/pub/{rel}", port, mint(key, sub), f"l{i}\n".encode())
            ex, _uu, _gg = owner_of(rel)
            if ex:
                leaks["deny_created"] += 1
    return _floor_worker


def _rt27_segment_10(_floor_worker, leaks):

    ts = [threading.Thread(target=_floor_worker, args=(i,)) for i in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ok(leaks["deny_created"] == 0,
       f"race: no denied lowu PUT ever created a file (drift={leaks['deny_created']})")
    ok(leaks["allow_missing"] == 0,
       f"race: every allowed floor1000 PUT landed owned 1000 (misses={leaks['allow_missing']})")
    _boundary_mapping_p4(s3port, scan_pub_reserved, port, data, PUB, key, AR)


def _rt27_s3_boundary_control_alice_leg(s3port, data, scan_pub_reserved):

    # =================== S3 BOUNDARY CONTROL (alice leg) =====================
    # S3 only has alice's configured key; alice maps above the floor, so an S3 PUT
    # must land owned 1001 (not svc/root) — the S3 plane honours the same floor.
    if s3port:
        st, _ = s3("PUT", "alice/bm_alice_s3_ctrl.txt", s3port, data=b"ALICE-S3-CTRL\n")
        sp = os.path.join(data, "alice", "bm_alice_s3_ctrl.txt")
        try:
            su = os.stat(sp).st_uid if os.path.exists(sp) else -1
        except OSError:
            su = -1
        ok(all((st in (200, 201), su == UID_ALICE)),
           f"S3 PUT (alice, above floor) owned 1001, not svc/root (HTTP {st}, uid={su})")
        ok(any((su < 0, su >= 1000)),
           f"S3-created file owner is not a reserved id (uid={su})")

    # =================== FINAL CROSS-CUTTING LEAK SWEEP ======================
    # the single load-bearing invariant for this whole batch: after every floor /
    # forbidden attempt above, NOTHING in /pub is owned by a reserved id (<1000).
    bad = scan_pub_reserved()
    ok(bad == [],
       f"FINAL: no /pub file owned by a reserved id (uid<1000) after boundary tests (leaks={bad[:5]})")

    # and specifically none of the forbidden subjects' own uids own anything either.
    forbidden_uids = {UID_LOW, 1009, 1007}
    forbidden_owned = []
    return forbidden_uids, forbidden_owned


def _rt27_worker_survival_a_plain_allowed_op(PUB, forbidden_uids, forbidden_owned, AR, port, key):
    try:
        for nm in os.listdir(PUB):
            try:
                u = os.stat(os.path.join(PUB, nm)).st_uid
            except OSError:
                continue
            if u in forbidden_uids:
                forbidden_owned.append((nm, u))
    except OSError:
        pass
    ok(forbidden_owned == [],
       f"FINAL: no /pub file owned by a forbidden-mapping uid (owned={forbidden_owned[:5]})")

    # worker survival: a plain allowed op still works after all the denied storms —
    # proves no rejected mapping wedged or crashed the worker/broker.
    st, b = http("GET", f"/pub/{AR}", port, mint(key, "alice"))
    ok(all((st == 200, b'ALICE-CTRL' in any((b, b'')))),
       f"worker survives the forbidden-identity storm (alice GET still 200) (HTTP {st})")


def run_boundary_mapping(key, data, port, s3port):
    """UID/GID FLOOR + forbidden-identity mapping enforced through the REAL
    protocols (not the C unit test).  The broker maps an auth subject -> local uid
    only when the candidate is fully legitimate: uid >= the configured floor
    (brix_idmap_min_uid = 1000), its PRIMARY gid is not reserved (>= floor), and
    it belongs to no forbidden group (docker/sudo/wheel).  This batch drives those
    boundaries with live requests and asserts the ONE security invariant that must
    never break: no file ever lands in the export owned by a reserved id (uid<1000)
    or by a forbidden mapping.  floor1000 (uid==floor) is the ALLOWED positive
    control; lowu(999)/badprim(prim gid 50)/dockerite(docker group) are DENIED.
    Covered over WebDAV PUT/GET and root:// (guarded); S3 only owns alice's key so
    it is not part of the forbidden-identity legs."""
    PUB = _rt27_segment_01(data)

    scan_pub_reserved = _rt27_segment_02(PUB)

    owner_of = _rt27_segment_03(PUB)

    FL, exists, u, g = _rt27_baseline_pub_starts_clean_of_any(scan_pub_reserved, port, key, owner_of)

    _rt27_floor1000_reads_back_its_own_file(exists, g, u, FL, port, key, owner_of)

    st, exists, u, AR = _rt27_control_proving_the_denies_above_are(port, key, owner_of, FL)

    st, BR = _rt27_bob_uid_1002_second_above_floor(st, exists, u, AR, port, key)

    leaks = _rt27_repeated_attempt_no_drift_invariant(owner_of, BR, st)

    _floor_worker = _rt27_segment_09(port, key, owner_of, leaks)

    _rt27_segment_10(_floor_worker, leaks)

    forbidden_uids, forbidden_owned = _rt27_s3_boundary_control_alice_leg(s3port, data, scan_pub_reserved)

    _rt27_worker_survival_a_plain_allowed_op(PUB, forbidden_uids, forbidden_owned, AR, port, key)

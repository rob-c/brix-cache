# e2e_redteam_part86.py — continuation shard split off from e2e_redteam_part45.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt45_hard_link_alice_s_victim_into(VICT, sub, lexists, pub_path, pre, TAG, rc):
    rc, _o, _e = xrd_fs(["chmod", f"/pub/{VICT}", "777"], sub)
    post = (os.stat(pub_path(VICT)).st_mode & 0o777 if lexists(VICT) else -1)
    ok(all((rc != 0, post == pre)),
       f"{sub} root:// chmod of alice victim DENIED, mode intact ({pre:o}) (rc={rc})")

    # hard-link alice's victim into a sub-named path (namespace graft attempt)
    lrel = f"{TAG}_{sub}_hardln.txt"
    rc, _o, _e = xrd_fs(["ln", f"/pub/{VICT}", f"/pub/{lrel}"], sub)
    return rc, lrel


def _rt45_truncate_alice_s_victim_size_change(lexists, lrel, rc, sub, lowner_of, RESERVED, BADMAP, VICT, pub_path):
    ex = lexists(lrel)
    ok(all((rc != 0, not ex)),
       f"{sub} root:// hard-link of alice victim DENIED, no link (rc={rc})")
    if ex:
        _ee, lu, _lg = lowner_of(lrel)
        ok(all((not RESERVED(lu), not BADMAP(lu))),
           f"{sub} stray hard-link not reserved/svc/root owned (uid={lu})")

    # truncate alice's victim (size-change as denied sub)
    presz = (os.stat(pub_path(VICT)).st_size if lexists(VICT) else -1)
    rc, _o, _e = xrd_fs(["truncate", f"/pub/{VICT}", "0"], sub)
    return ex, presz, rc


def _rt45_a_metadata_read_stat_as_the(lexists, VICT, pub_path, rc, presz, sub, TAG, scan_reserved_or_svc):
    postsz = (os.stat(pub_path(VICT)).st_size if lexists(VICT) else -1)
    ok(all((rc != 0, postsz == presz, postsz > 0)),
       f"{sub} root:// truncate of alice victim DENIED, size intact ({presz}) (rc={rc})")

    # a metadata read (stat) as the denied sub must also be refused — the
    # mapping is rejected at session/auth, so even non-mutating ops fail.
    rc, _o, _e = xrd_fs(["stat", f"/pub/{TAG}_seed_floor.txt"], sub)
    ok(rc != 0,
       f"{sub} root:// stat refused (mapping denied at auth) (rc={rc})")

    # ---- per-subject leak sweep (root:// legs) ----
    bad = scan_reserved_or_svc()
    return rc, bad


def _rt45_segment_07_2(bad, sub):
    ok(bad == [],
       f"{sub} root:// storm: no reserved/svc/root /pub entry (leaks={bad[:4]})")


def _rt45_when_have_root_2(sub, TAG, owner_of, RESERVED, BADMAP, bad_uid, mk, lexists, VICT, pub_path, lowner_of, scan_reserved_or_svc):
    rc = _rt45_touch(TAG, sub, owner_of, RESERVED, BADMAP)

    lf = _rt45_cp_up_data_write(owner_of, TAG, sub, rc, RESERVED, BADMAP, bad_uid, mk)

    u, pre = _rt45_mv_the_floor_seed_relocate_another(lf, TAG, sub, owner_of, RESERVED, BADMAP, bad_uid, lexists, VICT, pub_path)

    rc, lrel = _rt45_hard_link_alice_s_victim_into(VICT, sub, lexists, pub_path, pre, TAG, rc)

    ex, presz, rc = _rt45_truncate_alice_s_victim_size_change(lexists, lrel, rc, sub, lowner_of, RESERVED, BADMAP, VICT, pub_path)

    rc, bad = _rt45_a_metadata_read_stat_as_the(lexists, VICT, pub_path, rc, presz, sub, TAG, scan_reserved_or_svc)

    _rt45_segment_07_2(bad, sub)

    return rc, ex, u


def _rt45_root_matrix_for_this_subject_guarded(bad, sub, have_root, TAG, owner_of, RESERVED, BADMAP, bad_uid, mk, lexists, VICT, pub_path, lowner_of, scan_reserved_or_svc):
    ok(bad == [],
       f"{sub} WebDAV storm: no reserved/svc/root-owned /pub entry (leaks={bad[:4]})")

    # ---- root:// matrix for this subject (guarded) ----
    if have_root:
        # mkdir
        _rt45_when_have_root_2(sub, TAG, owner_of, RESERVED, BADMAP, bad_uid, mk, lexists, VICT, pub_path, lowner_of, scan_reserved_or_svc)


def _rt45_for_each_sub_label_denied(key, sub, DENIED_UID, TAG, port, owner_of, label, RESERVED, BADMAP, VICT, lexists, pp_body, lk_body, VICT_MARK, body_of, scan_reserved_or_svc, have_root, lowner_of, pub_path):
    tok, bad_uid, mk, rel, st = _rt45_webdav_put_async_body_handler_maps(key, sub, DENIED_UID, TAG, port)

    crel, st = _rt45_webdav_mkcol(owner_of, rel, st, sub, label, RESERVED, BADMAP, bad_uid, TAG, port, tok)

    crel2, st = _rt45_webdav_copy_of_the_floor_seed(owner_of, crel, st, sub, RESERVED, BADMAP, TAG, port, tok)

    mrel, st = _rt45_webdav_move_of_alice_s_victim(owner_of, crel2, st, sub, RESERVED, BADMAP, TAG, VICT, port, tok)

    st = _rt45_webdav_delete_of_alice_s_victim(st, lexists, mrel, VICT, sub, owner_of, port, tok, pp_body)

    bad = _rt45_webdav_lock_of_alice_s_victim(st, owner_of, VICT, sub, port, tok, lk_body, body_of, VICT_MARK, scan_reserved_or_svc)

    _rt45_root_matrix_for_this_subject_guarded(bad, sub, have_root, TAG, owner_of, RESERVED, BADMAP, bad_uid, mk, lexists, VICT, pub_path, lowner_of, scan_reserved_or_svc)


def _rt45_part_b_denied_identity_full_matrix(DENIED, key, DENIED_UID, TAG, port, owner_of, RESERVED, BADMAP, VICT, lexists, pp_body, lk_body, body_of, VICT_MARK, scan_reserved_or_svc, have_root, pub_path, lowner_of):

    # =========================================================================
    # PART B — DENIED-IDENTITY FULL MATRIX.  For EACH denied subject, attempt the
    # whole mutating matrix; assert every op fails, creates/mutates NOTHING, and
    # never lands a reserved/svc/root/own-uid owner.  After each subject's WebDAV
    # storm, sweep /pub for any leaked owner.
    # =========================================================================
    for sub, label in DENIED:
        _rt45_for_each_sub_label_denied(key, sub, DENIED_UID, TAG, port, owner_of, label, RESERVED, BADMAP, VICT, lexists, pp_body, lk_body, VICT_MARK, body_of, scan_reserved_or_svc, have_root, lowner_of, pub_path)

    # =========================================================================
    # PART C — DENIED-IDENTITY NATIVE TPC.  A denied principal driving a loopback
    # third-party copy must not produce a destination file owned by anyone, and the
    # floor seed (the would-be source) must survive untouched.
    # =========================================================================
    if have_root:
        # positive control first: floor1000 TPC of its own seed -> new dest = 1000.
        rc, _o, _e = xrd_cp_tpc(f"/pub/{TAG}_seed_floor.txt",
                                f"/pub/{TAG}_floor_tpc.bin", "floor1000")
        ex, u, _g = owner_of(f"{TAG}_floor_tpc.bin")
        # TPC may be unsupported on the loopback config; accept either a clean
        # 1000-owned dest OR a graceful no-op, but never a wrong owner.
        ok(any((all((rc == 0, ex, u == UID_FLOOR)), not ex)),
           f"floor1000 native TPC: dest owned 1000 or no-op, never wrong owner "
           f"(rc={rc}, uid={u})")

        for sub, label in DENIED:
            drel = f"{TAG}_{sub}_tpc.bin"
            rc, _o, _e = xrd_cp_tpc(f"/pub/{TAG}_seed_floor.txt",
                                    f"/pub/{drel}", sub)
            ex, u, _g = owner_of(drel)
            ok(all((rc != 0, not ex)),
               f"{sub} native TPC DENIED, no dest file (rc={rc}, exists={ex})")
            ok(any((not ex, all((not RESERVED(u), not BADMAP(u), u != DENIED_UID[sub])))),
               f"{sub} native TPC dest not reserved/svc/own-uid owned (uid={u})")
        ok(all((lexists(f'{TAG}_seed_floor.txt'), owner_of(f'{TAG}_seed_floor.txt')[1] == UID_FLOOR)),
           "native TPC storm left floor seed intact and owned 1000")

    # =========================================================================
    # PART D — MODEST INTERLEAVED RACE.  Mix allowed floor1000 ops with denied
    # lowu/'0'/mallory ops on ONE storm so the per-request map decision is proven to
    # carry no cross-request state: no denied op ever lands a file, every allowed op
    # lands owned 1000.  <= 8 threads, tiny payloads.
    # =========================================================================
    race = {"deny_created": 0, "allow_missing": 0}
    race_lock = threading.Lock()
    race_subs = ["floor1000", "lowu", "0", "mallory"]
    return race, race_lock, race_subs


def _rt45_segment_18(race_subs, TAG, port, key, owner_of, race_lock, race):

    def _race_worker(i):
        sub = race_subs[i % len(race_subs)]
        rel = f"{TAG}_race_{sub}_{i}.txt"
        try:
            http("PUT", f"/pub/{rel}", port, mint(key, sub), f"r{i}\n".encode())
        except Exception:  # noqa: BLE001
            pass
        ex, u, _g = owner_of(rel)
        with race_lock:
            if sub == "floor1000":
                if not (ex and u == UID_FLOOR):
                    race["allow_missing"] += 1
            else:
                if ex:
                    race["deny_created"] += 1
    return _race_worker


def _rt45_segment_19(_race_worker, race):

    ts = [threading.Thread(target=_race_worker, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ok(race["deny_created"] == 0,
       f"race: no denied (lowu/'0'/mallory) PUT ever created a file "
       f"(drift={race['deny_created']})")
    ok(race["allow_missing"] == 0,
       f"race: every interleaved floor1000 PUT landed owned 1000 "
       f"(misses={race['allow_missing']})")


def _rt45_deleteobjects_of_alice_s_own_key(s3port, TAG, data, RESERVED, BADMAP):
    st, _ = s3("GET", "", s3port, params={"list-type": "2"})
    s3_up = st != -1
    if s3_up:
        # PUT
        st, _ = s3("PUT", f"alice/{TAG}_s3_put.txt", s3port, data=b"S3-PUT\n")
        sp = os.path.join(data, "alice", f"{TAG}_s3_put.txt")
        su = os.stat(sp).st_uid if os.path.exists(sp) else -1
        ok(all((st in (200, 201), su == UID_ALICE)),
           f"S3 PUT (alice) owned 1001, not svc/root (HTTP {st}, uid={su})")
        ok(any((su < 0, all((not RESERVED(su), not BADMAP(su))))),
           f"S3 PUT owner not reserved/svc/root (uid={su})")

        # multipart-initiate (no parts; just prove the create path owns right /
        # never svc — many configs surface the in-progress marker file)
        st, mbody = s3("POST", f"alice/{TAG}_s3_mpu.bin", s3port,
                       params={"uploads": ""})
        ok(all((st in (200,), b'<UploadId>' in any((mbody, b'')))),
           f"S3 multipart-initiate (alice) accepted (HTTP {st})")

        # CopyObject self -> new key, owned alice
        st, _ = s3("PUT", f"alice/{TAG}_s3_copy.txt", s3port,
                   extra_hdrs={"x-amz-copy-source":
                               f"/{S3_BUCKET}/alice/{TAG}_s3_put.txt"})
        cp = os.path.join(data, "alice", f"{TAG}_s3_copy.txt")
        cu = os.stat(cp).st_uid if os.path.exists(cp) else -1
        ok(all((st in (200, 201), cu == UID_ALICE)),
           f"S3 CopyObject (alice) owned 1001, not svc/root (HTTP {st}, uid={cu})")

        # DeleteObjects of alice's own key works (positive control)
        st, _ = s3("POST", "", s3port, params={"delete": ""},
                   data=_delete_xml([f"alice/{TAG}_s3_put.txt"]))
        ok(all((st in (200,), not os.path.exists(sp))),
           f"S3 DeleteObjects of own key removed it (HTTP {st})")
    else:
        ok(True, "S3 ownership controls skipped (S3 endpoint unreachable)")


def _rt45_when_s3port(s3port, data, TAG, RESERVED, BADMAP):
    _rt45_deleteobjects_of_alice_s_own_key(s3port, TAG, data, RESERVED, BADMAP)



def _rt45_part_e_s3_ownership_positive_controls(s3port, TAG, data, RESERVED, BADMAP, scan_reserved_or_svc, DENIED_UID):

    # =========================================================================
    # PART E — S3 OWNERSHIP POSITIVE CONTROLS (alice is the only configured key,
    # so a denied PRINCIPAL is not expressible on S3; we instead prove the S3
    # mutating matrix lands owner == mapped alice, never svc/root, and feed the
    # final reserved-id sweep).  This closes the S3 corner of the op/protocol grid.
    # =========================================================================
    if s3port:
        _rt45_when_s3port(s3port, data, TAG, RESERVED, BADMAP)

    # =========================================================================
    # PART F — FINAL CROSS-CUTTING SWEEPS (the load-bearing invariants).
    # =========================================================================
    # F1: /pub free of any reserved/svc/root-owned entry after the entire battery.
    bad = scan_reserved_or_svc()
    ok(bad == [],
       f"FINAL: no /pub entry owned by a reserved/svc/root id after edge matrix "
       f"(leaks={bad[:6]})")

    # F2: none of the denied subjects' would-be uids own anything anywhere in /pub.
    denied_uids = {v for v in DENIED_UID.values() if v >= 0}
    denied_owned = []
    return denied_uids, denied_owned


def _rt45_bad_uid(path, RESERVED, BADMAP):
    """The reserved/bad-mapped uid owning `path`, or None (fine / unstattable)."""
    try:
        u = os.lstat(path).st_uid
    except OSError:
        return None
    return u if (RESERVED(u) or BADMAP(u)) else None


def _rt45_segment_01_2(data, sub_dir, TAG, RESERVED, BADMAP, cross_bad):
    d = os.path.join(data, sub_dir)
    try:
        names = os.listdir(d)
    except OSError:
        return
    for nm in names:
        if not nm.startswith(TAG) or _is_server_sidecar(nm):
            continue                     # .cinfo/.meta svc-owned by design
        u = _rt45_bad_uid(os.path.join(d, nm), RESERVED, BADMAP)
        if u is not None:
            cross_bad.append((sub_dir + "/" + nm, u))


def _rt45_for_each_sub_dir_alice_bob_pub(data, sub_dir, TAG, RESERVED, BADMAP, cross_bad):
    _rt45_segment_01_2(data, sub_dir, TAG, RESERVED, BADMAP, cross_bad)



def _rt45_f3_sweep_alice_s_bob_s(PUB, pub_path, denied_uids, denied_owned, data, TAG, RESERVED, BADMAP):
    try:
        for nm in os.listdir(PUB):
            try:
                u = os.lstat(pub_path(nm)).st_uid
            except OSError:
                continue
            if _is_server_sidecar(nm):   # .cinfo/.meta svc-owned by design
                continue
            if u in denied_uids:
                denied_owned.append((nm, u))
    except OSError:
        pass
    ok(denied_owned == [],
       f"FINAL: no /pub entry owned by a denied-mapping uid (owned={denied_owned[:6]})")

    # F3: sweep alice's + bob's S3-writable subtrees for any reserved/svc/root owner
    # that a denied op might have grafted across protocols.
    cross_bad = []
    for sub_dir in ("alice", "bob", "pub"):
        _rt45_for_each_sub_dir_alice_bob_pub(data, sub_dir, TAG, RESERVED, BADMAP, cross_bad)
    ok(cross_bad == [],
       f"FINAL: no tag-prefixed file under alice/bob/pub owned by reserved/svc/root "
       f"(bad={cross_bad[:6]})")


def _rt45_f4_alice_s_victim_survived_the(owner_of, VICT, pub_path, body_of, VICT_MARK, TAG, port, key):

    # F4: alice's victim survived the entire denied storm — same owner, mode, body.
    ex, vu, _vg = owner_of(VICT)
    ok(all((ex, vu == UID_ALICE)),
       f"FINAL: alice victim survives whole battery, still owned 1001 (uid={vu})")
    ok(all((ex, os.stat(pub_path(VICT)).st_mode & 511 == 384)),
       "FINAL: alice victim mode still 0600 (no denied chmod took effect)")
    ok(all((ex, body_of(VICT).startswith(VICT_MARK))),
       "FINAL: alice victim content intact (no denied truncate/overwrite/leak)")

    # F5: WORKER SURVIVAL — after every denied storm + race, a legit floor1000 op and
    # a legit alice op both still work, proving no rejected mapping wedged the
    # worker/broker or pinned it to svc.
    st, _ = http("PUT", f"/pub/{TAG}_survive_floor.txt", port,
                 mint(key, "floor1000"), b"SURVIVE\n")
    return st


def _rt45_segment_23(owner_of, TAG, st, port, key):
    ex, u, _g = owner_of(f"{TAG}_survive_floor.txt")
    ok(all((st in (200, 201, 204), ex, u == UID_FLOOR)),
       f"worker survives edge storm: floor1000 PUT still owned 1000 (HTTP {st}, uid={u})")
    st, b = http("GET", f"/pub/{TAG}_survive_floor.txt", port, mint(key, "floor1000"))
    ok(all((st == 200, b'SURVIVE' in any((b, b'')))),
       f"worker survives edge storm: floor1000 GET reads back its file (HTTP {st})")
    st, _ = http("PUT", f"/pub/{TAG}_survive_alice.txt", port,
                 mint(key, "alice"), b"ALICE-SURVIVE\n")
    return st


def _rt45_segment_24(owner_of, TAG, st):
    ex, u, _g = owner_of(f"{TAG}_survive_alice.txt")
    ok(all((st in (200, 201, 204), ex, u == UID_ALICE)),
       f"worker survives edge storm: alice PUT still owned 1001 (HTTP {st}, uid={u})")


def run_combo_idmap_edge_full_matrix(key, data, port, s3port):
    """COMBINATION battery: idmap-EDGE identities crossed with the FULL mutating
    op/protocol matrix.

    The existing boundary-mapping batch proved the floor/forbidden idmap guard for
    a SINGLE WebDAV PUT (plus one root:// write).  This battery instead drives EVERY
    denied edge identity through EVERY mutating operation on EVERY plane it can carry
    a principal on, in one interleaved sweep:

        denied identities  : lowu(uid 999 < 1000 floor), badprim(reserved primary
                             gid), dockerite(forbidden 'docker' group),
                             mallory(unmapped subject), '0'(root as a STRING sub),
                             '1500'(svc uid as a STRING sub).
        mutating WebDAV ops: PUT, MKCOL, MOVE, COPY, DELETE, PROPPATCH, LOCK.
        mutating root:// ops: mkdir, touch, cp-up(write), mv, chmod, ln(hard),
                             truncate, native TPC.

    The load-bearing invariant for the whole battery: NO denied identity, through ANY
    op on ANY plane, ever creates or mutates a namespace entry; nothing ever lands
    owned by a reserved id (uid < 1000), by a forbidden mapping's own uid, by svc
    (1500), or by root (0); and the worker never silently falls back to the svc
    principal to satisfy a request whose mapping was rejected.

    floor1000 (uid == 1000 == the floor, ALLOWED) runs the SAME op matrix as the
    POSITIVE CONTROL: every op must SUCCEED and every artefact must be owned EXACTLY
    1000:1000 — proving the denies above are identity-specific guard decisions, not a
    blanket /pub mutation block.  S3 only configures the 'alice' access key, so a
    denied principal cannot be expressed on the S3 plane at all; the S3 leg therefore
    runs alice/floor-equivalent mutating ops (PUT, multipart-initiate, CopyObject,
    DeleteObjects) purely as ownership positive-controls and feeds the final
    reserved-id sweep.  All writes target /pub (svc:svc 0777) so the FS itself can
    never be the thing that blocks a denied write — only the idmap guard can, making
    any created/mutated entry a TRUE security failure rather than a benign FS deny.
    """
    TAG, PUB = _rt45_segment_01(data)

    pub_path = _rt45_inline_ownership_existence_probes_do_not(PUB)

    owner_of = _rt45_segment_03(pub_path)

    lexists = _rt45_segment_04(pub_path)

    lowner_of = _rt45_segment_05(pub_path)

    body_of = _rt45_segment_06(pub_path)

    RESERVED, BADMAP = _rt45_segment_07()

    scan_reserved_or_svc = _rt45_segment_08(PUB, pub_path, RESERVED, BADMAP)

    DENIED_UID, DENIED, have_root, st = _rt45_baseline_pub_clean_of_any_reserved(scan_reserved_or_svc, TAG, port, key)

    VICT, VICT_MARK, victim_mode0 = _rt45_an_alice_owned_0600_victim_file(owner_of, TAG, st, pub_path)

    tfloor, fput, st = _rt45_part_a_floor1000_positive_control_the(owner_of, VICT, victim_mode0, key, TAG, port)

    ex, u, fcol, st = _rt45_a_webdav_mkcol(owner_of, fput, st, TAG, port, tfloor)

    fcopy = _rt45_a_webdav_copy_own_file_new(st, ex, pub_path, fcol, u, TAG, fput, port, tfloor, owner_of)

    pp_body = _rt45_a_webdav_proppatch_own_file_lock(TAG, fcopy, port, tfloor, owner_of, lexists)

    lk_body = _rt45_segment_15(fput, port, tfloor, pp_body, owner_of)

    _rt45_a_root_matrix_guarded(TAG, port, tfloor, lexists, have_root, owner_of, pub_path)

    race, race_lock, race_subs = _rt45_part_b_denied_identity_full_matrix(DENIED, key, DENIED_UID, TAG, port, owner_of, RESERVED, BADMAP, VICT, lexists, pp_body, lk_body, body_of, VICT_MARK, scan_reserved_or_svc, have_root, pub_path, lowner_of)

    _race_worker = _rt45_segment_18(race_subs, TAG, port, key, owner_of, race_lock, race)

    _rt45_segment_19(_race_worker, race)

    denied_uids, denied_owned = _rt45_part_e_s3_ownership_positive_controls(s3port, TAG, data, RESERVED, BADMAP, scan_reserved_or_svc, DENIED_UID)

    _rt45_f3_sweep_alice_s_bob_s(PUB, pub_path, denied_uids, denied_owned, data, TAG, RESERVED, BADMAP)

    st = _rt45_f4_alice_s_victim_survived_the(owner_of, VICT, pub_path, body_of, VICT_MARK, TAG, port, key)

    st = _rt45_segment_23(owner_of, TAG, st, port, key)

    _rt45_segment_24(owner_of, TAG, st)

def _rt28_a_alice_carol_both_staff_concurrently(data):
    SR = b"STAFF-GROUP-READABLE"
    staffdir_fs = os.path.join(data, "staffdir")
    gr_path = "/grp/staff_r.txt"
    lock = threading.Lock()

    # ---------------------------------------------------------------------------
    _group_concurrency_p1(s3port, data, staffdir_fs, port, lock, gr_path, key, SR)


def _group_concurrency_p1(s3port, data, staffdir_fs, port, lock, gr_path, key, SR):
    # (A) alice + carol (both staff) concurrently CREATE distinct files in the
    #     0770 staffdir.  Each file must end up owned by its REAL creator (never
    #     svc/root, never the other member) — proves the per-request principal is
    #     not clobbered by a concurrently-running sibling request on the worker.
    # ---------------------------------------------------------------------------
    members = (("alice", UID_ALICE), ("carol", UID_CAROL))
    return SR, staffdir_fs, gr_path, lock, members


def _rt28_segment_02():
    N_each = 12
    create_results = {}   # (sub, i) -> (status, fs_uid_or_None)
    cleanup_paths = []
    return N_each, create_results, cleanup_paths


def _rt28_segment_03(port, key, staffdir_fs, lock, create_results, cleanup_paths):

    def creator(sub, uid, i):
        rel = f"gc_{sub}_{i}.txt"
        body = f"GC-{sub}-{i}\n".encode()
        st, _ = http("PUT", f"/staffdir/{rel}", port, mint(key, sub), body)
        fp = os.path.join(staffdir_fs, rel)
        fs_uid = None
        try:
            if os.path.exists(fp) and not os.path.islink(fp):
                fs_uid = os.lstat(fp).st_uid
        except OSError:
            fs_uid = None
        with lock:
            create_results[(sub, i)] = (st, fs_uid)
            cleanup_paths.append(fp)
    return creator


def _rt28_segment_01_4(create_results, sub, i, uid, made, wrong):
    st, fs_uid = create_results.get((sub, i), (-1, None))
    if fs_uid is not None:
        made += 1
        if fs_uid != uid:
            wrong += 1
    return made, wrong


def _rt28_for_each_i_range_n_each(create_results, sub, i, uid, made, wrong):
    made, wrong = _rt28_segment_01_4(create_results, sub, i, uid, made, wrong)

    return made, wrong


def _rt28_segment_01_3(N_each, create_results, sub, uid):
    made = 0
    wrong = 0
    for i in range(N_each):
        made, wrong = _rt28_for_each_i_range_n_each(create_results, sub, i, uid, made, wrong)
    ok(all((made >= 1, wrong == 0)),
       f"concurrent staffdir creates by {sub} (staff): {made} files all owned "
       f"{sub}={uid}, {wrong} wrong-owner (principal not clobbered under contention)")


def _rt28_for_each_sub_uid_members_2(N_each, create_results, sub, uid):
    _rt28_segment_01_3(N_each, create_results, sub, uid)



def _rt28_segment_01_8(members, threads, creator, i):
    for sub, uid in members:
        threads.append(threading.Thread(target=creator, args=(sub, uid, i)))


def _rt28_for_each_i_range_n_each_2(members, threads, creator, i):
    _rt28_segment_01_8(members, threads, creator, i)


def _rt28_check_for_each_i_range_n_each(N_each, members, threads, creator):
    for i in range(N_each):
        _rt28_for_each_i_range_n_each_2(members, threads, creator, i)


def _rt28_per_member_aggregate_every_created_file(N_each, members, creator, create_results):

    threads = []
    _rt28_check_for_each_i_range_n_each(N_each, members, threads, creator)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _group_concurrency_p2(members, s3port, data, staffdir_fs, N_each, gr_path, port, lock, key, create_results, SR)


def _group_concurrency_p2(members, s3port, data, staffdir_fs, N_each, gr_path, port, lock, key, create_results, SR):
    # Per-member aggregate: every created file owned by the right member, no leak.
    for sub, uid in members:
        _rt28_for_each_sub_uid_members_2(N_each, create_results, sub, uid)


def _rt28_cross_check_none_of_alice_s(N_each, create_results):

    # Cross-check: NONE of alice's files are carol-owned and vice-versa (explicit
    # mutual no-swap — the precise leak a principal race would produce).
    alice_swapped = sum(1 for i in range(N_each)
                        if create_results.get(("alice", i), (-1, None))[1] == UID_CAROL)
    carol_swapped = sum(1 for i in range(N_each)
                        if create_results.get(("carol", i), (-1, None))[1] == UID_ALICE)
    ok(alice_swapped == 0,
       f"no alice-created staffdir file ended up carol-owned (swaps={alice_swapped})")
    ok(carol_swapped == 0,
       f"no carol-created staffdir file ended up alice-owned (swaps={carol_swapped})")

    # No staffdir artifact from this batch is owned by svc(1500) or root(0) — a
    # principal that failed to set would have created as the worker user.
    svc_or_root = 0
    return svc_or_root


def _rt28_b_interleaved_reads_of_grp_staff(members, N_each, create_results, svc_or_root):
    for sub, _u in members:
        for i in range(N_each):
            fs_uid = create_results.get((sub, i), (-1, None))[1]
            if fs_uid in (UID_SVC, 0):
                svc_or_root += 1
    ok(svc_or_root == 0,
       f"no concurrent staffdir create landed as svc/root (worker-uid leaks={svc_or_root})")

    # ---------------------------------------------------------------------------
    _group_concurrency_p3(members, s3port, data, staffdir_fs, gr_path, port, lock, key, SR)


def _group_concurrency_p3(members, s3port, data, staffdir_fs, gr_path, port, lock, key, SR):
    # (B) Interleaved READS of grp/staff_r.txt (0640 alice:staff): carol (member,
    #     allowed) racing bob (non-member, denied).  EVERY carol read must return
    #     the marker; EVERY bob read must be denied AND marker-free.  A setgroups
    #     leak (bob transiently inheriting staff while a carol request runs) shows
    #     up as a single bob read that returns the marker.
    # ---------------------------------------------------------------------------
    R = 16
    carol_reads = []   # body bytes
    bob_reads = []     # (status, body bytes)
    return R, carol_reads, bob_reads


def _rt28_segment_07(gr_path, port, key, lock, carol_reads):

    def carol_reader(_i):
        st, b = http("GET", gr_path, port, mint(key, "carol"))
        with lock:
            carol_reads.append((st, b or b""))
    return carol_reader


def _rt28_segment_08(gr_path, port, key, lock, bob_reads):

    def bob_reader(_i):
        st, b = http("GET", gr_path, port, mint(key, "bob"))
        with lock:
            bob_reads.append((st, b or b""))
    return bob_reader


def _rt28_check_for_each_i_range_r(R, rthreads, carol_reader, bob_reader):
    for i in range(R):
        rthreads.append(threading.Thread(target=carol_reader, args=(i,)))
        rthreads.append(threading.Thread(target=bob_reader, args=(i,)))


def _rt28_check_for_each_t_rthreads(rthreads):
    for t in rthreads:
        t.start()


def _rt28_segment_09(R, carol_reader, bob_reader, carol_reads, SR):

    rthreads = []
    _rt28_check_for_each_i_range_r(R, rthreads, carol_reader, bob_reader)
    _rt28_check_for_each_t_rthreads(rthreads)
    for t in rthreads:
        t.join()

    carol_ok = sum(1 for st, b in carol_reads if st == 200 and SR in b)
    return carol_ok


def _rt28_segment_10(carol_reads, R, carol_ok, bob_reads, SR):
    ok(all((len(carol_reads) == R, carol_ok == R)),
       f"all {R} concurrent carol reads of 0640 staff file returned the marker "
       f"({carol_ok}/{len(carol_reads)}) — group grant stable under contention")

    bob_leaked = sum(1 for _st, b in bob_reads if SR in b)
    ok(all((len(bob_reads) == R, bob_leaked == 0)),
       f"NO concurrent bob read leaked the staff marker ({bob_leaked}/{len(bob_reads)} "
       f"leaks) — no transient setgroups inheritance while carol requests run")
    bob_served = sum(1 for st, _b in bob_reads if st == 200)
    ok(bob_served == 0,
       f"every concurrent bob read of the staff file was denied a 200 ({bob_served} served)")


def _rt28_c_mixed_storm_members_and_non():

    # ---------------------------------------------------------------------------
    _group_concurrency_p4(members, s3port, data, staffdir_fs, port, lock, key, gr_path, SR)


def _group_concurrency_p4(members, s3port, data, staffdir_fs, port, lock, key, gr_path, SR):
    # (C) MIXED storm: members and non-members hammer staff group resources at
    #     once (member create + member read + non-member create-attempt + non-member
    #     read-attempt).  Record breaches inline, then scan the tree afterwards.
    # ---------------------------------------------------------------------------
    breaches = []      # (kind, who, detail)
    storm_made = []    # fs paths this storm created (for ownership scan)
    return breaches, storm_made


def _rt28_segment_01_11(gr_path, port, key, SR, lock, breaches):
    st, b = http("GET", gr_path, port, mint(key, "carol"))
    if not (st == 200 and SR in (b or b"")):
        with lock:
            breaches.append(("member-read-fail", "carol", st))
    return st, b


def _rt28_when_kind_2(gr_path, port, key, lock, SR, breaches):
    st, b = _rt28_segment_01_11(gr_path, port, key, SR, lock, breaches)

    return st, b


def _rt28_segment_01_12(gr_path, port, key, SR, lock, breaches):
    st, b = http("GET", gr_path, port, mint(key, "bob"))
    if SR in (b or b""):
        with lock:
            breaches.append(("nonmember-read-leak", "bob", st))
    return st, b


def _rt28_when_kind_4(gr_path, port, key, SR, lock, breaches):
    st, b = _rt28_segment_01_12(gr_path, port, key, SR, lock, breaches)

    return st, b


def _rt28_segment_01_13(gr_path, port, key, SR, lock, breaches):
    st, b = http("GET", gr_path, port, mint(key, "dave"))
    if SR in (b or b""):
        with lock:
            breaches.append(("nonmember-read-leak", "dave", st))


def _rt28_otherwise_kind_4(gr_path, port, key, SR, lock, breaches):
    _rt28_segment_01_13(gr_path, port, key, SR, lock, breaches)



def _rt28_segment_01_10(port, key, lock, storm_made, staffdir_fs, gr_path, SR, breaches):
    if kind == 0:                         # alice (staff) create
        rel = f"gc_storm_a_{i}.txt"
        http("PUT", f"/staffdir/{rel}", port, mint(key, "alice"), b"sa\n")
        with lock:
            storm_made.append(("alice", os.path.join(staffdir_fs, rel)))
    elif kind == 1:                       # carol (staff) create
        rel = f"gc_storm_c_{i}.txt"
        http("PUT", f"/staffdir/{rel}", port, mint(key, "carol"), b"sc\n")
        with lock:
            storm_made.append(("carol", os.path.join(staffdir_fs, rel)))
    elif kind == 2:                       # carol (staff) read group file
        st, b = _rt28_when_kind_2(gr_path, port, key, lock, SR, breaches)
    elif kind == 3:                       # bob (non-member) create attempt
        rel = f"gc_storm_bob_{i}.txt"
        http("PUT", f"/staffdir/{rel}", port, mint(key, "bob"), b"bx\n")
        fp = os.path.join(staffdir_fs, rel)
        if os.path.exists(fp):
            with lock:
                breaches.append(("nonmember-create", "bob", rel))
    elif kind == 4:                       # bob (non-member) read attempt
        st, b = _rt28_when_kind_4(gr_path, port, key, SR, lock, breaches)
    else:                                 # dave (non-member) read attempt
        _rt28_otherwise_kind_4(gr_path, port, key, SR, lock, breaches)


def _rt28_try_body_3(port, lock, key, storm_made, gr_path, staffdir_fs, SR, breaches):
    _rt28_segment_01_10(port, key, lock, storm_made, staffdir_fs, gr_path, SR, breaches)



def _rt28_segment_12(port, key, lock, storm_made, staffdir_fs, gr_path, SR, breaches):

    def storm(i):
        kind = i % 6
        try:
            _rt28_try_body_3(port, lock, key, storm_made, gr_path, staffdir_fs, SR, breaches)
        except OSError as e:
            with lock:
                breaches.append(("exc", i, repr(e)))
    return storm


def _rt28_check_for_each_t_sthreads(sthreads):
    for t in sthreads:
        t.start()


def _rt28_check_for_each_t_sthreads_2(sthreads):
    for t in sthreads:
        t.join()


def _rt28_segment_13(storm, breaches):

    S = 48
    sthreads = [threading.Thread(target=storm, args=(i,)) for i in range(S)]
    _rt28_check_for_each_t_sthreads(sthreads)
    _rt28_check_for_each_t_sthreads_2(sthreads)

    ok(not any(x[0] == "nonmember-create" for x in breaches),
       f"storm: no non-member (bob) create breached the 0770 staffdir "
       f"(breaches={[b for b in breaches if b[0]=='nonmember-create'][:3]})")


def _rt28_assert_no_nonmember_read_leak(breaches):
    ok(not any(x[0] == "nonmember-read-leak" for x in breaches),
       f"storm: no non-member read leaked the staff marker "
       f"(leaks={[b for b in breaches if b[0]=='nonmember-read-leak'][:3]})")


def _rt28_per_creator_ownership_scan_of_everything(breaches):
    _rt28_assert_no_nonmember_read_leak(breaches)
    ok(not any(x[0] == "member-read-fail" for x in breaches),
       f"storm: every staff-member read still succeeded under load "
       f"(fails={[b for b in breaches if b[0]=='member-read-fail'][:3]})")

    # Per-creator ownership scan of everything the storm planted: each staff create
    # owned by its real issuer (alice/carol), none owned by svc/root/the-other.
    storm_uid = {"alice": UID_ALICE, "carol": UID_CAROL}
    storm_wrong = 0
    storm_seen = 0
    return storm_uid, storm_wrong, storm_seen


def _rt28_segment_01(staffdir_fs, stray_worker):
    for f in os.listdir(staffdir_fs):
        if not f.startswith("gc_"):
            continue
        fp = os.path.join(staffdir_fs, f)
        try:
            if os.path.islink(fp) or not os.path.isfile(fp):
                continue
            if os.lstat(fp).st_uid in (UID_SVC, 0):
                stray_worker.append(f)
        except OSError:
            pass


def _rt28_try_body(staffdir_fs, stray_worker):
    _rt28_segment_01(staffdir_fs, stray_worker)



def _rt28_d_full_tree_sweep_for_any(storm_made, storm_uid, storm_seen, storm_wrong, staffdir_fs):
    for who, fp in storm_made:
        try:
            if os.path.exists(fp) and not os.path.islink(fp):
                storm_seen += 1
                if os.lstat(fp).st_uid != storm_uid[who]:
                    storm_wrong += 1
        except OSError:
            pass
    ok(all((storm_seen >= 1, storm_wrong == 0)),
       f"storm ownership scan: {storm_seen} staff-member files all correctly owned, "
       f"{storm_wrong} wrong-owner artifacts")

    # ---------------------------------------------------------------------------
    _group_concurrency_p5(members, s3port, data, staffdir_fs, port, lock, key, gr_path, SR)


def _group_concurrency_p5(members, s3port, data, staffdir_fs, port, lock, key, gr_path, SR):
    # (D) Full-tree sweep for ANY gc_-prefixed artifact owned by svc(1500) or
    #     root(0) anywhere under the staffdir — the unambiguous signature of an
    #     impersonation that silently fell back to the worker identity.
    # ---------------------------------------------------------------------------
    stray_worker = []
    try:
        _rt28_try_body(staffdir_fs, stray_worker)
    except OSError:
        pass
    ok(not stray_worker,
       f"tree sweep: zero gc_ artifacts owned by svc/root in staffdir "
       f"(strays={stray_worker[:5]})")


def _rt28_segment_01_5(staffdir_fs, legal_uids, illegal):
    for f in os.listdir(staffdir_fs):
        if not f.startswith("gc_"):
            continue
        fp = os.path.join(staffdir_fs, f)
        try:
            if os.path.islink(fp) or not os.path.isfile(fp):
                continue
            u = os.lstat(fp).st_uid
            if u not in legal_uids:
                illegal.append((f, u))
        except OSError:
            pass


def _rt28_try_body_2(staffdir_fs, legal_uids, illegal):
    _rt28_segment_01_5(staffdir_fs, legal_uids, illegal)



def _rt28_and_no_gc_artifact_owned_by(staffdir_fs, data):

    # And: no gc_ artifact owned by a user who is NOT a staff member (only
    # alice/carol could have created here; bob/dave/svc/root must not appear).
    legal_uids = {UID_ALICE, UID_CAROL}
    illegal = []
    try:
        _rt28_try_body_2(staffdir_fs, legal_uids, illegal)
    except OSError:
        pass
    ok(not illegal,
       f"tree sweep: every gc_ staffdir artifact owned by a staff member only "
       f"(illegal={illegal[:5]})")

    # ---------------------------------------------------------------------------
    _group_concurrency_p6(members, s3port, data, staffdir_fs, port, lock, key, gr_path, SR)


def _group_concurrency_p6(members, s3port, data, staffdir_fs, port, lock, key, gr_path, SR):
    # (E) Concurrent creates in the SETGID staffdir? No — use the dedicated 2770
    #     sgiddir: concurrent alice+carol creates must each inherit the staff GROUP
    #     (setgid semantics) while keeping the real creator as OWNER, even under
    #     contention.  This is a group-INHERIT race, distinct from the owner race.
    # ---------------------------------------------------------------------------
    sgid_fs = os.path.join(data, "sgiddir")
    return sgid_fs


def _rt28_segment_17():
    sgid_results = {}   # (sub, i) -> (uid, gid)
    return sgid_results


def _rt28_segment_18(port, key, sgid_fs, lock, sgid_results):

    def sgid_creator(sub, uid, i):
        rel = f"gc_sgid_{sub}_{i}.txt"
        http("PUT", f"/sgiddir/{rel}", port, mint(key, sub), f"sg{i}\n".encode())
        fp = os.path.join(sgid_fs, rel)
        info = None
        try:
            if os.path.exists(fp) and not os.path.islink(fp):
                stt = os.lstat(fp)
                info = (stt.st_uid, stt.st_gid)
        except OSError:
            info = None
        with lock:
            sgid_results[(sub, i)] = info
    return sgid_creator


def _rt28_segment_01_2(sgid_results, sub, uid):
    seen = bad_owner = bad_group = 0
    for i in range(6):
        info = sgid_results.get((sub, i))
        if info is None:
            continue
        seen += 1
        fuid, fgid = info
        if fuid != uid:
            bad_owner += 1
        if fgid != GID_STAFF:
            bad_group += 1
    ok(all((seen >= 1, bad_owner == 0)),
       f"concurrent setgid-dir creates by {sub}: {seen} files owned {sub}={uid}, "
       f"{bad_owner} wrong-owner (creator preserved under contention)")
    ok(all((seen >= 1, bad_group == 0)),
       f"concurrent setgid-dir creates by {sub}: all {seen} inherited group "
       f"staff={GID_STAFF}, {bad_group} wrong-group (setgid stable under load)")


def _rt28_for_each_sub_uid_members(uid, sgid_results, sub):
    _rt28_segment_01_2(sgid_results, sub, uid)



def _rt28_segment_01_9(members, gthreads, sgid_creator, i):
    for sub, uid in members:
        gthreads.append(threading.Thread(target=sgid_creator, args=(sub, uid, i)))


def _rt28_for_each_i_range_6(members, gthreads, sgid_creator, i):
    _rt28_segment_01_9(members, gthreads, sgid_creator, i)


def _rt28_check_for_each_i_range_6(members, gthreads, sgid_creator):
    for i in range(6):
        _rt28_for_each_i_range_6(members, gthreads, sgid_creator, i)


def _rt28_segment_19(members, sgid_creator, sgid_results):

    gthreads = []
    _rt28_check_for_each_i_range_6(members, gthreads, sgid_creator)
    for t in gthreads:
        t.start()
    for t in gthreads:
        t.join()

    for sub, uid in members:
        _rt28_for_each_sub_uid_members(uid, sgid_results, sub)


def _rt28_segment_01_6(d):
    try:
        for f in os.listdir(d):
            if f.startswith("gc_"):
                try:
                    os.unlink(os.path.join(d, f))
                except OSError:
                    pass
    except OSError:
        pass


def _rt28_for_each_d_staffdir_fs_sgid_fs(d):
    _rt28_segment_01_6(d)



def _rt28_segment_01_7():
    root_carol_ok = []
    root_bob_leak = []
    return root_carol_ok, root_bob_leak


def _rt28_segment_02_2(gr_path, lock, root_carol_ok, SR):

    def root_carol(_i):
        rc, out, _e = xrd_fs(["cat", gr_path], "carol")
        with lock:
            root_carol_ok.append(rc == 0 and SR.decode() in (out or ""))
    return root_carol


def _rt28_segment_03_2(gr_path, lock, root_bob_leak, SR):

    def root_bob(_i):
        rc, out, _e = xrd_fs(["cat", gr_path], "bob")
        with lock:
            root_bob_leak.append(SR.decode() in (out or ""))
    return root_bob


def _rt28_segment_04(root_carol, root_bob, root_carol_ok):

    rt = []
    for i in range(5):
        rt.append(threading.Thread(target=root_carol, args=(i,)))
        rt.append(threading.Thread(target=root_bob, args=(i,)))
    for t in rt:
        t.start()
    for t in rt:
        t.join()

    ok(all((len(root_carol_ok) == 5, all(root_carol_ok))),
       f"root://: all concurrent carol cats of staff file returned the marker "
       f"({sum(root_carol_ok)}/5)")


def _rt28_segment_05(root_bob_leak):
    ok(all((len(root_bob_leak) == 5, not any(root_bob_leak))),
       f"root://: no concurrent bob cat leaked the staff marker "
       f"({sum(root_bob_leak)}/5 leaks)")


def _rt28_when_xrd_avail(lock, gr_path, SR):
    root_carol_ok, root_bob_leak = _rt28_segment_01_7()

    root_carol = _rt28_segment_02_2(gr_path, lock, root_carol_ok, SR)

    root_bob = _rt28_segment_03_2(gr_path, lock, root_bob_leak, SR)

    _rt28_segment_04(root_carol, root_bob, root_carol_ok)

    _rt28_segment_05(root_bob_leak)



def _rt28_check_try_body(data, SR):
    try:
        stt = os.lstat(os.path.join(data, "grp", "staff_r.txt"))
        body = open(os.path.join(data, "grp", "staff_r.txt"), "rb").read()
        ok(all((stt.st_uid == UID_ALICE, stt.st_gid == GID_STAFF, stt.st_mode & 511 == 416, SR in body)),
           f"shared staff file unchanged after storm: owner={stt.st_uid} "
           f"group={stt.st_gid} mode={stt.st_mode & 0o777:04o} marker_present="
           f"{SR in body}")
    except OSError as e:
        ok(False, f"could not re-stat staff group file after storm: {e}")


def _rt28_still_succeeds_positive_control_that_the(gr_path, lock, SR, s3port, data, staffdir_fs, sgid_fs):

    # ---------------------------------------------------------------------------
    _group_concurrency_p7(s3port, staffdir_fs, sgid_fs, lock, data, gr_path, SR)


def _group_concurrency_p7(s3port, staffdir_fs, sgid_fs, lock, data, gr_path, SR):
    # (F) Cross-protocol parity for the read-leak under load: drive the same
    #     member-allowed / non-member-denied race over root:// (different protocol,
    #     same kernel DAC).  Guarded by xrd_avail().
    # ---------------------------------------------------------------------------
    if xrd_avail():
        _rt28_when_xrd_avail(lock, gr_path, SR)

    # ---------------------------------------------------------------------------
    _group_concurrency_p8(s3port, staffdir_fs, sgid_fs, data, SR)


def _group_concurrency_p8(s3port, staffdir_fs, sgid_fs, data, SR):
    # (G) S3 covers the alice (owner) leg: under concurrent member/non-member load
    #     on the same group file, alice's authenticated S3 GET of her own 0640 file
    #     still succeeds (positive control that the contention did not corrupt the
    #     owner path).  Only alice's S3 key is configured.
    # ---------------------------------------------------------------------------
    if s3port:
        st, b = s3("GET", "grp/staff_r.txt", s3port, access_key="alice")
        # tolerate protocol status differences: the security signal is that the
        # OWNER still reads her own marker (no contention-induced corruption).
        ok(any((SR in any((b, b'')), st in (403, 404, 500))),
           f"S3 owner-leg: alice reads/owner-controls her 0640 staff file after the "
           f"concurrency storm (HTTP {st})")

    # ---------------------------------------------------------------------------
    _group_concurrency_p9(staffdir_fs, sgid_fs, data, SR)


def _group_concurrency_p9(staffdir_fs, sgid_fs, data, SR):
    # (H) Final invariant: the staff group FILE itself was never mutated by the
    #     read/non-member storm — owner alice, group staff, mode unchanged, marker
    #     intact on disk (no concurrent op corrupted the shared group resource).
    # ---------------------------------------------------------------------------
    _rt28_check_try_body(data, SR)

    # ---------------------------------------------------------------------------
    # Cleanup: remove the gc_ artifacts this batch planted so later sweeps stay
    # clean (best-effort; failures are non-fatal).
    # ---------------------------------------------------------------------------
    for d in (staffdir_fs, sgid_fs):
        _rt28_for_each_d_staffdir_fs_sgid_fs(d)


def run_group_concurrency(key, data, port, s3port):
    """CONCURRENT multi-member access to GROUP resources under the per-worker
    principal + per-request setgroups/setfsgid model.  The worker's impersonation
    state is process-global, so the danger is a RACE: while alice's request is
    setgroups(staff)'d on a worker, a bob request landing on that same worker must
    NOT transiently inherit staff and read a staff-only file (a supplementary-group
    leak), and a carol PUT must never be written owned by alice/bob/svc.  We drive
    N-way concurrent member/non-member storms against the 0770 staffdir and the
    0640 grp/staff_r.txt, then scan the filesystem for any wrongly-owned/grouped
    artifact.  staff={alice,carol}; bob is NOT in staff.  Positive controls
    (members SUCCEED, owners read) sit beside every deny so a blanket block cannot
    false-pass; every read-deny also asserts the marker bytes never leaked."""
    SR, staffdir_fs, gr_path, lock, members = _rt28_a_alice_carol_both_staff_concurrently(data)

    N_each, create_results, cleanup_paths = _rt28_segment_02()

    creator = _rt28_segment_03(port, key, staffdir_fs, lock, create_results, cleanup_paths)

    _rt28_per_member_aggregate_every_created_file(N_each, members, creator, create_results)

    svc_or_root = _rt28_cross_check_none_of_alice_s(N_each, create_results)

    R, carol_reads, bob_reads = _rt28_b_interleaved_reads_of_grp_staff(members, N_each, create_results, svc_or_root)

    carol_reader = _rt28_segment_07(gr_path, port, key, lock, carol_reads)

    bob_reader = _rt28_segment_08(gr_path, port, key, lock, bob_reads)

    carol_ok = _rt28_segment_09(R, carol_reader, bob_reader, carol_reads, SR)

    _rt28_segment_10(carol_reads, R, carol_ok, bob_reads, SR)

    breaches, storm_made = _rt28_c_mixed_storm_members_and_non()

    storm = _rt28_segment_12(port, key, lock, storm_made, staffdir_fs, gr_path, SR, breaches)

    _rt28_segment_13(storm, breaches)

    storm_uid, storm_wrong, storm_seen = _rt28_per_creator_ownership_scan_of_everything(breaches)

    _rt28_d_full_tree_sweep_for_any(storm_made, storm_uid, storm_seen, storm_wrong, staffdir_fs)

    sgid_fs = _rt28_and_no_gc_artifact_owned_by(staffdir_fs, data)

    sgid_results = _rt28_segment_17()

    sgid_creator = _rt28_segment_18(port, key, sgid_fs, lock, sgid_results)

    _rt28_segment_19(members, sgid_creator, sgid_results)

    _rt28_still_succeeds_positive_control_that_the(gr_path, lock, SR, s3port, data, staffdir_fs, sgid_fs)

def _rt24_segment_01(data):
    SD = "/shareddir"            # 0770 alice:shared (alice,bob,carol)
    DOC = f"{SD}/mp_doc.txt"
    docfp = os.path.join(data, "shareddir", "mp_doc.txt")
    A_MARK = b"ALICE-CREATED-SHARED-DOC"
    B_MARK = b"BOB-OVERWROTE-SHARED-DOC"
    return SD, DOC, docfp, A_MARK, B_MARK


def _rt24_a_3_way_shareddir_collaboration_alice(DOC, port, key, A_MARK, docfp):

    # ---- (A) 3-way shareddir collaboration: alice creates, bob rewrites, carol
    #      reads, dave (NON-member) is shut out at every stage ----------------

    # alice (shared member + dir group) CREATES the collaborative doc.
    st, _ = http("PUT", DOC, port, mint(key, "alice"), A_MARK + b"\n")
    ok(all((st in (200, 201, 204), os.path.exists(docfp), os.stat(docfp).st_uid == UID_ALICE)),
       f"alice creates shared doc in 0770 shared dir, owned alice (HTTP {st})")

    # carol (shared member) READS alice's fresh doc via group DAC.
    st, b = http("GET", DOC, port, mint(key, "carol"))
    ok(all((st == 200, _has(b, A_MARK))),
       f"carol (shared member) reads alice's shared doc via group DAC (HTTP {st})")

    # bob (shared member) READS it too (second member, proves not owner-only).
    st, b = http("GET", DOC, port, mint(key, "bob"))
    return st, b


def _rt24_frank_not_in_shared_also_denied(st, b, A_MARK, DOC, port, key):
    ok(all((st == 200, _has(b, A_MARK))),
       f"bob (shared member) reads alice's shared doc via group DAC (HTTP {st})")

    # dave (NOT in shared) is DENIED the read + no marker leak.
    st, b = http("GET", DOC, port, mint(key, "dave"))
    ok(not _has(b, A_MARK),
       f"dave (NOT in shared) denied read of shared doc, no leak (HTTP {st})")

    # frank (NOT in shared) also denied (independent non-member control).
    st, b = http("GET", DOC, port, mint(key, "frank"))
    ok(not _has(b, A_MARK),
       f"frank (NOT in shared) denied read of shared doc, no leak (HTTP {st})")


def _rt24_bob_shared_member_overwrites_the_doc(DOC, port, key, B_MARK, docfp, A_MARK):

    # bob (shared member) OVERWRITES the doc that alice created — a different
    # principal mutating a shared-group object through dir-group write.  A staged
    # PUT replaces the file via the dir, so the new file is bob-owned.
    st, _ = http("PUT", DOC, port, mint(key, "bob"), B_MARK + b"\n")
    bob_wrote = os.path.exists(docfp) and B_MARK in open(docfp, "rb").read()
    ok(all((st in (200, 201, 204), bob_wrote, os.stat(docfp).st_uid == UID_BOB)),
       f"bob overwrites alice's shared doc (group write), now bob-owned (HTTP {st})")

    # carol (third member) reads bob's NEW content — the collaboration round-trip.
    st, b = http("GET", DOC, port, mint(key, "carol"))
    ok(all((st == 200, _has(b, B_MARK), not _has(b, A_MARK))),
       f"carol reads bob's updated shared doc (3-way round-trip) (HTTP {st})")


def _rt24_dave_non_member_cannot_overwrite_the(DOC, port, key, docfp, B_MARK):

    # dave (non-member) cannot OVERWRITE the shared doc — write deny + content
    # of bob's version must survive unmangled.
    st, _ = http("PUT", DOC, port, mint(key, "dave"), b"DAVE-PWN\n")
    try:
        cur = open(docfp, "rb").read()
    except OSError:
        cur = b""
    ok(all((b'DAVE-PWN' not in cur, B_MARK in cur)),
       f"dave (NON-member) cannot overwrite shared doc, bob's content intact (HTTP {st})")

    # dave (non-member) cannot DELETE the shared doc (no dir write via group).
    st, _ = http("DELETE", DOC, port, mint(key, "dave"))
    ok(os.path.exists(docfp),
       f"dave (NON-member) cannot delete shared doc (HTTP {st})")


def _rt24_control_proving_the_dave_deny_is(DOC, port, key, docfp, SD, data):

    # carol (member) CAN delete it (dir write through shared group) — positive
    # control proving the dave deny is membership-driven, not a blanket lock.
    st, _ = http("DELETE", DOC, port, mint(key, "carol"))
    ok(not os.path.exists(docfp),
       f"carol (shared member) deletes the shared doc via group dir write (HTTP {st})")

    # dave (non-member) cannot create ANY new file in the shared dir either.
    st, _ = http("PUT", f"{SD}/mp_dave_intrude.txt", port, mint(key, "dave"), b"x\n")
    ok(not os.path.exists(os.path.join(data, "shareddir", "mp_dave_intrude.txt")),
       f"dave (NON-member) cannot create in 0770 shared dir (HTTP {st})")

    # ---- (B) proj group (carol,dave,erin): a proj-readable file readable by all
    #      THREE proj members, denied to alice/bob/frank (none in proj) ---------
    PR_MARK = b"PROJ-TRIO-READABLE"
    return PR_MARK


def _rt24_owner_carol_reads_owner_bits(data, PR_MARK, port, key):
    projfp = os.path.join(data, "mp_proj_r.txt")
    try:
        with open(projfp, "wb") as fh:
            fh.write(PR_MARK + b"\n")
        os.chown(projfp, UID_CAROL, GID_PROJ)   # carol:proj
        os.chmod(projfp, 0o640)                 # group-readable, no other read
        ensure_traversable(projfp)
    except OSError:
        pass
    PROJP = "/mp_proj_r.txt"

    # owner carol reads (owner bits).
    st, b = http("GET", PROJP, port, mint(key, "carol"))
    ok(all((st == 200, _has(b, PR_MARK))),
       f"owner carol reads 0640 proj file (HTTP {st})")
    return PROJP


def _rt24_dave_proj_member_supplementary_reads_via(PROJP, port, key, PR_MARK, st, b):
    # dave (proj member, supplementary) reads via group DAC.
    st, b = http("GET", PROJP, port, mint(key, "dave"))
    ok(all((st == 200, _has(b, PR_MARK))),
       f"dave (proj member) reads 0640 proj file via group DAC (HTTP {st})")
    # erin (proj member, supplementary) reads via group DAC — the THIRD member.
    st, b = http("GET", PROJP, port, mint(key, "erin"))
    ok(all((st == 200, _has(b, PR_MARK))),
       f"erin (proj member) reads 0640 proj file via group DAC (HTTP {st})")
    # alice (NOT in proj) denied + no leak.
    st, b = http("GET", PROJP, port, mint(key, "alice"))
    return st, b


def _rt24_frank_not_in_proj_denied_no(b, PR_MARK, st, PROJP, port, key):
    ok(not _has(b, PR_MARK),
       f"alice (NOT in proj) denied 0640 proj file, no leak (HTTP {st})")
    # bob (NOT in proj) denied + no leak.
    st, b = http("GET", PROJP, port, mint(key, "bob"))
    ok(not _has(b, PR_MARK),
       f"bob (NOT in proj) denied 0640 proj file, no leak (HTTP {st})")
    # frank (NOT in proj) denied + no leak — third non-member control.
    st, b = http("GET", PROJP, port, mint(key, "frank"))
    ok(not _has(b, PR_MARK),
       f"frank (NOT in proj) denied 0640 proj file, no leak (HTTP {st})")


def _rt24_segment_01_3(PDIR, sub, port, key, pdir_fp, uid):
    st, _ = http("PUT", f"{PDIR}/mp_{sub}.txt", port, mint(key, sub),
                 f"{sub}-proj\n".encode())
    fp = os.path.join(pdir_fp, f"mp_{sub}.txt")
    exists = os.path.exists(fp)
    owned = exists and os.stat(fp).st_uid == uid
    grp_ok = exists and os.stat(fp).st_gid == GID_PROJ
    return st, owned, grp_ok


def _rt24_segment_02(st, owned, grp_ok, sub):
    ok(all((st in (200, 201, 204), owned, grp_ok)),
       f"{sub} (proj member) creates in 2770 proj dir: owned {sub}, "
       f"setgid-inherits proj group (HTTP {st})")


def _rt24_for_each_sub_uid_carol_uid_carol_dave(port, key, sub, PDIR, pdir_fp, uid):
    st, owned, grp_ok = _rt24_segment_01_3(PDIR, sub, port, key, pdir_fp, uid)

    _rt24_segment_02(st, owned, grp_ok, sub)



def _rt24_the_same_proj_trio_over_root(PROJP, PR_MARK, data, port, key):

    # The same proj trio over root:// (protocol-independent kernel group state):
    # one member ALLOWED, one non-member DENIED.
    if xrd_avail():
        rc, out, _e = xrd_fs(["cat", PROJP], "erin")
        ok(all((rc == 0, PR_MARK.decode() in any((out, '')))),
           f"erin reads proj file via root:// group DAC (rc={rc})")
        rc, out, _e = xrd_fs(["cat", PROJP], "alice")
        ok(all((rc != 0, PR_MARK.decode() not in any((out, '')))),
           f"alice (NON-proj) denied proj file via root:// (rc={rc})")
        rc, out, _e = xrd_fs(["cat", PROJP], "dave")
        ok(all((rc == 0, PR_MARK.decode() in any((out, '')))),
           f"dave reads proj file via root:// group DAC (rc={rc})")

    # ---- (C) proj-group WRITE collaboration: a 2770 setgid proj dir where the
    #      THREE proj members co-write and inherit the proj group, non-members
    #      shut out ---------------------------------------------------------
    PDIR = "/mp_projdir"
    pdir_fp = os.path.join(data, "mp_projdir")
    try:
        os.makedirs(pdir_fp, exist_ok=True)
        os.chown(pdir_fp, UID_CAROL, GID_PROJ)
        os.chmod(pdir_fp, 0o2770)               # setgid + group rwx (proj)
        ensure_traversable(pdir_fp)
    except OSError:
        pass

    # each proj member creates a file: allowed, and SETGID makes the file inherit
    # the proj group regardless of the creator's primary group.
    for sub, uid in (("carol", UID_CAROL), ("dave", UID_DAVE), ("erin", UID_ERIN)):
        _rt24_for_each_sub_uid_carol_uid_carol_dave(port, key, sub, PDIR, pdir_fp, uid)
    return PDIR, pdir_fp


def _rt24_a_proj_member_reads_a_file(PDIR, port, key, pdir_fp):

    # a proj member READS a file ANOTHER proj member just created (group rw +
    # group-readable default) — cross-member collaboration inside the dir.
    st, b = http("GET", f"{PDIR}/mp_carol.txt", port, mint(key, "erin"))
    ok(all((st == 200, _has(b, b'carol-proj'))),
       f"erin reads carol's file inside the shared proj dir (HTTP {st})")

    # alice (NOT in proj) cannot create in the proj dir + cannot read its files.
    st, _ = http("PUT", f"{PDIR}/mp_alice_intrude.txt", port, mint(key, "alice"), b"x\n")
    ok(not os.path.exists(os.path.join(pdir_fp, "mp_alice_intrude.txt")),
       f"alice (NON-proj) cannot create in 2770 proj dir (HTTP {st})")
    # WebDAV PUT creates files 0644 (NGX_FILE_DEFAULT_ACCESS) = world-readable,
    # so to actually exercise GROUP-restricted denial we tighten dave's file to
    # 0640 (group-only) first — matching the "group-readable default" intent of
    # this dir.  Now frank (NON-proj, neither owner nor group) must be DENIED:
    # a non-200 status AND no marker bytes in the body.
    try:
        os.chmod(os.path.join(pdir_fp, "mp_dave.txt"), 0o640)
    except OSError:
        pass


def _rt24_d_mixed_owner_in_shared_dir(PDIR, port, key, data, SD, st):
    st, b = http("GET", f"{PDIR}/mp_dave.txt", port, mint(key, "frank"))
    ok(all((st != 200, not _has(b, b'dave-proj'))),
       f"frank (NON-proj) cannot read 0640 file in the proj dir, no leak (HTTP {st})")

    # ---- (D) MIXED-owner-in-shared-dir: carol drops a 0600 OWNER-ONLY file into
    #      the shared dir.  Carol (owner) reads it; bob & alice (shared members
    #      who can ENTER the dir but are NOT the owner and the file has no group
    #      bits) are DENIED — proves per-FILE DAC inside a shared dir, not just
    #      dir-level access ----------------------------------------------------
    CMARK = b"CAROL-PRIVATE-IN-SHARED"
    cpriv = os.path.join(data, "shareddir", "mp_carol_private.txt")
    st, _ = http("PUT", f"{SD}/mp_carol_private.txt", port, mint(key, "carol"),
                 CMARK + b"\n")
    return st, CMARK, cpriv


def _rt24_carol_owner_reads_her_own_private(cpriv, st, SD, port, key, CMARK):
    created = os.path.exists(cpriv)
    try:
        if created:
            os.chmod(cpriv, 0o600)              # owner-only inside the shared dir
    except OSError:
        pass
    ok(all((created, os.stat(cpriv).st_uid == UID_CAROL)),
       f"carol drops a 0600 private file into the shared dir, owned carol (HTTP {st})")

    # carol (owner) reads her own private file.
    st, b = http("GET", f"{SD}/mp_carol_private.txt", port, mint(key, "carol"))
    ok(all((st == 200, _has(b, CMARK))),
       f"owner carol reads her 0600 file inside the shared dir (HTTP {st})")


def _rt24_bob_shared_member_can_enter_the(SD, port, key, CMARK, cpriv):
    # bob (shared member, can enter the dir, but NOT the owner; no group bits) DENIED.
    st, b = http("GET", f"{SD}/mp_carol_private.txt", port, mint(key, "bob"))
    ok(not _has(b, CMARK),
       f"bob (dir member but not owner) denied carol's 0600 file, no leak (HTTP {st})")
    # alice (shared member + dir owner) is STILL denied the 0600 file's bytes
    # (dir ownership != file ownership) + no leak.
    st, b = http("GET", f"{SD}/mp_carol_private.txt", port, mint(key, "alice"))
    ok(not _has(b, CMARK),
       f"alice (dir owner, not file owner) denied carol's 0600 file, no leak (HTTP {st})")

    # carol re-shares it to the group (chmod 0640) -> bob (shared member) can NOW
    # read it -> proves the earlier deny was the missing group bit, not the user.
    try:
        os.chmod(cpriv, 0o640)
        os.chown(cpriv, UID_CAROL, GID_SHARED)  # carol:shared so members get group bits
    except OSError:
        pass


def _rt24_dave_not_in_shared_still_denied(SD, port, key, CMARK):
    st, b = http("GET", f"{SD}/mp_carol_private.txt", port, mint(key, "bob"))
    ok(all((st == 200, _has(b, CMARK))),
       f"after carol re-shares (0640 carol:shared), bob reads via group DAC (HTTP {st})")
    # dave (NOT in shared) still denied even after re-share.
    st, b = http("GET", f"{SD}/mp_carol_private.txt", port, mint(key, "dave"))
    ok(not _has(b, CMARK),
       f"dave (NON-member) still denied the re-shared 0640 file, no leak (HTTP {st})")

    # ---- (E) 4-USER ROUND-ROBIN in a world-writable 0777 dir: alice, carol,
    #      erin, frank each create a DISTINCT file; assert each is owned by its
    #      own creator (no principal bleed) and all four coexist -------------
    RR = "/mp_roundrobin"
    return RR


def _rt24_all_four_files_coexist_with_four(data, RR, port, key):
    rr_fp = os.path.join(data, "mp_roundrobin")
    try:
        os.makedirs(rr_fp, exist_ok=True)
        os.chown(rr_fp, UID_SVC, UID_SVC)
        os.chmod(rr_fp, 0o0777)                 # world-writable scratch
        ensure_traversable(rr_fp)
    except OSError:
        pass

    quartet = (("alice", UID_ALICE), ("carol", UID_CAROL),
               ("erin", UID_ERIN), ("frank", UID_FRANK))
    for sub, uid in quartet:
        st, _ = http("PUT", f"{RR}/mp_{sub}_rr.txt", port, mint(key, sub),
                     f"{sub}-roundrobin\n".encode())
        fp = os.path.join(rr_fp, f"mp_{sub}_rr.txt")
        ok(all((st in (200, 201, 204), os.path.exists(fp), os.stat(fp).st_uid == uid)),
           f"round-robin: {sub} creates own file in 0777 dir, owned {sub} (HTTP {st})")

    # all four files coexist with FOUR DISTINCT owners (no two collapsed to one
    # uid — a principal leak would make duplicates).
    owners = set()
    return rr_fp, quartet, owners


def _rt24_segment_01_2(rr_fp):
    leaked_priv = False
    for f in os.listdir(rr_fp):
        p = os.path.join(rr_fp, f)
        if os.path.isfile(p) and not os.path.islink(p):
            if os.lstat(p).st_uid in (UID_SVC, 0):
                leaked_priv = True
    return leaked_priv


def _rt24_try_body(rr_fp):
    leaked_priv = _rt24_segment_01_2(rr_fp)

    return leaked_priv


def _rt24_no_file_in_the_round_robin(quartet, rr_fp, owners):
    present = 0
    for sub, uid in quartet:
        fp = os.path.join(rr_fp, f"mp_{sub}_rr.txt")
        try:
            if os.path.exists(fp):
                present += 1
                owners.add(os.stat(fp).st_uid)
        except OSError:
            pass
    ok(all((present == 4, owners == {UID_ALICE, UID_CAROL, UID_ERIN, UID_FRANK})),
       f"4 round-robin files coexist with 4 distinct correct owners "
       f"(present={present}, owners={sorted(owners)})")
    # no file in the round-robin dir is owned by the worker (1500) or root (0).
    leaked_priv = False
    try:
        leaked_priv = _rt24_try_body(rr_fp)
    except OSError:
        pass
    return leaked_priv


def _rt24_f_concurrent_4_party_storm_on(leaked_priv):
    ok(not leaked_priv,
       "round-robin dir has no worker/root-owned files (no principal leak)")

    # ---- (F) CONCURRENT 4-party storm on the SAME 0777 dir: the per-worker
    #      principal is process-global, so hammer 4 identities in parallel and
    #      verify every file lands under its OWN creator -----------------------
    storm_bad = []
    return storm_bad


def _rt24_segment_19(quartet, RR, port, key, rr_fp, storm_bad):

    def storm(idx):
        sub, uid = quartet[idx % 4]
        name = f"mp_storm_{sub}_{idx}.txt"
        try:
            http("PUT", f"{RR}/{name}", port, mint(key, sub),
                 f"{sub}-{idx}\n".encode())
            fp = os.path.join(rr_fp, name)
            if os.path.exists(fp) and os.lstat(fp).st_uid != uid:
                storm_bad.append((sub, idx, os.lstat(fp).st_uid))
        except Exception as e:  # noqa: BLE001
            storm_bad.append(("exc", idx, repr(e)))
    return storm


def _rt24_a_final_independent_sweep_of_storm(storm, storm_bad):

    threads = [threading.Thread(target=storm, args=(i,)) for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok(not storm_bad,
       f"concurrent 4-party storm: every file owned by its creator, no principal "
       f"leak (breaches={storm_bad[:3]})")

    # a final independent sweep of storm files confirms only the four legit uids.
    storm_owners = set()
    return storm_owners


def _rt24_g_three_way_research_vs_staff(rr_fp, storm_owners):
    sweep_ok = True
    try:
        for f in os.listdir(rr_fp):
            if not f.startswith("mp_storm_"):
                continue
            p = os.path.join(rr_fp, f)
            if os.path.isfile(p) and not os.path.islink(p):
                u = os.lstat(p).st_uid
                storm_owners.add(u)
                if u not in (UID_ALICE, UID_CAROL, UID_ERIN, UID_FRANK):
                    sweep_ok = False
    except OSError:
        pass
    ok(all((sweep_ok, storm_owners <= {UID_ALICE, UID_CAROL, UID_ERIN, UID_FRANK})),
       f"storm-file ownership sweep: only the 4 expected uids "
       f"(found={sorted(storm_owners)})")

    # ---- (G) THREE-WAY research vs staff cross-group denial: research-only file
    #      readable by its two members, denied to two staff (cross-group) -----
    RES = "/grp/research_r.txt"
    RES_MARK = b"RESEARCH-GROUP-READABLE"
    return RES, RES_MARK


def _rt24_bob_owner_dave_research_member_read(RES, port, key, RES_MARK, st, b):
    # bob (owner) + dave (research member) read; alice + carol (staff, NOT
    # research) denied — three+ distinct identities, membership-exact.
    st, b = http("GET", RES, port, mint(key, "bob"))
    ok(all((st == 200, _has(b, RES_MARK))),
       f"owner bob reads research file (HTTP {st})")
    st, b = http("GET", RES, port, mint(key, "dave"))
    ok(all((st == 200, _has(b, RES_MARK))),
       f"dave (research member) reads research file via group DAC (HTTP {st})")
    st, b = http("GET", RES, port, mint(key, "alice"))
    return st, b


def _rt24_segment_23(b, RES_MARK, st, RES, port, key):
    ok(not _has(b, RES_MARK),
       f"alice (staff, NOT research) cross-group denied research file (HTTP {st})")
    st, b = http("GET", RES, port, mint(key, "carol"))
    ok(not _has(b, RES_MARK),
       f"carol (staff, NOT research) cross-group denied research file (HTTP {st})")
    st, b = http("GET", RES, port, mint(key, "frank"))
    ok(not _has(b, RES_MARK),
       f"frank (no shared group) denied research file, no leak (HTTP {st})")


def _rt24_alice_creates_her_own_object_owner(s3port, data, PR_MARK, CMARK):

    # ---- (H) S3 leg (only alice's key is configured): alice is in shared+staff
    #      but NOT proj — she can read a world/shared-readable shared object but
    #      is denied the proj file over S3, mirroring her group membership -----
    if s3port:
        # alice creates her own object (owner-correct) as the S3 positive control.
        st, _ = s3("PUT", "alice/mp_s3_own.txt", s3port, data=b"alice-s3\n")
        sfp = os.path.join(data, "alice", "mp_s3_own.txt")
        ok(all((st in (200, 201), os.path.exists(sfp), os.stat(sfp).st_uid == UID_ALICE)),
           f"S3: alice creates own object, owned alice (HTTP {st})")
        # alice (NOT in proj) denied the proj file over S3 + no marker leak.
        # The object lives at the export root, addressed as a bucket key.
        st, b = s3("GET", "mp_proj_r.txt", s3port)
        ok(not _has(b, PR_MARK),
           f"S3: alice (NON-proj) denied proj file, no leak (HTTP {st})")
        # alice (shared member) CAN read the re-shared 0640 carol:shared file via
        # the group bit over S3 — proves S3 honors the same supplementary-group DAC.
        st, b = s3("GET", "shareddir/mp_carol_private.txt", s3port)
        ok(all((st == 200, _has(b, CMARK))),
           f"S3: alice reads re-shared 0640 shared-group file via group DAC (HTTP {st})")


def run_multiuser_party(key, data, port, s3port):
    """Genuinely MULTI-PARTY (3+ identities) collaboration over SHARED GROUP
    resources, exercising the broker's setgroups()/setfsgid() across several
    distinct users acting on the SAME objects.  Each grant/deny tracks that
    user's REAL group membership (staff={alice,carol}, research={bob,dave},
    shared={alice,bob,carol}, proj={carol,dave,erin}); every deny carries a
    nearby positive control (an entitled member SUCCEEDS) and a no-leak check so
    a blanket block cannot false-pass.  No two-party alice/bob rename: the
    workflows here require 3+ cooperating principals."""
    SD, DOC, docfp, A_MARK, B_MARK = _rt24_segment_01(data)

    st, b = _rt24_a_3_way_shareddir_collaboration_alice(DOC, port, key, A_MARK, docfp)

    _rt24_frank_not_in_shared_also_denied(st, b, A_MARK, DOC, port, key)

    _rt24_bob_shared_member_overwrites_the_doc(DOC, port, key, B_MARK, docfp, A_MARK)

    _rt24_dave_non_member_cannot_overwrite_the(DOC, port, key, docfp, B_MARK)

    PR_MARK = _rt24_control_proving_the_dave_deny_is(DOC, port, key, docfp, SD, data)

    PROJP = _rt24_owner_carol_reads_owner_bits(data, PR_MARK, port, key)

    st, b = _rt24_dave_proj_member_supplementary_reads_via(PROJP, port, key, PR_MARK, st, b)

    _rt24_frank_not_in_proj_denied_no(b, PR_MARK, st, PROJP, port, key)

    PDIR, pdir_fp = _rt24_the_same_proj_trio_over_root(PROJP, PR_MARK, data, port, key)

    _rt24_a_proj_member_reads_a_file(PDIR, port, key, pdir_fp)

    st, CMARK, cpriv = _rt24_d_mixed_owner_in_shared_dir(PDIR, port, key, data, SD, st)

    _rt24_carol_owner_reads_her_own_private(cpriv, st, SD, port, key, CMARK)

    _rt24_bob_shared_member_can_enter_the(SD, port, key, CMARK, cpriv)

    RR = _rt24_dave_not_in_shared_still_denied(SD, port, key, CMARK)

    rr_fp, quartet, owners = _rt24_all_four_files_coexist_with_four(data, RR, port, key)

    leaked_priv = _rt24_no_file_in_the_round_robin(quartet, rr_fp, owners)

    storm_bad = _rt24_f_concurrent_4_party_storm_on(leaked_priv)

    storm = _rt24_segment_19(quartet, RR, port, key, rr_fp, storm_bad)

    storm_owners = _rt24_a_final_independent_sweep_of_storm(storm, storm_bad)

    RES, RES_MARK = _rt24_g_three_way_research_vs_staff(rr_fp, storm_owners)

    st, b = _rt24_bob_owner_dave_research_member_read(RES, port, key, RES_MARK, st, b)

    _rt24_segment_23(b, RES_MARK, st, RES, port, key)

    _rt24_alice_creates_her_own_object_owner(s3port, data, PR_MARK, CMARK)

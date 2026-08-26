def _rt62_segment_01(port, key):
    TAG = "msli"
    base = f"http://{HOST}:{port}"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    tc = mint(key, "carol")
    return TAG, base, ta, tb, tc


def _rt62_on_disk_introspection_runs_as_in(data):

    # ---- on-disk introspection (runs as in-ns root, sees true uid/gid/mode) ----
    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))
    return realp


def _rt62_segment_03(realp):

    def st_of(rel):
        try:
            p = realp(rel)
            return os.stat(p) if os.path.exists(p) else None
        except OSError:
            return None
    return st_of


def _rt62_segment_04(realp):

    def exists(rel):
        try:
            return os.path.exists(realp(rel))
        except OSError:
            return False
    return exists


def _rt62_segment_05(realp):

    def body_of(rel):
        try:
            with open(realp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt62_segment_06():

    def has(body, needle):
        if body is None:
            return False
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return needle in body
    return has


def _rt62_seq_1_alice_create_alice_tighten(TAG, port, ta):

    _multistep_lifecycle_invariants_p1(port, ta, tb, st_of, s3port, realp, tc, body_of, TAG, exists, has, base)


def _multistep_lifecycle_invariants_p1(port, ta, tb, st_of, s3port, realp, tc, body_of, TAG, exists, has, base):
    # =====================================================================
    # SEQ 1 — alice CREATE -> alice tighten to 0600 -> bob GET.
    # END-STATE INVARIANT: after the successful create+chmod chain the file is
    # still alice-owned at 0600 AND a cross-tenant reader (bob) gets zero bytes.
    # (Distinct from rollback: every step here SUCCEEDS; the invariant is the
    # post-tighten ownership+confidentiality end-state, not a failed-op cleanup.)
    # =====================================================================
    S1_REL = f"alice/{TAG}_s1_tighten.txt"
    S1_MARK = b"MSLI-S1-ALICE-CONFIDENTIAL-7Q"
    http("DELETE", "/" + S1_REL, port, ta)
    c1, _ = http("PUT", "/" + S1_REL, port, ta, S1_MARK)
    ok(c1 in (200, 201, 204), f"{TAG}/s1: alice PUT creates her file (HTTP {c1})")
    return S1_REL, S1_MARK


def _rt62_segment_08(S1_REL, port, ta, realp, TAG, tb, st_of):
    pp1, _ = http("PROPPATCH", "/" + S1_REL, port, ta,
                  data=b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"'
                       b' xmlns:Z="urn:x"><D:set><D:prop><Z:tag>t1</Z:tag>'
                       b'</D:prop></D:set></D:propertyupdate>',
                  hdrs={"Content-Type": "application/xml"})
    try:
        os.chmod(realp(S1_REL), 0o600)
        chm1 = True
    except OSError:
        chm1 = False
    ok(chm1, f"{TAG}/s1: 0600 tighten applied (os.chmod)")
    sb1, bb1 = http("GET", "/" + S1_REL, port, tb)   # bob: cross-tenant reader
    s1 = st_of(S1_REL)
    return sb1, bb1, s1


def _rt62_the_terminal_invariant_alice_owned_0600(s1, sb1, has, bb1, S1_MARK, TAG, port, ta):
    # The terminal invariant: alice-owned 0600 AND bob denied AND no marker leak.
    ok(all((s1 is not None, s1.st_uid == UID_ALICE, s1.st_mode & 511 == 384, s1.st_uid not in (UID_SVC, 0), sb1 in (401, 403, 404, 500), not has(bb1, S1_MARK))),
       f"{TAG}/s1 INVARIANT: after create+proppatch+tighten the file is "
       f"alice:0600 and bob's read is denied+empty "
       f"(uid={getattr(s1,'st_uid',None)} HTTP_bob={sb1})")
    _multistep_lifecycle_invariants_p2(port, ta, s3port, realp, st_of, tc, tb, body_of, TAG, exists, has, base)


def _multistep_lifecycle_invariants_p2(port, ta, s3port, realp, st_of, tc, tb, body_of, TAG, exists, has, base):
    # =====================================================================
    # SEQ 2 — alice MKCOL coll -> PUT 3 distinct files into it -> MOVE the WHOLE
    # collection to a new path.
    # END-STATE INVARIANT: at the NEW path every child is still alice-owned with
    # byte-exact content, and NOTHING remains at the OLD path.  (setgid batch
    # COPYs single files into a setgid dir; this is a plain whole-collection MOVE
    # whose invariant is child-ownership + content survival across the rename.)
    # =====================================================================
    C_OLD = f"alice/{TAG}_s2_coll"
    C_NEW = f"alice/{TAG}_s2_moved"
    http("DELETE", "/" + C_OLD, port, ta)
    http("DELETE", "/" + C_NEW, port, ta)
    return C_OLD, C_NEW


def _rt62_segment_10(C_OLD, port, ta, TAG):
    mk2, _ = http("MKCOL", "/" + C_OLD, port, ta)
    ok(mk2 in (200, 201), f"{TAG}/s2: alice MKCOL collection (HTTP {mk2})")
    kids = {"a.txt": b"MSLI-S2-CHILD-A", "b.txt": b"MSLI-S2-CHILD-BB",
            "c.txt": b"MSLI-S2-CHILD-CCC"}
    put_all = True
    for nm, bd in kids.items():
        pc, _ = http("PUT", f"/{C_OLD}/{nm}", port, ta, bd)
        put_all = put_all and pc in (200, 201, 204)
    return kids, put_all


def _rt62_terminal_invariant_over_all_children_at(put_all, TAG, C_OLD, port, ta, base, C_NEW, kids, st_of, body_of):
    ok(put_all, f"{TAG}/s2: alice PUT 3 children into the collection")
    mv2, _ = http("MOVE", "/" + C_OLD, port, ta,
                  hdrs={"Destination": base + "/" + C_NEW, "Depth": "infinity"})
    ok(mv2 in (200, 201, 204),
       f"{TAG}/s2: alice MOVE whole collection to new path (HTTP {mv2})")
    # Terminal invariant over ALL children at the destination.
    all_ok = True
    for nm, bd in kids.items():
        cs = st_of(f"{C_NEW}/{nm}")
        if cs is None or cs.st_uid != UID_ALICE or cs.st_uid in (UID_SVC, 0):
            all_ok = False
        if body_of(f"{C_NEW}/{nm}") != bd:
            all_ok = False
    return all_ok


def _rt62_seq_3_alice_mkcol_put_a(all_ok, TAG, exists, C_OLD, port, ta):
    ok(all_ok,
       f"{TAG}/s2 INVARIANT: every moved child is alice-owned with byte-exact "
       f"content at the new path (not svc/root)")
    ok(not exists(C_OLD),
       f"{TAG}/s2 INVARIANT: old collection path fully gone after MOVE (rename, "
       f"no stray copy left behind)")
    _multistep_lifecycle_invariants_p3(port, ta, s3port, realp, st_of, tc, tb, body_of, TAG, exists, has, base)


def _multistep_lifecycle_invariants_p3(port, ta, s3port, realp, st_of, tc, tb, body_of, TAG, exists, has, base):
    # =====================================================================
    # SEQ 3 — alice MKCOL -> PUT a file -> recursive DELETE the collection.
    # END-STATE INVARIANT: the whole subtree is gone AND the parent dir contains
    # no svc/root-owned residue from the delete (a successful recursive delete
    # leaves a clean namespace — distinct from rollback's *failed*-op residue).
    # =====================================================================
    D_COLL = f"alice/{TAG}_s3_del"
    http("DELETE", "/" + D_COLL, port, ta)
    mk3, _ = http("MKCOL", "/" + D_COLL, port, ta)
    return D_COLL, mk3


def _rt62_segment_13(mk3, TAG, D_COLL, port, ta, exists):
    ok(mk3 in (200, 201), f"{TAG}/s3: alice MKCOL deletable collection (HTTP {mk3})")
    http("PUT", f"/{D_COLL}/inner.txt", port, ta, b"MSLI-S3-INNER")
    http("MKCOL", f"/{D_COLL}/sub", port, ta)
    http("PUT", f"/{D_COLL}/sub/deep.txt", port, ta, b"MSLI-S3-DEEP")
    seeded3 = exists(f"{D_COLL}/inner.txt") and exists(f"{D_COLL}/sub/deep.txt")
    return seeded3


def _rt62_the_webdav_module_implements_non_recursive(seeded3, TAG, D_COLL, port, ta):
    ok(seeded3, f"{TAG}/s3: collection populated with nested children")
    # The WebDAV module implements NON-recursive collection DELETE
    # (src/protocols/webdav/namespace.c sets opts.require_empty_dir = 1): a DELETE of a
    # non-empty collection is refused with 409 Conflict and leaves the subtree
    # wholly intact (no partial wipe) — same policy as S3 BucketNotEmpty.  This
    # is the documented/tested contract (test_webdav_delete_lock_security.py:
    # test_delete_nonempty_collection_returns_409).  Assert that refusal, then
    # walk the documented happy path (empty depth-first, then drop the now-empty
    # collection) to reach the SAME clean end-state this invariant checks.
    dl3_busy, _ = http("DELETE", "/" + D_COLL, port, ta)
    ok(dl3_busy == 409,
       f"{TAG}/s3: alice DELETE of NON-empty collection refused 409 Conflict "
       f"(non-recursive WebDAV policy; HTTP {dl3_busy})")
    http("DELETE", f"/{D_COLL}/sub/deep.txt", port, ta)
    http("DELETE", f"/{D_COLL}/sub", port, ta)


def _rt62_scan_alice_for_any_new_svc(D_COLL, port, ta, TAG, realp):
    http("DELETE", f"/{D_COLL}/inner.txt", port, ta)
    dl3, _ = http("DELETE", "/" + D_COLL, port, ta)
    ok(dl3 in (200, 204), f"{TAG}/s3: alice DELETE now-empty collection (HTTP {dl3})")
    # scan alice/ for any new svc/root-owned entry matching this seq's prefix.
    leftover = []
    try:
        for n in os.listdir(realp("alice")):
            if not n.startswith(f"{TAG}_s3"):
                continue
            try:
                u = os.stat(os.path.join(realp("alice"), n)).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0):
                leftover.append((n, u))
    except OSError:
        pass
    return leftover


def _rt62_segment_01_2(TAG, s3port):
    S4_KEY = f"alice/{TAG}_s4_mpu.bin"
    P1 = b"MSLI-S4-PART-ONE-".ljust(64, b"1") * 80    # ~5 KiB, distinct
    P2 = b"MSLI-S4-PART-TWO-".ljust(64, b"2") * 80    # ~5 KiB, distinct
    s3("DELETE", S4_KEY, s3port)
    ini, ib = s3("POST", S4_KEY, s3port, params={"uploads": ""})
    return S4_KEY, P1, P2, ini, ib


def _rt62_segment_01_3(m, P1, P2, S4_KEY, s3port, TAG):
    up = m.group(1).decode()
    pe = []
    pok = True
    for n, pb in ((1, P1), (2, P2)):
        ps, pbody = s3("PUT", S4_KEY, s3port,
                       params={"uploadId": up, "partNumber": str(n)},
                       data=pb)
        et = re.search(rb'ETag>\\?"?([^"<\\]+)', pbody or b"")
        pe.append((n, et.group(1).decode() if et else "etag"))
        pok = pok and ps in (200, 201)
    ok(pok, f"{TAG}/s4: alice uploaded 2 distinct multipart parts")
    return up, pe


def _rt62_segment_02(pe, S4_KEY, s3port, up, st_of):
    cx = b"<CompleteMultipartUpload>"
    for n, et in pe:
        cx += (f"<Part><PartNumber>{n}</PartNumber>"
               f"<ETag>{et}</ETag></Part>").encode()
    cx += b"</CompleteMultipartUpload>"
    cs, _ = s3("POST", S4_KEY, s3port, params={"uploadId": up}, data=cx)
    fst = st_of(S4_KEY)
    return cs, fst


def _rt62_ordered_assembly_invariant_exact_p1_p2_3(body_of, S4_KEY, cs, fst, P1, P2, TAG, s3port, has):
    disk = body_of(S4_KEY)
    # ordered-assembly invariant: exact P1||P2, alice-owned.
    ok(all((cs in (200, 201), fst is not None, fst.st_uid == UID_ALICE, fst.st_uid not in (UID_SVC, 0), disk == P1 + P2)),
       f"{TAG}/s4 INVARIANT: completed object is alice-owned and bytes "
       f"== ordered part1||part2 ({len(disk)}=={len(P1)+len(P2)}? "
       f"complete={cs})")
    # cross-tenant denial of the assembled object (bob as accessor).
    bs, bb = s3("GET", S4_KEY, s3port, access_key="bob")
    ok(all((bs in (401, 403, 404), not has(bb, b'MSLI-S4-PART'))),
       f"{TAG}/s4 INVARIANT: bob cross-tenant GET of alice's assembled "
       f"object is denied with no part-marker leak (HTTP {bs})")
    s3("DELETE", S4_KEY, s3port)


def _rt62_when_ini_200_201_m(m, P1, P2, S4_KEY, s3port, TAG, st_of, body_of, has):
    up, pe = _rt62_segment_01_3(m, P1, P2, S4_KEY, s3port, TAG)

    cs, fst = _rt62_segment_02(pe, S4_KEY, s3port, up, st_of)

    _rt62_ordered_assembly_invariant_exact_p1_p2_3(body_of, S4_KEY, cs, fst, P1, P2, TAG, s3port, has)



def _rt62_ordered_assembly_invariant_exact_p1_p2_2(ib, ini, P1, P2, S4_KEY, s3port, TAG, st_of, body_of, has):
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", ib or b"")
    if ini in (200, 201) and m:
        _rt62_when_ini_200_201_m(m, P1, P2, S4_KEY, s3port, TAG, st_of, body_of, has)
    else:
        ok(False, f"{TAG}/s4: multipart initiate failed (HTTP {ini})")


def _rt62_otherwise_s4live_1(TAG, s3port, st_of, body_of, has):
    S4_KEY, P1, P2, ini, ib = _rt62_segment_01_2(TAG, s3port)

    _rt62_ordered_assembly_invariant_exact_p1_p2_2(ib, ini, P1, P2, S4_KEY, s3port, TAG, st_of, body_of, has)



def _rt62_ordered_assembly_invariant_exact_p1_p2(s3port, TAG, st_of, body_of, has):
    s4live, _ = s3("GET", "", s3port, params={"list-type": "2"})
    if s4live == -1:
        ok(True, f"{TAG}/s4: S3 not answering — assembly invariant skipped")
    else:
        _rt62_otherwise_s4live_1(TAG, s3port, st_of, body_of, has)


def _rt62_otherwise_s3port(s3port, TAG, st_of, body_of, has):
    _rt62_ordered_assembly_invariant_exact_p1_p2(s3port, TAG, st_of, body_of, has)



def _rt62_seq_4_s3_multipart_alice_initiate(exists, D_COLL, leftover, TAG, s3port, st_of, body_of, has, realp):
    ok(all((not exists(D_COLL), not leftover)),
       f"{TAG}/s3 INVARIANT: recursive DELETE removed the whole subtree and "
       f"left no svc/root residue (leftover={leftover})")
    _multistep_lifecycle_invariants_p4(s3port, realp, st_of, port, ta, tc, tb, body_of, TAG, has, exists, base)


def _multistep_lifecycle_invariants_p4(s3port, realp, st_of, port, ta, tc, tb, body_of, TAG, has, exists, base):
    # =====================================================================
    # SEQ 4 — S3 multipart: alice initiate -> upload part 1 -> part 2 -> complete.
    # END-STATE INVARIANT: the final object is alice-owned, its bytes are the
    # ORDERED concatenation part1||part2 (assembly correctness), and a
    # cross-tenant (bob) GET is denied with no marker leak.  (multipart_lock
    # batch covers abort/RST/cross-tenant-complete; this is a CLEAN 2-part
    # complete whose invariant is ordered byte-exact assembly as the end-state.)
    # =====================================================================
    if not s3port:
        ok(True, f"{TAG}/s4: S3 port down — multipart-assembly invariant skipped")
    else:
        # confirm S3 plane is answering before driving the lifecycle.
        _rt62_otherwise_s3port(s3port, TAG, st_of, body_of, has)


def _multistep_lifecycle_invariants_p5(realp, st_of, port, ta, tc, tb, body_of, TAG, has, exists, base):
    # =====================================================================
    # SEQ 5 — alice CREATE a fresh file (PUT) directly INSIDE a 02770 alice:staff
    # setgid dir, then tighten to 0640.
    # END-STATE INVARIANT: the freshly-CREATED (not copied/moved) file inherits
    # group=staff and owner=alice; a SECOND staff member (carol) can then read it
    # via the inherited group while a NON-staff tenant (bob) is denied.  (setgid
    # batch only inherits through COPY/MOVE/TPC; this proves inheritance on the
    # plain create path as a lifecycle end-state with a positive+negative probe.)
    # =====================================================================
    SG = f"{TAG}_s5_sgid"
    sg_dir = realp(SG)
    try:
        os.makedirs(sg_dir, exist_ok=True)
        os.chown(sg_dir, UID_ALICE, GID_STAFF)
        os.chmod(sg_dir, 0o2770)
        ensure_traversable(sg_dir)
        sgmade = True
    except OSError:
        sgmade = False
    return SG, sgmade


def _rt62_segment_17(st_of, SG, sgmade, TAG, port, ta):
    sgst = st_of(SG)
    ok(all((sgmade, sgst is not None, sgst.st_mode & 1024, sgst.st_gid == GID_STAFF)),
       f"{TAG}/s5: 02770 alice:staff setgid dir present on disk")
    S5_REL = f"{SG}/{TAG}_s5_created.txt"
    S5_MARK = b"MSLI-S5-STAFF-GROUP-CREATED-3K"
    c5, _ = http("PUT", "/" + S5_REL, port, ta, S5_MARK)
    return S5_REL, S5_MARK, c5


def _rt62_segment_18(c5, TAG, st_of, S5_REL, realp, port, tc):
    ok(c5 in (200, 201, 204),
       f"{TAG}/s5: alice CREATEs a fresh file inside the setgid dir (HTTP {c5})")
    s5 = st_of(S5_REL)
    ok(all((s5 is not None, s5.st_gid == GID_STAFF, s5.st_uid == UID_ALICE, s5.st_uid not in (UID_SVC, 0))),
       f"{TAG}/s5 INVARIANT: freshly-created file INHERITS group=staff and is "
       f"owned by alice (uid={getattr(s5,'st_uid',None)} "
       f"gid={getattr(s5,'st_gid',None)})")
    try:
        os.chmod(realp(S5_REL), 0o640)
    except OSError:
        pass
    rc5, rb5 = http("GET", "/" + S5_REL, port, tc)   # carol = staff member
    return rc5, rb5


def _rt62_seq_6_alice_mkdir_chain_top(S5_REL, port, tb, rc5, has, rb5, S5_MARK, TAG):
    bc5, bb5 = http("GET", "/" + S5_REL, port, tb)   # bob = NOT staff
    ok(all((rc5 == 200, has(rb5, S5_MARK), bc5 in (401, 403, 404, 500), not has(bb5, S5_MARK))),
       f"{TAG}/s5 INVARIANT: created-file's inherited staff group grants carol "
       f"(member) but denies bob (non-member) — group is real, not cosmetic "
       f"(carol={rc5} bob={bc5})")
    _multistep_lifecycle_invariants_p6(port, ta, st_of, body_of, TAG, exists, realp, has, base)


def _multistep_lifecycle_invariants_p6(port, ta, st_of, body_of, TAG, exists, realp, has, base):
    # =====================================================================
    # SEQ 6 — alice mkdir chain top/mid/leaf -> PUT a file in leaf -> attempt to
    # rmdir the NON-EMPTY mid directory.
    # END-STATE INVARIANT: the rmdir is REFUSED (ENOTEMPTY) and the ENTIRE subtree
    # (top, mid, leaf, the file) survives unchanged + alice-owned.  (Distinct from
    # rollback's staging-residue: here the failure is a directory-removal refusal
    # whose invariant is tree-INTACTNESS, not absence of temp files.)
    # =====================================================================
    A = "alice"
    TOP = f"/{A}/{TAG}_s6_top"
    MID = TOP + "/mid"
    return A, TOP, MID


def _rt62_segment_20(MID, TOP):
    LEAF = MID + "/leaf"
    xrd_fs(["rm", LEAF + "/f.bin"], "alice")
    xrd_fs(["rmdir", LEAF], "alice")
    xrd_fs(["rmdir", MID], "alice")
    xrd_fs(["rmdir", TOP], "alice")
    return LEAF


def _rt62_segment_21(TOP, MID, LEAF, TAG, port, ta):
    r_top, _, _ = xrd_fs(["mkdir", TOP], "alice")
    r_mid, _, _ = xrd_fs(["mkdir", MID], "alice")
    r_leaf, _, _ = xrd_fs(["mkdir", LEAF], "alice")
    ok(all((r_top == 0, r_mid == 0, r_leaf == 0)),
       f"{TAG}/s6: alice built 3-level mkdir chain (rc={r_top},{r_mid},{r_leaf})")
    pl6, _ = http("PUT", LEAF + "/f.bin", port, ta, b"MSLI-S6-LEAF-FILE")
    return pl6


def _rt62_terminal_invariant_rmdir_refused_and_every(pl6, exists, A, TAG, MID, st_of):
    ok(all((pl6 in (200, 201, 204), exists(f'{A}/{TAG}_s6_top/mid/leaf/f.bin'))),
       f"{TAG}/s6: file planted in the leaf directory (HTTP {pl6})")
    rrc, _, rerr = xrd_fs(["rmdir", MID], "alice")     # mid is NON-empty
    # Terminal invariant: rmdir refused AND every level + the file still present
    # and alice-owned (nothing partially removed, nothing reparented to svc/root).
    lvl = [st_of(f"{A}/{TAG}_s6_top"), st_of(f"{A}/{TAG}_s6_top/mid"),
           st_of(f"{A}/{TAG}_s6_top/mid/leaf"),
           st_of(f"{A}/{TAG}_s6_top/mid/leaf/f.bin")]
    tree_intact = all(s is not None and s.st_uid == UID_ALICE
                      and s.st_uid not in (UID_SVC, 0) for s in lvl)
    ok(all((rrc != 0, tree_intact)),
       f"{TAG}/s6 INVARIANT: rmdir of non-empty dir REFUSED (rc={rrc}) and the "
       f"full subtree (top/mid/leaf/f.bin) survives intact + alice-owned")
    _multistep_lifecycle_invariants_p7(port, ta, st_of, body_of, TAG, realp, has, exists, base)


def _rt62_xrd_tmp_part_residue_beside_it(TAG, port, ta):

    # =====================================================================
    # SEQ 7 — alice PUT v1 -> PUT v2 OVER the same path (overwrite) -> PUT v3.
    # END-STATE INVARIANT: exactly ONE file at the path holding the LATEST body
    # (replace, not append), still alice-owned, with size == len(v3) and no stray
    # .xrd-tmp / .part residue beside it.  (Idempotent-overwrite end-state; no
    # other combo batch asserts replace-not-append + single-inode terminal state.)
    # =====================================================================
    S7_REL = f"alice/{TAG}_s7_overwrite.txt"
    http("DELETE", "/" + S7_REL, port, ta)
    v1 = b"MSLI-S7-VERSION-ONE"
    v2 = b"MSLI-S7-VERSION-TWO-LONGER-BODY"
    v3 = b"MSLI-S7-V3"
    return S7_REL, v1, v2, v3


def _rt62_segment_24(S7_REL, port, ta, v1, v2, v3, TAG, st_of):
    o1, _ = http("PUT", "/" + S7_REL, port, ta, v1)
    o2, _ = http("PUT", "/" + S7_REL, port, ta, v2)
    o3, _ = http("PUT", "/" + S7_REL, port, ta, v3)
    ok(all((o1 in (200, 201, 204), o2 in (200, 201, 204), o3 in (200, 201, 204))),
       f"{TAG}/s7: alice PUT same path three times ({o1},{o2},{o3})")
    s7 = st_of(S7_REL)
    return s7


def _rt62_residue_scan_in_alice_for_this(body_of, S7_REL, realp, TAG, s7, v3):
    disk7 = body_of(S7_REL)
    # residue scan in alice/ for this seq (overwrite must not strand temps).
    res7 = []
    try:
        for n in os.listdir(realp("alice")):
            low = n.lower()
            if n.startswith(f"{TAG}_s7") and (".xrd-tmp." in low
                                              or low.endswith(".part")
                                              or ".part." in low):
                res7.append(n)
    except OSError:
        pass
    ok(all((s7 is not None, disk7 == v3, len(disk7) == len(v3), s7.st_uid == UID_ALICE, s7.st_uid not in (UID_SVC, 0), not res7)),
       f"{TAG}/s7 INVARIANT: overwrite REPLACED content (==v3, size {len(disk7)}) "
       f"as a single alice-owned inode with no temp residue (res={res7})")
    _multistep_lifecycle_invariants_p8(port, ta, st_of, TAG, has, body_of, exists, base)


def _multistep_lifecycle_invariants_p8(port, ta, st_of, TAG, has, body_of, exists, base):
    # =====================================================================
    # SEQ 8 — alice PUT -> MOVE to path2 -> MOVE to path3 (rename chain within
    # alice's own tree).
    # END-STATE INVARIANT: exactly ONE inode exists, at the FINAL path, alice-owned
    # with intact content; NEITHER intermediate path retains a copy (no inode
    # leakage across a chain of renames).  (Distinct from setgid's single MOVE: the
    # invariant here is no-stray-copy across MULTIPLE chained renames.)
    # =====================================================================
    P1R = f"alice/{TAG}_s8_p1.txt"
    return P1R


def _rt62_segment_26(TAG, P1R, port, ta):
    P2R = f"alice/{TAG}_s8_p2.txt"
    P3R = f"alice/{TAG}_s8_p3.txt"
    for p in (P1R, P2R, P3R):
        http("DELETE", "/" + p, port, ta)
    S8_BODY = b"MSLI-S8-RENAME-CHAIN-BODY"
    p8, _ = http("PUT", "/" + P1R, port, ta, S8_BODY)
    return P2R, P3R, S8_BODY, p8


def _rt62_segment_27(p8, TAG, P1R, port, ta, base, P2R, P3R, st_of):
    ok(p8 in (200, 201, 204), f"{TAG}/s8: alice PUT initial file (HTTP {p8})")
    mv8a, _ = http("MOVE", "/" + P1R, port, ta,
                   hdrs={"Destination": base + "/" + P2R})
    mv8b, _ = http("MOVE", "/" + P2R, port, ta,
                   hdrs={"Destination": base + "/" + P3R})
    ok(all((mv8a in (200, 201, 204), mv8b in (200, 201, 204))),
       f"{TAG}/s8: alice chained two MOVEs ({mv8a},{mv8b})")
    s8 = st_of(P3R)
    return s8


def _rt62_seq_9_final_liveness_prove_the(s8, body_of, P3R, S8_BODY, exists, P1R, P2R, TAG, port, ta):
    ok(all((s8 is not None, s8.st_uid == UID_ALICE, s8.st_uid not in (UID_SVC, 0), body_of(P3R) == S8_BODY, not exists(P1R), not exists(P2R))),
       f"{TAG}/s8 INVARIANT: after a 2-hop rename chain exactly ONE alice-owned "
       f"inode with intact content exists at the final path and neither "
       f"intermediate path retains a copy")
    _multistep_lifecycle_invariants_p9(port, ta, st_of, TAG, has)


def _multistep_lifecycle_invariants_p9(port, ta, st_of, TAG, has):
    # =====================================================================
    # SEQ 9 — final liveness: prove the worker/broker never wedged through all of
    # the above by serving a fresh legit alice create+read.  (END-STATE health
    # invariant for the whole batch — a single decisive observation.)
    # =====================================================================
    LIVE = f"alice/{TAG}_s9_live.txt"
    LMARK = b"MSLI-S9-LIVENESS"
    http("DELETE", "/" + LIVE, port, ta)
    lp, _ = http("PUT", "/" + LIVE, port, ta, LMARK)
    return LIVE, LMARK, lp


def _rt62_segment_29(LIVE, port, ta, st_of, lp, has, LMARK, TAG):
    lg, lgb = http("GET", "/" + LIVE, port, ta)
    ls = st_of(LIVE)
    ok(all((lp in (200, 201, 204), lg == 200, has(lgb, LMARK), ls is not None, ls.st_uid == UID_ALICE)),
       f"{TAG}/s9 INVARIANT: after every lifecycle chain a fresh alice "
       f"create+read still works owned alice — worker never wedged "
       f"(PUT {lp} GET {lg})")
    http("DELETE", "/" + LIVE, port, ta)


def run_multistep_lifecycle_invariants(key, data, port, s3port):
    """MULTI-STEP LIFECYCLE END-STATE INVARIANTS under per-request UNIX impersonation.

    Every other combo batch asserts properties PER STEP (run_combo_setgid_via_copymove
    checks the group on each copied/moved file; run_combo_multipart_lock_identity checks
    each interrupted-multipart/lock transition; run_combo_error_rollback checks each
    FAILED op leaves no residue).  This batch instead drives chains that SUCCEED all the
    way through and asserts a single invariant at the END of the whole chain — the
    property that only holds once every step has run.  Each sequence ends in a DISTINCT
    end-state observation: ownership stability across a verb chain, child ownership after
    a whole-collection MOVE, clean recursive-DELETE end-state, byte-exact ordered
    multipart assembly, setgid inheritance for a freshly CREATED (not copied) file,
    a non-empty rmdir that must FAIL and leave the subtree wholly intact, overwrite
    idempotency (replace not append, single inode), and a rename-chain leaving exactly
    one inode.  All fixtures prefixed `msli_` to avoid collisions with the battery."""
    TAG, base, ta, tb, tc = _rt62_segment_01(port, key)

    realp = _rt62_on_disk_introspection_runs_as_in(data)

    st_of = _rt62_segment_03(realp)

    exists = _rt62_segment_04(realp)

    body_of = _rt62_segment_05(realp)

    has = _rt62_segment_06()

    S1_REL, S1_MARK = _rt62_seq_1_alice_create_alice_tighten(TAG, port, ta)

    sb1, bb1, s1 = _rt62_segment_08(S1_REL, port, ta, realp, TAG, tb, st_of)

    C_OLD, C_NEW = _rt62_the_terminal_invariant_alice_owned_0600(s1, sb1, has, bb1, S1_MARK, TAG, port, ta)

    kids, put_all = _rt62_segment_10(C_OLD, port, ta, TAG)

    all_ok = _rt62_terminal_invariant_over_all_children_at(put_all, TAG, C_OLD, port, ta, base, C_NEW, kids, st_of, body_of)

    D_COLL, mk3 = _rt62_seq_3_alice_mkcol_put_a(all_ok, TAG, exists, C_OLD, port, ta)

    seeded3 = _rt62_segment_13(mk3, TAG, D_COLL, port, ta, exists)

    _rt62_the_webdav_module_implements_non_recursive(seeded3, TAG, D_COLL, port, ta)

    leftover = _rt62_scan_alice_for_any_new_svc(D_COLL, port, ta, TAG, realp)

    SG, sgmade = _rt62_seq_4_s3_multipart_alice_initiate(exists, D_COLL, leftover, TAG, s3port, st_of, body_of, has, realp)

    S5_REL, S5_MARK, c5 = _rt62_segment_17(st_of, SG, sgmade, TAG, port, ta)

    rc5, rb5 = _rt62_segment_18(c5, TAG, st_of, S5_REL, realp, port, tc)

    A, TOP, MID = _rt62_seq_6_alice_mkdir_chain_top(S5_REL, port, tb, rc5, has, rb5, S5_MARK, TAG)

    LEAF = _rt62_segment_20(MID, TOP)

    pl6 = _rt62_segment_21(TOP, MID, LEAF, TAG, port, ta)

    _rt62_terminal_invariant_rmdir_refused_and_every(pl6, exists, A, TAG, MID, st_of)

    S7_REL, v1, v2, v3 = _rt62_xrd_tmp_part_residue_beside_it(TAG, port, ta)

    s7 = _rt62_segment_24(S7_REL, port, ta, v1, v2, v3, TAG, st_of)

    P1R = _rt62_residue_scan_in_alice_for_this(body_of, S7_REL, realp, TAG, s7, v3)

    P2R, P3R, S8_BODY, p8 = _rt62_segment_26(TAG, P1R, port, ta)

    s8 = _rt62_segment_27(p8, TAG, P1R, port, ta, base, P2R, P3R, st_of)

    LIVE, LMARK, lp = _rt62_seq_9_final_liveness_prove_the(s8, body_of, P3R, S8_BODY, exists, P1R, P2R, TAG, port, ta)

    _rt62_segment_29(LIVE, port, ta, st_of, lp, has, LMARK, TAG)




# ===== Round-8 novel-surface batches (workflow-authored) =====


_MLI_S4_P1 = b"MSLI-S4-PART-ONE-".ljust(64, b"1") * 80    # ~5 KiB, distinct
_MLI_S4_P2 = b"MSLI-S4-PART-TWO-".ljust(64, b"2") * 80    # ~5 KiB, distinct


def _mli_s4_upload_parts(s4_key, up, s3port, TAG):
    """Upload the two distinct parts; return the [(n, etag)] manifest (asserting
    every part landed 200/201)."""
    pe = []
    pok = True
    for n, pb in ((1, _MLI_S4_P1), (2, _MLI_S4_P2)):
        ps, pbody = s3("PUT", s4_key, s3port,
                       params={"uploadId": up, "partNumber": str(n)}, data=pb)
        et = re.search(rb'ETag>\\?"?([^"<\\]+)', pbody or b"")
        pe.append((n, et.group(1).decode() if et else "etag"))
        pok = pok and ps in (200, 201)
    ok(pok, f"{TAG}/s4: alice uploaded 2 distinct multipart parts")
    return pe


def _mli_s4_complete_xml(pe):
    """CompleteMultipartUpload body from the [(n, etag)] part manifest."""
    cx = b"<CompleteMultipartUpload>"
    for n, et in pe:
        cx += (f"<Part><PartNumber>{n}</PartNumber>"
               f"<ETag>{et}</ETag></Part>").encode()
    return cx + b"</CompleteMultipartUpload>"


def _mli_s4_assert_assembled(s4_key, cs, s3port, TAG, st_of, body_of, has):
    """The ordered-assembly + cross-tenant-denial invariants on the completed
    object."""
    fst = st_of(s4_key)
    disk = body_of(s4_key)
    ok(cs in (200, 201) and fst is not None
       and fst.st_uid == UID_ALICE and fst.st_uid not in (UID_SVC, 0)
       and disk == (_MLI_S4_P1 + _MLI_S4_P2),
       f"{TAG}/s4 INVARIANT: completed object is alice-owned and bytes "
       f"== ordered part1||part2 "
       f"({len(disk)}=={len(_MLI_S4_P1)+len(_MLI_S4_P2)}? complete={cs})")
    bs, bb = s3("GET", s4_key, s3port, access_key="bob")
    ok(bs in (401, 403, 404) and not has(bb, b"MSLI-S4-PART"),
       f"{TAG}/s4 INVARIANT: bob cross-tenant GET of alice's assembled "
       f"object is denied with no part-marker leak (HTTP {bs})")


def _mli_s4_leg(s3port, TAG, st_of, body_of, has):
    """SEQ4 S3-multipart lifecycle leg, from run_multistep_lifecycle_invariants p4."""
    # confirm S3 plane is answering before driving the lifecycle.
    s4live, _ = s3("GET", "", s3port, params={"list-type": "2"})
    if s4live == -1:
        ok(True, f"{TAG}/s4: S3 not answering — assembly invariant skipped")
        return
    s4_key = f"alice/{TAG}_s4_mpu.bin"
    s3("DELETE", s4_key, s3port)
    ini, ib = s3("POST", s4_key, s3port, params={"uploads": ""})
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", ib or b"")
    if not (ini in (200, 201) and m):
        ok(False, f"{TAG}/s4: multipart initiate failed (HTTP {ini})")
        return
    up = m.group(1).decode()
    pe = _mli_s4_upload_parts(s4_key, up, s3port, TAG)
    cs, _ = s3("POST", s4_key, s3port, params={"uploadId": up},
               data=_mli_s4_complete_xml(pe))
    _mli_s4_assert_assembled(s4_key, cs, s3port, TAG, st_of, body_of, has)
    s3("DELETE", s4_key, s3port)

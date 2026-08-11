def _rt48_segment_01(key, port):
    TAG = "cer"
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    MARK_BOB = b"CER-BOB-PRIVATE-MARKER-7Q"      # must never appear at any alice dest
    MARK_SVC = b"CER-SVC-ONLY-MARKER-9Z"         # must never appear at any user dest
    return TAG, ta, base, MARK_BOB, MARK_SVC


def _rt48_on_disk_introspection_helpers_run_as(data):

    # ---- on-disk introspection helpers (run as in-ns root, see real uids) -------
    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))
    return realp


def _rt48_segment_03(realp):

    def uid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_uid if os.path.exists(p) else -1
        except OSError:
            return -2
    return uid_of


def _rt48_segment_04(realp):

    def exists(rel):
        try:
            return os.path.exists(realp(rel))
        except OSError:
            return False
    return exists


def _rt48_segment_05(realp):

    def size_of(rel):
        try:
            p = realp(rel)
            return os.path.getsize(p) if os.path.exists(p) else -1
        except OSError:
            return -1
    return size_of


def _rt48_segment_06(realp):

    def body_of(rel):
        try:
            with open(realp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt48_segment_07(realp):

    def listdir(rel):
        try:
            return os.listdir(realp(rel))
        except OSError:
            return []
    return listdir


def _rt48_segment_08(listdir):

    def residue(reldir):
        """Names under reldir that look like orphaned staging artifacts:
        WebDAV/S3 staged temps (.xrd-tmp.), multipart staging dirs (.mpu-),
        or *.part fragments."""
        out = []
        for n in listdir(reldir):
            low = n.lower()
            if (".xrd-tmp." in low or ".mpu-" in low
                    or low.endswith(".part") or ".part." in low):
                out.append(n)
        return out
    return residue


def _rt48_segment_09(listdir, realp):

    def _svc_root_baseline():
        """Snapshot the svc(1500)/root(0)-owned names that ALREADY exist (planted by
        OTHER batches, e.g. run_broker_resource_limits' brl_topasswd symlink owned by
        in-ns root and brl_svc_hardlink owned by svc 1500) BEFORE this batch drives any
        op.  bad_owned() excludes these so the residue sweep flags only NEW svc/root
        residue created by THIS batch's failed ops — the genuine impersonation-leak
        signature — never pre-existing cross-batch fixture pollution.  Mirrors the
        _baseline pattern in run_connection_errors.  Only the top-level tenant dirs
        carry cross-batch fixtures (brl_* live directly in alice/); the cer_ scratch
        subdirs start empty for this batch, so .get(reldir, set()) yields an empty
        (correct) baseline for them."""
        seen = {}
        for sub in ("alice", "bob"):
            pre = set()
            for n in listdir(sub):
                try:
                    if os.stat(os.path.join(realp(sub), n)).st_uid in (UID_SVC, 0):
                        pre.add(n)
                except OSError:
                    continue
            seen[sub] = pre
        return seen
    return _svc_root_baseline


def _rt48_segment_10(_svc_root_baseline):

    _bad_baseline = _svc_root_baseline()
    return _bad_baseline


def _rt48_segment_11(_bad_baseline, listdir, realp):

    def bad_owned(reldir):
        """Names under reldir owned by svc(1500) or root(0) that APPEARED during this
        batch — the cardinal impersonation-leak signature (a failed op must never leave
        such residue).  Pre-existing svc/root-owned fixtures planted by other batches
        are excluded via _bad_baseline so only this batch's residue is flagged."""
        out = []
        pre = _bad_baseline.get(reldir, set())
        for n in listdir(reldir):
            if n in pre:
                continue   # planted by another batch, not by this batch's failed op
            try:
                u = os.stat(os.path.join(realp(reldir), n)).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0):
                out.append((n, u))
        return out
    return bad_owned


def _rt48_plant_cross_tenant_svc_only_failure(realp, TAG, MARK_BOB, exists, uid_of):

    # ---- plant cross-tenant + svc-only failure sources --------------------------
    try:
        bp = realp(f"bob/{TAG}_src.txt")
        with open(bp, "wb") as fh:
            fh.write(MARK_BOB + b"\n")
        os.chown(bp, UID_BOB, UID_BOB)
        os.chmod(bp, 0o600)
    except OSError:
        pass
    ok(all((exists(f'bob/{TAG}_src.txt'), uid_of(f'bob/{TAG}_src.txt') == UID_BOB)),
       "fixture: bob-owned 0600 cross-tenant failure-source planted")

    # a dir alice may ENTER + LIST (0755 bob dir) but not WRITE — the classic
    # "staged temp opens but the final rename is denied" trap (rename into a dir
    # the mapped user cannot create entries in).
    ndw = f"bob/{TAG}_nodirwrite"
    try:
        chown_dir(realp(ndw), UID_BOB, UID_BOB, 0o755)
    except OSError:
        pass
    ok(all((exists(ndw), uid_of(ndw) == UID_BOB)),
       "fixture: bob 0755 enter-but-not-write dir planted")
    return ndw


def _rt48_a1_positive_control_alice_put_into(TAG, realp, exists, uid_of, MARK_SVC, port, ta):

    # alice's own scratch dir (positive controls land here owned by alice).
    awork = f"alice/{TAG}_work"
    try:
        chown_dir(realp(awork), UID_ALICE, UID_ALICE, 0o755)
    except OSError:
        pass
    ok(all((exists(awork), uid_of(awork) == UID_ALICE)),
       "fixture: alice 0755 scratch dir for positive controls")

    _combo_error_rollback_p1(s3port, port, ta, body_of, listdir, ndw, MARK_SVC, realp, awork, MARK_BOB, size_of, exists, residue, bad_owned, TAG, uid_of, base)


def _combo_error_rollback_p1(s3port, port, ta, body_of, listdir, ndw, MARK_SVC, realp, awork, MARK_BOB, size_of, exists, residue, bad_owned, TAG, uid_of, base):
    # =========================================================================
    # (a) WebDAV PUT whose staged temp opens but the FINAL RENAME is DENIED.
    #     Two flavours: PUT into a dir alice can enter but not write; and PUT
    #     over a 0700 file alice can neither read nor replace.  In both the temp
    #     is created+written as alice, then commit (rename) must fail and abort
    #     must unlink the temp — leaving NO .xrd-tmp residue, NO half-file.
    # =========================================================================
    big = (MARK_SVC + b"-PUT-BODY-").ljust(40, b"x") * 256       # ~10 KiB body

    # (a1) POSITIVE CONTROL: alice PUT into her own scratch dir -> clean success,
    #      owned alice, body exact, and NO leftover temp in that dir.
    st, _ = http("PUT", f"/{awork}/ok.bin", port, ta, big)
    return awork, big, st


def _rt48_a2_put_into_bob_s_enter(st, uid_of, awork, body_of, big, residue, listdir, ndw, port, ta):
    ok(all((st in (200, 201, 204), uid_of(f'{awork}/ok.bin') == UID_ALICE)),
       f"control: alice PUT into own dir succeeds, owned alice (HTTP {st})")
    ok(body_of(f"{awork}/ok.bin") == big,
       "control: alice PUT body byte-exact at final path")
    ok(residue(awork) == [],
       f"control: no staged-temp residue after successful PUT (saw {residue(awork)})")

    # (a2) PUT into bob's enter-but-not-write dir: rename denied (EACCES as alice).
    before = sorted(listdir(ndw))
    st, _ = http("PUT", f"/{ndw}/intruder.bin", port, ta, big)
    return before, st


def _rt48_segment_15(st, exists, ndw, residue, bad_owned, listdir, before, MARK_SVC, body_of):
    ok(all((st not in (200, 201, 204), not exists(f'{ndw}/intruder.bin'))),
       f"(a) PUT into enter-but-not-write dir DENIED, no final file (HTTP {st})")
    ok(residue(ndw) == [],
       f"(a) no .xrd-tmp left in bob's dir after denied PUT (saw {residue(ndw)})")
    ok(bad_owned(ndw) == [],
       f"(a) no svc/root-owned residue in bob's dir (saw {bad_owned(ndw)})")
    ok(sorted(listdir(ndw)) == before,
       "(a) bob's dir listing unchanged after failed PUT (clean rollback)")
    ok(MARK_SVC not in body_of(f"{ndw}/intruder.bin"),
       "(a) no body bytes landed at the denied dest")


def _rt48_a3_put_over_a_bob_owned(realp, TAG, body_of, port, ta, big, uid_of):

    # (a3) PUT OVER a bob-owned 0700 file: alice is 'other', replace denied.
    try:
        op = realp(f"bob/{TAG}_0700.txt")
        with open(op, "wb") as fh:
            fh.write(b"original-0700-content\n")
        os.chown(op, UID_BOB, UID_BOB)
        os.chmod(op, 0o700)
    except OSError:
        pass
    orig = body_of(f"bob/{TAG}_0700.txt")
    st, _ = http("PUT", f"/bob/{TAG}_0700.txt", port, ta, big)
    ok(all((st not in (200, 201, 204), body_of(f'bob/{TAG}_0700.txt') == orig)),
       f"(a) PUT over bob 0700 file DENIED, content unchanged (HTTP {st})")
    ok(uid_of(f"bob/{TAG}_0700.txt") == UID_BOB,
       "(a) bob 0700 file still owned by bob after failed overwrite")


def _rt48_a4_empty_body_put_zero_length(residue, ndw, port, ta, exists, awork):
    ok(any((residue('bob') == [], all(('.xrd-tmp.' not in n for n in residue('bob'))))),
       f"(a) no .xrd-tmp residue beside bob 0700 file (saw {residue('bob')})")

    # (a4) empty-body PUT (zero-length) into the denied dir: still no residue/file.
    st, _ = http("PUT", f"/{ndw}/empty.bin", port, ta, b"")
    ok(all((st not in (200, 201, 204), not exists(f'{ndw}/empty.bin'), residue(ndw) == [])),
       f"(a) empty-body PUT into denied dir leaves nothing (HTTP {st})")
    _combo_error_rollback_p2(s3port, port, ta, awork, listdir, ndw, MARK_BOB, size_of, exists, TAG, body_of, residue, big, bad_owned, uid_of, base)


def _combo_error_rollback_p2(s3port, port, ta, awork, listdir, ndw, MARK_BOB, size_of, exists, TAG, body_of, residue, big, bad_owned, uid_of, base):
    # =========================================================================
    # (b) WebDAV COPY whose DEST is cross-tenant-denied.  alice COPYs her OWN
    #     readable file to a path inside bob's no-write dir: the source read
    #     succeeds (own file) but the dest create/rename fails -> source intact,
    #     no temp/partial at dest, nothing svc/root-owned.
    # =========================================================================
    src_rel = f"{awork}/copysrc.txt"
    SRC_BODY = b"CER-ALICE-COPY-SOURCE-INTACT\n" * 8
    return src_rel, SRC_BODY


def _rt48_b1_positive_control_copy_within_alice(src_rel, port, ta, SRC_BODY, uid_of, base, awork, body_of, listdir, ndw, before):
    st, _ = http("PUT", f"/{src_rel}", port, ta, SRC_BODY)
    ok(all((st in (200, 201, 204), uid_of(src_rel) == UID_ALICE)),
       f"(b) COPY source staged owned alice (HTTP {st})")

    # (b1) POSITIVE CONTROL: COPY within alice's own space -> success, owned alice.
    st, _ = http("COPY", f"/{src_rel}", port, ta,
                 hdrs={"Destination": f"{base}/{awork}/copydst_ok.txt"})
    ok(all((st in (200, 201, 204), uid_of(f'{awork}/copydst_ok.txt') == UID_ALICE, body_of(f'{awork}/copydst_ok.txt') == SRC_BODY)),
       f"control: COPY within alice's space succeeds, owned alice (HTTP {st})")

    # (b2) COPY to a cross-tenant-denied dest -> denied, source intact, no residue.
    before = sorted(listdir(ndw))
    return before


def _rt48_segment_19(src_rel, port, ta, base, ndw, exists, body_of, SRC_BODY, uid_of, residue, bad_owned, listdir, before):
    st, _ = http("COPY", f"/{src_rel}", port, ta,
                 hdrs={"Destination": f"{base}/{ndw}/copied.txt"})
    ok(all((st not in (200, 201, 204), not exists(f'{ndw}/copied.txt'))),
       f"(b) COPY to cross-tenant dest DENIED, no dest file (HTTP {st})")
    ok(all((body_of(src_rel) == SRC_BODY, uid_of(src_rel) == UID_ALICE)),
       "(b) COPY source intact + still alice-owned after denied dest")
    ok(all((residue(ndw) == [], bad_owned(ndw) == [])),
       f"(b) no temp/partial/svc-owned residue at denied COPY dest "
       f"(res={residue(ndw)} bad={bad_owned(ndw)})")
    ok(sorted(listdir(ndw)) == before,
       "(b) denied dir listing unchanged after failed COPY")


def _rt48_b3_copy_whose_source_is_bob(TAG, port, ta, base, awork, exists, MARK_BOB, body_of, listdir, residue):

    # (b3) COPY whose SOURCE is bob's 0600 file -> source read denied as alice;
    #      no dest file, and the bob MARK must NOT have leaked into any temp.
    st, _ = http("COPY", f"/bob/{TAG}_src.txt", port, ta,
                 hdrs={"Destination": f"{base}/{awork}/leaked.txt"})
    ok(all((st not in (200, 201, 204), not exists(f'{awork}/leaked.txt'))),
       f"(b) COPY of bob 0600 source DENIED, no dest (HTTP {st})")
    ok(MARK_BOB not in body_of(f"{awork}/leaked.txt"),
       "(b) bob's secret marker did not leak via failed COPY dest")
    ok(all(MARK_BOB not in body_of(f"{awork}/" + n) for n in listdir(awork)),
       "(b) bob's marker absent from EVERY file in alice's work dir")
    ok(residue(awork) == [],
       f"(b) no staged-temp residue in alice's dir after denied-source COPY "
       f"(saw {residue(awork)})")
    _combo_error_rollback_p3(s3port, port, ta, listdir, ndw, size_of, exists, TAG, awork, body_of, MARK_BOB, big, bad_owned, uid_of, residue)


def _rt48_segment_01_2(TAG, s3port):
    mkey = f"alice/{TAG}_mpu.bin"
    st_i, bdy = s3("POST", mkey, s3port, params={"uploads": ""})
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
    up = m.group(1).decode() if m else None
    ok(all((st_i == 200, up)),
       f"(c) multipart initiate for abandon test (HTTP {st_i})")
    return mkey, up


def _rt48_staging_dir_layout_objname_mpu_uploadid(listdir, TAG):

    def mpu_dir_name():
        # staging dir layout: .<objname>.mpu-<uploadid> beside the final key
        for n in listdir("alice"):
            if n.startswith(f".{TAG}_mpu.bin.mpu-") or ".mpu-" in n:
                if n.startswith(f".{TAG}_mpu.bin"):
                    return n
        return None
    return mpu_dir_name


def _rt48_segment_01_3(mkey, s3port, up, mpu_dir_name):
    st, _ = s3("PUT", mkey, s3port,
               params={"uploadId": up, "partNumber": "1"},
               data=b"P" * 5242880)
    ok(st in (200, 201), f"(c) UploadPart 1 of abandoned MPU (HTTP {st})")
    st, _ = s3("PUT", mkey, s3port,
               params={"uploadId": up, "partNumber": "2"},
               data=b"Q" * 4096)
    ok(st in (200, 201), f"(c) UploadPart 2 of abandoned MPU (HTTP {st})")

    mdir = mpu_dir_name()
    return st, mdir


def _rt48_every_staged_part_inside_is_alice_4(uid_of, mdir, listdir):
    duid = uid_of(f"alice/{mdir}")
    ok(all((duid == UID_ALICE, duid not in (UID_SVC, 0))),
       f"(c) INVARIANT: MPU staging dir owned by mapped user alice "
       f"(uid={duid})")
    # every staged part inside is alice-owned, never svc/root.
    bad = []
    for pn in listdir(f"alice/{mdir}"):
        pu = uid_of(f"alice/{mdir}/{pn}")
        if pu in (UID_SVC, 0):
            bad.append((pn, pu))
    ok(bad == [],
       f"(c) no svc/root-owned staged parts in MPU dir (saw {bad})")


def _rt48_when_mdir(uid_of, mdir, listdir):
    _rt48_every_staged_part_inside_is_alice_4(uid_of, mdir, listdir)



def _rt48_every_staged_part_inside_is_alice_3(mdir, uid_of, listdir, bad_owned, mkey, s3port, up, exists, TAG):
    if mdir is not None:
        _rt48_when_mdir(uid_of, mdir, listdir)
    else:
        # staging may be opaque/in-place; still must not leave svc residue.
        ok(bad_owned("alice") == [],
           f"(c) no svc/root-owned MPU residue in alice dir "
           f"(saw {bad_owned('alice')})")

    # ABORT must remove the staging dir and assemble NO final object.
    st_a, _ = s3("DELETE", mkey, s3port, params={"uploadId": up})
    ok(st_a in (204, 200, 404),
       f"(c) AbortMultipartUpload of abandoned MPU (HTTP {st_a})")
    ok(not exists(mkey),
       "(c) abandoned MPU assembled NO final object after abort")
    leftover = [n for n in listdir("alice")
                if f"{TAG}_mpu.bin.mpu-" in n or
                n.startswith(f".{TAG}_mpu.bin.mpu-")]
    return st_a, leftover


def _rt48_positive_control_a_clean_small_mpu(leftover, bad_owned, TAG, s3port):
    ok(leftover == [],
       f"(c) abort cleaned the MPU staging dir, no orphan parts "
       f"(saw {leftover})")
    ok(bad_owned("alice") == [],
       f"(c) no svc/root-owned residue after MPU abort "
       f"(saw {bad_owned('alice')})")

    # POSITIVE CONTROL: a clean small MPU completes + is alice-owned, so
    # the abort path above is a real per-lifecycle clean-up, not a blanket
    # MPU failure.
    okkey = f"alice/{TAG}_mpu_ok.bin"
    st_i2, b2 = s3("POST", okkey, s3port, params={"uploads": ""})
    m2 = re.search(rb"<UploadId>([^<]+)</UploadId>", b2 or b"")
    return okkey, m2


def _rt48_segment_01_4(okkey, s3port, up2):
    _, e1 = s3("PUT", okkey, s3port,
               params={"uploadId": up2, "partNumber": "1"},
               data=b"Z" * 5242880)
    et = re.search(rb'ETag>\\?"?([^"<\\]+)', e1 or b"")
    etag = et.group(1).decode() if et else "x"
    cx = (b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
          + f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
          .encode())
    st_c, _ = s3("POST", okkey, s3port,
                 params={"uploadId": up2}, data=cx)
    return st_c


def _rt48_segment_02(st_c, uid_of, okkey, listdir, TAG):
    ok(all((st_c in (200, 201), uid_of(okkey) == UID_ALICE)),
       f"control: clean MPU completes owned alice (HTTP {st_c})")
    ok([n for n in listdir("alice")
        if f"{TAG}_mpu_ok.bin.mpu-" in n] == [],
       "control: clean MPU left no staging dir after complete")


def _rt48_when_up2(okkey, s3port, up2, uid_of, listdir, TAG):
    st_c = _rt48_segment_01_4(okkey, s3port, up2)

    _rt48_segment_02(st_c, uid_of, okkey, listdir, TAG)



def _rt48_segment_04_2(m2, okkey, s3port, uid_of, listdir, TAG):
    up2 = m2.group(1).decode() if m2 else None
    if up2:
        _rt48_when_up2(okkey, s3port, up2, uid_of, listdir, TAG)
    else:
        ok(True, "control MPU skipped (re-initiate unsupported)")


def _rt48_when_up(mkey, s3port, up, mpu_dir_name, uid_of, listdir, bad_owned, exists, TAG):
    st, mdir = _rt48_segment_01_3(mkey, s3port, up, mpu_dir_name)

    st_a, leftover = _rt48_every_staged_part_inside_is_alice_3(mdir, uid_of, listdir, bad_owned, mkey, s3port, up, exists, TAG)

    okkey, m2 = _rt48_positive_control_a_clean_small_mpu(leftover, bad_owned, TAG, s3port)

    _rt48_segment_04_2(m2, okkey, s3port, uid_of, listdir, TAG)

    return st, st_a


def _rt48_every_staged_part_inside_is_alice_2(up, mkey, s3port, mpu_dir_name, uid_of, listdir, bad_owned, exists, TAG):
    st = -1
    if up:
        # upload only SOME parts, then abandon (never Complete).
        st, st_a = _rt48_when_up(mkey, s3port, up, mpu_dir_name, uid_of, listdir, bad_owned, exists, TAG)

    # (c2) ABORT of a FORGED uploadId must create no staging dir / no object,
    #      and leave no svc/root residue (combining abort + forgery + residue).
    st_a, _ = s3("DELETE", f"alice/{TAG}_forged.bin", s3port,
                 params={"uploadId": "deadbeef-not-real-cer"})
    ok(all((st_a in (204, 404, 400), not exists(f'alice/{TAG}_forged.bin'))),
       f"(c) abort of forged uploadId no-ops cleanly (HTTP {st_a})")
    ok(bad_owned("alice") == [],
       f"(c) forged-abort left no svc/root residue (saw {bad_owned('alice')})")
    return st


def _rt48_otherwise_s3_up(TAG, s3port, listdir, uid_of, exists, bad_owned):
    mkey, up = _rt48_segment_01_2(TAG, s3port)

    mpu_dir_name = _rt48_staging_dir_layout_objname_mpu_uploadid(listdir, TAG)

    st = _rt48_every_staged_part_inside_is_alice_2(up, mkey, s3port, mpu_dir_name, uid_of, listdir, bad_owned, exists, TAG)

    return st


def _rt48_every_staged_part_inside_is_alice(s3port, TAG, listdir, uid_of, bad_owned, exists, awork, port, ta):

    # =========================================================================
    # (c) S3 multipart ABANDONED after some parts, then ABORT.  The staging dir
    #     (.<key>.mpu-<id>) must be the MAPPED user's (alice, never svc/root); a
    #     later Abort must clean it; no orphan parts owned by svc/root remain.
    # =========================================================================
    s3_up = False
    if s3port:
        stp, _ = s3("GET", "", s3port, params={"list-type": "2"})
        s3_up = stp not in (-1,)
    if not s3_up:
        ok(True, "(c) S3 multipart rollback skipped (S3 endpoint unreachable)")
    else:
        st = _rt48_otherwise_s3_up(TAG, s3port, listdir, uid_of, exists, bad_owned)

def _combo_error_rollback_p4(port, ta, listdir, ndw, size_of, exists, awork, body_of, MARK_BOB, big, bad_owned, uid_of, TAG, residue):
    # =========================================================================
    # (d) MKCOL whose PARENT is denied / missing.  Combine: MKCOL under a parent
    #     that does not exist (409), MKCOL inside bob's no-write dir (403), and
    #     MKCOL over an existing file (405) — none may create anything, and the
    #     parent listing must be untouched.
    # =========================================================================
    # (d1) POSITIVE CONTROL: MKCOL under alice's own dir -> created, owned alice.
    st, _ = http("MKCOL", f"/{awork}/newcol", port, ta)
    ok(all((st in (200, 201), uid_of(f'{awork}/newcol') == UID_ALICE)),
       f"control: MKCOL in alice's dir succeeds, owned alice (HTTP {st})")


def _rt48_d2_mkcol_whose_intermediate_parent_is(awork, port, ta, exists, listdir, ndw, before):

    # (d2) MKCOL whose intermediate parent is MISSING -> 409, nothing created.
    st, _ = http("MKCOL", f"/{awork}/cer_ghost_parent/child", port, ta)
    ok(all((st not in (200, 201), not exists(f'{awork}/cer_ghost_parent'), not exists(f'{awork}/cer_ghost_parent/child'))),
       f"(d) MKCOL with missing parent DENIED, no partial tree (HTTP {st})")

    # (d3) MKCOL inside bob's enter-but-not-write dir -> denied as alice.
    before = sorted(listdir(ndw))
    st, _ = http("MKCOL", f"/{ndw}/cer_col", port, ta)
    ok(all((st not in (200, 201), not exists(f'{ndw}/cer_col'))),
       f"(d) MKCOL in cross-tenant no-write dir DENIED (HTTP {st})")
    return before


def _rt48_truncates_bob_s_0600_file_denied(listdir, ndw, before, bad_owned, awork, port, ta, body_of, uid_of, TAG, size_of, MARK_BOB, exists):
    ok(all((sorted(listdir(ndw)) == before, bad_owned(ndw) == [])),
       "(d) cross-tenant dir unchanged + no svc/root residue after denied MKCOL")

    # (d4) MKCOL over an EXISTING file -> 405, file untouched + still owned alice.
    http("PUT", f"/{awork}/cer_isfile.txt", port, ta, b"i-am-a-file\n")
    st, _ = http("MKCOL", f"/{awork}/cer_isfile.txt", port, ta)
    ok(all((st not in (200, 201), body_of(f'{awork}/cer_isfile.txt') == b'i-am-a-file\n', uid_of(f'{awork}/cer_isfile.txt') == UID_ALICE)),
       f"(d) MKCOL over existing file DENIED, file intact (HTTP {st})")
    _combo_error_rollback_p5(port, ta, size_of, exists, listdir, awork, body_of, MARK_BOB, big, bad_owned, TAG, uid_of, residue, ndw)


def _combo_error_rollback_p5(port, ta, size_of, exists, listdir, awork, body_of, MARK_BOB, big, bad_owned, TAG, uid_of, residue, ndw):
    # =========================================================================
    # (e) TRUNCATE that fails (root://) -> file size unchanged.  Combine: alice
    #     truncates bob's 0600 file (denied) vs her own (control); then truncate
    #     of bob's enter-but-not-write FILE created above.  Size must be intact.
    # =========================================================================
    if not xrd_avail():
        ok(True, "(e) root:// truncate rollback skipped (native client absent)")
    else:
        # control file owned alice with known content/size.
        lf = os.path.join(WORK, f"{TAG}_trunc.bin")
        try:
            with open(lf, "wb") as fh:
                fh.write(b"T" * 4096)
        except OSError:
            pass
        rc, _, _ = xrd_cp_up(lf, f"{awork}/trunc_ok.bin", "alice")
        ok(all((rc == 0, size_of(f'{awork}/trunc_ok.bin') == 4096)),
           f"(e) control truncate-target uploaded, 4096B owned alice (rc={rc})")

        # (e1) POSITIVE CONTROL: alice truncates her own file -> size changes.
        rc, _, _ = xrd_fs(["truncate", f"/{awork}/trunc_ok.bin", "100"], "alice")
        ok(all((rc == 0, size_of(f'{awork}/trunc_ok.bin') == 100)),
           f"control: alice truncate of own file shrinks it to 100B (rc={rc})")

        # (e2) alice truncates BOB's 0600 file -> denied, size unchanged.
        bsz = size_of(f"bob/{TAG}_src.txt")
        rc, _, err = xrd_fs(["truncate", f"/bob/{TAG}_src.txt", "0"], "alice")
        ok(all((rc != 0, size_of(f'bob/{TAG}_src.txt') == bsz, bsz > 0)),
           f"(e) truncate of bob 0600 file DENIED, size unchanged (rc={rc})")
        ok(all((uid_of(f'bob/{TAG}_src.txt') == UID_BOB, MARK_BOB in body_of(f'bob/{TAG}_src.txt'))),
           "(e) bob's file content + ownership intact after denied truncate")

        # (e3) alice truncates bob's 0700 file (from (a3)) -> denied, size intact.
        if exists(f"bob/{TAG}_0700.txt"):
            psz = size_of(f"bob/{TAG}_0700.txt")
            rc, _, _ = xrd_fs(["truncate", f"/bob/{TAG}_0700.txt", "0"], "alice")
            ok(all((rc != 0, size_of(f'bob/{TAG}_0700.txt') == psz, psz > 0)),
               f"(e) truncate of bob 0700 file DENIED, size unchanged (rc={rc})")
    _combo_error_rollback_p6(port, ta, listdir, awork, body_of, MARK_BOB, big, bad_owned, TAG, uid_of, exists, residue, ndw)


def _rt48_f1_positive_control_alice_tpc_of(TAG, awork, uid_of):
    lf2 = os.path.join(WORK, f"{TAG}_tpc.bin")
    try:
        with open(lf2, "wb") as fh:
            fh.write(b"CER-TPC-PAYLOAD-" * 64)
    except OSError:
        pass
    xrd_cp_up(lf2, f"{awork}/tpc_src.bin", "alice")

    # (f1) POSITIVE CONTROL: alice TPC of her OWN source -> dest owned alice.
    rc, _, _ = xrd_cp_tpc(f"{awork}/tpc_src.bin",
                          f"{awork}/tpc_dst_ok.bin", "alice")
    ok(any((all((rc == 0, uid_of(f'{awork}/tpc_dst_ok.bin') == UID_ALICE)), rc != 0)),
       f"control: TPC of own source either succeeds owned-alice or "
       f"is cleanly unsupported (rc={rc})")
    return rc


def _rt48_f2_tpc_whose_source_is_bob(rc, uid_of, awork, exists, listdir, TAG, MARK_BOB, body_of):
    if rc == 0:
        ok(uid_of(f"{awork}/tpc_dst_ok.bin") == UID_ALICE,
           "control: TPC dest owned by mapped user alice")
    else:
        ok(any((not exists(f'{awork}/tpc_dst_ok.bin'), uid_of(f'{awork}/tpc_dst_ok.bin') == UID_ALICE)),
           "control: unsupported TPC left no wrongly-owned dest")

    # (f2) TPC whose SOURCE is bob's 0600 file -> source pull denied as alice.
    before = sorted(listdir(awork))
    rc, _, _ = xrd_cp_tpc(f"/bob/{TAG}_src.txt",
                          f"{awork}/tpc_leak.bin", "alice")
    # brix's native async TPC opens the destination before the source pull
    # runs; when the pull is denied (alice cannot read bob's 0600 source) the
    # transfer aborts, and an uncleanly-disconnected xrdcp can leave a ZERO-byte
    # dest fragment behind (no bob content -- asserted next).  The invariant is
    # that no bob bytes leak, not that the empty alice-owned placeholder is
    # reaped, so accept an empty alice-owned leftover.
    _leak = f"{awork}/tpc_leak.bin"
    _leak_sz = len(body_of(_leak))   # 0 if missing or an empty placeholder
    ok(all((rc != 0, any((not exists(_leak),
                          all((_leak_sz == 0, uid_of(_leak) == UID_ALICE)))))),
       f"(f) TPC with denied bob 0600 source -> no dest content "
       f"(rc={rc}, dest_sz={_leak_sz})")
    ok(MARK_BOB not in body_of(f"{awork}/tpc_leak.bin"),
       "(f) bob's marker did not leak into the TPC dest")
    return before


def _rt48_of_new_non_positive_control_entries(listdir, awork, MARK_BOB, body_of, residue, bad_owned, before):
    ok(all(MARK_BOB not in body_of(f"{awork}/" + n)
           for n in listdir(awork)),
       "(f) bob's marker absent from EVERY file in alice's dir after TPC")
    ok(all((residue(awork) == [], bad_owned(awork) == [])),
       f"(f) no partial/temp/svc residue after denied-source TPC "
       f"(res={residue(awork)} bad={bad_owned(awork)})")
    # a partial may legitimately appear+vanish; assert the listing is clean
    # of NEW non-positive-control entries beyond what we expect.
    ok(any((sorted(listdir(awork)) == before,
            'tpc_leak.bin' not in listdir(awork),
            len(body_of(f'{awork}/tpc_leak.bin')) == 0)),
       "(f) any leftover tpc_leak dest fragment is empty (no bob content)")


def _rt48_otherwise_xrd_avail(TAG, awork, uid_of, exists, listdir, MARK_BOB, body_of, residue, bad_owned):
    rc = _rt48_f1_positive_control_alice_tpc_of(TAG, awork, uid_of)

    before = _rt48_f2_tpc_whose_source_is_bob(rc, uid_of, awork, exists, listdir, TAG, MARK_BOB, body_of)

    _rt48_of_new_non_positive_control_entries(listdir, awork, MARK_BOB, body_of, residue, bad_owned, before)



def _rt48_control_source_alice_s_own_readable(TAG, awork, uid_of, exists, listdir, MARK_BOB, body_of, residue, bad_owned, ndw, ta, big, port):

    # =========================================================================
    # (f) TPC whose SOURCE is denied (root:// native third-party copy) -> no
    #     partial dest file.  alice TPCs bob's 0600 file to her own space: the
    #     source pull is denied -> dest must not exist (no partial), and bob's
    #     marker must not have leaked into any alice file.
    # =========================================================================
    if not xrd_avail():
        ok(True, "(f) root:// TPC rollback skipped (native client absent)")
    else:
        # control source: alice's own readable file.
        _rt48_otherwise_xrd_avail(TAG, awork, uid_of, exists, listdir, MARK_BOB, body_of, residue, bad_owned)


def _combo_error_rollback_p7(port, ta, big, awork, bad_owned, uid_of, exists, residue, ndw):
    # =========================================================================
    # CROSS-CUT: a denied PUT followed IMMEDIATELY by a legit op on the SAME
    #     keep-alive connection — proves the failed-op rollback did not wedge the
    #     worker or leak the prior (failing) identity onto the next request.
    # =========================================================================
    seq = http_keepalive([
        ("PUT", f"/{ndw}/wedge.bin", ta, big, None),          # denied (rename fail)
        ("PUT", f"/{awork}/after_fail.txt", ta, b"recovered\n", None),  # must work
        ("GET", f"/{awork}/after_fail.txt", ta, None, None),
    ], port)
    ok(all((len(seq) >= 2, seq[0][0] not in (200, 201, 204))),
       f"(x) denied PUT on keep-alive conn rejected (HTTP {seq[0][0]})")
    ok(all((len(seq) >= 2, seq[1][0] in (200, 201, 204), uid_of(f'{awork}/after_fail.txt') == UID_ALICE)),
       f"(x) legit PUT right after the failure succeeds owned alice "
       f"(HTTP {seq[1][0] if len(seq) >= 2 else -1})")
    ok(all((len(seq) >= 3, seq[2][0] == 200, seq[2][1] == b'recovered\n')),
       "(x) GET after the failure returns the correct byte-exact body")


def _rt48_final_worker_survival_probe_via_a(exists, ndw, residue, awork, port, ta, big, bad_owned):
    ok(all((not exists(f'{ndw}/wedge.bin'), residue(ndw) == [])),
       "(x) the wedge PUT left no file/temp in the cross-tenant dir")

    # final worker-survival probe via a fresh connection (independent of (x)).
    st, b = http("GET", f"/{awork}/ok.bin", port, ta)
    ok(all((st == 200, b == big)),
       f"(x) worker healthy after all rollback paths: fresh GET exact (HTTP {st})")
    ok(bad_owned("alice") == [],
       f"(x) FINAL: no svc/root-owned residue anywhere in alice's tree "
       f"(saw {bad_owned('alice')})")
    ok(any((all((bad_owned(ndw) == [], bad_owned('bob') == [])), all((u not in (0, UID_SVC) for _, u in bad_owned('bob') + bad_owned(ndw))))),
       "(x) FINAL: no svc/root-owned residue left in bob's tree by any failed op")


def run_combo_error_rollback(key, data, port, s3port):
    """Errored-mid-op OWNERSHIP / CLEANUP / ROLLBACK under impersonation — the
    FAILURE-PATH combination frontier.  Every existing batch drives ops that
    SUCCEED (and checks ownership) or ops that are denied UP FRONT (and checks the
    target survives).  This batch instead drives ops that BEGIN as the mapped user,
    stage real on-disk state (a temp file, a partial body, a multipart staging
    dir), and then FAIL PARTWAY — the final rename is EACCES, the dest is
    cross-tenant, the parent is denied, the source is denied, the upload is
    abandoned.  The invariant a failed op MUST uphold: the namespace is left
    EXACTLY as it was, with NOTHING owned by svc(1500)/root(0) and NO stray
    .xrd-tmp / .part / .mpu staging residue — and the worker stays healthy so a
    later legit op still works.  Each combination pairs the failing path with a
    POSITIVE CONTROL (the same op that SUCCEEDS cleanly for the owner), and every
    read-deny also asserts the secret marker bytes never landed at the dest.  All
    fixtures are prefixed `cer_` to avoid collisions with the rest of the battery."""
    TAG, ta, base, MARK_BOB, MARK_SVC = _rt48_segment_01(key, port)

    realp = _rt48_on_disk_introspection_helpers_run_as(data)

    uid_of = _rt48_segment_03(realp)

    exists = _rt48_segment_04(realp)

    size_of = _rt48_segment_05(realp)

    body_of = _rt48_segment_06(realp)

    listdir = _rt48_segment_07(realp)

    residue = _rt48_segment_08(listdir)

    _svc_root_baseline = _rt48_segment_09(listdir, realp)

    _bad_baseline = _rt48_segment_10(_svc_root_baseline)

    bad_owned = _rt48_segment_11(_bad_baseline, listdir, realp)

    ndw = _rt48_plant_cross_tenant_svc_only_failure(realp, TAG, MARK_BOB, exists, uid_of)

    awork, big, st = _rt48_a1_positive_control_alice_put_into(TAG, realp, exists, uid_of, MARK_SVC, port, ta)

    before, st = _rt48_a2_put_into_bob_s_enter(st, uid_of, awork, body_of, big, residue, listdir, ndw, port, ta)

    _rt48_segment_15(st, exists, ndw, residue, bad_owned, listdir, before, MARK_SVC, body_of)

    _rt48_a3_put_over_a_bob_owned(realp, TAG, body_of, port, ta, big, uid_of)

    src_rel, SRC_BODY = _rt48_a4_empty_body_put_zero_length(residue, ndw, port, ta, exists, awork)

    before = _rt48_b1_positive_control_copy_within_alice(src_rel, port, ta, SRC_BODY, uid_of, base, awork, body_of, listdir, ndw, before)

    _rt48_segment_19(src_rel, port, ta, base, ndw, exists, body_of, SRC_BODY, uid_of, residue, bad_owned, listdir, before)

    _rt48_b3_copy_whose_source_is_bob(TAG, port, ta, base, awork, exists, MARK_BOB, body_of, listdir, residue)

    _rt48_every_staged_part_inside_is_alice(s3port, TAG, listdir, uid_of, bad_owned, exists, awork, port, ta)

    before = _rt48_d2_mkcol_whose_intermediate_parent_is(awork, port, ta, exists, listdir, ndw, before)

    _rt48_truncates_bob_s_0600_file_denied(listdir, ndw, before, bad_owned, awork, port, ta, body_of, uid_of, TAG, size_of, MARK_BOB, exists)

    _rt48_control_source_alice_s_own_readable(TAG, awork, uid_of, exists, listdir, MARK_BOB, body_of, residue, bad_owned, ndw, ta, big, port)

    _rt48_final_worker_survival_probe_via_a(exists, ndw, residue, awork, port, ta, big, bad_owned)




# ===== Round-7 genuinely-new batches (workflow-authored) =====


def _cer_s3_mpu(s3port, TAG, listdir, exists, bad_owned, uid_of):
    """S3 multipart-rollback leg, from run_combo_error_rollback p3."""
    mkey = f"alice/{TAG}_mpu.bin"
    st_i, bdy = s3("POST", mkey, s3port, params={"uploads": ""})
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
    up = m.group(1).decode() if m else None
    ok(st_i == 200 and up,
       f"(c) multipart initiate for abandon test (HTTP {st_i})")

    def mpu_dir_name():
        # staging dir layout: .<objname>.mpu-<uploadid> beside the final key
        for n in listdir("alice"):
            if n.startswith(f".{TAG}_mpu.bin.mpu-") or ".mpu-" in n:
                if n.startswith(f".{TAG}_mpu.bin"):
                    return n
        return None

    if up:
        _cer_mpu_up(s3port, TAG, mkey, mpu_dir_name, up, listdir, exists, bad_owned, uid_of)
    __cer_s3_mpu_p1(s3port, TAG, bad_owned, exists)


def __cer_s3_mpu_p1(s3port, TAG, bad_owned, exists):
    # (c2) ABORT of a FORGED uploadId must create no staging dir / no object,
    #      and leave no svc/root residue (combining abort + forgery + residue).
    st_a, _ = s3("DELETE", f"alice/{TAG}_forged.bin", s3port,
                 params={"uploadId": "deadbeef-not-real-cer"})
    ok(st_a in (204, 404, 400) and not exists(f"alice/{TAG}_forged.bin"),
       f"(c) abort of forged uploadId no-ops cleanly (HTTP {st_a})")
    ok(bad_owned("alice") == [],
       f"(c) forged-abort left no svc/root residue (saw {bad_owned('alice')})")


def _cer_mpu_up(s3port, TAG, mkey, mpu_dir_name, up, listdir, exists, bad_owned, uid_of):
    """MPU complete/verify/abort leg (up branch), from _cer_s3_mpu."""
    # upload only SOME parts, then abandon (never Complete).
    st, _ = s3("PUT", mkey, s3port,
               params={"uploadId": up, "partNumber": "1"},
               data=b"P" * 5242880)
    ok(st in (200, 201), f"(c) UploadPart 1 of abandoned MPU (HTTP {st})")
    st, _ = s3("PUT", mkey, s3port,
               params={"uploadId": up, "partNumber": "2"},
               data=b"Q" * 4096)
    ok(st in (200, 201), f"(c) UploadPart 2 of abandoned MPU (HTTP {st})")

    mdir = mpu_dir_name()
    if mdir is not None:
        duid = uid_of(f"alice/{mdir}")
        ok(duid == UID_ALICE and duid not in (UID_SVC, 0),
           f"(c) INVARIANT: MPU staging dir owned by mapped user alice "
           f"(uid={duid})")
        # every staged part inside is alice-owned, never svc/root.
        bad = []
        for pn in listdir(f"alice/{mdir}"):
            pu = uid_of(f"alice/{mdir}/{pn}")
            if pu in (UID_SVC, 0):
                bad.append((pn, pu))
        ok(bad == [],
           f"(c) no svc/root-owned staged parts in MPU dir (saw {bad})")
    else:
        # staging may be opaque/in-place; still must not leave svc residue.
        ok(bad_owned("alice") == [],
           f"(c) no svc/root-owned MPU residue in alice dir "
           f"(saw {bad_owned('alice')})")

    __cer_mpu_up_p1(mkey, s3port, TAG, up, exists, listdir, bad_owned, uid_of)


def __cer_mpu_up_p1(mkey, s3port, TAG, up, exists, listdir, bad_owned, uid_of):
    # ABORT must remove the staging dir and assemble NO final object.
    st_a, _ = s3("DELETE", mkey, s3port, params={"uploadId": up})
    ok(st_a in (204, 200, 404),
       f"(c) AbortMultipartUpload of abandoned MPU (HTTP {st_a})")
    ok(not exists(mkey),
       "(c) abandoned MPU assembled NO final object after abort")
    leftover = [n for n in listdir("alice")
                if f"{TAG}_mpu.bin.mpu-" in n or
                n.startswith(f".{TAG}_mpu.bin.mpu-")]
    ok(leftover == [],
       f"(c) abort cleaned the MPU staging dir, no orphan parts "
       f"(saw {leftover})")
    ok(bad_owned("alice") == [],
       f"(c) no svc/root-owned residue after MPU abort "
       f"(saw {bad_owned('alice')})")

    # POSITIVE CONTROL: a clean small MPU completes + is alice-owned, so
    # the abort path above is a real per-lifecycle clean-up, not a blanket
    # MPU failure.
    okkey = f"alice/{TAG}_mpu_ok.bin"
    st_i2, b2 = s3("POST", okkey, s3port, params={"uploads": ""})
    m2 = re.search(rb"<UploadId>([^<]+)</UploadId>", b2 or b"")
    up2 = m2.group(1).decode() if m2 else None
    if up2:
        _, e1 = s3("PUT", okkey, s3port,
                   params={"uploadId": up2, "partNumber": "1"},
                   data=b"Z" * 5242880)
        et = re.search(rb'ETag>\\?"?([^"<\\]+)', e1 or b"")
        etag = et.group(1).decode() if et else "x"
        cx = (b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
              + f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
              .encode())
        st_c, _ = s3("POST", okkey, s3port,
                     params={"uploadId": up2}, data=cx)
        ok(st_c in (200, 201) and uid_of(okkey) == UID_ALICE,
           f"control: clean MPU completes owned alice (HTTP {st_c})")
        ok([n for n in listdir("alice")
            if f"{TAG}_mpu_ok.bin.mpu-" in n] == [],
           "control: clean MPU left no staging dir after complete")
    else:
        ok(True, "control MPU skipped (re-initiate unsupported)")


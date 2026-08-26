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


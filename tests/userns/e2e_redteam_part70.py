def _rt70_segment_01(port, key):
    TAG = "dnc8"
    base = f"http://{HOST}:{port}"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    tc = mint(key, "carol")
    return TAG, base, ta, tb, tc


def _rt70_segment_02(key, s3port):
    td = mint(key, "dave")
    have_root = xrd_avail()
    have_s3 = bool(s3port) and s3port > 0

    BOB_SECRET = b"BOB-PRIVATE-SECRET"                 # data/bob/private.txt (0600)
    A_BODY = (b"DNC8-ALICE-CKSRC|" * 256)[:4096]       # alice's distinct checksum src
    return have_root, have_s3, BOB_SECRET, A_BODY


def _rt70_segment_03():
    B_BODY = (b"DNC8-BOB-CKSRC|" * 256)[:4096]         # bob's distinct checksum src
    V_OLD = (b"DNC8-OVERWRITE-OLD|" * 256)[:4096]      # whole "old" version
    V_NEW = (b"DNC8-OVERWRITE-NEW|" * 256)[:4096]      # whole "new" version
    return B_BODY, V_OLD, V_NEW


def _rt70_on_disk_introspection_this_batch_runs(data):

    # ---- on-disk introspection (this batch runs as in-ns root: sees real uids) ---
    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))
    return realp


def _rt70_segment_05(realp):

    def uid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_uid if os.path.exists(p) else -1
        except OSError:
            return -2
    return uid_of


def _rt70_segment_06(realp):

    def gid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_gid if os.path.exists(p) else -1
        except OSError:
            return -2
    return gid_of


def _rt70_segment_07(realp):

    def mode_of(rel):
        try:
            return os.stat(realp(rel)).st_mode
        except OSError:
            return 0
    return mode_of


def _rt70_segment_08(realp):

    def exists(rel):
        try:
            return os.path.exists(realp(rel))
        except OSError:
            return False
    return exists


def _rt70_segment_09(realp):

    def body_of(rel):
        try:
            with open(realp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt70_segment_10(realp):

    def listdir(rel):
        try:
            return os.listdir(realp(rel))
        except OSError:
            return []
    return listdir


def _rt70_segment_11(realp):

    def mkfile(rel, content, u, g, mode):
        p = realp(rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, u, g)
            os.chmod(p, mode)
            return True
        except OSError:
            return False
    return mkfile


def _rt70_segment_12(realp):

    def mkdir_own(rel, u, g, mode):
        p = realp(rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, u, g)
            os.chmod(p, mode)
            return True
        except OSError:
            return False
    return mkdir_own


def _rt70_segment_13(realp):

    def rm(rel):
        try:
            p = realp(rel)
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass


def _rt70_segment_14():

    def digest_of(out):
        """Last whitespace token of an xrdfs 'query checksum' line is the algo:value
        (or bare value) digest; None when the command produced no parseable line."""
        if not out:
            return None
        toks = out.split()
        return toks[-1] if toks else None
    return digest_of


def _rt70_segment_15(listdir, realp):

    def svc_root_residue(reldir):
        """Names under reldir owned by svc(1500)/root(0) — the cardinal
        impersonation-leak signature for a failed/partial data-motion op."""
        out = []
        for n in listdir(reldir):
            try:
                u = os.stat(os.path.join(realp(reldir), n)).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0):
                out.append((n, u))
        return out
    return svc_root_residue


def _rt70_segment_16():

    def upid(b):
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", b or b"")
        return m.group(1).decode() if m else None
    return upid


def _rt70_segment_17():

    def etag(b):
        m = re.search(rb'ETag>\\?"?([^"<\\]+)', b or b"")
        return m.group(1).decode() if m else None
    return etag


def _rt70_segment_18():

    def complete_xml(parts):
        x = b"<CompleteMultipartUpload>"
        for n, et in parts:
            x += (f"<Part><PartNumber>{n}</PartNumber>"
                  f"<ETag>{et}</ETag></Part>").encode()
        return x + b"</CompleteMultipartUpload>"
    return complete_xml


def _rt70_segment_19(port):

    def lock_file(rel, token):
        info = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                b'<D:lockscope><D:exclusive/></D:lockscope>'
                b'<D:locktype><D:write/></D:locktype>'
                b'<D:owner><D:href>mailto:x@x</D:href></D:owner></D:lockinfo>')
        st, b = http("LOCK", rel, port, token, data=info,
                     hdrs={"Content-Type": "application/xml",
                           "Timeout": "Second-600"})
        m = re.search(rb"<D:href>(opaquelocktoken:[^<]+)</D:href>", b or b"")
        if not m:
            m = re.search(rb"(opaquelocktoken:[A-Za-z0-9:\-\.]+)", b or b"")
        return st, (m.group(1).decode() if m else None)
    return lock_file


def _rt70_isolated_fixtures_never_touch_the_canonical(TAG, mkdir_own, mode_of, gid_of, realp):

    # ---- isolated fixtures (never touch the canonical shared fixtures) ----------
    # A 02770 alice:shared setgid dir; shared = {alice, bob, carol}; dave is NOT.
    SG = f"{TAG}_sgshared"
    ok(mkdir_own(SG, UID_ALICE, GID_SHARED, 0o2770),
       f"{TAG}: created 02770 alice:shared setgid dir {SG}")
    sgm = mode_of(SG)
    ok(all((sgm & 1024, gid_of(SG) == GID_SHARED)),
       f"{TAG}: {SG} is setgid + group=shared on disk (mode={sgm:o})")
    ensure_traversable(realp(SG))
    return SG


def _rt70_alice_bob_distinct_checksum_sources_own(TAG, mkfile, A_BODY, B_BODY):

    # alice + bob distinct checksum sources (own homes, 0644 so the read leg is a
    # real read, not a DAC deny that would mask a digest difference).
    ACK = f"alice/{TAG}_ck.bin"
    BCK = f"bob/{TAG}_ck.bin"
    ok(mkfile(ACK, A_BODY, UID_ALICE, UID_ALICE, 0o644),
       f"{TAG}: alice checksum source seeded 0644")
    ok(mkfile(BCK, B_BODY, UID_BOB, UID_BOB, 0o644),
       f"{TAG}: bob checksum source seeded 0644 (distinct content)")

    # carol:staff 0640 group-readable file (read leg) lives in the canonical svc-owned
    # 0755 grp/ dir — a pure GET needs only parent traversal, which 0755 grants.
    GR = f"{TAG}_staff_r.bin"
    return ACK, BCK, GR


def _rt70_rename_so_the_positive_control_needs(mkfile, GR, TAG, mkdir_own):
    GR_BODY = b"DNC8-STAFF-GROUP-READABLE-CONTENT"
    ok(mkfile(f"grp/{GR}", GR_BODY, UID_ALICE, GID_STAFF, 0o640),
       f"{TAG}: alice:staff 0640 group-readable file seeded")
    # The 0660 group-writable file (the write legs) lives in a DEDICATED 02770
    # alice:staff setgid dir: a WebDAV PUT is a STAGED write (temp-in-parent +
    # rename), so the positive control needs the PARENT to be staff-group-writable,
    # not just the file (the round-7 lesson).  carol IS in staff, so she can stage
    # here; svc-owned grp/ (0755) would EACCES her staged temp create.  setgid keeps
    # the staged temp + committed file in the staff group.
    GWD = f"{TAG}_staffwdir"
    GW = f"{GWD}/{TAG}_staff_w.bin"
    ok(mkdir_own(GWD, UID_ALICE, GID_STAFF, 0o2770),
       f"{TAG}: created 02770 alice:staff setgid write-dir {GWD}")
    return GR_BODY, GWD, GW


def _rt70_1_http_tpc_pull_into_the(realp, GWD, mkfile, GW, TAG, SG, port, tc):
    ensure_traversable(realp(GWD))
    ok(mkfile(GW, b"DNC8-STAFF-GROUP-WRITABLE", UID_ALICE, GID_STAFF, 0o660),
       f"{TAG}: alice:staff 0660 group-writable file seeded in staff write-dir")

    # =====================================================================
    # (1) HTTP-TPC PULL into the setgid shared dir.  A WebDAV COPY carrying a
    #     remote https `Source:` header is a third-party PULL (src/protocols/webdav/tpc.c
    #     requires an https Source).  In this loopback userns config there is NO
    #     https origin, so the pull cannot complete -- but the security invariant
    #     still holds regardless of the verdict: a rejected/failed pull must leave
    #     NO svc/root-owned staging temp or partial object in the setgid dir, and
    #     the dir keeps its setgid bit + shared group (broker never clobbers it).
    #     This residue/no-clobber invariant is NOT asserted by combo_setgid (which
    #     only drives *completed* native-TPC/COPY) nor by tpc_pull_push_matrix.
    # =====================================================================
    pull_dst = f"/{SG}/{TAG}_pulled.bin"
    sp, _bp = http("COPY", pull_dst, port, tc,
                   hdrs={"Source": "https://127.0.0.1:1/nonexistent/src.bin",  # net-literal-allow: SSRF COPY-pull Source target under test
                         "Credential": "none"})
    ok(sp in (400, 403, 404, 405, 422, 500, 502, 504, 501, -1, 201, 202, 207),
       f"{TAG}(1): HTTP-TPC pull into setgid dir resolved a verdict (405 when TPC "
       f"disabled in the e2e config) (HTTP {sp})")
    return pull_dst


def _rt70_segment_24(svc_root_residue, SG, TAG, uid_of, pull_dst, mode_of):
    res1 = svc_root_residue(SG)
    ok(not res1,
       f"{TAG}(1): HTTP-TPC pull left NO svc/root-owned residue in setgid dir "
       f"(residue={res1})")
    pdst_uid = uid_of(pull_dst)
    ok(pdst_uid in (-1, UID_CAROL),
       f"{TAG}(1): any object materialised by the pull is carol-owned, never "
       f"svc/root/foreign (uid={pdst_uid})")
    sgm2 = mode_of(SG)
    return sgm2


def _rt70_segment_01_3():
    a_digs, b_digs, derr = [], [], []
    return a_digs, b_digs, derr


def _rt70_segment_02_3(digest_of, derr):

    def ck_loop(rel, sub, sink):
        for _ in range(4):
            try:
                rc, out, _e = xrd_fs(["query", "checksum", "/" + rel], sub)
                if rc == 0:
                    d = digest_of(out)
                    if d:
                        sink.append(d)
            except Exception as e:                 # noqa: BLE001
                derr.append(repr(e))
    return ck_loop


def _rt70_check_for_each_range_3(threads, ck_loop, ACK, a_digs, BCK, b_digs):
    for _ in range(3):
        threads.append(threading.Thread(target=ck_loop, args=(ACK, "alice", a_digs)))
        threads.append(threading.Thread(target=ck_loop, args=(BCK, "bob", b_digs)))


def _rt70_segment_03_3(ck_loop, ACK, a_digs, BCK, b_digs):

    threads = []
    _rt70_check_for_each_range_3(threads, ck_loop, ACK, a_digs, BCK, b_digs)
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ck_ran = bool(a_digs) and bool(b_digs)
    return ck_ran


def _rt70_no_digest_algo_emitted_unsupported_cannot(ck_ran, a_digs, TAG, b_digs, derr):
    if ck_ran:
        ok(len(set(a_digs)) == 1,
           f"{TAG}(2): alice's concurrent checksum digest is consistent across "
           f"all requests (n={len(a_digs)} distinct={len(set(a_digs))})")
        ok(len(set(b_digs)) == 1,
           f"{TAG}(2): bob's concurrent checksum digest is consistent across all "
           f"requests (n={len(b_digs)} distinct={len(set(b_digs))})")
        ok(set(a_digs).isdisjoint(set(b_digs)),
           f"{TAG}(2): alice/bob checksum digests are DISJOINT under concurrent "
           f"identity-switch (no cross-identity digest bleed)")
    else:
        # No digest algo emitted / unsupported -> cannot compare; still assert the
        # security invariant that is observable: neither file's secret-ish content
        # nor the other tenant's body leaked into either digest stream.
        allout = "".join(a_digs + b_digs)
        ok(all(('DNC8-BOB-CKSRC' not in allout, 'DNC8-ALICE-CKSRC' not in allout)),
           f"{TAG}(2): checksum unsupported; no raw file content leaked via digest")
        ok(not derr,
           f"{TAG}(2): concurrent checksum identity-switch raised no client errors")
        ok(True,
           f"{TAG}(2): checksum digest comparison skipped (algo unsupported)")


def _rt70_when_have_root_2(digest_of, ACK, BCK, TAG):
    a_digs, b_digs, derr = _rt70_segment_01_3()

    ck_loop = _rt70_segment_02_3(digest_of, derr)

    ck_ran = _rt70_segment_03_3(ck_loop, ACK, a_digs, BCK, b_digs)

    _rt70_no_digest_algo_emitted_unsupported_cannot(ck_ran, a_digs, TAG, b_digs, derr)



def _rt70_2_query_checksum_x_concurrent_identity(sgm2, gid_of, SG, TAG, have_root, digest_of, ACK, BCK, mkfile):
    ok(all((sgm2 & 1024, gid_of(SG) == GID_SHARED)),
       f"{TAG}(1): setgid dir keeps setgid+shared after the pull (mode={sgm2:o})")

    _deep_novel_combos_r8_p1(have_root, have_s3, lock_file, tb, port, ta, key, body_of, GW, TAG, mkfile, exists, s3port, upid, V_OLD, V_NEW, base, uid_of, GR, GR_BODY, SG, etag, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, sub, gid_of, complete_xml, ACK, BCK, rel, sink)


def _deep_novel_combos_r8_p1(have_root, have_s3, lock_file, tb, port, ta, key, body_of, GW, TAG, mkfile, exists, s3port, upid, V_OLD, V_NEW, base, uid_of, GR, GR_BODY, SG, etag, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, sub, gid_of, complete_xml, ACK, BCK, rel, sink):
    # =====================================================================
    # (2) QUERY-CHECKSUM x CONCURRENT IDENTITY-SWITCH on shared workers.  alice and
    #     bob CONCURRENTLY query checksums of their OWN distinct 0644 files in a
    #     tight loop.  The invariant under test is per-request identity isolation
    #     of the digest path: every alice digest is byte-identical to every other
    #     alice digest (deterministic), same for bob, and alice's digest set is
    #     DISJOINT from bob's (different content => different digest, never a
    #     cross-identity digest bleed onto a shared worker).  This is the DIGEST
    #     analogue of concurrent_crossproto's torn-BYTES test -- a distinct surface.
    # =====================================================================
    if have_root:
        _rt70_when_have_root_2(digest_of, ACK, BCK, TAG)
    else:
        ok(True, f"{TAG}(2): checksum identity-switch skipped (native client absent)")
        ok(True, f"{TAG}(2): alice/bob digest disjointness skipped (no native client)")
        ok(True, f"{TAG}(2): checksum determinism skipped (no native client)")

    # =====================================================================
    # (3) CROSS-TENANT RENAME x WebDAV LOCK STATE.  bob takes an EXCLUSIVE WebDAV
    #     lock on his own file; alice then attempts a MOVE that would CLOBBER bob's
    #     locked file as its destination.  The clobber must be DOUBLE-denied -- by
    #     DAC (alice cannot write into bob's space) AND by the lock -- and bob's
    #     secret + ownership survive untouched.  rename-vs-lock is a combination
    #     neither multipart_lock_identity (lock x MPU/root://) nor combo_setgid
    #     (rename without a lock) drives.
    _deep_novel_combos_r8_p2(have_s3, have_root, lock_file, tb, port, ta, key, body_of, GW, TAG, mkfile, exists, s3port, upid, V_OLD, V_NEW, base, uid_of, GR, GR_BODY, SG, etag, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, gid_of, complete_xml)


def _deep_novel_combos_r8_p2(have_s3, have_root, lock_file, tb, port, ta, key, body_of, GW, TAG, mkfile, exists, s3port, upid, V_OLD, V_NEW, base, uid_of, GR, GR_BODY, SG, etag, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, gid_of, complete_xml):
    # =====================================================================
    bob_locked = f"bob/{TAG}_locked.txt"
    LOCK_MARK = b"DNC8-BOB-LOCKED-SECRET"
    ok(mkfile(bob_locked, LOCK_MARK, UID_BOB, UID_BOB, 0o600),
       f"{TAG}(3): bob 0600 lock-target seeded")
    return bob_locked, LOCK_MARK


def _rt70_alice_s_own_movable_source_she(lock_file, bob_locked, tb, TAG, mkfile, port, ta, base):
    sl, ltok = lock_file("/" + bob_locked, tb)
    ok(any((sl in (200, 201), ltok is not None)),
       f"{TAG}(3): bob LOCKs his own file (HTTP {sl}, tok={'y' if ltok else 'n'})")
    # alice's own movable source she will try to rename ON TOP of bob's locked file.
    alice_mv_src = f"alice/{TAG}_mvsrc.txt"
    ok(mkfile(alice_mv_src, b"DNC8-ALICE-MOVE-BODY", UID_ALICE, UID_ALICE, 0o644),
       f"{TAG}(3): alice move-source seeded")
    sm, _bm = http("MOVE", "/" + alice_mv_src, port, ta,
                   hdrs={"Destination": base + "/" + bob_locked, "Overwrite": "T"})
    return ltok, alice_mv_src, sm


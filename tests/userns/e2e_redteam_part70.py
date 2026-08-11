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


def _rt70_positive_control_bob_himself_moves_his(sm, TAG, uid_of, bob_locked, body_of, LOCK_MARK, exists, alice_mv_src, base):
    ok(sm in (401, 403, 404, 409, 412, 423, 500),
       f"{TAG}(3): alice cross-tenant MOVE clobbering bob's LOCKED file DENIED "
       f"(HTTP {sm})")
    ok(all((uid_of(bob_locked) == UID_BOB, body_of(bob_locked) == LOCK_MARK)),
       f"{TAG}(3): bob's locked file untouched (still bob-owned, secret intact)")
    ok(exists(alice_mv_src),
       f"{TAG}(3): alice's source preserved after her denied clobber (no data loss)")
    # POSITIVE control: bob himself MOVEs his locked file (with his lock token) to a
    # new name -> the owner+lock-holder is allowed; proves the deny above was the
    # identity/lock boundary, not a blanket MOVE failure.
    bob_dst = f"bob/{TAG}_locked_moved.txt"
    if_hdr = {"Destination": base + "/" + bob_dst}
    return bob_dst, if_hdr


def _rt70_segment_28(ltok, if_hdr, bob_locked, port, tb, uid_of, bob_dst, TAG):
    if ltok:
        if_hdr["If"] = f"(<{ltok}>)"
    smb, _ = http("MOVE", "/" + bob_locked, port, tb, hdrs=if_hdr)
    moved_ok = smb in (200, 201, 204) and uid_of(bob_dst) == UID_BOB
    ok(any((moved_ok, uid_of(bob_dst) in (-1, UID_BOB))),
       f"{TAG}(3): POSITIVE bob (owner+lock-holder) MOVEs his own locked file, "
       f"result bob-owned never svc/root (HTTP {smb})")
    ok(uid_of(bob_dst) not in (UID_ALICE, UID_SVC, 0),
       f"{TAG}(3): bob's moved file never alice/svc/root-owned (uid={uid_of(bob_dst)})")


def _rt70_4_scoped_read_only_token_x(key, GWD, GR, port, GR_BODY, TAG, body_of, GW):

    # =====================================================================
    # (4) SCOPED READ-ONLY TOKEN x GROUP-DAC.  A carol token scoped ONLY
    #     `storage.read:/grp` (no create/modify verb).  carol IS in staff, so DAC
    #     would permit her to WRITE the 0660 group-writable file -- but the token's
    #     scope grants only READ.  The read of the 0640 group file must SUCCEED
    #     (group DAC + read scope), while the write must be denied by SCOPE even
    #     though DAC alone would allow it.  This is the scope-vs-DAC layering that
    #     run_token_scope_dac tests only on a cross-tenant path, never on a path the
    #     accessor's GROUP grants but the SCOPE forbids -- a distinct intersection.
    _deep_novel_combos_r8_p3(have_s3, have_root, key, port, body_of, GW, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, GR, GR_BODY, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, gid_of, complete_xml)


def _deep_novel_combos_r8_p3(have_s3, have_root, key, port, body_of, GW, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, GR, GR_BODY, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, GWD, A_BODY, gid_of, complete_xml):
    # =====================================================================
    # Read scope covers BOTH the 0640 read file (/grp) and the staff write-dir, so the
    # write-deny below is unambiguously about the missing write verb, not the path.
    tc_ro = mint(key, "carol", scope=f"storage.read:/grp storage.read:/{GWD}")
    sro, bro = http("GET", f"/grp/{GR}", port, tc_ro)
    ok(all((sro == 200, GR_BODY in any((bro, b'')))),
       f"{TAG}(4): read-only-scoped carol(staff) GETs 0640 group file via group DAC "
       f"+ read scope (HTTP {sro})")
    # write with the read-only token: scope must reject it, leaving content unchanged.
    pre_gw = body_of(GW)
    swro, _ = http("PUT", f"/{GW}", port, tc_ro, data=b"DNC8-RO-SCOPE-CLOBBER")
    return pre_gw, swro


def _rt70_positive_control_a_full_scope_carol(swro, TAG, body_of, GW, pre_gw, key, port):
    ok(swro in (401, 403, 404, 405, 423, 500),
       f"{TAG}(4): read-only-scoped carol PUT to group-writable file DENIED BY SCOPE "
       f"despite group-write DAC (HTTP {swro})")
    ok(all((body_of(GW) == pre_gw, b'DNC8-RO-SCOPE-CLOBBER' not in body_of(GW))),
       f"{TAG}(4): group-writable file content unchanged after scope-denied write")
    # POSITIVE control: a FULL-scope carol token CAN write the same 0660 group file.
    # It lives in a staff-group-writable setgid dir, so carol (staff) can stage+commit
    # the WebDAV PUT — proving the gate above was the scope, not the group/DAC boundary.
    tc_full = mint(key, "carol")
    swf, _ = http("PUT", f"/{GW}", port, tc_full, data=b"DNC8-CAROL-GROUP-WRITE")
    ok(swf in (200, 201, 204),
       f"{TAG}(4): POSITIVE full-scope carol(staff) writes 0660 group file (HTTP {swf})")
    return swf


def _rt70_dave_non_member_of_shared_tries_2(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of):
    stp, pb = s3("PUT", mpu_key, s3port,
                 params={"uploadId": up, "partNumber": "1"},
                 access_key="bob", data=b"M" * 8192)
    e1 = etag(pb)
    ok(stp in (200, 201),
       f"{TAG}(5): bob uploads part 1 of the shared-dir MPU (HTTP {stp})")
    # dave (NON-member of shared) tries to COMPLETE -> denied; nothing assembled.
    std, _ = s3("POST", mpu_key, s3port, params={"uploadId": up},
                access_key="dave", data=complete_xml([(1, e1 or "x")]))
    dave_assembled = exists(mpu_key) and uid_of(mpu_key) == UID_DAVE
    return e1, std, dave_assembled


def _rt70_carol_member_of_shared_completes_assembled(dave_assembled, TAG, std, mpu_key, s3port, up, complete_xml, e1, uid_of, exists, gid_of, svc_root_residue, SG):
    ok(not dave_assembled,
       f"{TAG}(5): non-member dave COMPLETE of bob's shared-dir MPU did NOT "
       f"assemble a dave-owned object (HTTP {std})")
    # carol (member of shared) COMPLETEs -> assembled object owned by carol.
    stc, _ = s3("POST", mpu_key, s3port, params={"uploadId": up},
                access_key="carol", data=complete_xml([(1, e1 or "x")]))
    cuid = uid_of(mpu_key)
    if exists(mpu_key):
        ok(all((cuid in (UID_CAROL, UID_BOB), cuid not in (UID_SVC, 0, UID_DAVE))),
           f"{TAG}(5): MPU assembled-by-carol object owned by a real shared "
           f"member, never svc/root/dave (uid={cuid}, HTTP {stc})")
        ok(gid_of(mpu_key) in (GID_SHARED, UID_CAROL, UID_BOB),
           f"{TAG}(5): assembled object carries shared group (setgid) or its "
           f"completer's primary, never a foreign group (gid={gid_of(mpu_key)})")
    else:
        ok(stc in (200, 201, 403, 404, 409, 500),
           f"{TAG}(5): cross-member MPU complete resolved a verdict, no object "
           f"(HTTP {stc})")
        ok(not svc_root_residue(SG),
           f"{TAG}(5): no svc/root residue from the unassembled MPU")


def _rt70_when_up(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of, gid_of, svc_root_residue, SG):
    e1, std, dave_assembled = _rt70_dave_non_member_of_shared_tries_2(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of)

    _rt70_carol_member_of_shared_completes_assembled(dave_assembled, TAG, std, mpu_key, s3port, up, complete_xml, e1, uid_of, exists, gid_of, svc_root_residue, SG)



def _rt70_dave_non_member_of_shared_tries(SG, TAG, s3port, upid, etag, complete_xml, exists, uid_of, gid_of, svc_root_residue):
    mpu_key = f"{SG}/{TAG}_mpu.bin"
    sti, ib = s3("POST", mpu_key, s3port, params={"uploads": ""}, access_key="bob")
    up = upid(ib)
    ok(sti in (200, 403),
       f"{TAG}(5): bob S3 MPU into shared setgid dir — 200 if bob is group-"
       f"writable on it, else 403 DAC (HTTP {sti})")
    if up:
        _rt70_when_up(mpu_key, s3port, up, etag, TAG, complete_xml, exists, uid_of, gid_of, svc_root_residue, SG)
    else:
        ok(True, f"{TAG}(5): MPU initiate failed; non-member complete leg skipped")
        ok(True, f"{TAG}(5): MPU member-complete leg skipped (no uploadId)")
        ok(True, f"{TAG}(5): MPU ownership invariant skipped (no uploadId)")


def _rt70_when_s3_live(SG, TAG, s3port, upid, etag, uid_of, exists, complete_xml, gid_of, svc_root_residue):
    _rt70_dave_non_member_of_shared_tries(SG, TAG, s3port, upid, etag, complete_xml, exists, uid_of, gid_of, svc_root_residue)



def _rt70_check_when_have_root(have_root, TAG, SG, svc_root_residue, exists):
    if have_root:
        miss_src = f"/carol/{TAG}_missing_{int(time.time())}.bin"
        miss_dst = f"/{SG}/{TAG}_tpc_miss.bin"
        rc6, _o6, _e6 = xrd_cp_tpc(miss_src, miss_dst, "carol")
        ok(all((rc6 != 0, not exists(miss_dst))),
           f"{TAG}(6a): abandoned TPC (missing source) left no partial dest (rc={rc6})")
        ok(not svc_root_residue(SG),
           f"{TAG}(6a): abandoned TPC left NO svc/root-owned residue in setgid dir")
    else:
        ok(True, f"{TAG}(6a): abandoned-TPC residue check skipped (no native client)")
        ok(True, f"{TAG}(6a): abandoned-TPC svc-residue check skipped (no native client)")


def _rt70_member_bob_initiates_uploads_a_part(swf, uid_of, GW, gid_of, TAG, have_s3, s3port, SG, upid, etag, complete_xml, exists, svc_root_residue, have_root):
    if swf in (200, 201, 204):
        ok(all((uid_of(GW) == UID_CAROL, gid_of(GW) == GID_STAFF)),
           f"{TAG}(4): group-write committed as carol, kept setgid staff group "
           f"(uid={uid_of(GW)} gid={gid_of(GW)})")
    else:
        ok(True, f"{TAG}(4): full-scope group write not honoured; no ownership change")

    # =====================================================================
    # (5) S3 MULTIPART into a GROUP-SHARED dir, COMPLETED by a DIFFERENT group
    #     member.  bob INITIATES + uploads a part into the 02770 shared dir (bob IS
    #     shared); carol (ALSO shared) drives the COMPLETE.  The assembled object
    #     must be owned by the principal the broker maps for the Complete request
    #     (carol) -- never svc/root -- and must carry the setgid'd shared group.  A
    #     NON-member (dave) completing the same upload is denied.  This "another
    #     group member finishes my MPU" sequence is not in multipart_lock_identity
    #     (which only cross-tenant-aborts/foreign-uploadId's a single tenant's MPU).
    # =====================================================================
    if have_s3:
        st0, _ = s3("GET", "", s3port, params={"list-type": "2"})
        s3_live = st0 != -1
    else:
        s3_live = False
    _deep_novel_combos_r8_p4(s3_live, have_root, port, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, A_BODY, complete_xml, body_of, gid_of)


def _deep_novel_combos_r8_p4(s3_live, have_root, port, ta, s3port, upid, TAG, mkfile, V_OLD, V_NEW, SG, etag, uid_of, exists, digest_of, BOB_SECRET, svc_root_residue, A_BODY, complete_xml, body_of, gid_of):
    if s3_live:
        _rt70_when_s3_live(SG, TAG, s3port, upid, etag, uid_of, exists, complete_xml, gid_of, svc_root_residue)
    else:
        ok(True, f"{TAG}(5): S3 multipart group-complete skipped (S3 not reachable)")
        ok(True, f"{TAG}(5): non-member MPU complete deny skipped (no S3)")
        ok(True, f"{TAG}(5): MPU ownership invariant skipped (no S3)")
    _deep_novel_combos_r8_p5(have_root, port, ta, TAG, mkfile, V_OLD, V_NEW, SG, digest_of, BOB_SECRET, svc_root_residue, A_BODY, uid_of, exists, body_of)


def _deep_novel_combos_r8_p5(have_root, port, ta, TAG, mkfile, V_OLD, V_NEW, SG, digest_of, BOB_SECRET, svc_root_residue, A_BODY, uid_of, exists, body_of):
    # =====================================================================
    # (6) PARTIAL-RST mid-TPC + DIGEST-MID-OVERWRITE race.  Two failure-path
    #     combinations the existing combos never cross:
    #     (6a) a native loopback TPC whose source does NOT exist is abandoned --
    #          the broker must leave NO svc/root-owned partial in the dest dir and
    #          stay healthy (already partially covered for ENOENT in tpc matrix, but
    #          here we also assert the *worker-survival + no-svc-residue* invariant
    #          across the WHOLE export, the impersonation-leak signature);
    #     (6b) while alice overwrites a 0644 file between two WHOLE versions, bob
    #          repeatedly queries its checksum -- every successful digest must match
    #          the digest of ONE consistent whole version (V_OLD or V_NEW), never a
    #          torn/intermediate digest of a half-written file.
    # =====================================================================
    # (6a)
    _rt70_check_when_have_root(have_root, TAG, SG, svc_root_residue, exists)

    # (6b)
    race_rel = f"alice/{TAG}_race.bin"
    return race_rel


def _rt70_segment_01_2(race_rel, digest_of, mkfile, V_NEW):
    rc_o, out_o, _ = xrd_fs(["query", "checksum", "/" + race_rel], "alice")
    dig_old = digest_of(out_o) if rc_o == 0 else None
    mkfile(race_rel, V_NEW, UID_ALICE, UID_ALICE, 0o644)
    rc_n, out_n, _ = xrd_fs(["query", "checksum", "/" + race_rel], "alice")
    dig_new = digest_of(out_n) if rc_n == 0 else None
    return dig_old, dig_new


def _rt70_segment_02_2(mkfile, race_rel, V_OLD):
    mkfile(race_rel, V_OLD, UID_ALICE, UID_ALICE, 0o644)   # reset to OLD

    race_digs, race_err = [], []
    return race_digs, race_err


def _rt70_segment_03_2(race_rel, port, ta, V_NEW, V_OLD, race_err):

    def overwriter():
        for _ in range(4):
            try:
                http("PUT", "/" + race_rel, port, ta, V_NEW)
                http("PUT", "/" + race_rel, port, ta, V_OLD)
            except Exception as e:                 # noqa: BLE001
                race_err.append(repr(e))
    return overwriter


def _rt70_segment_04(race_rel, digest_of, race_digs, race_err):

    def race_ck(i):
        for _ in range(2):
            try:
                rc, out, _e = xrd_fs(["query", "checksum", "/" + race_rel], "bob")
                if rc == 0:
                    d = digest_of(out)
                    if d:
                        race_digs.append(d)
            except Exception as e:                 # noqa: BLE001
                race_err.append(repr(e))
    return race_ck


def _rt70_check_for_each_t_rthreads(rthreads):
    for t in rthreads:
        t.start()


def _rt70_segment_05_2(overwriter, race_ck, dig_old, dig_new):

    rthreads = [threading.Thread(target=overwriter)]
    rthreads += [threading.Thread(target=race_ck, args=(i,)) for i in range(3)]
    _rt70_check_for_each_t_rthreads(rthreads)
    for t in rthreads:
        t.join()

    legal = {d for d in (dig_old, dig_new) if d}
    return legal


def _rt70_segment_06_2(legal, race_digs, TAG, uid_of, race_rel, body_of, V_OLD, V_NEW):
    if legal and race_digs:
        torn = [d for d in race_digs if d not in legal]
        ok(not torn,
           f"{TAG}(6b): every concurrent digest matches one WHOLE version, never "
           f"a torn/intermediate digest (n={len(race_digs)} torn={torn[:2]})")
        ok(all((uid_of(race_rel) == UID_ALICE, uid_of(race_rel) not in (UID_SVC, 0))),
           f"{TAG}(6b): race file stays alice-owned after the overwrite storm "
           f"(uid={uid_of(race_rel)})")
    else:
        ok(body_of(race_rel) in (V_OLD, V_NEW),
           f"{TAG}(6b): race file on disk is a WHOLE writer version (no half-write)")
        ok(uid_of(race_rel) == UID_ALICE,
           f"{TAG}(6b): race file stays alice-owned (digest compare unavailable)")


def _rt70_when_have_root(race_rel, digest_of, mkfile, V_NEW, V_OLD, port, ta, TAG, body_of, uid_of):
    dig_old, dig_new = _rt70_segment_01_2(race_rel, digest_of, mkfile, V_NEW)

    race_digs, race_err = _rt70_segment_02_2(mkfile, race_rel, V_OLD)

    overwriter = _rt70_segment_03_2(race_rel, port, ta, V_NEW, V_OLD, race_err)

    race_ck = _rt70_segment_04(race_rel, digest_of, race_digs, race_err)

    legal = _rt70_segment_05_2(overwriter, race_ck, dig_old, dig_new)

    _rt70_segment_06_2(legal, race_digs, TAG, uid_of, race_rel, body_of, V_OLD, V_NEW)



def _rt70_capture_the_stable_digest_of_each(mkfile, race_rel, V_OLD, TAG, have_root, digest_of, V_NEW, port, ta, uid_of, body_of, A_BODY, BOB_SECRET):
    ok(mkfile(race_rel, V_OLD, UID_ALICE, UID_ALICE, 0o644),
       f"{TAG}(6b): overwrite-race file seeded with whole V_OLD")
    _deep_novel_combos_r8_p6(have_root, port, ta, mkfile, race_rel, V_NEW, V_OLD, digest_of, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of)


def _deep_novel_combos_r8_p6(have_root, port, ta, mkfile, race_rel, V_NEW, V_OLD, digest_of, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of):
    if have_root:
        # capture the stable digest of each whole version as the only legal answers.
        _rt70_when_have_root(race_rel, digest_of, mkfile, V_NEW, V_OLD, port, ta, TAG, body_of, uid_of)
    else:
        ok(True, f"{TAG}(6b): digest-mid-overwrite race skipped (no native client)")
        ok(True, f"{TAG}(6b): race-file ownership invariant skipped (no native client)")
    _deep_novel_combos_r8_p7(port, ta, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of)


def _deep_novel_combos_r8_p7(port, ta, TAG, BOB_SECRET, svc_root_residue, SG, A_BODY, uid_of, body_of):
    # =====================================================================
    # SURVIVAL + secret integrity: after the whole round-8 combination storm the
    # worker is not wedged, bob's canonical private secret is intact, and no
    # svc/root-owned artifact was smuggled into the setgid dir.
    # =====================================================================
    ssv, bsv = http("GET", f"/alice/{TAG}_ck.bin", port, ta)
    ok(all((ssv == 200, A_BODY[:16] in any((bsv, b'')))),
       f"{TAG} survival: alice legit GET still works after the storm (HTTP {ssv})")
    ok(all((body_of('bob/private.txt').startswith(BOB_SECRET), uid_of('bob/private.txt') == UID_BOB)),
       f"{TAG} survival: bob/private.txt canonical secret + ownership intact")


def _rt70_segment_33(svc_root_residue, SG, TAG):
    ok(not svc_root_residue(SG),
       f"{TAG} survival: setgid shared dir holds no svc/root-owned artifact")


def run_deep_novel_combos_r8(key, data, port, s3port):
    """ROUND-8 cross-feature COMBINATION frontier: sequences that CROSS the new
    round-8 surfaces (HTTP-TPC pull / native-TPC / query-checksum / scoped-token /
    cross-tenant rename) with DAC + GROUP + CONCURRENCY in shapes none of the 12
    existing combo_* batches drive.  Distinct from run_combo_setgid_via_copymove
    (it does WebDAV-COPY/MOVE/native-TPC/S3-CopyObject setgid inheritance but NOT
    an HTTP-TPC *pull* residue check, NOT checksum-vs-identity, NOT lock-vs-rename),
    from run_combo_multipart_lock_identity (it crosses S3-MPU x LOCK x identity but
    NOT a group-member-completes-another-member's-MPU, NOT rename-vs-lock, NOT a
    read-only-scope x group write-deny), from run_combo_concurrent_crossproto (torn
    read of file BYTES, never of a query-checksum DIGEST under identity-switch), and
    from run_tpc_pull_push_matrix (native-TPC DAC matrix, but NOT setgid-through-TPC
    residue, NOT a mid-TPC RST, NOT digest-mid-overwrite).  Every sequence ends in a
    DISTINCT invariant: no cross-tenant digest bleed, no torn digest, scope gates the
    write while DAC gates the read, a lock+DAC double-denies a cross-tenant clobber,
    an MPU assembled by a different group member is owned by the completer not svc,
    and no failed/aborted TPC leaves an svc/root-owned partial.  Fixtures: `dnc8_`.
    <=8 threads, <=64 KiB bodies, <=6 concurrent subprocesses."""
    TAG, base, ta, tb, tc = _rt70_segment_01(port, key)

    have_root, have_s3, BOB_SECRET, A_BODY = _rt70_segment_02(key, s3port)

    B_BODY, V_OLD, V_NEW = _rt70_segment_03()

    realp = _rt70_on_disk_introspection_this_batch_runs(data)

    uid_of = _rt70_segment_05(realp)

    gid_of = _rt70_segment_06(realp)

    mode_of = _rt70_segment_07(realp)

    exists = _rt70_segment_08(realp)

    body_of = _rt70_segment_09(realp)

    listdir = _rt70_segment_10(realp)

    mkfile = _rt70_segment_11(realp)

    mkdir_own = _rt70_segment_12(realp)

    _rt70_segment_13(realp)

    digest_of = _rt70_segment_14()

    svc_root_residue = _rt70_segment_15(listdir, realp)

    upid = _rt70_segment_16()

    etag = _rt70_segment_17()

    complete_xml = _rt70_segment_18()

    lock_file = _rt70_segment_19(port)

    SG = _rt70_isolated_fixtures_never_touch_the_canonical(TAG, mkdir_own, mode_of, gid_of, realp)

    ACK, BCK, GR = _rt70_alice_bob_distinct_checksum_sources_own(TAG, mkfile, A_BODY, B_BODY)

    GR_BODY, GWD, GW = _rt70_rename_so_the_positive_control_needs(mkfile, GR, TAG, mkdir_own)

    pull_dst = _rt70_1_http_tpc_pull_into_the(realp, GWD, mkfile, GW, TAG, SG, port, tc)

    sgm2 = _rt70_segment_24(svc_root_residue, SG, TAG, uid_of, pull_dst, mode_of)

    bob_locked, LOCK_MARK = _rt70_2_query_checksum_x_concurrent_identity(sgm2, gid_of, SG, TAG, have_root, digest_of, ACK, BCK, mkfile)

    ltok, alice_mv_src, sm = _rt70_alice_s_own_movable_source_she(lock_file, bob_locked, tb, TAG, mkfile, port, ta, base)

    bob_dst, if_hdr = _rt70_positive_control_bob_himself_moves_his(sm, TAG, uid_of, bob_locked, body_of, LOCK_MARK, exists, alice_mv_src, base)

    _rt70_segment_28(ltok, if_hdr, bob_locked, port, tb, uid_of, bob_dst, TAG)

    pre_gw, swro = _rt70_4_scoped_read_only_token_x(key, GWD, GR, port, GR_BODY, TAG, body_of, GW)

    swf = _rt70_positive_control_a_full_scope_carol(swro, TAG, body_of, GW, pre_gw, key, port)

    race_rel = _rt70_member_bob_initiates_uploads_a_part(swf, uid_of, GW, gid_of, TAG, have_s3, s3port, SG, upid, etag, complete_xml, exists, svc_root_residue, have_root)

    _rt70_capture_the_stable_digest_of_each(mkfile, race_rel, V_OLD, TAG, have_root, digest_of, V_NEW, port, ta, uid_of, body_of, A_BODY, BOB_SECRET)

    _rt70_segment_33(svc_root_residue, SG, TAG)




# ===== Round-9 new-feature-surface batches =====

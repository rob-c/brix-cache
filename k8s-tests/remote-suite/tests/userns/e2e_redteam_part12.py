def _rt12_segment_01(key):
    ta, tb = mint(key, "alice"), mint(key, "bob")
    TAG = "csr_"            # fixture/file prefix to avoid collisions with other batteries
    return ta, tb, TAG


def _rt12_segment_02():

    def st_uid(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1
    return st_uid


def _rt12_segment_03(data):

    def apath(name):
        return os.path.join(data, "alice", name)
    return apath


def _rt12_segment_04(data):

    def bpath(name):
        return os.path.join(data, "bob", name)
    return bpath


def _rt12_segment_05():

    def rm_quiet(p):
        try:
            os.unlink(p)
        except OSError:
            pass
    return rm_quiet


def _rt12_misowned_entry(data, sub, name, wanted_uid, tag):
    path = os.path.join(data, sub, name)
    try:
        status = os.lstat(path)
    except OSError:
        return None
    if (status.st_mode & 0o170000) != 0o100000:
        return None
    owner = status.st_uid
    if owner in (UID_SVC, 0) or all((name.startswith(tag), owner != wanted_uid)):
        return sub, name, owner
    return None


def _rt12_scan_misowned(data, tag):
    bad = []
    for sub, wanted_uid in (("alice", UID_ALICE), ("bob", UID_BOB)):
        try:
            names = os.listdir(os.path.join(data, sub))
        except OSError:
            continue
        for name in names:
            issue = _rt12_misowned_entry(data, sub, name, wanted_uid, tag)
            if issue is not None:
                bad.append(issue)
    return bad


def _rt12_segment_06(data, TAG):

    def scan_misowned():
        """Count regular files in alice/ + bob/ that belong to the WRONG uid (the
        other tenant), to svc(1500), or to root(0).  Only judges our TAG files plus
        any svc/root-owned file (a svc/root-owned data file is always a leak signal)."""
        return _rt12_scan_misowned(data, TAG)
    return scan_misowned


def _rt12_a_keep_alive_interleave_a_b(TAG, ta, tb, port):

    # ============================================================================
    # A) KEEP-ALIVE INTERLEAVE — a,b,a,b... on ONE TCP connection.  If the principal
    #    is reused stale, alice's PUT could create bob-owned files or land in bob/.
    # ============================================================================
    inter = []
    for i in range(8):
        a_name, b_name = f"{TAG}ka_a_{i}.txt", f"{TAG}ka_b_{i}.txt"
        inter.append(("PUT", f"/alice/{a_name}", ta, b"A-keepalive\n", None))
        inter.append(("PUT", f"/bob/{b_name}", tb, b"B-keepalive\n", None))
    res = http_keepalive(inter, port)
    ok(len(res) == 16, f"keep-alive interleave: all 16 requests answered on one conn "
       f"(got {len(res)})")
    ka_ok = sum(1 for (s, _b) in res if s in (200, 201, 204))
    return ka_ok


def _rt12_segment_08(ka_ok, apath, TAG, bpath, st_uid):
    ok(ka_ok == 16, f"keep-alive interleave: every PUT accepted (2xx={ka_ok}/16)")
    a_mis = b_mis = 0
    for i in range(8):
        ap, bp = apath(f"{TAG}ka_a_{i}.txt"), bpath(f"{TAG}ka_b_{i}.txt")
        if not (os.path.exists(ap) and st_uid(ap) == UID_ALICE):
            a_mis += 1
        if not (os.path.exists(bp) and st_uid(bp) == UID_BOB):
            b_mis += 1
    ok(a_mis == 0, f"keep-alive: all 8 alice files owned alice, none stale-principal "
       f"(mismatch={a_mis})")
    ok(b_mis == 0, f"keep-alive: all 8 bob files owned bob, none stale-principal "
       f"(mismatch={b_mis})")


def _rt12_no_alice_file_leaked_into_bob(bpath, TAG, apath):
    # no alice file leaked into bob's dir or vice-versa (path landed under wrong owner)
    cross = 0
    for i in range(8):
        if os.path.exists(bpath(f"{TAG}ka_a_{i}.txt")):
            cross += 1
        if os.path.exists(apath(f"{TAG}ka_b_{i}.txt")):
            cross += 1
    ok(cross == 0, f"keep-alive: no request landed in the other tenant's dir (cross={cross})")

    # ============================================================================
    # B) BURST ORDERING — aaaa...bbbb...aaaa on one connection (run of same identity
    #    then a flip).  A flip without re-establishing the principal would write the
    #    first post-flip request under the previous identity.
    # ============================================================================
    burst = []
    order = (["a"] * 5) + (["b"] * 5) + (["a"] * 5) + (["b"] * 5)
    return burst, order


def _rt12_segment_01_2(who, data, TAG, i, st_uid, flip_bad):
    want = UID_ALICE if who == "a" else UID_BOB
    d = "alice" if who == "a" else "bob"
    fp = os.path.join(data, d, f"{TAG}burst_{i}.txt")
    if not (os.path.exists(fp) and st_uid(fp) == want):
        flip_bad += 1
    return flip_bad


def _rt12_for_each_i_who_enumerate_order(who, data, TAG, i, st_uid, flip_bad):
    flip_bad = _rt12_segment_01_2(who, data, TAG, i, st_uid, flip_bad)

    return flip_bad


def _rt12_segment_01_3(who, burst, TAG, i, ta, tb):
    if who == "a":
        burst.append(("PUT", f"/alice/{TAG}burst_{i}.txt", ta, b"a\n", None))
    else:
        burst.append(("PUT", f"/bob/{TAG}burst_{i}.txt", tb, b"b\n", None))


def _rt12_for_each_i_who_enumerate_order_2(who, burst, ta, tb, TAG, i):
    _rt12_segment_01_3(who, burst, TAG, i, ta, tb)



def _rt12_check_for_each_i_who_enumerate_order(order, burst, ta, tb, TAG):
    for i, who in enumerate(order):
        _rt12_for_each_i_who_enumerate_order_2(who, burst, ta, tb, TAG, i)


def _rt12_segment_10(order, burst, TAG, ta, tb, port, data, st_uid):
    _rt12_check_for_each_i_who_enumerate_order(order, burst, ta, tb, TAG)
    bres = http_keepalive(burst, port)
    ok(sum(1 for (s, _b) in bres if s in (200, 201, 204)) == 20,
       f"burst-order: all 20 PUTs accepted ({sum(1 for (s,_b) in bres if s in (200,201,204))}/20)")
    flip_bad = 0
    for i, who in enumerate(order):
        flip_bad = _rt12_for_each_i_who_enumerate_order(who, data, TAG, i, st_uid, flip_bad)
    return flip_bad


def _rt12_c_pipelined_puts_same_path_alternating(flip_bad, TAG, ta, tb, port):
    ok(flip_bad == 0, f"burst-order: every post-flip request used the CORRECT principal "
       f"(no stale carry-over; bad={flip_bad})")

    # ============================================================================
    # C) PIPELINED PUTs same path, alternating identities — last writer wins but the
    #    file must end up owned by WHOEVER actually wrote it, never svc/root, and the
    #    body must match an identity that was allowed to write (alice owns alice/).
    # ============================================================================
    shared = f"{TAG}pipe_shared.txt"
    pipe = []
    for i in range(6):
        tok = ta if i % 2 == 0 else tb
        body = b"alice-wins\n" if i % 2 == 0 else b"bob-attempt\n"
        # both target /alice/<shared>: alice writes succeed, bob writes must be denied
        pipe.append(("PUT", f"/alice/{shared}", tok, body, None))
    http_keepalive(pipe, port)
    return shared


def _rt12_alice_s_dir_is_0755_alice(apath, shared, st_uid):
    sp = apath(shared)
    # alice's dir is 0755 alice-owned: bob (other) cannot create/replace here.
    final_uid = st_uid(sp)
    ok(all((os.path.exists(sp), final_uid == UID_ALICE)),
       f"pipelined same-path: final file owned alice, never bob/svc/root (uid={final_uid})")
    try:
        fb = open(sp, "rb").read()
    except OSError:
        fb = b""
    ok(b"bob-attempt" not in fb,
       "pipelined same-path: bob's interleaved write did NOT overwrite alice's file body")


def _rt12_d_simultaneous_same_path_create_by(TAG, data, rm_quiet):

    # ============================================================================
    # D) SIMULTANEOUS SAME-PATH CREATE by alice & bob (true threads) into a world-
    #    writable shared dir.  Whoever wins, the file must be owned by a REAL mapped
    #    user (1001 or 1002) — never svc/root — and must not be a torn mix.
    # ============================================================================
    pub_shared = f"{TAG}pub_race.txt"
    pp = os.path.join(data, "pub", pub_shared)
    rm_quiet(pp)
    race_status = {}
    return pub_shared, pp, race_status


def _rt12_segment_14(ta, tb, pub_shared, port, race_status):

    def create_pub(who):
        tok = ta if who == "alice" else tb
        s, _b = http("PUT", f"/pub/{pub_shared}", port, tok,
                     (who + "-pub\n").encode())
        race_status[who] = s
    return create_pub


def _rt12_segment_15(rm_quiet, pp, create_pub, st_uid):

    for _round in range(6):       # repeat to widen the race window
        rm_quiet(pp)
        ths = [threading.Thread(target=create_pub, args=(w,))
               for w in ("alice", "bob", "alice", "bob")]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
    winner = st_uid(pp)
    ok(all((os.path.exists(pp), winner in (UID_ALICE, UID_BOB))),
       f"same-path race in /pub: winner is a real mapped user, not svc/root "
       f"(uid={winner})")
    ok(all((winner != UID_SVC, winner != 0)),
       f"same-path race: created file NEVER owned by worker(1500)/root(0) (uid={winner})")
    rm_quiet(pp)


def _rt12_e_open_as_a_then_immediately(TAG, port, ta, apath):

    # ============================================================================
    # E) OPEN-AS-A then immediately OP-AS-B referencing A's just-created private file.
    #    alice creates a 0600 file; bob (driving on the SAME worker right after) must
    #    NOT be able to read it (no principal carry-over from the create).
    # ============================================================================
    SECRET = b"ALICE-OPEN-RACE-MARKER-7731\n"
    arace = f"{TAG}open_race.txt"
    http("PUT", f"/alice/{arace}", port, ta, SECRET)
    fp = apath(arace)
    try:
        os.chmod(fp, 0o600)
    except OSError:
        pass
    return SECRET, arace, fp


def _rt12_bob_immediately_reads_it_via_keep(fp, st_uid, arace, ta, tb, port):
    ok(all((os.path.exists(fp), st_uid(fp) == UID_ALICE, os.lstat(fp).st_mode & 63 == 0)),
       f"open-race setup: alice's 0600 marker file in place (uid={st_uid(fp)})")
    # bob immediately reads it via keep-alive right after an alice op on the same conn
    seq = [("GET", f"/alice/{arace}", ta, None, None),   # alice reads own (control)
           ("GET", f"/alice/{arace}", tb, None, None)]   # bob reads alice's 0600 (deny)
    sres = http_keepalive(seq, port)
    a_st, a_body = sres[0] if len(sres) > 0 else (-1, b"")
    b_st, b_body = sres[1] if len(sres) > 1 else (-1, b"")
    return a_st, a_body, b_st, b_body


def _rt12_f_many_concurrent_collection_copys_true(a_st, SECRET, a_body, b_st, b_body, ta, tb, TAG, port):
    ok(all((a_st == 200, SECRET in any((a_body, b'')))),
       f"control: alice reads her own 0600 file on the shared conn (HTTP {a_st})")
    ok(all((b_st in (401, 403, 404), SECRET not in any((b_body, b'')))),
       f"open-race: bob CANNOT read alice's 0600 file via principal carry-over "
       f"(HTTP {b_st})")

    # ============================================================================
    # F) MANY CONCURRENT COLLECTION COPYs (true threads).  COPY of a collection runs
    #    inline (recursive walk + per-child create) — a long op that holds the
    #    principal; many in flight stress for desync.  Each alice COPY's destination
    #    tree must be wholly alice-owned; bob's must be bob-owned; broker must not wedge.
    # ============================================================================
    # seed a small collection for each user
    for who, tok, d in (("alice", ta, "alice"), ("bob", tb, "bob")):
        http("MKCOL", f"/{d}/{TAG}coll_src", port, tok)
        for j in range(3):
            http("PUT", f"/{d}/{TAG}coll_src/f{j}.txt", port, tok,
                 (who + f"-{j}\n").encode())
    copy_bad = []
    return copy_bad


def _rt12_segment_19(ta, tb, TAG, port, copy_bad):

    def coll_copy(idx):
        who = "alice" if idx % 2 == 0 else "bob"
        tok = ta if who == "alice" else tb
        d = who
        dst = f"/{d}/{TAG}coll_dst_{idx}"
        s, _b = http("COPY", f"/{d}/{TAG}coll_src", port, tok,
                     hdrs={"Destination": f"http://{HOST}:{port}{dst}",
                           "Depth": "infinity"})
        if s not in (200, 201, 204, 207):
            copy_bad.append((who, idx, s))
    return coll_copy


def _rt12_check_for_each_t_cths(cths):
    for t in cths:
        t.start()


def _rt12_every_copied_tree_must_be_owned(coll_copy, copy_bad):

    cths = [threading.Thread(target=coll_copy, args=(i,)) for i in range(12)]
    _rt12_check_for_each_t_cths(cths)
    for t in cths:
        t.join()
    ok(all((len(copy_bad) <= 12, all((b[2] not in (-1,) for b in copy_bad)))),
       f"concurrent collection COPY: no broker hang/connection-death "
       f"(failures={copy_bad[:3]})")
    # every copied tree must be owned by the DRIVING user only (no desync cross-owner)
    coll_mis = 0
    return coll_mis


def _rt12_segment_01_5(dirs, files, root_, st_uid, want, coll_seen, coll_mis):
    for name in list(dirs) + list(files):
        pth = os.path.join(root_, name)
        u = st_uid(pth)
        coll_seen += 1
        if u != want:
            coll_mis += 1
    return coll_seen, coll_mis


def _rt12_for_each_root_dirs_files_os_walk_dstdir(dirs, files, root_, st_uid, want, coll_seen, coll_mis):
    coll_seen, coll_mis = _rt12_segment_01_5(dirs, files, root_, st_uid, want, coll_seen, coll_mis)

    return coll_seen, coll_mis


def _rt12_broker_survives_a_follow_up_legit(data, TAG, st_uid, coll_mis, port, ta):
    coll_seen = 0
    for idx in range(12):
        who = "alice" if idx % 2 == 0 else "bob"
        want = UID_ALICE if who == "alice" else UID_BOB
        dstdir = os.path.join(data, who, f"{TAG}coll_dst_{idx}")
        if not os.path.isdir(dstdir):
            continue
        for root_, dirs, files in os.walk(dstdir):
            coll_seen, coll_mis = _rt12_for_each_root_dirs_files_os_walk_dstdir(dirs, files, root_, st_uid, want, coll_seen, coll_mis)
    ok(coll_seen > 0, f"concurrent COPY: at least one destination tree materialised "
       f"(entries seen={coll_seen})")
    ok(coll_mis == 0, f"concurrent COPY: every copied entry owned by the DRIVING user "
       f"(no broker principal desync; cross-owner={coll_mis})")
    # broker survives: a follow-up legit op still works after the COPY storm
    st, _ = http("PUT", f"/alice/{TAG}post_copy.txt", port, ta, b"survived\n")
    return st


def _rt12_g_lock_token_theft_race_alice(apath, TAG, st, st_uid, port, ta):
    pcp = apath(f"{TAG}post_copy.txt")
    ok(all((st in (200, 201, 204), os.path.exists(pcp), st_uid(pcp) == UID_ALICE)),
       f"broker SURVIVES the COPY storm: follow-up alice PUT owned alice (HTTP {st})")

    # ============================================================================
    # G) LOCK-TOKEN THEFT RACE — alice LOCKs her file; bob (concurrently, same worker)
    #    tries to mutate it presenting alice's lock token in If:.  The lock token is
    #    NOT an authorization grant — bob is still "other" on alice's 0644 file and the
    #    broker must deny his write.
    # ============================================================================
    lk = f"{TAG}lock_target.txt"
    http("PUT", f"/alice/{lk}", port, ta, b"lock-race-body\n")
    try:
        os.chmod(apath(lk), 0o644)
    except OSError:
        pass
    return lk


def _rt12_segment_23(lk, port, ta):
    li = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
          b'<D:lockscope><D:exclusive/></D:lockscope>'
          b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    lst, lbody = http("LOCK", f"/alice/{lk}", port, ta, data=li,
                      hdrs={"Content-Type": "application/xml", "Timeout": "Second-600"})
    m = re.search(rb"<[^>]*locktoken[^>]*>\s*<[^>]*href[^>]*>\s*([^<\s]+)",
                  lbody or b"", re.I)
    if not m:
        m = re.search(rb"(urn:uuid:[0-9a-fA-F-]+|opaquelocktoken:[^<\s]+)", lbody or b"")
    token_uri = m.group(1).decode() if m else "urn:uuid:00000000-0000-0000-0000-000000000000"
    return lst, token_uri


def _rt12_bob_replays_alice_s_stolen_lock(lst, lk, port, tb, token_uri, apath):
    ok(lst in (200, 201), f"lock-token theft setup: alice LOCK acquired (HTTP {lst})")
    # bob replays alice's stolen lock token to PUT over her file
    bst, _ = http("PUT", f"/alice/{lk}", port, tb, b"BOB-STOLE-LOCK\n",
                  hdrs={"If": f"(<{token_uri}>)"})
    body_now = b""
    try:
        body_now = open(apath(lk), "rb").read()
    except OSError:
        pass
    ok(all((bst not in (200, 201, 204), b'BOB-STOLE-LOCK' not in body_now)),
       f"lock-token theft: bob replaying alice's lock token did NOT overwrite her file "
       f"(HTTP {bst})")


def _rt12_control_alice_with_her_own_lock(st_uid, apath, lk, port, ta, token_uri, s3port, TAG, data, rm_quiet):
    ok(st_uid(apath(lk)) == UID_ALICE,
       "lock-token theft: alice's locked file remained alice-owned")
    # control: alice WITH her own lock token can still write her own file
    ast, _ = http("PUT", f"/alice/{lk}", port, ta, b"alice-rewrite\n",
                  hdrs={"If": f"(<{token_uri}>)"})
    ok(ast in (200, 201, 204),
       f"control: alice with her own lock token writes her own file (HTTP {ast})")

    # ============================================================================
    # H) MULTIPART CROSS-IDENTITY DRIVE (S3) — alice initiates an uploadId, bob drives
    #    the part/complete with a BOB-signed request.  Parts + final object must map by
    #    the DRIVING identity (the key lives under alice/, where bob is denied): bob
    #    must NOT be able to complete an alice-initiated upload into alice's space.
    # ============================================================================
    if s3port:
        mk = f"alice/{TAG}mpu_cross.bin"
        st_i, ibody = s3("POST", mk, s3port, params={"uploads": ""}, access_key="alice")
        um = re.search(rb"<UploadId>([^<]+)</UploadId>", ibody or b"")
        ok(all((st_i == 200, um is not None)),
           f"multipart cross-identity setup: alice initiated uploadId (HTTP {st_i})")
        if um:
            upid = um.group(1).decode()
            # bob signs the part upload (only access_key 'alice' is configured, so a
            # bob-signed request is also an INVALID signature -> must be rejected).
            st_pb, _ = s3("PUT", mk, s3port,
                          params={"uploadId": upid, "partNumber": "1"},
                          data=b"Q" * 4096, access_key="bob")
            ok(st_pb not in (200, 201, 204),
               f"multipart cross-identity: bob-signed UploadPart REJECTED (HTTP {st_pb})")
            # alice legitimately uploads + completes (control: the upload still works)
            st_pa, pbody = s3("PUT", mk, s3port,
                              params={"uploadId": upid, "partNumber": "1"},
                              data=b"Q" * 4096, access_key="alice")
            et = re.search(rb'ETag>\\?"?([^"<\\]+)', pbody or b"")
            etag = et.group(1).decode() if et else "etag"
            comp = (f"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                    f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>").encode()
            st_cb, _ = s3("POST", mk, s3port, params={"uploadId": upid},
                          data=comp, access_key="bob")
            ok(st_cb not in (200, 201),
               f"multipart cross-identity: bob-signed Complete REJECTED (HTTP {st_cb})")
            st_ca, _ = s3("POST", mk, s3port, params={"uploadId": upid},
                          data=comp, access_key="alice")
            mfp = os.path.join(data, mk)
            muid = st_uid(mfp)
            ok(all((st_ca in (200, 201), os.path.exists(mfp), muid == UID_ALICE)),
               f"control: alice completes her OWN upload, object owned alice "
               f"(HTTP {st_ca}, uid={muid})")
            rm_quiet(mfp)
    else:
        ok(True, "S3 multipart cross-identity skipped (S3 port not up)")

    # ============================================================================
    # I) CONCURRENT MIXED PROTOCOL/OP STORM (true threads) with embedded cross-tenant
    #    attacks — alice PUT, bob PUT, alice MKCOL, bob DELETE-own, alice->bob PUT
    #    (deny), bob->alice MKCOL (deny).  Hunts a race window where a leaked principal
    #    lets a cross-tenant op slip through.
    # ============================================================================
    storm_bad = []
    return storm_bad


def _rt12_segment_26():
    NSTORM = 36
    return NSTORM


def _rt12_segment_01_6(TAG, port, ta, bpath, storm_bad):
    s, _b = http("PUT", f"/bob/{TAG}st_x_{i}.txt", port, ta, b"X\n")
    xp = bpath(f"{TAG}st_x_{i}.txt")
    if s in (200, 201, 204) or os.path.exists(xp):
        storm_bad.append(("a->b-put", i, s))
    return s


def _rt12_when_kind_4(port, ta, TAG, bpath, storm_bad):
    s = _rt12_segment_01_6(TAG, port, ta, bpath, storm_bad)

    return s


def _rt12_segment_01_4(TAG, port, ta, tb, bpath, storm_bad, apath):
    kind = i % 6
    if kind == 0:
        http("PUT", f"/alice/{TAG}st_a_{i}.txt", port, ta, b"a\n")
    elif kind == 1:
        http("PUT", f"/bob/{TAG}st_b_{i}.txt", port, tb, b"b\n")
    elif kind == 2:
        http("MKCOL", f"/alice/{TAG}st_dir_{i}", port, ta)
    elif kind == 3:
        http("PUT", f"/bob/{TAG}st_bd_{i}.txt", port, tb, b"d\n")
        http("DELETE", f"/bob/{TAG}st_bd_{i}.txt", port, tb)
    elif kind == 4:                                   # alice -> bob (deny)
        s = _rt12_when_kind_4(port, ta, TAG, bpath, storm_bad)
    else:                                             # bob -> alice (deny)
        s, _b = http("MKCOL", f"/alice/{TAG}st_y_{i}", port, tb)
        yp = apath(f"{TAG}st_y_{i}")
        if s in (200, 201) or os.path.isdir(yp):
            storm_bad.append(("b->a-mkcol", i, s))


def _rt12_try_body(port, ta, tb, TAG, bpath, apath, storm_bad):
    _rt12_segment_01_4(TAG, port, ta, tb, bpath, storm_bad, apath)



def _rt12_segment_27(TAG, port, ta, tb, bpath, storm_bad, apath):

    def storm(i):
        try:
            _rt12_try_body(port, ta, tb, TAG, bpath, apath, storm_bad)
        except Exception as e:  # noqa: BLE001
            storm_bad.append(("exc", i, repr(e)))
    return storm


def _rt12_j_post_storm_global_ownership_scan(NSTORM, storm, storm_bad, scan_misowned):

    sths = [threading.Thread(target=storm, args=(i,)) for i in range(NSTORM)]
    for t in sths:
        t.start()
    for t in sths:
        t.join()
    ok(not storm_bad,
       f"mixed protocol/op storm: no cross-tenant op slipped through a race window "
       f"(breaches={storm_bad[:4]})")

    # ============================================================================
    # J) POST-STORM GLOBAL OWNERSHIP SCAN — after EVERY storm above, scan both user
    #    dirs and assert zero wrong-owner regular files (the decisive principal-leak
    #    detector: a single svc/root/cross-tenant owned data file fails the battery).
    # ============================================================================
    misowned = scan_misowned()
    return misowned


def _rt12_explicit_svc_root_sweep_across_pub(misowned, data, TAG, ta, tb):
    ok(not misowned,
       f"post-storm scan: zero wrong-owner regular files in alice/ + bob/ "
       f"(leaks={misowned[:4]})")
    # explicit svc/root sweep across pub/ too (created files there must be 1001/1002)
    pub_bad = []
    try:
        for f in os.listdir(os.path.join(data, "pub")):
            pth = os.path.join(data, "pub", f)
            stx = os.lstat(pth)
            if (stx.st_mode & 0o170000) == 0o100000 and stx.st_uid in (UID_SVC, 0) \
                    and not _is_server_sidecar(f):   # .cinfo/.meta svc-owned by design
                pub_bad.append((f, stx.st_uid))
    except OSError:
        pass
    ok(not pub_bad,
       f"post-storm scan: no svc/root-owned file in the shared /pub dir (leaks={pub_bad[:4]})")

    # ============================================================================
    # K) FINAL LIVENESS — after all the storms, both identities still work correctly
    #    and independently on a fresh keep-alive connection (broker not wedged, no
    #    sticky principal left behind by the last op).
    # ============================================================================
    fin = [("PUT", f"/alice/{TAG}final_a.txt", ta, b"final-a\n", None),
           ("PUT", f"/bob/{TAG}final_b.txt", tb, b"final-b\n", None),
           ("GET", f"/alice/{TAG}final_a.txt", ta, None, None),
           ("GET", f"/bob/{TAG}final_b.txt", tb, None, None)]
    return fin


def _rt12_segment_30(fin, port, apath, TAG, bpath, st_uid):
    fres = http_keepalive(fin, port)
    fa, fb_ = apath(f"{TAG}final_a.txt"), bpath(f"{TAG}final_b.txt")
    ok(all((len(fres) == 4, fres[0][0] in (200, 201, 204), fres[1][0] in (200, 201, 204))),
       f"final liveness: both identities still write after all storms "
       f"(a={fres[0][0] if fres else '?'}, b={fres[1][0] if len(fres) > 1 else '?'})")
    ok(all((os.path.exists(fa), st_uid(fa) == UID_ALICE)),
       "final liveness: alice's last file owned alice (no sticky principal)")
    ok(all((os.path.exists(fb_), st_uid(fb_) == UID_BOB)),
       "final liveness: bob's last file owned bob (no sticky principal)")
    return fres


def _rt12_segment_31(fres):
    ok(all((len(fres) == 4, fres[2][0] == 200, b'final-a' in any((fres[2][1], b'')))),
       "final liveness: alice reads her own final file back")
    ok(all((len(fres) == 4, fres[3][0] == 200, b'final-b' in any((fres[3][1], b'')))),
       "final liveness: bob reads his own final file back")


def run_concurrency_state_race(key, data, port, s3port):
    """CONCURRENCY / ORDERING / STATE-CONFUSION races against the per-worker, process-
    global impersonation principal.  Every storm below tries to make an op execute
    under a STALE or LEAKED principal (alice's setfsuid bleeding into bob's request or
    vice-versa), then proves it did not by: (a) the op landing in the correct owner's
    space, (b) the created/mutated file's st_uid matching the DRIVING identity (never
    the worker svc=1500, never root=0, never the other tenant), (c) the worker
    SURVIVING (a follow-up legit op still works), and (d) a full os.lstat scan of both
    user dirs finding zero wrong-owner regular files after the storm.  Each deny carries
    a nearby positive control so a blanket block cannot false-pass."""
    ta, tb, TAG = _rt12_segment_01(key)

    st_uid = _rt12_segment_02()

    apath = _rt12_segment_03(data)

    bpath = _rt12_segment_04(data)

    rm_quiet = _rt12_segment_05()

    scan_misowned = _rt12_segment_06(data, TAG)

    ka_ok = _rt12_a_keep_alive_interleave_a_b(TAG, ta, tb, port)

    _rt12_segment_08(ka_ok, apath, TAG, bpath, st_uid)

    burst, order = _rt12_no_alice_file_leaked_into_bob(bpath, TAG, apath)

    flip_bad = _rt12_segment_10(order, burst, TAG, ta, tb, port, data, st_uid)

    shared = _rt12_c_pipelined_puts_same_path_alternating(flip_bad, TAG, ta, tb, port)

    _rt12_alice_s_dir_is_0755_alice(apath, shared, st_uid)

    pub_shared, pp, race_status = _rt12_d_simultaneous_same_path_create_by(TAG, data, rm_quiet)

    create_pub = _rt12_segment_14(ta, tb, pub_shared, port, race_status)

    _rt12_segment_15(rm_quiet, pp, create_pub, st_uid)

    SECRET, arace, fp = _rt12_e_open_as_a_then_immediately(TAG, port, ta, apath)

    a_st, a_body, b_st, b_body = _rt12_bob_immediately_reads_it_via_keep(fp, st_uid, arace, ta, tb, port)

    copy_bad = _rt12_f_many_concurrent_collection_copys_true(a_st, SECRET, a_body, b_st, b_body, ta, tb, TAG, port)

    coll_copy = _rt12_segment_19(ta, tb, TAG, port, copy_bad)

    coll_mis = _rt12_every_copied_tree_must_be_owned(coll_copy, copy_bad)

    st = _rt12_broker_survives_a_follow_up_legit(data, TAG, st_uid, coll_mis, port, ta)

    lk = _rt12_g_lock_token_theft_race_alice(apath, TAG, st, st_uid, port, ta)

    lst, token_uri = _rt12_segment_23(lk, port, ta)

    _rt12_bob_replays_alice_s_stolen_lock(lst, lk, port, tb, token_uri, apath)

    storm_bad = _rt12_control_alice_with_her_own_lock(st_uid, apath, lk, port, ta, token_uri, s3port, TAG, data, rm_quiet)

    NSTORM = _rt12_segment_26()

    storm = _rt12_segment_27(TAG, port, ta, tb, bpath, storm_bad, apath)

    misowned = _rt12_j_post_storm_global_ownership_scan(NSTORM, storm, storm_bad, scan_misowned)

    fin = _rt12_explicit_svc_root_sweep_across_pub(misowned, data, TAG, ta, tb)

    fres = _rt12_segment_30(fin, port, apath, TAG, bpath, st_uid)

    _rt12_segment_31(fres)

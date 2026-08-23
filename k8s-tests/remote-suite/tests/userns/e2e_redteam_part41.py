def _rt41_segment_01(key, data):
    T = "cbp_"                                   # tag prefixes every fixture/file
    ta = mint(key, "alice")
    tc = mint(key, "carol")
    adir = os.path.join(data, "alice")
    pubdir = os.path.join(data, "pub")           # svc:svc 0777 — only idmap stops writes
    return T, ta, tc, adir, pubdir


def _rt41_the_principals_the_broker_must_refuse(key):
    GR = "/grp"
    SR = b"STAFF-GROUP-READABLE"                  # body of grp/staff_r.txt (0640 alice:staff)
    BOB_SECRET = b"BOB-PRIVATE-SECRET"            # bob/private.txt 0600 — must never leak

    # The principals the BROKER must refuse to map (each holds a VALID write-scoped
    # token, so authz passes; only the idmap guard may stop them).
    DENIED = ["mallory", "lowu", "badprim", "dockerite", "root", "svc", "sys100"]
    DENIED_TOK = {s: mint(key, s) for s in DENIED}
    return GR, SR, BOB_SECRET, DENIED, DENIED_TOK


def _rt41_segment_03():

    def _has(body, needle):
        return needle in (body or b"")
    return _has


def _rt41_recovery_probe_a_legit_alice_put(T, port, ta, adir):

    # ---- recovery probe: a legit alice PUT+GET roundtrip proving the worker AND
    #      the single broker socket are still live & correctly-mapping ------------
    def recover(label, n=[0]):
        n[0] += 1
        rel = f"/alice/{T}rec_{n[0]}.txt"
        body = f"rec-{n[0]}-{label[:10]}".encode()
        stp, _ = http("PUT", rel, port, ta, body)
        stg, gb = http("GET", rel, port, ta)
        fp = os.path.join(adir, f"{T}rec_{n[0]}.txt")
        owned = os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE
        ok(all((stp in (200, 201, 204), stg == 200, gb == body, owned)),
           f"recovery after {label}: alice PUT+GET roundtrips, owned 1001, broker "
           f"not wedged by the deny storm (PUT {stp}, GET {stg})")
    return recover


def _rt41_0_plant_one_fifo_inside_alice(recover, adir, T, DENIED, DENIED_TOK, ta, port, pubdir):

    recover("baseline")

    # =====================================================================
    # 0) Plant ONE FIFO inside alice's tree.  Under the flood we will open it
    #    and prove the single broker does not block on it (O_NONBLOCK).
    # =====================================================================
    fifo = os.path.join(adir, f"{T}fifo")
    fifo_ok = False
    try:
        if not os.path.lexists(fifo):
            os.mkfifo(fifo, 0o600)
            os.chown(fifo, UID_ALICE, UID_ALICE)
        fifo_ok = True
    except OSError as e:
        ok(True, f"FIFO fixture skipped ({e.__class__.__name__})")

    # =====================================================================
    # A) PRINCIPAL-LEAK ACROSS THE PER-WORKER BOUNDARY, denied->legit, on ONE
    #    kept-alive connection.  A denied 'mallory' (unmapped) PUT must not
    #    leave the worker's process-global principal set to mallory/svc so the
    #    NEXT request (legit alice) runs as the wrong uid.  We pair each denied
    #    subject with an immediate alice op on the SAME socket.
    # =====================================================================
    for sub in DENIED:
        leg = f"/alice/{T}leak_{sub}.txt"
        seq = [
            ("PUT", f"/pub/{T}leak_src_{sub}.txt", DENIED_TOK[sub],
             f"{sub.upper()}-FLOOD\n".encode(), None),   # denied (idmap refuses)
            ("PUT", leg, ta, b"alice-after-deny\n", None),  # legit, MUST own 1001
            ("GET", leg, ta, None, None),
        ]
        res = http_keepalive(seq, port)
        # the denied src must not have been created in /pub (world-writable -> only
        # the idmap guard can stop it) nor created owned by a denied/reserved uid.
        srcp = os.path.join(pubdir, f"{T}leak_src_{sub}.txt")
        src_made = os.path.exists(srcp)
        src_uid = os.stat(srcp).st_uid if src_made else -1
        ok(all((res[0][0] not in (200, 201, 204), not src_made)),
           f"denied '{sub}' PUT refused on shared conn, no /pub file "
           f"(HTTP {res[0][0]}, made={src_made})")
        ok(any((not src_made, src_uid >= 1000)),
           f"denied '{sub}' left no reserved-owned residue in /pub (uid={src_uid})")
        # the FOLLOW-UP alice op on the SAME worker connection must own as ALICE,
        # never as the just-denied principal nor as the svc worker (1500).
        fp = os.path.join(adir, f"{T}leak_{sub}.txt")
        a_made = os.path.exists(fp)
        a_uid = os.stat(fp).st_uid if a_made else -1
        ok(all((res[1][0] in (200, 201, 204), a_made, a_uid == UID_ALICE)),
           f"after denied '{sub}', next alice op on same conn owns 1001 "
           f"(not leaked principal/svc) (HTTP {res[1][0]}, uid={a_uid})")
        ok(all((a_uid != UID_SVC, a_uid != 0)),
           f"after denied '{sub}', follow-up file not svc(1500)/root-owned (uid={a_uid})")
        ok(all((res[2][0] == 200, res[2][1] == b'alice-after-deny\n')),
           f"after denied '{sub}', alice reads back her OWN bytes, not crossed "
           f"(HTTP {res[2][0]})")
    return fifo_ok


def _rt41_b_reverse_order_legit_alice_op(recover, T, ta, DENIED_TOK, port, pubdir):

    recover("denied->legit keepalive sweep")

    # =====================================================================
    # B) Reverse order: legit alice op THEN a denied op on the same conn — the
    #    denied op must still be refused (alice's good mapping must not "stick"
    #    and silently authorize the unmapped subject as alice).
    # =====================================================================
    for sub in ("mallory", "root", "svc"):
        seq = [
            ("PUT", f"/alice/{T}pre_{sub}.txt", ta, b"alice-first\n", None),
            ("PUT", f"/pub/{T}post_{sub}.txt", DENIED_TOK[sub],
             f"{sub.upper()}-RIDE\n".encode(), None),
        ]
        res = http_keepalive(seq, port)
        postp = os.path.join(pubdir, f"{T}post_{sub}.txt")
        post_made = os.path.exists(postp)
        post_uid = os.stat(postp).st_uid if post_made else -1
        ok(res[0][0] in (200, 201, 204),
           f"legit alice op precedes denied '{sub}' fine (HTTP {res[0][0]})")
        ok(all((res[1][0] not in (200, 201, 204), not post_made)),
           f"denied '{sub}' after a good alice op still REFUSED — good mapping "
           f"does not stick (HTTP {res[1][0]}, made={post_made})")
        ok(any((not post_made, all((post_uid >= 1000, post_uid != UID_ALICE)))),
           f"denied '{sub}' after alice left no alice/reserved-owned residue "
           f"(uid={post_uid})")

    recover("legit->denied keepalive sweep")

    # =====================================================================
    # C) THE STORM: <=8 threads.  Mix three job classes concurrently —
    #      (i)  broker-DENIED floods (unmapped/sub-floor/forbidden/escalation),
    #      (ii) LEGIT supplementary-group reads (carol reads the 0640 staff
    #           file — exercises setgroups under pressure),
    #      (iii)LEGIT owner writes (alice writes her own dir),
    #    plus a KNOWN-ANSWER channel-desync probe interleaved on its own.
    #    Assert no class starves the others and the broker channel never crosses
    #    a reply (carol never gets a wrong body/uid; alice files own 1001).
    # =====================================================================
    breaches = []          # security failures (created-as-denied / cross content)
    carol_results = []     # (status, leaked_secret_bool, got_staff_bool)
    return breaches, carol_results


def _rt41_segment_07():
    alice_owner_bad = []   # alice storm files that ended up wrong-owned
    fifo_times = []        # wall-time of FIFO opens under load (hang detector)
    return alice_owner_bad, fifo_times


def _rt41_segment_01_4(DENIED, T, port, DENIED_TOK, pubdir, breaches):
    sub = DENIED[i % len(DENIED)]
    rel = f"{T}storm_{sub}_{i}.txt"
    st, _ = http("PUT", f"/pub/{rel}", port, DENIED_TOK[sub],
                 f"{sub.upper()}-STORM-{i}\n".encode())
    fp = os.path.join(pubdir, rel)
    if st in (200, 201, 204) or os.path.exists(fp):
        breaches.append(("denied-created", sub, i, st))
    return rel, st, fp


def _rt41_when_kind_0(DENIED, T, port, DENIED_TOK, pubdir, breaches):
    rel, st, fp = _rt41_segment_01_4(DENIED, T, port, DENIED_TOK, pubdir, breaches)

    return rel, st, fp


def _rt41_segment_01_3(DENIED, T, port, DENIED_TOK, pubdir, breaches, GR, tc, carol_results, _has, BOB_SECRET, SR, ta, adir, alice_owner_bad, fifo_ok, fifo_times):
    if kind == 0:                              # (i) DENIED flood -> /pub
        rel, st, fp = _rt41_when_kind_0(DENIED, T, port, DENIED_TOK, pubdir, breaches)
    elif kind == 1:                            # (ii) carol group-DAC read
        st, b = http("GET", f"{GR}/staff_r.txt", port, tc)
        carol_results.append(
            (st, _has(b, BOB_SECRET), st == 200 and _has(b, SR)))
    elif kind == 2:                            # (iii) alice owner write
        rel = f"{T}storm_a_{i}.txt"
        st, _ = http("PUT", f"/alice/{rel}", port, ta,
                     f"a-storm-{i}\n".encode())
        fp = os.path.join(adir, rel)
        if os.path.exists(fp) and os.stat(fp).st_uid != UID_ALICE:
            alice_owner_bad.append((i, os.stat(fp).st_uid))
    else:                                      # FIFO open under load (O_NONBLOCK)
        if fifo_ok:
            t0 = time.time()
            http("GET", f"/alice/{T}fifo", port, ta)
            fifo_times.append(time.time() - t0)


def _rt41_try_body(DENIED, port, pubdir, T, DENIED_TOK, tc, fifo_ok, breaches, carol_results, ta, adir, GR, _has, BOB_SECRET, SR, alice_owner_bad, fifo_times):
    _rt41_segment_01_3(DENIED, T, port, DENIED_TOK, pubdir, breaches, GR, tc, carol_results, _has, BOB_SECRET, SR, ta, adir, alice_owner_bad, fifo_ok, fifo_times)



def _rt41_segment_08(DENIED, T, port, DENIED_TOK, pubdir, breaches, GR, tc, carol_results, _has, BOB_SECRET, SR, ta, adir, alice_owner_bad, fifo_ok, fifo_times):

    def job(i):
        kind = i % 4
        try:
            _rt41_try_body(DENIED, port, pubdir, T, DENIED_TOK, tc, fifo_ok, breaches, carol_results, ta, adir, GR, _has, BOB_SECRET, SR, alice_owner_bad, fifo_times)
        except Exception as e:  # noqa: BLE001
            breaches.append(("exc", i, repr(e)))
    return job


def _rt41_segment_01_2(threads, base):
    wave = threads[base:base + 8]
    for t in wave:
        t.start()
    for t in wave:
        t.join()


def _rt41_for_each_base_range_0_len_threads_8(threads, base):
    _rt41_segment_01_2(threads, base)



def _rt41_check_for_each_base_range_0_len_threads_8(threads):
    for base in range(0, len(threads), 8):
        _rt41_for_each_base_range_0_len_threads_8(threads, base)


def _rt41_cap_to_8_live_threads_at(job, breaches, carol_results):

    threads = [threading.Thread(target=job, args=(i,)) for i in range(24)]
    # cap to <=8 live threads at a time: run in waves of 8.
    _rt41_check_for_each_base_range_0_len_threads_8(threads)

    ok(not breaches,
       f"under denied-flood storm: no denied principal ever created a file / no "
       f"crash (breaches={breaches[:3]})")
    ok(all((carol_results, all((r[2] for r in carol_results)))),
       f"every interleaved carol group-DAC read SUCCEEDED under the storm — legit "
       f"op not starved by the deny flood ({len(carol_results)} reads)")
    ok(all((carol_results, not any((r[1] for r in carol_results)))),
       "no interleaved carol read leaked bob's private secret (no crossed reply)")


def _rt41_d_known_answer_desync_probe_serially(alice_owner_bad, fifo_ok, fifo_times, recover, DENIED, T, port, DENIED_TOK, GR, tc, _has, SR, BOB_SECRET):
    ok(not alice_owner_bad,
       f"every alice storm write owned 1001 under the flood — no principal cross "
       f"(bad={alice_owner_bad[:3]})")
    if fifo_ok:
        ok(all((fifo_times, all((t < 5.0 for t in fifo_times)))),
           f"FIFO open(s) UNDER the deny storm did not wedge the single broker "
           f"({len(fifo_times)} opens, max {max(fifo_times):.2f}s)")
    else:
        ok(True, "FIFO-under-storm skipped (no fifo fixture)")

    recover("concurrent deny storm")

    # =====================================================================
    # D) KNOWN-ANSWER DESYNC PROBE: serially fire a denied request immediately
    #    before a deterministic carol staff-read, repeated, and confirm carol
    #    ALWAYS gets the identical correct body — proving the broker's request
    #    queue never pairs carol's reply with the denied request's slot.
    # =====================================================================
    desync_bad = 0
    for i in range(10):
        sub = DENIED[i % len(DENIED)]
        # denied op first (drives a refused broker exchange)...
        http("PUT", f"/pub/{T}ka_{sub}_{i}.txt", port, DENIED_TOK[sub], b"ka\n")
        # ...then the known-answer carol read — must be byte-identical every time.
        st, b = http("GET", f"{GR}/staff_r.txt", port, tc)
        if not (st == 200 and _has(b, SR)) or _has(b, BOB_SECRET):
            desync_bad += 1
    return desync_bad


def _rt41_check_for_each_sub_mallory_lowu_badprim(pubdir, T, GR, SR, BOB_SECRET):
    for sub in ("mallory", "lowu", "badprim"):
        lf = os.path.join(WORK, f"{T}cp_{sub}.bin")
        try:
            with open(lf, "wb") as fh:
                fh.write(f"{sub}-stream\n".encode())
        except OSError:
            continue
        rc, _o, _e = xrd_cp_up(lf, f"/pub/{T}cp_{sub}.bin", sub)
        cpp = os.path.join(pubdir, f"{T}cp_{sub}.bin")
        made = os.path.exists(cpp)
        cuid = os.stat(cpp).st_uid if made else -1
        ok(all((rc != 0, not made)),
           f"root:// denied '{sub}' xrdcp DENIED, no /pub file (rc={rc})")
        ok(any((not made, cuid >= 1000)),
           f"root:// denied '{sub}' left no reserved residue (uid={cuid})")
        # immediately after the refused stream op, a legit carol group read.
        rc2, out, _e = xrd_fs(["cat", f"{GR}/staff_r.txt"], "carol")
        ok(all((rc2 == 0, SR.decode() in any((out, '')), BOB_SECRET.decode() not in any((out, '')))),
           f"root:// carol group read OK right after denied '{sub}' — no "
           f"stream-plane principal leak (rc={rc2})")
    return lf, fh, rc


def _rt41_immediately_after_the_refused_stream_op(T, pubdir, GR, SR, BOB_SECRET, adir):
    lf, fh, rc = _rt41_check_for_each_sub_mallory_lowu_badprim(pubdir, T, GR, SR, BOB_SECRET)
    # a denied stream op followed by a legit ALICE write that must own 1001.
    lf = os.path.join(WORK, f"{T}cp_alice.bin")
    try:
        with open(lf, "wb") as fh:
            fh.write(b"alice-stream-after-deny\n")
        rc, _o, _e = xrd_cp_up(lf, f"/alice/{T}cp_alice.bin", "alice")
        afp = os.path.join(adir, f"{T}cp_alice.bin")
        aok = os.path.exists(afp) and os.stat(afp).st_uid == UID_ALICE
        ok(all((rc == 0, aok)),
           f"root:// alice write after a denied stream op owns 1001 (rc={rc})")
    except OSError:
        ok(True, "root:// alice-after-deny stream fixture skipped (OSError)")


def _rt41_when_xrd_avail(pubdir, T, GR, SR, BOB_SECRET, adir):
    _rt41_immediately_after_the_refused_stream_op(T, pubdir, GR, SR, BOB_SECRET, adir)



def _rt41_interleave_a_denied_op_between_alice(desync_bad, DENIED, T, port, ta, DENIED_TOK, adir, pubdir, GR, SR, BOB_SECRET):
    ok(desync_bad == 0,
       f"known-answer carol read after each denied op stayed correct x10 — broker "
       f"reply pairing never desynced (mismatches={desync_bad})")

    # interleave a denied op between alice WRITE and alice READBACK and confirm the
    # readback returns alice's own freshly-written bytes (not a crossed/denied body).
    ka_bad = 0
    for i in range(8):
        sub = DENIED[i % len(DENIED)]
        rel = f"/alice/{T}kaw_{i}.txt"
        payload = f"alice-ka-{i}\n".encode()
        http("PUT", rel, port, ta, payload)
        http("PUT", f"/pub/{T}kaw_d_{i}.txt", port, DENIED_TOK[sub], b"d\n")
        st, b = http("GET", rel, port, ta)
        fp = os.path.join(adir, f"{T}kaw_{i}.txt")
        if not (st == 200 and b == payload) or \
           not (os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE):
            ka_bad += 1
    ok(ka_bad == 0,
       f"denied op sandwiched in alice write->read never crossed content/owner "
       f"x8 (mismatches={ka_bad})")

    # =====================================================================
    # E) Cross-PROTOCOL pressure: drive the SAME deny/legit interleave over the
    #    root:// stream plane (different code path to the SAME broker).  A denied
    #    'mallory'/'lowu' write must fail and leave no file; an immediately
    #    following legit carol group read must still succeed & own correctly.
    # =====================================================================
    if xrd_avail():
        _rt41_when_xrd_avail(pubdir, T, GR, SR, BOB_SECRET, adir)


def _rt41_f_final_ownership_scan_of_the(pubdir, T, GR, port, tc, _has, SR):

    # =====================================================================
    # F) FINAL ownership SCAN of the world-writable /pub dir: across this whole
    #    storm NO file we tagged may exist owned by svc(1500)/root(0)/a denied
    #    sub-floor uid.  /pub is 0777 so the FS never blocks a write — every
    #    cbp_ file here would be a true idmap-guard breach.
    # =====================================================================
    residue = []
    try:
        for f in os.listdir(pubdir):
            if not f.startswith(T):
                continue
            p = os.path.join(pubdir, f)
            try:
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                u = os.lstat(p).st_uid
            except OSError:
                continue
            residue.append((f, u))
    except OSError:
        pass
    ok(not residue,
       f"NO cbp_ file in world-writable /pub survived the deny storm — every "
       f"denied mapping was refused at the broker (residue={residue[:4]})")

    # and the canonical secrets were never disturbed/served: alice's staff file is
    # still exactly readable by carol (group) and bob's private file still hidden.
    st, b = http("GET", f"{GR}/staff_r.txt", port, tc)
    ok(all((st == 200, _has(b, SR))),
       f"post-storm: carol still reads the 0640 staff file via group DAC (HTTP {st})")


def _rt41_g_fifo_open_after_the_storm(port, ta, _has, BOB_SECRET, fifo_ok, T, recover):
    st, b = http("GET", "/bob/private.txt", port, ta)
    ok(all((st != 200, not _has(b, BOB_SECRET))),
       f"post-storm: alice still denied bob's 0600 private file, no leak (HTTP {st})")

    # =====================================================================
    # G) FIFO open AFTER the storm settles — confirm the single broker is not
    #    left wedged by any half-completed open during the flood.
    # =====================================================================
    if fifo_ok:
        t0 = time.time()
        st, _ = http("GET", f"/alice/{T}fifo", port, ta)
        dt_fifo = time.time() - t0
        ok(dt_fifo < 5.0,
           f"post-storm FIFO open did not hang the broker ({dt_fifo:.2f}s, HTTP {st})")
        t0 = time.time()
        st, _ = http("PUT", f"/alice/{T}fifo", port, ta, b"x" * 64)
        ok(time.time() - t0 < 5.0,
           f"post-storm FIFO PUT did not hang the broker (HTTP {st})")

    # final two roundtrips prove the worker AND broker fully survived everything.
    recover("full storm complete")
    recover("final sanity")


def run_combo_broker_pressure(key, data, port, s3port):
    """COMBINATION frontier: broker BACK-PRESSURE crossed with legitimate ops.

    Resource limits, FIFO-hang, group-DAC, principal-leak and broker-desync have
    each been probed ALONE.  Here we INTERLEAVE a stream of broker-DENIED mapping
    requests (unmapped 'mallory', sub-floor 'lowu', reserved-primary 'badprim',
    forbidden-group 'dockerite', escalation 'root'/'svc'/'sys100', plus opens of a
    planted FIFO) WITH legitimate supplementary-group ops (carol reads the 0640
    staff file, alice writes her own dir) under MODEST concurrency (<=8 threads),
    and assert the union holds:
      * every legit op still SUCCEEDS correctly (the denied flood does not starve /
        wedge it) and owns/reads as the RIGHT identity;
      * the broker request/reply channel never DESYNCS — a known-answer carol read
        interleaved into the storm returns the SAME correct answer every time (a
        crossed reply would hand carol a wrong principal or a wrong body);
      * NO principal leaks across the per-worker boundary — a denied 'mallory'
        request on a kept-alive connection must NOT let the very next request act as
        mallory or as the svc worker (the follow-up alice op owns 1001, never 1500/
        mallory/<denied-uid>);
      * a FIFO open UNDER the flood does not wedge the single broker (O_NONBLOCK);
      * after the storm a final legit alice PUT+GET roundtrips and a full ownership
        scan of the world-writable /pub dir finds zero svc/root/denied-uid residue.
    Does NOT kill the broker (run_broker_failclosed owns that) and never sends MB or
    spawns dozens of threads (host-OOM guard)."""
    T, ta, tc, adir, pubdir = _rt41_segment_01(key, data)

    GR, SR, BOB_SECRET, DENIED, DENIED_TOK = _rt41_the_principals_the_broker_must_refuse(key)

    _has = _rt41_segment_03()

    recover = _rt41_recovery_probe_a_legit_alice_put(T, port, ta, adir)

    fifo_ok = _rt41_0_plant_one_fifo_inside_alice(recover, adir, T, DENIED, DENIED_TOK, ta, port, pubdir)

    breaches, carol_results = _rt41_b_reverse_order_legit_alice_op(recover, T, ta, DENIED_TOK, port, pubdir)

    alice_owner_bad, fifo_times = _rt41_segment_07()

    job = _rt41_segment_08(DENIED, T, port, DENIED_TOK, pubdir, breaches, GR, tc, carol_results, _has, BOB_SECRET, SR, ta, adir, alice_owner_bad, fifo_ok, fifo_times)

    _rt41_cap_to_8_live_threads_at(job, breaches, carol_results)

    desync_bad = _rt41_d_known_answer_desync_probe_serially(alice_owner_bad, fifo_ok, fifo_times, recover, DENIED, T, port, DENIED_TOK, GR, tc, _has, SR, BOB_SECRET)

    _rt41_interleave_a_denied_op_between_alice(desync_bad, DENIED, T, port, ta, DENIED_TOK, adir, pubdir, GR, SR, BOB_SECRET)

    _rt41_f_final_ownership_scan_of_the(pubdir, T, GR, port, tc, _has, SR)

    _rt41_g_fifo_open_after_the_storm(port, ta, _has, BOB_SECRET, fifo_ok, T, recover)

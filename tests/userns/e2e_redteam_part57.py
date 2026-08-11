def _rt57_subjects_that_must_map_to_a(data, key):
    T = "bis_"
    pubdir = os.path.join(data, "pub")        # 0777 svc -> only idmap sets the owner

    # Subjects that MUST map to a fixed legit uid.
    LEGIT = [("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL),
             ("dave", UID_DAVE), ("erin", UID_ERIN), ("frank", UID_FRANK)]
    LEGIT_TOK = {s: mint(key, s) for s, _ in LEGIT}
    WANT = dict(LEGIT)
    return T, pubdir, LEGIT, LEGIT_TOK, WANT


def _rt57_segment_02(pubdir):

    def pub_path(name):
        return os.path.join(pubdir, name)
    return pub_path


def _rt57_segment_03(pub_path):

    def rm(name):
        p = pub_path(name)
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    return rm


def _rt57_1_identity_cache_ttl_correctness_rotate(T, port, LEGIT_TOK, pub_path, WANT, rm):

    # =====================================================================
    # (1) IDENTITY-CACHE TTL / CORRECTNESS: rotate alice->bob->carol->dave...
    #     repeatedly through the SAME server into the SAME /pub dir.  If the broker
    #     caches the mapped identity and a stale entry survives the switch, a later
    #     request will create a file owned by the WRONG (previously-cached) uid.
    #     Every created file MUST be owned by exactly the requesting subject's uid.
    _broker_internals_stress_p1(LEGIT, port, pub_path, rm, LEGIT_TOK, T, key, WANT, want)


def _broker_internals_stress_p1(LEGIT, port, pub_path, rm, LEGIT_TOK, T, key, WANT, want):
    # =====================================================================
    ROT = ["alice", "bob", "carol", "alice", "carol", "bob",
           "alice", "dave", "frank", "carol", "alice", "erin"]
    rot_bad = []          # (round, sub, expected_uid, actual_uid)
    for rnd, sub in enumerate(ROT):
        name = f"{T}rot_{rnd}.txt"
        st, _ = http("PUT", f"/pub/{name}", port, LEGIT_TOK[sub],
                     f"{sub}-rot-{rnd}\n".encode())
        fp = pub_path(name)
        made = os.path.exists(fp)
        actual = os.stat(fp).st_uid if made else -1
        if not (st in (200, 201, 204) and made and actual == WANT[sub]):
            rot_bad.append((rnd, sub, WANT[sub], actual))
        rm(name)
    ok(not rot_bad,
       f"identity-cache rotation alice/bob/carol/dave/erin/frank x{len(ROT)}: every "
       f"file owned by the CURRENT subject's uid, no stale-cache cross "
       f"(bad={rot_bad[:3]})")

    # Read-back arm: write+GET as alice immediately AFTER a bob mapping, repeatedly;
    # alice must read HER bytes and the file must own 1001 (bob's just-used identity
    # did not bleed into alice's open).
    rb_bad = 0
    return rb_bad


def _rt57_2_principal_string_edge_cases_via(T, port, LEGIT_TOK, pub_path, rm, rb_bad):
    for i in range(6):
        bn = f"{T}rb_b_{i}.txt"
        an = f"{T}rb_a_{i}.txt"
        http("PUT", f"/pub/{bn}", port, LEGIT_TOK["bob"], f"bob-{i}\n".encode())
        ap = f"alice-rb-{i}\n".encode()
        http("PUT", f"/pub/{an}", port, LEGIT_TOK["alice"], ap)
        st, gb = http("GET", f"/pub/{an}", port, LEGIT_TOK["alice"])
        fp = pub_path(an)
        bfp = pub_path(bn)
        bob_owned = os.path.exists(bfp) and os.stat(bfp).st_uid == UID_BOB
        if not (st == 200 and gb == ap and os.path.exists(fp)
                and os.stat(fp).st_uid == UID_ALICE and bob_owned):
            rb_bad += 1
        rm(bn)
        rm(an)
    ok(rb_bad == 0,
       f"bob-then-alice interleave x6: bob file owns 1002, alice reads her own bytes "
       f"& owns 1001 right after -- no cache bleed (mismatches={rb_bad})")

    # =====================================================================
    # (2) PRINCIPAL-STRING EDGE CASES via the token sub claim.  Each hostile sub
    #     must EITHER deny (no file) OR map deterministically to a legit (>=1000,
    #     non-svc) uid -- never to root/svc/system -- AND the SAME edge string must
    #     yield the SAME outcome on a repeat (no steerable nondeterminism).
    _broker_internals_stress_p2(LEGIT, port, pub_path, rm, LEGIT_TOK, T, key, WANT, want)


def _broker_internals_stress_p2(LEGIT, port, pub_path, rm, LEGIT_TOK, T, key, WANT, want):
    # =====================================================================
    NUL = "alice" + chr(0) + "x"
    HOMO = "al" + chr(0x456) + "ce"          # cyrillic-i homoglyph of "alice"
    WIDE = chr(0xFF41) + "lice"              # fullwidth 'a' + "lice"
    return NUL, HOMO, WIDE


def _rt57_segment_06(HOMO, WIDE, NUL):
    edges = [
        ("overlong-1k", "z" * 1024),
        ("overlong-4k", "q" * 4096),
        ("embedded-newline", "ali\nce"),
        ("embedded-tab", "ali\tce"),
        ("embedded-space", "al ice"),
        ("leading-space", " alice"),
        ("trailing-space", "alice "),
        ("homoglyph-cyrillic", HOMO),
        ("fullwidth-unicode", WIDE),
        ("embedded-nul", NUL),
        ("numeric-1001", "1001"),
        ("numeric-zero", "0"),
        ("name-root", "root"),
        ("name-svc", "svc"),
        ("uppercase-ALICE", "ALICE"),
        ("dotdot-alice", "alice/.."),
    ]
    return edges


def _rt57_segment_07(T, port, key, pub_path):

    def edge_attempt(sub, tag):
        rel = f"{T}edge_{tag}.txt"
        st, _ = http("PUT", f"/pub/{rel}", port, mint(key, sub), b"edge\n")
        fp = pub_path(rel)
        made = os.path.exists(fp)
        uid = os.stat(fp).st_uid if made else -1
        return st, made, uid, fp
    return edge_attempt


def _rt57_core_safety_nothing_privileged_system_ever_2(edge_attempt, sub, tag):
    st1, made1, uid1, fp1 = edge_attempt(sub, tag + "_a")
    st2, made2, uid2, fp2 = edge_attempt(sub, tag + "_b")
    # Core safety: nothing privileged/system, ever.
    priv = any((all((made1, uid1 < 1000)), all((made2, uid2 < 1000))))
    svc = any((all((made1, uid1 == UID_SVC)), all((made2, uid2 == UID_SVC))))
    ok(all((not priv, not svc)),
       f"edge sub {tag}: never mapped to a reserved(<1000)/svc uid "
       f"(uids={uid1},{uid2})")
    return made1, uid1, fp1, made2, uid2, fp2


def _rt57_determinism_same_edge_string_same_outcome(made1, made2, uid1, uid2, tag, fp1, fp2):
    # Determinism: SAME edge string -> SAME outcome class.
    ok(all((made1 == made2, uid1 == uid2)),
       f"edge sub {tag}: deterministic -- repeat yields identical outcome "
       f"(made={made1}/{made2}, uid={uid1}/{uid2})")
    for f in (fp1, fp2):
        try:
            if os.path.exists(f):
                os.remove(f)
        except OSError:
            pass


def _rt57_for_each_tag_sub_edges(edge_attempt, sub, tag):
    made1, uid1, fp1, made2, uid2, fp2 = _rt57_core_safety_nothing_privileged_system_ever_2(edge_attempt, sub, tag)

    _rt57_determinism_same_edge_string_same_outcome(made1, made2, uid1, uid2, tag, fp1, fp2)



def _rt57_core_safety_nothing_privileged_system_ever(edges, edge_attempt, HOMO, WIDE, T, port, key, pub_path, rm, LEGIT_TOK):

    for tag, sub in edges:
        _rt57_for_each_tag_sub_edges(edge_attempt, sub, tag)

    # A homoglyph/unicode/whitespace/case variant of "alice" must NOT silently
    # resolve to the REAL alice uid (1001) -- impersonation by visual/whitespace/case
    # collision would be an escalation.  Either denied, or mapped to some OTHER id,
    # but not aliased onto 1001 as if it were her.
    _broker_internals_stress_p3(LEGIT, port, pub_path, rm, HOMO, WIDE, LEGIT_TOK, T, key, WANT, want)


def _broker_internals_stress_p3(LEGIT, port, pub_path, rm, HOMO, WIDE, LEGIT_TOK, T, key, WANT, want):
    for tag, sub in (("homoglyph-cyrillic", HOMO), ("fullwidth-unicode", WIDE),
                     ("leading-space", " alice"), ("trailing-space", "alice "),
                     ("uppercase-ALICE", "ALICE")):
        rel = f"{T}collide_{tag}.txt"
        st, _ = http("PUT", f"/pub/{rel}", port, mint(key, sub), b"x\n")
        fp = pub_path(rel)
        made = os.path.exists(fp)
        uid = os.stat(fp).st_uid if made else -1
        ok(any((not made, uid != UID_ALICE)),
           f"alice-collision sub {tag}: not aliased onto the REAL alice uid 1001 "
           f"(made={made}, uid={uid})")
        rm(rel)

    # =====================================================================
    # (3) RAPID IDENTITY SWITCHING on ONE kept-alive connection.  Pipeline a
    #     rotation alice,bob,alice,carol,dave,alice,bob,carol on a SINGLE TCP
    #     connection; each PUT must be owned by the actor's uid -- proving the
    #     per-request principal is reset on the worker between pipelined requests
    #     and never leaks from the previous request.
    _broker_internals_stress_p4(LEGIT, port, pub_path, rm, LEGIT_TOK, T, WANT, want)


def _broker_internals_stress_p4(LEGIT, port, pub_path, rm, LEGIT_TOK, T, WANT, want):
    # =====================================================================
    SWITCH = ["alice", "bob", "alice", "carol", "dave", "alice", "bob", "carol"]
    seq = []
    for i, sub in enumerate(SWITCH):
        seq.append(("PUT", f"/pub/{T}ka_{i}.txt", LEGIT_TOK[sub],
                    f"{sub}-ka-{i}\n".encode(), None))
    return SWITCH, seq


def _rt57_segment_01(i, res, pub_path, T, all_ok_status):
    st = res[i][0] if i < len(res) else -1
    if st not in (200, 201, 204):
        all_ok_status = False
    fp = pub_path(f"{T}ka_{i}.txt")
    made = os.path.exists(fp)
    uid = os.stat(fp).st_uid if made else -1
    return all_ok_status, made, uid


def _rt57_segment_02_2(made, uid, WANT, sub, ka_owner_bad, i, rm, T):
    if not (made and uid == WANT[sub]):
        ka_owner_bad.append((i, sub, WANT[sub], uid))
    rm(f"{T}ka_{i}.txt")


def _rt57_for_each_i_sub_enumerate_switch(i, res, pub_path, T, ka_owner_bad, sub, WANT, rm, all_ok_status):
    all_ok_status, made, uid = _rt57_segment_01(i, res, pub_path, T, all_ok_status)

    _rt57_segment_02_2(made, uid, WANT, sub, ka_owner_bad, i, rm, T)

    return all_ok_status


def _rt57_segment_09(seq, port, SWITCH, pub_path, T, WANT, rm):
    res = http_keepalive(seq, port)
    ka_owner_bad = []
    all_ok_status = True
    for i, sub in enumerate(SWITCH):
        all_ok_status = _rt57_for_each_i_sub_enumerate_switch(i, res, pub_path, T, ka_owner_bad, sub, WANT, rm, all_ok_status)
    ok(all_ok_status,
       f"keep-alive identity switch: every pipelined request served (statuses "
       f"{[r[0] for r in res[:len(SWITCH)]]})")
    return ka_owner_bad


def _rt57_read_back_arm_on_a_kept(ka_owner_bad, T, LEGIT_TOK, port, pub_path):
    ok(not ka_owner_bad,
       f"keep-alive identity switch alice/bob/carol/dave on ONE conn: each file "
       f"owned by ITS actor's uid, no cross-request principal leak "
       f"(bad={ka_owner_bad[:3]})")

    # Read-back arm on a kept-alive conn: bob writes his own file, THEN carol on the
    # SAME socket must be DENIED bob's 0600 private.txt (no leftover bob auth on the
    # worker after bob's request) and must NOT see bob's secret bytes.
    BOB_SECRET = b"BOB-PRIVATE-SECRET"
    seq2 = [
        ("PUT", f"/pub/{T}kapriv.txt", LEGIT_TOK["bob"], b"bob-owns-this\n", None),
        ("GET", "/bob/private.txt", LEGIT_TOK["carol"], None, None),
    ]
    res2 = http_keepalive(seq2, port)
    bp = pub_path(f"{T}kapriv.txt")
    return BOB_SECRET, res2, bp


def _rt57_4_8_concurrent_distinct_identities_each(bp, res2, BOB_SECRET, rm, T):
    bob_made = os.path.exists(bp) and os.stat(bp).st_uid == UID_BOB
    ok(all((res2[0][0] in (200, 201, 204), bob_made)),
       f"keep-alive: bob's own write lands owned 1002 first (HTTP {res2[0][0]})")
    ok(all((res2[1][0] != 200, BOB_SECRET not in any((res2[1][1], b'')))),
       f"keep-alive: carol after bob on SAME conn DENIED bob's 0600 private.txt, "
       f"no secret leak from the prior bob request (HTTP {res2[1][0]})")
    rm(f"{T}kapriv.txt")

    # =====================================================================
    # (4) <=8 CONCURRENT DISTINCT IDENTITIES each create a file in /pub.  Under
    #     true concurrency the broker must keep per-request identities separate --
    #     zero files may end up owned by the wrong subject's uid (6 threads < cap).
    _broker_internals_stress_p5(LEGIT, port, pub_path, rm, LEGIT_TOK, T, want)


def _broker_internals_stress_p5(LEGIT, port, pub_path, rm, LEGIT_TOK, T, want):
    # =====================================================================
    conc_bad = []
    return conc_bad


def _rt57_segment_12():
    conc_lock = threading.Lock()
    return conc_lock


def _rt57_segment_13(T, port, LEGIT_TOK, pub_path, conc_lock, conc_bad):

    def conc_job(sub, want):
        name = f"{T}conc_{sub}.txt"
        try:
            st, _ = http("PUT", f"/pub/{name}", port, LEGIT_TOK[sub],
                         f"{sub}-conc\n".encode())
            fp = pub_path(name)
            made = os.path.exists(fp)
            uid = os.stat(fp).st_uid if made else -1
            if not (st in (200, 201, 204) and made and uid == want):
                with conc_lock:
                    conc_bad.append((sub, want, uid))
        except Exception as e:  # noqa: BLE001
            with conc_lock:
                conc_bad.append((sub, want, repr(e)))
    return conc_job


def _rt57_check_for_each_t_threads(threads):
    for t in threads:        # exactly 6 distinct identities, under the <=8 cap
        t.start()


def _rt57_segment_14(LEGIT, conc_job, conc_bad, rm, T):

    threads = [threading.Thread(target=conc_job, args=(s, u)) for s, u in LEGIT]
    _rt57_check_for_each_t_threads(threads)
    for t in threads:
        t.join()
    ok(not conc_bad,
       f"<=8 concurrent distinct identities each own their /pub file by exactly "
       f"their uid -- zero owner cross under concurrency (bad={conc_bad[:3]})")
    for sub, _u in LEGIT:
        rm(f"{T}conc_{sub}.txt")


def _rt57_liveness_the_worker_and_broker_survived(T, port, LEGIT_TOK, pub_path, rm):

    # Liveness: the worker AND broker survived the cache rotation + edge-string
    # parsing + concurrency, and still map a clean alice op correctly.
    st, _ = http("PUT", f"/pub/{T}final.txt", port, LEGIT_TOK["alice"], b"ok\n")
    fp = pub_path(f"{T}final.txt")
    final_ok = (st in (200, 201, 204) and os.path.exists(fp)
                and os.stat(fp).st_uid == UID_ALICE)
    ok(final_ok,
       f"post-stress: broker still maps alice->1001 cleanly, worker not wedged "
       f"(HTTP {st})")
    rm(f"{T}final.txt")


def run_broker_internals_stress(key, data, port, s3port):
    """Stress the broker's IDENTITY-CACHE + principal-string parser + per-request
    impersonation switch.  Proves: (1) a stale identity cache NEVER serves the
    wrong uid when alice/bob/carol/dave rotate through the SAME export; (2) hostile
    token-`sub` edge strings (1-4KB overlong, embedded ws, unicode/homoglyph, NUL,
    numeric, reserved names) map DETERMINISTICALLY to the same local id every time or
    are DENIED -- and NEVER to root/svc/system; (3) rapid legit identity switching on
    ONE kept-alive connection serves each request as its true identity (no principal
    leak across pipelined requests); (4) <=8 concurrent distinct identities each
    create a file owned by exactly their own uid (zero owner cross).

    Writes go into the world-writable /pub (0777 svc) because only alice/ and bob/
    have provisioned home dirs -- /pub lets ANY mapped identity create, so the file's
    OWNER is purely the broker's mapped uid (exactly the property under test) and any
    misowned residue is a real idmap breach.  All files are bis_-tagged and removed."""
    T, pubdir, LEGIT, LEGIT_TOK, WANT = _rt57_subjects_that_must_map_to_a(data, key)

    pub_path = _rt57_segment_02(pubdir)

    rm = _rt57_segment_03(pub_path)

    rb_bad = _rt57_1_identity_cache_ttl_correctness_rotate(T, port, LEGIT_TOK, pub_path, WANT, rm)

    NUL, HOMO, WIDE = _rt57_2_principal_string_edge_cases_via(T, port, LEGIT_TOK, pub_path, rm, rb_bad)

    edges = _rt57_segment_06(HOMO, WIDE, NUL)

    edge_attempt = _rt57_segment_07(T, port, key, pub_path)

    SWITCH, seq = _rt57_core_safety_nothing_privileged_system_ever(edges, edge_attempt, HOMO, WIDE, T, port, key, pub_path, rm, LEGIT_TOK)

    ka_owner_bad = _rt57_segment_09(seq, port, SWITCH, pub_path, T, WANT, rm)

    BOB_SECRET, res2, bp = _rt57_read_back_arm_on_a_kept(ka_owner_bad, T, LEGIT_TOK, port, pub_path)

    conc_bad = _rt57_4_8_concurrent_distinct_identities_each(bp, res2, BOB_SECRET, rm, T)

    conc_lock = _rt57_segment_12()

    conc_job = _rt57_segment_13(T, port, LEGIT_TOK, pub_path, conc_lock, conc_bad)

    _rt57_segment_14(LEGIT, conc_job, conc_bad, rm, T)

    _rt57_liveness_the_worker_and_broker_survived(T, port, LEGIT_TOK, pub_path, rm)

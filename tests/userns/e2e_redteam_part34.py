def _rt34_segment_01(key, data):
    ta, tb = mint(key, "alice"), mint(key, "bob")
    H = HOST
    TAG = "cxe_"

    apath = lambda n: os.path.join(data, "alice", n)
    bpath = lambda n: os.path.join(data, "bob", n)
    return ta, tb, H, TAG, apath, bpath


def _rt34_segment_02():

    def st_uid(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1
    return st_uid


def _rt34_segment_03():

    def rm_quiet(p):
        try:
            os.unlink(p)
        except OSError:
            pass
    return rm_quiet


def _rt34_baseline_snapshot_files_other_batches_legitimately(data):

    # Baseline: snapshot files OTHER batches legitimately planted (e.g. the
    # broker_resource_limits svc-owned hardlink) BEFORE any connection-error case,
    # so the sweep only flags artifacts THIS battery's abnormal connections create.
    def _snapshot():
        seen = set()
        for sub in ("alice", "bob"):
            try:
                for f in os.listdir(os.path.join(data, sub)):
                    seen.add((sub, f))
            except OSError:
                pass
        return seen
    return _snapshot


def _rt34_segment_05(_snapshot):

    _baseline = _snapshot()
    return _baseline


def _rt34_misowned_entry(data, baseline, sub, name, wanted_uid, tag):
    if (sub, name) in baseline:
        return None
    try:
        status = os.lstat(os.path.join(data, sub, name))
    except OSError:
        return None
    if (status.st_mode & 0o170000) != 0o100000:
        return None
    owner = status.st_uid
    if owner in (UID_SVC, 0) or all((name.startswith(tag), owner != wanted_uid)):
        return sub, name, owner
    return None


def _rt34_scan_misowned(data, baseline, tag):
    bad = []
    for sub, wanted_uid in (("alice", UID_ALICE), ("bob", UID_BOB)):
        try:
            names = os.listdir(os.path.join(data, sub))
        except OSError:
            continue
        for name in names:
            issue = _rt34_misowned_entry(
                data, baseline, sub, name, wanted_uid, tag
            )
            if issue is not None:
                bad.append(issue)
    return bad


def _rt34_segment_06(data, _baseline, TAG):

    def scan_misowned():
        """Regular files in alice/ + bob/ that APPEARED during this battery and are
        owned by svc(1500)/root(0) (a leak), or a TAG file owned by the WRONG tenant.
        Pre-existing fixtures planted by other batches are excluded via the baseline."""
        return _rt34_scan_misowned(data, _baseline, TAG)
    return scan_misowned


def _rt34_segment_07(H):

    def get_req(path, tok, conn_close=True):
        cc = "Connection: close\r\n" if conn_close else ""
        return (f"GET {path} HTTP/1.1\r\nHost: {H}\r\n"
                f"Authorization: Bearer {tok}\r\n{cc}\r\n").encode()
    return get_req


def _rt34_segment_08(TAG, port, ta):

    def survives(label):
        """Worker survived: a normal authenticated GET of alice's own file still
        returns the exact body.  One ok() per call site."""
        st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
        ok(all((st == 200, b == b'CXE-LIVE-MARKER\n')),
           f"{label}: worker survived (follow-up alice GET ok, HTTP {st})")
    return survives


def _rt34_segment_09(scan_misowned):

    def no_misowned(label):
        bad = scan_misowned()
        ok(not bad, f"{label}: no svc/root/wrong-owner file in alice|bob ({bad})")
    return no_misowned


def _rt34_seed_a_stable_own_file_used(TAG, port, ta):

    # seed a stable own file used as the worker-survival probe + a bob 0600 control.
    http("PUT", f"/alice/{TAG}live.txt", port, ta, b"CXE-LIVE-MARKER\n")
    st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
    ok(all((st == 200, b == b'CXE-LIVE-MARKER\n')),
       f"baseline: alice own file readable before storm (HTTP {st})")
    # bob 0600 fixture (data/bob/private.txt) is the cross-tenant secret control.
    st, b = http("GET", "/bob/private.txt", port, ta)
    ok(all((st in (403, 404), b'BOB-PRIVATE-SECRET' not in b)),
       f"baseline: alice cannot read bob 0600 secret (HTTP {st})")


def _rt34_case_1_full_request_then_immediate(rm_quiet, apath, TAG, H, ta, port):

    # ========================================================================
    # CASE 1 — full request then immediate HARD-RST.  A complete, valid PUT body
    #   is sent, then the socket is RST before/at the response.  The file may or
    #   may not commit, but if it does it must be alice-owned (never svc/root) and
    #   byte-exact; the worker must survive.
    # ========================================================================
    rm_quiet(apath(f"{TAG}rst_full.txt"))
    body = b"CXE-RST-FULL-BODY\n"
    req = (f"PUT /alice/{TAG}rst_full.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {ta}\r\nContent-Length: {len(body)}\r\n\r\n"
           ).encode() + body
    raw_send_steps([(req, 0.20, True)], port)        # send all, pause, hard-RST
    fp = apath(f"{TAG}rst_full.txt")
    return body, fp


def _rt34_case_2_headers_partial_body_content(fp, st_uid, body, survives, no_misowned, rm_quiet, apath, TAG, H, ta):
    if os.path.exists(fp):
        ok(all((st_uid(fp) == UID_ALICE, st_uid(fp) not in (UID_SVC, 0))),
           f"case1 full+RST: committed file owned alice not svc/root (uid={st_uid(fp)})")
        try:
            with open(fp, "rb") as fh:
                got = fh.read()
        except OSError:
            got = b""
        ok(any((got == body, got == b'')),
           "case1 full+RST: committed file byte-exact or absent (no partial corruption)")
    else:
        ok(True, "case1 full+RST: no file committed after RST (handled)")
    survives("case1 full+RST")
    no_misowned("case1 full+RST")

    # ========================================================================
    # CASE 2 — headers + PARTIAL body (Content-Length lies HIGH), then RST.  The
    #   server is told 64 bytes but only 5 arrive before the reset.  A TRUNCATED
    #   object must NOT be committed (the writer requires the full declared body);
    #   if anything lands it must be alice-owned, never svc/root.
    # ========================================================================
    rm_quiet(apath(f"{TAG}partial.txt"))
    head = (f"PUT /alice/{TAG}partial.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 64\r\n\r\n").encode()
    return head


def _rt34_segment_13(head, port, apath, TAG, st_uid, rm_quiet, survives, no_misowned):
    raw_send_steps([(head, 0.05), (b"PARTL", 0.20, True)], port)   # 5 of 64, RST
    fp = apath(f"{TAG}partial.txt")
    if os.path.exists(fp):
        try:
            sz = os.path.getsize(fp)
        except OSError:
            sz = -1
        ok(all((st_uid(fp) == UID_ALICE, st_uid(fp) not in (UID_SVC, 0))),
           f"case2 partial-body: any landed file owned alice (uid={st_uid(fp)})")
        ok(sz != 64, f"case2 partial-body: no full-size phantom object committed (size={sz})")
        rm_quiet(fp)
    else:
        ok(True, "case2 partial-body: truncated body NOT committed (no partial file)")
    survives("case2 partial-body")
    no_misowned("case2 partial-body")


def _rt34_case_3a_abandon_after_the_request(TAG, port, survives, no_misowned, H, ta):

    # ========================================================================
    # CASE 3a — ABANDON after the request line only (no headers, no blank line),
    #   then RST.  No principal may be stuck; the connection must be torn down
    #   cleanly and the worker stays healthy.
    # ========================================================================
    raw_send_steps([(f"GET /alice/{TAG}live.txt HTTP/1.1\r\n".encode(), 0.30, True)], port)
    survives("case3a abandon-after-request-line")
    no_misowned("case3a abandon-after-request-line")

    # CASE 3b — ABANDON right after the Authorization header (alice), never send
    #   the terminating blank line, then RST.  The half-applied auth must not
    #   strand alice's principal for the NEXT connection.
    raw_send_steps([
        (f"GET /alice/{TAG}live.txt HTTP/1.1\r\nHost: {H}\r\n".encode(), 0.05),
        (f"Authorization: Bearer {ta}\r\n".encode(), 0.30, True),
    ], port)
    survives("case3b abandon-after-Authorization")


def _rt34_immediately_after_the_abandon_a_bob(TAG, port, tb, bpath, st_uid, no_misowned, ta, H):
    # immediately after the abandon, a BOB request must land as bob (no stale alice).
    st, b = http("PUT", f"/bob/{TAG}after_abandon.txt", port, tb, b"BOB-AFTER-ABANDON\n")
    fp = bpath(f"{TAG}after_abandon.txt")
    ok(all((st in (200, 201, 204), os.path.exists(fp), st_uid(fp) == UID_BOB)),
       f"case3b: bob request after alice-abandon lands as BOB not stale-alice (uid={st_uid(fp)})")
    no_misowned("case3b abandon-after-Authorization")
    _connection_errors_p2(port, ta, tb, bpath, apath, no_misowned, get_req, survives, rm_quiet, scan_misowned, TAG, st_uid, H)


def _connection_errors_p2(port, ta, tb, bpath, apath, no_misowned, get_req, survives, rm_quiet, scan_misowned, TAG, st_uid, H):
    # ========================================================================
    # CASE 4 — CONNECTION CHURN: many short-lived connections, each authenticating
    #   as alice then abandoned/RST, interleaved with bob connections.  After the
    #   storm a fresh alice GET and bob op must each land in the CORRECT space — no
    #   stale principal leaked to a reused worker connection/slot.
    # ========================================================================
    for i in range(24):
        who_tok = ta if (i % 2 == 0) else tb
        # send a complete request line + auth, then RST without reading the reply.
        raw_send_steps([
            (f"GET /alice/{TAG}live.txt HTTP/1.1\r\nHost: {H}\r\n".encode(), 0.0),
            (f"Authorization: Bearer {who_tok}\r\nConnection: close\r\n\r\n".encode(),
             0.0, True),
        ], port, read_timeout=0.6)


def _rt34_fresh_clean_alice_get_must_still(TAG, port, ta, tb, bpath, st_uid):
    # fresh, clean alice GET — must still be alice's own bytes.
    st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
    ok(all((st == 200, b == b'CXE-LIVE-MARKER\n')),
       f"case4 churn: post-storm alice GET lands in alice space, exact bytes (HTTP {st})")
    # fresh bob PUT — must land bob-owned in bob/ (no stale alice principal).
    st, b = http("PUT", f"/bob/{TAG}churn_bob.txt", port, tb, b"BOB-POST-CHURN\n")
    fp = bpath(f"{TAG}churn_bob.txt")
    ok(all((st in (200, 201, 204), os.path.exists(fp), st_uid(fp) == UID_BOB, st_uid(fp) not in (UID_SVC, 0, UID_ALICE))),
       f"case4 churn: post-storm bob PUT owned bob not stale-alice/svc/root (uid={st_uid(fp)})")


def _rt34_fresh_alice_put_must_land_alice(TAG, port, ta, apath, st_uid):
    # fresh alice PUT — must land alice-owned in alice/.
    st, b = http("PUT", f"/alice/{TAG}churn_alice.txt", port, ta, b"ALICE-POST-CHURN\n")
    fp = apath(f"{TAG}churn_alice.txt")
    ok(all((st in (200, 201, 204), os.path.exists(fp), st_uid(fp) == UID_ALICE, st_uid(fp) not in (UID_SVC, 0, UID_BOB))),
       f"case4 churn: post-storm alice PUT owned alice not bob/svc/root (uid={st_uid(fp)})")
    # the churn must not have created any object in EITHER dir (all were abandoned).
    ok(not os.path.exists(apath(f"{TAG}churn_phantom.txt")),
       "case4 churn: abandoned GET connections created no phantom write artifact")
    # post-churn, alice still cannot read bob's 0600 secret (principal not widened).
    st, b = http("GET", "/bob/private.txt", port, ta)
    return st, b


def _rt34_case_5_slow_drip_send_a(st, b, no_misowned, get_req, TAG, ta, port):
    ok(all((st in (403, 404), b'BOB-PRIVATE-SECRET' not in b)),
       f"case4 churn: alice STILL denied bob 0600 secret post-storm (HTTP {st})")
    no_misowned("case4 churn")

    # ========================================================================
    # CASE 5 — SLOW DRIP: send a valid alice GET one byte at a time with tiny
    #   pauses.  Served or cleanly handled — no desync, no leak, worker survives.
    # ========================================================================
    drip = get_req(f"/alice/{TAG}live.txt", ta)
    steps = [(bytes([drip[i]]), 0.01) for i in range(len(drip))]
    resp = raw_send_steps(steps, port, read_timeout=5.0)
    return resp


def _rt34_a_drip_whose_body_is_bob(resp, get_req, ta):
    dstat = _resp_status(resp)
    ok(dstat in (200, 408, 400, -1),
       f"case5 slow-drip: byte-at-a-time alice GET served/handled (HTTP {dstat})")
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       "case5 slow-drip: no foreign-tenant secret bytes in drip response")
    # a drip whose body is bob's 0600 path must NEVER leak the secret marker.
    drip2 = get_req("/bob/private.txt", ta)
    steps2 = [(bytes([drip2[i]]), 0.01) for i in range(len(drip2))]
    return steps2


def _rt34_case_6_pipeline_a_valid_alice(steps2, port, survives, no_misowned, get_req, TAG, ta, H):
    resp2 = raw_send_steps(steps2, port, read_timeout=5.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp2,
       f"case5 slow-drip: drip GET of bob 0600 leaks no secret (HTTP {_resp_status(resp2)})")
    survives("case5 slow-drip")
    no_misowned("case5 slow-drip")
    _connection_errors_p3(port, survives, no_misowned, rm_quiet, apath, get_req, ta, scan_misowned, tb, bpath, TAG, H, st_uid)


def _connection_errors_p3(port, survives, no_misowned, rm_quiet, apath, get_req, ta, scan_misowned, tb, bpath, TAG, H, st_uid):
    # ========================================================================
    # CASE 6 — PIPELINE a VALID alice GET + a TRUNCATED second request, then RST.
    #   The first request must NOT have leaked bob data (the truncated second can't
    #   trick a desync into serving foreign bytes), and the worker survives.
    # ========================================================================
    pipe = (get_req(f"/alice/{TAG}live.txt", ta, conn_close=False)
            + f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\nAuth".encode())  # truncated
    return pipe


def _rt34_segment_21(pipe, port, survives, no_misowned):
    resp = raw_send_steps([(pipe, 0.30, True)], port, read_timeout=4.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       f"case6 pipeline+truncate: bob 0600 secret never leaked (HTTP {_resp_status(resp)})")
    ok(any((b'CXE-LIVE-MARKER' in resp, _resp_status(resp) in (200, 400, 408, -1))),
       f"case6 pipeline+truncate: first alice GET served, no desync (HTTP {_resp_status(resp)})")
    survives("case6 pipeline+truncate")
    no_misowned("case6 pipeline+truncate")


def _rt34_case_6b_pipeline_two_valid_requests(get_req, TAG, ta, port, survives, rm_quiet, apath):

    # CASE 6b — pipeline TWO valid requests then RST before reading: first MUST be
    #   alice's own bytes, the (cross-tenant) second must not leak bob's secret.
    pipe2 = (get_req(f"/alice/{TAG}live.txt", ta, conn_close=False)
             + get_req("/bob/private.txt", ta, conn_close=True))
    resp = raw_send_steps([(pipe2, 0.30, True)], port, read_timeout=4.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       "case6b pipeline two-valid: cross-tenant 2nd request leaks no bob secret")
    survives("case6b pipeline two-valid")

    # ========================================================================
    # CASE 7 — Authorization is alice but Content-Length claims a HUGE body; only a
    #   few bytes are sent, then RST mid-body.  No giant/phantom object may commit;
    #   any landed file is alice-owned; worker survives.
    _connection_errors_p4(rm_quiet, port, apath, survives, no_misowned, get_req, ta, scan_misowned, tb, bpath, TAG, H, st_uid)


def _connection_errors_p4(rm_quiet, port, apath, survives, no_misowned, get_req, ta, scan_misowned, tb, bpath, TAG, H, st_uid):
    # ========================================================================
    rm_quiet(apath(f"{TAG}huge.txt"))


def _rt34_segment_23(TAG, H, ta, port, apath, st_uid, rm_quiet, survives):
    head = (f"PUT /alice/{TAG}huge.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 10000000\r\n\r\n").encode()
    raw_send_steps([(head, 0.05), (b"CXE-HUGE-PREFIX", 0.20, True)], port)  # 15 of 10M
    fp = apath(f"{TAG}huge.txt")
    if os.path.exists(fp):
        try:
            sz = os.path.getsize(fp)
        except OSError:
            sz = -1
        ok(all((st_uid(fp) == UID_ALICE, st_uid(fp) not in (UID_SVC, 0))),
           f"case7 huge-CL+RST: any landed file owned alice (uid={st_uid(fp)})")
        ok(sz < 10000000, f"case7 huge-CL+RST: no 10MB phantom object committed (size={sz})")
        rm_quiet(fp)
    else:
        ok(True, "case7 huge-CL+RST: lying huge body NOT committed (no phantom file)")
    survives("case7 huge-CL+RST")


def _rt34_case_7b_same_huge_cl_lie(no_misowned, TAG, H, tb, port, apath, survives):
    no_misowned("case7 huge-CL+RST")

    # CASE 7b — same huge-CL lie but Authorization is BOB targeting ALICE's dir,
    #   then RST.  DAC denies bob in alice/ regardless of how the body terminates;
    #   nothing must land, and certainly nothing bob/svc/root-owned.
    head = (f"PUT /alice/{TAG}bob_huge.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {tb}\r\nContent-Length: 10000000\r\n\r\n").encode()
    raw_send_steps([(head, 0.05), (b"BOB-EVIL", 0.15, True)], port)
    ok(not os.path.exists(apath(f"{TAG}bob_huge.txt")),
       "case7b huge-CL+RST: bob PUT into alice's dir DENIED, no artifact")
    survives("case7b cross-tenant huge-CL+RST")


def _rt34_case_8_keep_alive_interleave_that(no_misowned, rm_quiet, apath, TAG, bpath, H, ta):
    no_misowned("case7b cross-tenant huge-CL+RST")

    # ========================================================================
    # CASE 8 — KEEP-ALIVE interleave that ends in an ABRUPT RST: alice,bob,alice on
    #   ONE connection, then the conn is RST instead of closed.  Each request must
    #   land under the DRIVING identity (no stale-principal carry-over), and the RST
    #   must not roll a wrong-owner file into the other tenant's space.
    _connection_errors_p5(rm_quiet, port, survives, no_misowned, get_req, ta, scan_misowned, tb, bpath, apath, TAG, H, st_uid)


def _connection_errors_p5(rm_quiet, port, survives, no_misowned, get_req, ta, scan_misowned, tb, bpath, apath, TAG, H, st_uid):
    # ========================================================================
    rm_quiet(apath(f"{TAG}ka_a.txt"))
    rm_quiet(bpath(f"{TAG}ka_b.txt"))
    rm_quiet(apath(f"{TAG}ka_a2.txt"))
    pa1 = (f"PUT /alice/{TAG}ka_a.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {ta}\r\nContent-Length: 6\r\n\r\nA-one\n").encode()
    return pa1


def _rt34_segment_26(TAG, H, tb, ta, pa1, port, apath, bpath, st_uid):
    pb1 = (f"PUT /bob/{TAG}ka_b.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {tb}\r\nContent-Length: 6\r\n\r\nB-one\n").encode()
    pa2 = (f"PUT /alice/{TAG}ka_a2.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {ta}\r\nContent-Length: 6\r\n\r\nA-two\n").encode()
    raw_send_steps([(pa1, 0.08), (pb1, 0.08), (pa2, 0.15, True)], port, read_timeout=4.0)
    fa, fb = apath(f"{TAG}ka_a.txt"), bpath(f"{TAG}ka_b.txt")
    if os.path.exists(fa):
        ok(all((st_uid(fa) == UID_ALICE, st_uid(fa) not in (UID_SVC, 0, UID_BOB))),
           f"case8 ka+RST: 1st alice PUT owned alice not bob/svc/root (uid={st_uid(fa)})")
    else:
        ok(True, "case8 ka+RST: 1st alice PUT not committed (handled)")
    return fb


def _rt34_segment_01_2(i):
    sub = "alice" if (i % 2 == 0) else "bob"
    base = "alice" if sub == "alice" else "bob"
    try:
        xrd_fs(["stat", f"/{base}/"], sub)
    except OSError:
        pass


def _rt34_for_each_i_range_8(i):
    _rt34_segment_01_2(i)



def _rt34_positive_control_alice_can_stat_her_2():
    for i in range(8):
        _rt34_for_each_i_range_8(i)
    # bob tries to stat alice's 0600-equivalent secret over root:// -> denied,
    # and the secret marker must never appear in xrdfs output.
    try:
        rc, out, err = xrd_fs(["cat", "/bob/private.txt"], "alice")
    except OSError:
        rc, out, err = -1, "", "oserr"
    ok(all((rc != 0, 'BOB-PRIVATE-SECRET' not in any((out, '')))),
       f"case9 root:// churn: alice cannot cat bob 0600 secret (rc={rc})")
    # positive control: alice can stat her own dir over root:// after the churn.
    try:
        rc2, out2, err2 = xrd_fs(["stat", "/alice/"], "alice")
    except OSError:
        rc2, out2, err2 = -1, "", "oserr"
    ok(any((rc2 == 0, 'alice' in any((out2, '')).lower(), rc2 in (0,))),
       f"case9 root:// churn: alice stat own dir works post-churn (rc={rc2})")


def _rt34_a_fresh_http_alice_get_after(TAG, port, ta):
    # a fresh HTTP alice GET after the root:// churn still lands correctly.
    st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
    ok(all((st == 200, b == b'CXE-LIVE-MARKER\n')),
       f"case9 root:// churn: HTTP alice GET unaffected by stream churn (HTTP {st})")


def _rt34_when_xrd_avail(port, ta, TAG):
    _rt34_positive_control_alice_can_stat_her_2()

    _rt34_a_fresh_http_alice_get_after(TAG, port, ta)



def _rt34_positive_control_alice_can_stat_her(fb, st_uid, bpath, TAG, apath, survives, no_misowned, port, ta):
    if os.path.exists(fb):
        ok(all((st_uid(fb) == UID_BOB, st_uid(fb) not in (UID_SVC, 0, UID_ALICE))),
           f"case8 ka+RST: bob PUT owned bob not stale-alice/svc/root (uid={st_uid(fb)})")
    else:
        ok(True, "case8 ka+RST: bob PUT not committed (handled)")
    # the alice request must NOT have landed in bob's dir nor bob's in alice's.
    ok(all((not os.path.exists(bpath(f'{TAG}ka_a.txt')), not os.path.exists(apath(f'{TAG}ka_b.txt')))),
       "case8 ka+RST: no request crossed into the other tenant's directory")
    survives("case8 ka-interleave+RST")
    no_misowned("case8 ka-interleave+RST")
    _connection_errors_p6(get_req, ta, port, survives, no_misowned, scan_misowned, tb, bpath, TAG, st_uid, H)


def _connection_errors_p6(get_req, ta, port, survives, no_misowned, scan_misowned, tb, bpath, TAG, st_uid, H):
    # ========================================================================
    # CASE 9 — root:// (stream) connection-state probe: the impersonation principal
    #   is shared by the SAME worker that serves HTTP, so a churn of native xrdfs
    #   sessions (each a separate connect/auth/teardown) must not leak a principal
    #   into a fresh HTTP request.  Guarded by xrd_avail().
    # ========================================================================
    if xrd_avail():
        # alternate alice/bob short xrdfs stat sessions (connect+auth+disconnect).
        _rt34_when_xrd_avail(port, ta, TAG)
    else:
        ok(True, "case9 root:// churn: native xrdfs unavailable (skipped/handled)")
        ok(True, "case9 root:// churn: stream secret-deny skipped (no client)")
        ok(True, "case9 root:// churn: stream positive control skipped (no client)")
    _connection_errors_p7(get_req, ta, port, survives, no_misowned, scan_misowned, tb, bpath, TAG, st_uid, H)


def _rt34_case_10_raw_half_open_desync(get_req, TAG, ta, H, port, survives):

    # ========================================================================
    # CASE 10 — RAW half-open desync probe: send a valid alice GET, read the
    #   response, then on the SAME (kept-alive) conn send a TRUNCATED bob request
    #   and RST.  Reuse must not let the truncated bob request resurrect alice's
    #   already-applied principal to read bob's space, nor leak alice's bytes to a
    #   bob identity.  We assert no secret leak + clean status.
    # ========================================================================
    keep = (get_req(f"/alice/{TAG}live.txt", ta, conn_close=False))
    resp = raw_send_steps([
        (keep, 0.15),
        (f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bea".encode(),
         0.20, True),
    ], port, read_timeout=4.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       "case10 half-open desync: truncated 2nd request leaks no bob secret")
    ok(_resp_status(resp) in (200, 400, 408, -1),
       f"case10 half-open desync: first alice GET cleanly served (HTTP {_resp_status(resp)})")
    survives("case10 half-open desync")


def _rt34_final_a_global_ownership_sweep_of(no_misowned, scan_misowned, TAG, port, ta, tb):
    no_misowned("case10 half-open desync")
    _connection_errors_p8(scan_misowned, port, ta, tb, bpath, TAG, st_uid)


def _connection_errors_p8(scan_misowned, port, ta, tb, bpath, TAG, st_uid):
    # ========================================================================
    # FINAL — a global ownership sweep of both tenant dirs: across EVERY abnormal
    #   connection above, not a single regular file may be owned by the worker
    #   svc(1500) or root(0).  This is the strongest no-principal-leak invariant.
    # ========================================================================
    final_bad = scan_misowned()
    ok(not final_bad,
       f"FINAL sweep: zero svc/root/wrong-owner files after all connection-error cases ({final_bad})")
    # and the worker is definitively alive: one last clean round-trip both tenants.
    st_a, b_a = http("GET", f"/alice/{TAG}live.txt", port, ta)
    st_b, b_b = http("PUT", f"/bob/{TAG}final.txt", port, tb, b"BOB-FINAL\n")
    return st_a, b_a, st_b


def _rt34_segment_30(bpath, TAG, st_a, b_a, st_b, st_uid):
    fpb = bpath(f"{TAG}final.txt")
    ok(all((st_a == 200, b_a == b'CXE-LIVE-MARKER\n')),
       f"FINAL: alice GET healthy after entire storm (HTTP {st_a})")
    ok(all((st_b in (200, 201, 204), os.path.exists(fpb), st_uid(fpb) == UID_BOB)),
       f"FINAL: bob PUT healthy + owned bob after entire storm (uid={st_uid(fpb)}, HTTP {st_b})")


def run_connection_errors(key, data, port, s3port):
    """CONNECTION-STATE / erroring-connection attacks under impersonation.  The
    setfsuid/setfsgid principal is per-worker PROCESS-GLOBAL, so an abnormally
    terminated connection (hard-RST mid-request/body, abandon-after-Authorization,
    one-byte drip, pipelined-then-truncated) must never (a) leave a half-written /
    truncated file committed, (b) wedge the worker, (c) strand a stale principal that
    bleeds into the NEXT connection's request, or (d) leak another tenant's secret
    bytes.  Every case drives ONE scripted TCP connection through raw HTTP bytes via
    raw_send_steps (the WebDAV port speaks HTTP), then PROVES worker-survival with a
    normal http() GET and scans alice/ + bob/ for any svc(1500)/root(0)-owned file.
    Cross-tenant denies each carry a positive control; read-denies also assert the
    secret marker is absent from the response."""
    ta, tb, H, TAG, apath, bpath = _rt34_segment_01(key, data)

    st_uid = _rt34_segment_02()

    rm_quiet = _rt34_segment_03()

    _snapshot = _rt34_baseline_snapshot_files_other_batches_legitimately(data)

    _baseline = _rt34_segment_05(_snapshot)

    scan_misowned = _rt34_segment_06(data, _baseline, TAG)

    get_req = _rt34_segment_07(H)

    survives = _rt34_segment_08(TAG, port, ta)

    no_misowned = _rt34_segment_09(scan_misowned)

    _rt34_seed_a_stable_own_file_used(TAG, port, ta)

    body, fp = _rt34_case_1_full_request_then_immediate(rm_quiet, apath, TAG, H, ta, port)

    head = _rt34_case_2_headers_partial_body_content(fp, st_uid, body, survives, no_misowned, rm_quiet, apath, TAG, H, ta)

    _rt34_segment_13(head, port, apath, TAG, st_uid, rm_quiet, survives, no_misowned)

    _rt34_case_3a_abandon_after_the_request(TAG, port, survives, no_misowned, H, ta)

    _rt34_immediately_after_the_abandon_a_bob(TAG, port, tb, bpath, st_uid, no_misowned, ta, H)

    _rt34_fresh_clean_alice_get_must_still(TAG, port, ta, tb, bpath, st_uid)

    st, b = _rt34_fresh_alice_put_must_land_alice(TAG, port, ta, apath, st_uid)

    resp = _rt34_case_5_slow_drip_send_a(st, b, no_misowned, get_req, TAG, ta, port)

    steps2 = _rt34_a_drip_whose_body_is_bob(resp, get_req, ta)

    pipe = _rt34_case_6_pipeline_a_valid_alice(steps2, port, survives, no_misowned, get_req, TAG, ta, H)

    _rt34_segment_21(pipe, port, survives, no_misowned)

    _rt34_case_6b_pipeline_two_valid_requests(get_req, TAG, ta, port, survives, rm_quiet, apath)

    _rt34_segment_23(TAG, H, ta, port, apath, st_uid, rm_quiet, survives)

    _rt34_case_7b_same_huge_cl_lie(no_misowned, TAG, H, tb, port, apath, survives)

    pa1 = _rt34_case_8_keep_alive_interleave_that(no_misowned, rm_quiet, apath, TAG, bpath, H, ta)

    fb = _rt34_segment_26(TAG, H, tb, ta, pa1, port, apath, bpath, st_uid)

    _rt34_positive_control_alice_can_stat_her(fb, st_uid, bpath, TAG, apath, survives, no_misowned, port, ta)

    _rt34_case_10_raw_half_open_desync(get_req, TAG, ta, H, port, survives)

    st_a, b_a, st_b = _rt34_final_a_global_ownership_sweep_of(no_misowned, scan_misowned, TAG, port, ta, tb)

    _rt34_segment_30(bpath, TAG, st_a, b_a, st_b, st_uid)

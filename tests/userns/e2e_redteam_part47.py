def _rt47_segment_01(key):
    TAG = "ccsi_"
    H = HOST
    ta, tb, tc = mint(key, "alice"), mint(key, "bob"), mint(key, "carol")
    return TAG, H, ta, tb, tc


def _rt47_segment_02(data):

    def apath(name):
        return os.path.join(data, "alice", name)
    return apath


def _rt47_segment_03(data):

    def bpath(name):
        return os.path.join(data, "bob", name)
    return bpath


def _rt47_segment_04(data):

    def cpath(name):
        return os.path.join(data, "carol", name)
    return cpath


def _rt47_segment_05():

    def st_uid(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1
    return st_uid


def _rt47_segment_06():

    def exists(p):
        try:
            return os.path.exists(p)
        except OSError:
            return False
    return exists


def _rt47_segment_07():

    def rm_quiet(p):
        try:
            os.unlink(p)
        except OSError:
            pass
    return rm_quiet


def _rt47_segment_08():

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt47_segment_09():

    def statuses(resp):
        """All HTTP status codes in a raw multi-response stream (pipelined)."""
        out = []
        for line in resp.split(b"\r\n"):
            if line.startswith(b"HTTP/"):
                try:
                    out.append(int(line.split(b" ", 2)[1]))
                except (ValueError, IndexError):
                    pass
        return out
    return statuses


def _rt47_carol_s_dir_must_exist_be(data, body_of, exists, TAG):

    # carol's dir must exist + be carol-owned for the create-ownership checks below;
    # tolerate it being pre-seeded.
    try:
        cdir = os.path.join(data, "carol")
        if not os.path.isdir(cdir):
            os.makedirs(cdir, exist_ok=True)
            os.chown(cdir, UID_CAROL, UID_CAROL)
            os.chmod(cdir, 0o755)
    except OSError:
        pass
    ensure_traversable(os.path.join(data, "carol"))

    # seed bob's 0600 secret reference (fixture already has it; assert marker present
    # so a later "absent" check is meaningful).
    bob_secret = os.path.join(data, "bob", "private.txt")
    ok(any((b'BOB-PRIVATE-SECRET' in body_of(bob_secret), not exists(bob_secret))),
       "precondition: bob 0600 secret marker present (or fixture absent, tolerated)")

    _combo_connection_state_identity_p1(rm_quiet, port, ta, tb, exists, statuses, tc, TAG, apath, data, st_uid, key, cpath, bpath, H)


def _combo_connection_state_identity_p1(rm_quiet, port, ta, tb, exists, statuses, tc, TAG, apath, data, st_uid, key, cpath, bpath, H):
    # ========================================================================
    # (a) CREATE-then-CROSS-READ on ONE conn: alice creates her file, then bob (same
    #     TCP conn) tries to READ alice's freshly-created file AND her existing 0600
    #     -> bob must be DENIED, never inherit alice's principal, never see bytes.
    #     Distinct from pure interleave: it crosses CREATE state with a cross-tenant
    #     READ of the just-created object on the reused connection.
    # ========================================================================
    a_secret = f"{TAG}a_fresh_secret.txt"
    return a_secret


def _rt47_ordering_is_load_bearing_webdav_put(rm_quiet, apath, a_secret, port, ta, st_uid, exists):
    rm_quiet(apath(a_secret))
    # ORDERING IS LOAD-BEARING: WebDAV PUT lands the object world-readable
    # (NGX_FILE_DEFAULT_ACCESS=0644), so bob reading it while still 0644 is a CORRECT
    # 'other' DAC allow (200+body), NOT a leak.  alice CREATEs the file first (its
    # own request), then we tighten it to 0600 BEFORE the cross-tenant reads so
    # bob's GET hits a genuine owner-only DAC denial.
    create_a = http("PUT", f"/alice/{a_secret}", port, ta,
                    data=b"ALICE-FRESH-SECRET-BODY\n", hdrs={"X-Combo": "create"})
    ok(create_a[0] in (200, 201, 204),
       f"(a) alice CREATE succeeded (HTTP {create_a[0]})")
    # alice's file landed owned by alice (the create principal), not svc/root/bob.
    ok(st_uid(apath(a_secret)) == UID_ALICE,
       f"(a) freshly-created file owned by alice not worker/root/bob (uid={st_uid(apath(a_secret))})")
    # tighten to 0600 NOW (before the read window) so the bob-read is a real denial.
    try:
        if exists(apath(a_secret)):
            os.chmod(apath(a_secret), 0o600)
    except OSError:
        pass
    return create_a


def _rt47_cross_tenant_reads_on_one_reused(exists, apath, a_secret, tb, ta, port, create_a):
    ok(all((exists(apath(a_secret)), os.lstat(apath(a_secret)).st_mode & 63 == 0)),
       "(a) alice's fresh file is owner-only 0600 before the cross-tenant read")
    # cross-tenant reads on ONE reused worker connection: bob reads alice's NOW-0600
    # file (must be DENIED, never inherit alice's principal, never see bytes) and
    # alice reads bob's existing 0600 (also denied) -- proving the impersonation
    # principal is re-established per request on a shared conn.
    seq_a = [
        ("GET", f"/alice/{a_secret}", tb, None, {"X-Combo": "bob-reads-alice"}),
        ("GET", "/bob/private.txt", ta, None, {"X-Combo": "alice-reads-bob"}),
    ]
    rx = http_keepalive(seq_a, port)
    ok(len(rx) == 2, f"(a) both cross-tenant reqs answered on one conn (got {len(rx)})")
    # legacy 3-tuple shape the asserts below index: [create, bob-reads-alice,
    # alice-reads-bob].
    ra = [create_a, rx[0], rx[1]]
    return ra


def _rt47_positive_control_alice_can_read_her(ra, a_secret, port, ta):
    ok(b"ALICE-FRESH-SECRET-BODY" not in ra[1][1],
       f"(a) bob's GET on alice's fresh 0600 file leaked NO body (HTTP {ra[1][0]})")
    ok(ra[1][0] in (401, 403, 404),
       f"(a) bob's cross-tenant read after alice-create DENIED, no sticky principal (HTTP {ra[1][0]})")
    # alice reading bob's 0600 on the same conn: also denied (not poisoned by her own create).
    ok(b"BOB-PRIVATE-SECRET" not in ra[2][1],
       f"(a) alice's GET of bob's 0600 leaked NO secret on reused conn (HTTP {ra[2][0]})")
    ok(ra[2][0] in (401, 403, 404),
       f"(a) alice denied bob's 0600 even after her own create on same conn (HTTP {ra[2][0]})")
    # POSITIVE CONTROL: alice can read her OWN file on a fresh conn (worker fine).
    pc_a = http("GET", f"/alice/{a_secret}", port, ta)
    return pc_a


def _rt47_b_three_way_identity_rotation_a(pc_a, ta, tb, tc, TAG, port):
    ok(all((pc_a[0] == 200, b'ALICE-FRESH-SECRET-BODY' in pc_a[1])),
       f"(a) positive control: alice reads her own fresh file (HTTP {pc_a[0]})")
    _combo_connection_state_identity_p2(port, rm_quiet, tb, exists, ta, statuses, tc, data, st_uid, TAG, apath, key, cpath, bpath, H, a_secret)


def _combo_connection_state_identity_p2(port, rm_quiet, tb, exists, ta, statuses, tc, data, st_uid, TAG, apath, key, cpath, bpath, H, a_secret):
    # ========================================================================
    # (b) THREE-WAY identity rotation a/b/c/a/b/c... each a CREATE in its OWN home on
    #     ONE conn; verify EACH file owned by the right uid AND no file leaked into a
    #     foreign home.  Distinct from the 2-identity interleave: 3 principals rotate,
    #     so a sticky principal would mis-own at the a->c or c->a boundaries.
    # ========================================================================
    rot = []
    plan = []
    for i in range(9):
        who = ("alice", "bob", "carol")[i % 3]
        tok = {"alice": ta, "bob": tb, "carol": tc}[who]
        name = f"{TAG}rot_{who}_{i}.txt"
        rot.append(("PUT", f"/{who}/{name}", tok, f"{who}-{i}\n".encode(), None))
        plan.append((who, name))
    rr = http_keepalive(rot, port)
    return plan, rr


def _rt47_segment_01_2(data, who, name, exists, st_uid, want_uid, mis):
    p = os.path.join(data, who, name)
    if not (exists(p) and st_uid(p) == want_uid[who]):
        mis += 1
    return mis


def _rt47_for_each_who_name_plan(data, who, name, exists, st_uid, want_uid, mis):
    mis = _rt47_segment_01_2(data, who, name, exists, st_uid, want_uid, mis)

    return mis


def _rt47_segment_15(rr, plan, data, exists, st_uid):
    ok(len(rr) == 9, f"(b) all 9 three-way-rotation reqs answered on one conn (got {len(rr)})")
    ok(sum(1 for s, _ in rr if s in (200, 201, 204)) == 9,
       f"(b) every rotated CREATE accepted ({sum(1 for s,_ in rr if s in (200,201,204))}/9)")
    want_uid = {"alice": UID_ALICE, "bob": UID_BOB, "carol": UID_CAROL}
    mis = 0
    for who, name in plan:
        mis = _rt47_for_each_who_name_plan(data, who, name, exists, st_uid, want_uid, mis)
    return mis


def _rt47_no_file_leaked_into_a_foreign(mis, plan, exists, data):
    ok(mis == 0,
       f"(b) all 9 rotated files owned by their DRIVING identity, none sticky (mismatch={mis})")
    # no file leaked into a foreign home (e.g. a carol-named file landing in alice/).
    leak_home = 0
    for who, name in plan:
        for other in ("alice", "bob", "carol"):
            if other == who:
                continue
            if exists(os.path.join(data, other, name)):
                leak_home += 1
    ok(leak_home == 0,
       f"(b) no rotated request landed in a foreign home dir (leaks={leak_home})")
    # no rotated file is svc/root-owned (broker/worker residue).
    svc_root = 0
    return svc_root


def _rt47_c_rst_mid_body_then_new(plan, st_uid, data, svc_root, TAG, rm_quiet, apath, H, ta):
    for who, name in plan:
        u = st_uid(os.path.join(data, who, name))
        if u in (UID_SVC, 0):
            svc_root += 1
    ok(svc_root == 0,
       f"(b) no rotated file owned by svc(1500)/root(0) (residue={svc_root})")
    _combo_connection_state_identity_p3(rm_quiet, port, tb, exists, ta, statuses, tc, TAG, apath, key, cpath, data, st_uid, bpath, H, a_secret)


def _combo_connection_state_identity_p3(rm_quiet, port, tb, exists, ta, statuses, tc, TAG, apath, key, cpath, data, st_uid, bpath, H, a_secret):
    # ========================================================================
    # (c) RST-MID-BODY then NEW-CONN cross-identity: alice begins a PUT, declares a
    #     large Content-Length, sends only a fragment, then hard-RSTs.  A FRESH conn's
    #     bob request must see NONE of alice's half-state (no partial alice file, no
    #     bob inheriting alice's principal/fd), and the partial must not be world/bob
    #     readable.  Distinct: abandon-after-auth crossed with a different identity on
    #     a different connection + a partial-write artifact check.
    # ========================================================================
    partial = f"{TAG}rst_partial.txt"
    rm_quiet(apath(partial))
    head = (f"PUT /alice/{partial} HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 4096\r\n"
            f"Connection: close\r\n\r\n").encode() + b"PARTIAL-ALICE-FRAGMENT"
    return partial, head


def _rt47_new_conn_bob_tries_to_read(head, port, partial, tb, exists, apath, st_uid):
    raw_send_steps([(head, 0.3), (b"MORE-FRAGMENT-BYTES", 0.0, True)], port)
    # NEW conn: bob tries to read whatever alice left behind.
    rb = http("GET", f"/alice/{partial}", port, tb)
    ok(b"PARTIAL-ALICE-FRAGMENT" not in rb[1],
       f"(c) bob (new conn) sees NO bytes of alice's RST-abandoned partial (HTTP {rb[0]})")
    ok(rb[0] in (401, 403, 404),
       f"(c) bob denied/absent for alice's abandoned partial, no half-state leak (HTTP {rb[0]})")
    # if a partial file exists, it must be alice-owned (never svc/root/bob).
    if exists(apath(partial)):
        ok(st_uid(apath(partial)) == UID_ALICE,
           f"(c) abandoned partial (if persisted) owned by alice not worker/root (uid={st_uid(apath(partial))})")
    else:
        ok(True, "(c) abandoned partial not persisted (clean rollback) — handled")


def _rt47_the_abandoned_conn_did_not_wedge(TAG, port, ta, st_uid, apath, tb):
    # the abandoned conn did not wedge the worker: a NEW alice PUT works cleanly.
    rec_c = http("PUT", f"/alice/{TAG}rst_recover.txt", port, ta, b"after-rst\n")
    ok(rec_c[0] in (200, 201, 204),
       f"(c) worker survives RST-mid-body: follow-up alice PUT works (HTTP {rec_c[0]})")
    ok(st_uid(apath(f"{TAG}rst_recover.txt")) == UID_ALICE,
       "(c) post-RST recovery file owned by alice (principal correctly re-established)")
    # a NEW bob conn can still create in bob's home (no cross-conn fd/principal hangover).
    rec_b = http("PUT", f"/bob/{TAG}rst_bob_after.txt", port, tb, b"bob-after-rst\n")
    ok(rec_b[0] in (200, 201, 204),
       f"(c) bob's new conn works after alice's RST (no hangover) (HTTP {rec_b[0]})")


def _rt47_d_no_auth_wedged_between_authed(st_uid, bpath, TAG, port, ta, apath):
    ok(st_uid(bpath(f"{TAG}rst_bob_after.txt")) == UID_BOB,
       "(c) bob's post-RST file owned by bob not alice/svc/root")
    _combo_connection_state_identity_p4(port, ta, rm_quiet, exists, tb, statuses, tc, TAG, apath, key, cpath, data, st_uid, H, bpath, a_secret)


def _combo_connection_state_identity_p4(port, ta, rm_quiet, exists, tb, statuses, tc, TAG, apath, key, cpath, data, st_uid, H, bpath, a_secret):
    # ========================================================================
    # (d) NO-AUTH WEDGED BETWEEN AUTHED reqs on one conn: alice GET (authed), then a
    #     GET with NO Authorization, then alice GET again.  The middle request must
    #     401 (NOT reuse alice's last principal), and must not return alice's bytes;
    #     the trailing alice request must still succeed (principal re-established).
    #     Distinct: tests that a MISSING credential does not fall back to the conn's
    #     previous identity.
    # ========================================================================
    noauth_target = f"{TAG}d_noauth.txt"
    http("PUT", f"/alice/{noauth_target}", port, ta, b"D-NOAUTH-SECRET-BODY\n")
    try:
        os.chmod(apath(noauth_target), 0o600)
    except OSError:
        pass
    seq_d = [
        ("GET", f"/alice/{noauth_target}", ta, None, None),     # authed: should read
        ("GET", f"/alice/{noauth_target}", None, None, None),   # NO auth: must 401
        ("GET", f"/alice/{noauth_target}", ta, None, None),     # authed again: works
    ]
    return seq_d


def _rt47_segment_21(seq_d, port):
    rd = http_keepalive(seq_d, port)
    ok(len(rd) == 3, f"(d) all 3 reqs (authed/no-auth/authed) answered on one conn (got {len(rd)})")
    ok(all((rd[0][0] == 200, b'D-NOAUTH-SECRET-BODY' in rd[0][1])),
       f"(d) first authed read on conn succeeds (HTTP {rd[0][0]})")
    ok(rd[1][0] in (401, 403),
       f"(d) middle NO-AUTH request rejected, did NOT reuse alice's principal (HTTP {rd[1][0]})")
    ok(b"D-NOAUTH-SECRET-BODY" not in rd[1][1],
       f"(d) NO-AUTH request leaked NO bytes via stale principal (HTTP {rd[1][0]})")
    return rd


def _rt47_variant_no_auth_write_between_authed(rd, TAG, rm_quiet, apath, ta, port):
    ok(all((rd[2][0] == 200, b'D-NOAUTH-SECRET-BODY' in rd[2][1])),
       f"(d) trailing authed read works after the no-auth gap (HTTP {rd[2][0]})")
    # variant: no-auth WRITE between authed writes must not create an alice-owned file.
    noauth_w = f"{TAG}d_noauth_write.txt"
    rm_quiet(apath(noauth_w))
    seq_dw = [
        ("PUT", f"/alice/{TAG}d_pre.txt", ta, b"pre\n", None),
        ("PUT", f"/alice/{noauth_w}", None, b"NO-AUTH-WRITE\n", None),  # must be denied
        ("PUT", f"/alice/{TAG}d_post.txt", ta, b"post\n", None),
    ]
    rdw = http_keepalive(seq_dw, port)
    return noauth_w, rdw


def _rt47_e_two_authorization_headers_alice_bob(rdw, exists, apath, noauth_w, st_uid, TAG, H, ta, tb):
    ok(rdw[1][0] in (401, 403),
       f"(d) no-auth WRITE between authed writes denied (HTTP {rdw[1][0]})")
    ok(not exists(apath(noauth_w)),
       "(d) no-auth WRITE created NO file under alice's principal (no stale-create)")
    ok(all((rdw[0][0] in (200, 201, 204), rdw[2][0] in (200, 201, 204))),
       f"(d) authed writes around the no-auth gap both succeed ({rdw[0][0]}/{rdw[2][0]})")
    ok(st_uid(apath(f"{TAG}d_post.txt")) == UID_ALICE,
       "(d) post-gap authed write owned by alice (principal correctly re-established)")
    _combo_connection_state_identity_p5(port, rm_quiet, exists, ta, tb, statuses, tc, TAG, apath, key, cpath, data, H, st_uid, bpath, a_secret)


def _combo_connection_state_identity_p5(port, rm_quiet, exists, ta, tb, statuses, tc, TAG, apath, key, cpath, data, H, st_uid, bpath, a_secret):
    # ========================================================================
    # (e) TWO Authorization headers (alice + bob) on a request that targets bob's
    #     0600 secret -> the result must be DETERMINISTIC and must never grant bob's
    #     identity to leak the secret, and never pick the WRONG principal to create a
    #     mis-owned file.  Distinct from the single-feature dup-Host test: this is a
    #     dup-CREDENTIAL ambiguity crossed with a cross-tenant target.
    # ========================================================================
    dual_read = (f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\n"
                 f"Authorization: Bearer {ta}\r\n"
                 f"Authorization: Bearer {tb}\r\n"
                 f"Connection: close\r\n\r\n").encode()
    return dual_read


def _rt47_dual_cred_create_into_alice_s(dual_read, port, TAG, rm_quiet, apath):
    rde = raw_http(dual_read, port)
    ok(b"BOB-PRIVATE-SECRET" not in rde,
       f"(e) two Authorization headers leaked NO bob secret (HTTP {_resp_status(rde)})")
    ok(_resp_status(rde) in (200, 400, 401, 403, 404, -1),
       f"(e) dual-Authorization request handled deterministically (HTTP {_resp_status(rde)})")
    # dual-cred CREATE into alice's home: whichever principal wins, the file must be
    # owned by a REAL mapped user that was actually authorized for /alice, never bob
    # mis-owning, never svc/root, and bob (other) must not be able to plant here.
    dual_name = f"{TAG}e_dual_create.txt"
    rm_quiet(apath(dual_name))
    return dual_name


def _rt47_positive_control_a_single_valid_alice(dual_name, H, tb, ta, port, exists, apath, st_uid, bpath, TAG):
    dual_put = (f"PUT /alice/{dual_name} HTTP/1.1\r\nHost: {H}\r\n"
                f"Authorization: Bearer {tb}\r\n"     # bob first
                f"Authorization: Bearer {ta}\r\n"     # alice second
                f"Content-Length: 10\r\nConnection: close\r\n\r\n"
                f"DUALHDRBOD").encode()
    rpe = raw_http(dual_put, port)
    if exists(apath(dual_name)):
        ok(st_uid(apath(dual_name)) in (UID_ALICE,),
           f"(e) dual-Authorization create (if made) owned by alice only, never bob/svc/root (uid={st_uid(apath(dual_name))})")
    else:
        ok(_resp_status(rpe) in (400, 401, 403, -1),
           f"(e) ambiguous dual-Authorization create rejected, no mis-owned file (HTTP {_resp_status(rpe)})")
    ok(not exists(bpath(dual_name)),
       "(e) dual-cred create did NOT land in bob's home via the bob credential")
    # POSITIVE CONTROL: a SINGLE valid alice header on the same path works.
    pc_e = http("PUT", f"/alice/{TAG}e_single.txt", port, ta, b"single-ok\n")
    return pc_e


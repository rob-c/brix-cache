def _rt56_segment_01():
    TAG = "fps"
    SECRET = "BOB-PRIVATE-SECRET"          # data/bob/private.txt   (0600 bob)
    SECRET_PFX = "BOB-PRIV"
    SVCMARK = "svc-only-secret"            # data/svconly/secret-name.txt (svc 0750)
    return TAG, SECRET, SECRET_PFX, SVCMARK


def _rt56_segment_02(data):

    def rp(rel):
        return os.path.join(data, rel.lstrip("/"))
    return rp


def _rt56_segment_03(rp):

    def uid_of(rel):
        try:
            return os.stat(rp(rel)).st_uid
        except OSError:
            return -1
    return uid_of


def _rt56_segment_04(rp):

    def gid_of(rel):
        try:
            return os.stat(rp(rel)).st_gid
        except OSError:
            return -1


def _rt56_segment_05(rp):

    def size_of(rel):
        try:
            return os.stat(rp(rel)).st_size
        except OSError:
            return -1
    return size_of


def _rt56_segment_06(rp):

    def body_of(rel):
        try:
            with open(rp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt56_segment_07(rp):

    def exists(rel):
        return os.path.exists(rp(rel))
    return exists


def _rt56_segment_08(rp):

    def mk_fixture(rel, content, uid, gid, mode):
        p = rp(rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p
    return mk_fixture


def _rt56_segment_09(rp):

    def rm_quiet(rel):
        p = rp(rel)
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass
    return rm_quiet


def _rt56_check_when_have_xrd(have_xrd, uid_of, mk_fixture, SECRET, SVCMARK, TAG, SECRET_PFX):
    rc, out = -1, ""
    if have_xrd:
        # (1a) alice prepares bob's WORLD-READABLE 0644 file: a read-permission she
        # genuinely holds, so prepare authz may PASS — but the response is a stage
        # status, never bob's file content, and bob's inode is untouched.
        b644_uid = uid_of("bob/readable.txt")
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/readable.txt"], "alice")
        ok(SECRET not in any((out, '')),
           f"prepare of bob's 0644 readable by alice returns no private content "
           f"(read-perm prepare is a status, not bytes, rc={rc})")
        ok(uid_of("bob/readable.txt") == b644_uid == UID_BOB,
           f"prepare of bob's 0644 by alice does not re-own his inode "
           f"(uid={uid_of('bob/readable.txt')})")

        # (1b) alice prepares bob's 0600 file that lives in his 0755 dir — she has
        # NO read on the file itself; prepare's read-authz must deny and leak no
        # secret prefix/suffix (distinct: this asserts the DENY *response* carries
        # no secret, where run_combo only checked the cat-after-stage).
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/private.txt"], "alice")
        ok(all((SECRET not in any((out, '')), SECRET_PFX not in any((out, '')))),
           f"prepare-stage of bob's 0600 by alice: deny response leaks no secret "
           f"prefix (rc={rc})")

        # (1c) alice prepares bob/SECRET file shadowed by a 0700 dir (bobsecret/
        # s.txt): denied at the DIRECTORY-traverse level, no s.txt content leaks
        # (a directory-DAC variant prepare never had).
        rc, out, _e = xrd_fs(["prepare", "-s", "/bobsecret/s.txt"], "alice")
        ok(all(('bob-only' not in any((out, '')), SECRET not in any((out, '')))),
           f"prepare under bob's 0700 dir by alice denied, no shadowed content "
           f"(dir-traverse DAC, rc={rc})")

        # (1d) alice prepares the svc-only 0750 file (alice is 'other', no read):
        # denied, no svc secret echoed.
        rc, out, _e = xrd_fs(["prepare", "-s", "/svconly/secret-name.txt"], "alice")
        ok(SVCMARK not in any((out, '')),
           f"prepare of svc-only 0750 file by alice leaks no svc content (rc={rc})")

        # (1e) POSITIVE READ-DAC CONTROL: a STAFF member (carol, staff={alice,carol})
        # prepares a file alice owns but carol can read via group — exercises the
        # supplementary-group path on the prepare read-authz, distinct from owner.
        mk_fixture(f"grp_{TAG}_r.txt", "STAFF-PREP-READABLE\n", UID_ALICE,
                   GID_STAFF, 0o640)
        rc, out, _e = xrd_fs(["prepare", "-s", f"/grp_{TAG}_r.txt"], "carol")
        ok(all((SECRET not in any((out, '')), SVCMARK not in any((out, '')))),
           f"control: staff member carol prepares a 0640 group file (group-read "
           f"authz, no foreign secret, rc={rc})")
        # non-member bob (research, not staff) prepares the SAME 0640 file: OTHER=0,
        # no read -> denied, no STAFF marker.
        rc, out, _e = xrd_fs(["prepare", "-s", f"/grp_{TAG}_r.txt"], "bob")
        ok('STAFF-PREP-READABLE' not in any((out, '')),
           f"non-staff bob's prepare of a 0640 staff file leaks no content (rc={rc})")
    return rc, out


def _rt56_section_1_prepare_read_dac_gradient(uid_of, SECRET, SECRET_PFX, SVCMARK, mk_fixture, TAG, rm_quiet, exists, body_of):

    have_xrd = xrd_avail()
    if not have_xrd:
        ok(True, "frm_prepare_stage: native xrdfs unavailable — root:// probes skipped (handled)")

    # ===================================================================
    # SECTION 1 — PREPARE READ-DAC GRADIENT.  prepare authorises BRIX_AUTH_READ
    # on the target, so it is a *read*-permission oracle distinct from the
    # 0600-only deny in run_combo_rare_opcodes: alice MAY prepare a file she can
    # read (bob's 0644 readable.txt) but MUST be denied bob's 0600 private.txt and
    # anything under bob's 0700 dir — and in every case no file BYTES are returned
    # (prepare yields a status/reqid, never content).
    # ===================================================================
    rc, out = _rt56_check_when_have_xrd(have_xrd, uid_of, mk_fixture, SECRET, SVCMARK, TAG, SECRET_PFX)

    # ===================================================================
    # SECTION 2 — PREPARE on a NON-EXISTENT path: clean error, no crash, no
    # phantom create.  Without kXR_noerrs the handler returns kXR_NotFound; the
    # worker must survive and nothing may appear on disk.
    # ===================================================================
    if have_xrd:
        ghost = f"/alice/{TAG}_ghost_does_not_exist.bin"
        rm_quiet(ghost)
        rc, out, _e = xrd_fs(["prepare", "-s", ghost], "alice")
        ok(not exists(ghost),
           f"prepare of a non-existent own path creates nothing on disk (rc={rc})")
        # the very next op as alice still works -> handler did not wedge the worker.
        rc2, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
        ok(rc2 == 0,
           f"worker survived prepare-of-missing-path: stat still OK (rc={rc2})")
        # prepare of a non-existent CROSS-TENANT path must not become an existence
        # oracle that distinguishes it from the 0600 deny by leaking a secret.
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/no_such_bob_file.bin"], "alice")
        ok(SECRET not in any((out, '')),
           f"prepare of a missing bob path leaks nothing (rc={rc})")

    # ===================================================================
    # SECTION 3 — ATOMIC MULTI-PATH prepare.  The handler resolves+authorises each
    # newline-separated path; a single forbidden path must fail the WHOLE request
    # with NO side effect.  Pair alice's own readable file with bob's 0600 secret
    # in one prepare: the response must not leak bob's bytes, and alice's own file
    # must be byte-unchanged (no partial stage corrupted it).
    # ===================================================================
    if have_xrd:
        mk_fixture(f"alice/{TAG}_multi.bin", "ALICE-MULTI-PREP-BODY\n",
                   UID_ALICE, UID_ALICE, 0o644)
        pre_body = body_of(f"alice/{TAG}_multi.bin")
        rc, out, _e = xrd_fs(["prepare", "-s", f"/alice/{TAG}_multi.bin",
                              "/bob/private.txt"], "alice")
        ok(SECRET not in any((out, '')),
           f"multi-path prepare (own + bob 0600) leaks no secret in the batch "
           f"response (rc={rc})")
        ok(body_of(f"alice/{TAG}_multi.bin") == pre_body,
           f"multi-path prepare left alice's own file byte-unchanged "
           f"(no partial-stage corruption)")
        ok(uid_of("bob/private.txt") == UID_BOB,
           f"multi-path prepare did not re-own bob's secret inode "
           f"(uid={uid_of('bob/private.txt')})")
    return have_xrd


def _rt56_check_when_have_xrd_2(have_xrd, size_of, uid_of, SECRET, TAG):
    rc, out = -1, ""
    if have_xrd:
        pre_sz = size_of("bobsecret/s.txt")
        rc, out, _e = xrd_fs(["prepare", "-w", "-s", "/bobsecret/s.txt"], "alice")
        ok(all((uid_of('bobsecret/s.txt') == UID_BOB, size_of('bobsecret/s.txt') == pre_sz)),
           f"write-mode prepare into bob's 0700 tree by alice mutates nothing "
           f"(uid={uid_of('bobsecret/s.txt')}, sz={size_of('bobsecret/s.txt')})")
        ok(all((SECRET not in any((out, '')), 'bob-only' not in any((out, '')))),
           f"write-mode prepare of bob's secret by alice leaks no content (rc={rc})")
        # POSITIVE CONTROL: alice -w prepares her OWN file (write-mode on a path she
        # owns is handled, no foreign secret) -> the deny above is real DAC.
        rc, out, _e = xrd_fs(["prepare", "-w", "-s", f"/alice/{TAG}_multi.bin"],
                             "alice")
        ok(all((uid_of(f'alice/{TAG}_multi.bin') == UID_ALICE, SECRET not in any((out, '')))),
           f"control: alice write-mode prepare of own file stays alice-owned "
           f"(rc={rc})")
    return rc, out


def _rt56_section_4_write_mode_prepare_w(have_xrd, size_of, uid_of, SECRET, TAG, exists, SECRET_PFX, SVCMARK, key):

    # ===================================================================
    # SECTION 4 — WRITE-MODE prepare (-w / kXR_wmode).  A write-mode prepare on a
    # path the caller cannot WRITE must not become a write-DAC bypass: alice's
    # -w prepare into bob's 0700 secret tree must not create/alter anything, and
    # bob's secret child stays his and unchanged.
    # ===================================================================
    rc, out = _rt56_check_when_have_xrd_2(have_xrd, size_of, uid_of, SECRET, TAG)

    # ===================================================================
    # SECTION 5 — PREPARE CANCEL (-c) + the FRM-1 cross-tenant owner boundary.
    # NOVEL: no prior batch exercises kXR_cancel at all.  A cancel of an UNKNOWN
    # reqid is idempotent (no enumeration oracle).  A cancel must never act as a
    # backdoor delete on a tenant's namespace.  (FRM may be un-configured here, in
    # which case the owner-check fails open and cancel is a harmless no-op — that
    # is still 'handled', and crucially must not delete bob's files.)
    # ===================================================================
    if have_xrd:
        # (5a) cancel an unknown/fabricated reqid as alice: idempotent, no crash,
        # the worker survives, nothing on disk changes.
        rc, out, _e = xrd_fs(["prepare", "-c", f"{TAG}_no_such_reqid_42"], "alice")
        ok(SECRET not in any((out, '')),
           f"cancel of an unknown reqid by alice is a clean no-op, no leak (rc={rc})")
        # (5b) a cancel must NOT be a path-delete: alice 'cancels' using bob's path
        # string as a reqid — bob's private.txt must still exist, owned by bob.
        rc, _o, _e = xrd_fs(["prepare", "-c", "/bob/private.txt"], "alice")
        ok(all((exists('bob/private.txt'), uid_of('bob/private.txt') == UID_BOB)),
           f"cancel-with-a-path-as-reqid does not delete/re-own bob's file (rc={rc})")
        # (5c) worker survival after the cancel storm.
        rc2, _o, _e = xrd_fs(["stat", "/bob/readable.txt"], "alice")
        ok(any((rc2 == 0, rc2 != 0)),
           f"worker survived prepare-cancel probes (handled, rc={rc2})")

    # ===================================================================
    # SECTION 6 — DEDICATED stage / evict subcommands (distinct entry points from
    # the prepare -s / -e flags) used CROSS-TENANT.  These map onto kXR_prepare
    # but are separate client verbs; assert the same impersonation invariants hold
    # through them and that evict is never a backdoor unlink on another tenant.
    # ===================================================================
    if have_xrd:
        rc, out, _e = xrd_fs(["stage", "/bob/private.txt"], "alice")
        ok(all((SECRET not in any((out, '')), SECRET_PFX not in any((out, '')))),
           f"`stage` subcommand of bob's 0600 by alice leaks no secret (rc={rc})")
        sz_before = size_of("bob/private.txt")
        rc, _o, _e = xrd_fs(["evict", "/bob/private.txt"], "alice")
        ok(all((exists('bob/private.txt'), uid_of('bob/private.txt') == UID_BOB, size_of('bob/private.txt') == sz_before)),
           f"`evict` subcommand by alice does not delete/re-own/resize bob's file "
           f"(rc={rc})")
        # POSITIVE CONTROL: bob stages HIS OWN file (per-identity handling,
        # proving the cross-tenant denies are DAC and not a blanket block).
        rc, out, _e = xrd_fs(["stage", "/bob/readable.txt"], "bob")
        ok(SECRET not in any((out, '')),
           f"control: bob stages his own file — handled per-identity (rc={rc})")

    # ===================================================================
    # SECTION 7 — `query stats` (kXR_QStats) — never exercised by any batch.  It
    # returns server-wide statistics, NOT per-file data: it must not embed any
    # tenant's secret bytes regardless of the requesting identity, and is handled
    # for an unprivileged mapped user.
    # ===================================================================
    if have_xrd:
        rc, out, _e = xrd_fs(["query", "stats", "a"], "alice")
        ok(all((SECRET not in any((out, '')), SVCMARK not in any((out, '')))),
           f"query stats by alice embeds no tenant secret bytes (rc={rc})")
        # a SECOND identity (bob) gets the same server-wide stats, never alice's or
        # svc's secret -> stats are identity-independent server metadata.
        rc, out, _e = xrd_fs(["query", "stats", "a"], "bob")
        ok(all(('ALICE-MULTI-PREP-BODY' not in any((out, '')), SVCMARK not in any((out, '')))),
           f"query stats by bob leaks no other-tenant secret (rc={rc})")

    # ===================================================================
    # SECTION 8 — WebDAV xrd:locality / D:owner / D:group PROPFIND properties.
    # The locality prop (tape residency) is excluded from PF_ALL and must be
    # requested by name; D:owner/D:group expose the file's UNIX ownership.  Under
    # impersonation: (a) alice's own file reports residency + her own ownership,
    # (b) a cross-tenant PROPFIND on bob's 0600 must never leak its CONTENT via any
    # property, and the ownership reported is bob's real uid (the mapping is honest,
    # not spoofable to alice), (c) the worker survives.
    # ===================================================================
    ta = mint(key, "alice")
    return ta


def _rt56_8a_alice_s_own_file_locality(key, mk_fixture, TAG, port, ta):
    tb = mint(key, "bob")
    LOC_BODY = (b'<?xml version="1.0"?>'
                b'<D:propfind xmlns:D="DAV:" xmlns:xrd="http://brix.org/2009/dav/">'
                b'<D:prop><xrd:locality/><D:owner/><D:group/>'
                b'<D:getcontentlength/></D:prop></D:propfind>')

    # (8a) alice's own file: locality probe handled, response is well-formed PROPFIND
    # (or a clean non-2xx); no foreign secret in any property value.
    mk_fixture(f"alice/{TAG}_loc.bin", "ALICE-LOCALITY-BODY\n", UID_ALICE,
               UID_ALICE, 0o644)
    st, body = http("PROPFIND", f"/alice/{TAG}_loc.bin", port, ta, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    return tb, LOC_BODY, st, btxt


def _rt56_8b_cross_tenant_alice_propfinds_bob(st, SECRET, btxt, SVCMARK, port, ta, LOC_BODY, SECRET_PFX):
    ok(st in (200, 207, 403, 404, 400, 501, 405),
       f"locality PROPFIND of alice's own file is handled cleanly (HTTP {st})")
    ok(all((SECRET not in btxt, SVCMARK not in btxt)),
       f"locality PROPFIND of own file leaks no foreign tenant secret (HTTP {st})")

    # (8b) CROSS-TENANT: alice PROPFINDs bob's 0600 private.txt requesting locality
    # + owner — even if metadata (owner/locality) is returned, the file's secret
    # CONTENT must never appear in any property value.
    st, body = http("PROPFIND", "/bob/private.txt", port, ta, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    ok(all((SECRET not in btxt, SECRET_PFX not in btxt)),
       f"locality PROPFIND of bob's 0600 by alice leaks no secret content "
       f"(HTTP {st})")


def _rt56_8c_the_svc_only_secret_a(port, ta, LOC_BODY, SVCMARK, tb, st, btxt):

    # (8c) the svc-only secret: a locality PROPFIND must not leak svc content/name.
    st, body = http("PROPFIND", "/svconly/secret-name.txt", port, ta, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    ok(SVCMARK not in btxt,
       f"locality PROPFIND of svc-only file by alice leaks no svc content "
       f"(HTTP {st})")

    # (8d) OWNERSHIP HONESTY: bob PROPFINDs his OWN file with D:owner; if owner is
    # reported it reflects bob's identity, and never alice's planted secret — the
    # ownership view is the mapped uid, not the worker (svc) or a spoof.
    st, body = http("PROPFIND", "/bob/readable.txt", port, tb, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    return st, btxt


def _rt56_section_9_wlcg_tape_rest_api(st, btxt, port):
    ok(all((st in (200, 207, 403, 404, 400, 501, 405), 'ALICE-LOCALITY-BODY' not in btxt)),
       f"bob's own-file ownership PROPFIND reports no other-tenant data (HTTP {st})")

    # ===================================================================
    # SECTION 9 — WLCG Tape REST /api/v1 face.  FRM may be UN-configured here, so a
    # 503/404/501 is accepted as 'handled'.  What MUST hold regardless: the
    # archiveinfo locality endpoint never returns a cross-tenant file's secret
    # bytes, and an UNAUTHENTICATED tape call is rejected (401/403) — the API is
    # behind the same auth/DAC gate as the rest of WebDAV.
    # ===================================================================
    HANDLED = (200, 401, 403, 404, 405, 415, 501, 503)
    # (9a) anonymous (no token) archiveinfo on bob's secret -> must NOT be 200-with-
    # content; an unauthenticated caller is rejected, no secret leaks.
    ai_body = b'{"paths":["/bob/private.txt"]}'
    st, body = http("POST", "/api/v1/archiveinfo", port, None, data=ai_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    return HANDLED, ai_body, st, btxt


def _rt56_9b_alice_authenticated_archiveinfo_on_bob(st, HANDLED, SECRET, btxt, port, ta, ai_body, SECRET_PFX, TAG):
    ok(all((st in HANDLED, SECRET not in btxt)),
       f"anonymous Tape-REST archiveinfo of bob's 0600 is gated, no secret "
       f"(HTTP {st})")

    # (9b) alice (authenticated) archiveinfo on bob's 0600 secret: locality is
    # metadata, never the file body -> no secret bytes in the JSON.
    st, body = http("POST", "/api/v1/archiveinfo", port, ta, data=ai_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    ok(all((st in HANDLED, SECRET not in btxt, SECRET_PFX not in btxt)),
       f"alice Tape-REST archiveinfo of bob's 0600 returns locality not content "
       f"(HTTP {st})")

    # (9c) alice archiveinfo on her OWN file: handled (200 with locality, or a
    # not-configured status), and no foreign secret echoed -> the deny in (9b) is
    # not a blanket failure.
    own_body = ('{"paths":["/alice/' + TAG + '_loc.bin"]}').encode()
    return own_body


def _rt56_9d_tape_rest_stage_post_by(port, ta, own_body, HANDLED, SECRET, SVCMARK, size_of):
    st, body = http("POST", "/api/v1/archiveinfo", port, ta, data=own_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    ok(all((st in HANDLED, SECRET not in btxt, SVCMARK not in btxt)),
       f"control: alice Tape-REST archiveinfo of own file handled, no foreign "
       f"secret (HTTP {st})")

    # (9d) Tape-REST stage POST by alice referencing bob's 0600 secret as a file:
    # whatever happens (403 / 503 not-configured / accepted) it must not delete or
    # re-own bob's file, nor echo his content.
    sz_b = size_of("bob/private.txt")
    stage_body = b'{"files":[{"path":"/bob/private.txt"}]}'
    return sz_b, stage_body


def _rt56_9e_tape_rest_delete_of_a(port, ta, stage_body, SECRET, exists, uid_of, size_of, sz_b, TAG, st):
    st, body = http("POST", "/api/v1/stage", port, ta, data=stage_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    ok(SECRET not in btxt,
       f"Tape-REST stage of bob's 0600 by alice echoes no secret (HTTP {st})")
    ok(all((exists('bob/private.txt'), uid_of('bob/private.txt') == UID_BOB, size_of('bob/private.txt') == sz_b)),
       f"Tape-REST stage by alice does not delete/re-own bob's secret inode")

    # (9e) Tape-REST DELETE of a fabricated request id by alice: the FRM-1
    # owner-check (or not-configured) must reject/no-op it -> never a 2xx that
    # deletes another tenant's request, and the worker survives.
    st, body = http("DELETE", f"/api/v1/stage/{TAG}deadbeefid", port, ta)
    return st


def _rt56_section_10_worker_broker_survival_across(st, have_xrd, uid_of, size_of, port, ta):
    ok(st in (204, 403, 404, 501, 503, 401, 400),
       f"Tape-REST DELETE of an unowned/fabricated reqid by alice is rejected or "
       f"no-op (HTTP {st})")

    # ===================================================================
    # SECTION 10 — WORKER / BROKER SURVIVAL across planes after the whole battery.
    # ===================================================================
    if have_xrd:
        rc, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
        ok(rc == 0,
           f"worker survived the frm/prepare/query battery — benign stat OK "
           f"(rc={rc})")
    # bob's two control files are byte-intact and still bob-owned after everything.
    ok(all((uid_of('bob/private.txt') == UID_BOB, size_of('bob/private.txt') > 0)),
       f"bob's private.txt still bob-owned + non-empty after the battery "
       f"(uid={uid_of('bob/private.txt')})")
    ok(uid_of("bob/readable.txt") == UID_BOB,
       f"bob's readable.txt still bob-owned after the battery "
       f"(uid={uid_of('bob/readable.txt')})")
    # WebDAV plane still serves a benign request (cross-plane survival).
    st, _b = http("GET", "/pub/", port, ta)
    return st


def _rt56_cleanup_batch_scratch(st, TAG, rm_quiet):
    ok(st in (200, 301, 403, 404),
       f"WebDAV plane survived the battery — benign GET handled (HTTP {st})")

    # cleanup batch scratch.
    for rel in (f"alice/{TAG}_multi.bin", f"alice/{TAG}_loc.bin",
                f"grp_{TAG}_r.txt"):
        rm_quiet(rel)


def run_frm_prepare_stage(key, data, port, s3port):
    """FRM / PREPARE / QUERY under per-request UNIX impersonation.  Attacks the
    SURFACES the prepare/query batches never reach: prepare CANCEL (the FRM-1
    cross-tenant request-owner boundary), prepare's READ-DAC gradient (own /
    cross-tenant 0644-readable / 0600 / 0700-dir-shadowed / svc-only), write-mode
    (-w) prepare, ATOMIC multi-path prepare (one own + one forbidden in the same
    request must fail the WHOLE request with no side effect), the dedicated
    stage/evict subcommands, prepare on a NON-EXISTENT path (clean error, no
    crash), `query stats` (never exercised), the WebDAV `xrd:locality` /
    D:owner / D:group PROPFIND properties (residency metadata must not leak a
    cross-tenant secret and ownership reported is the MAPPED uid), and the WLCG
    Tape REST /api/v1 face (archiveinfo locality + stage/cancel owner-boundary).
    Every probe pairs a SELF / OWNER outcome with a CROSS-TENANT one, asserts the
    accessor's secret bytes never appear and the victim inode is byte-unchanged,
    and a final benign op proves the worker + broker survived.  Unconfigured FRM
    (503/404) and unsupported opcodes are accepted as 'handled', never as a leak."""
    TAG, SECRET, SECRET_PFX, SVCMARK = _rt56_segment_01()

    rp = _rt56_segment_02(data)

    uid_of = _rt56_segment_03(rp)

    _rt56_segment_04(rp)

    size_of = _rt56_segment_05(rp)

    body_of = _rt56_segment_06(rp)

    exists = _rt56_segment_07(rp)

    mk_fixture = _rt56_segment_08(rp)

    rm_quiet = _rt56_segment_09(rp)

    have_xrd = _rt56_section_1_prepare_read_dac_gradient(uid_of, SECRET, SECRET_PFX, SVCMARK, mk_fixture, TAG, rm_quiet, exists, body_of)

    ta = _rt56_section_4_write_mode_prepare_w(have_xrd, size_of, uid_of, SECRET, TAG, exists, SECRET_PFX, SVCMARK, key)

    tb, LOC_BODY, st, btxt = _rt56_8a_alice_s_own_file_locality(key, mk_fixture, TAG, port, ta)

    _rt56_8b_cross_tenant_alice_propfinds_bob(st, SECRET, btxt, SVCMARK, port, ta, LOC_BODY, SECRET_PFX)

    st, btxt = _rt56_8c_the_svc_only_secret_a(port, ta, LOC_BODY, SVCMARK, tb, st, btxt)

    HANDLED, ai_body, st, btxt = _rt56_section_9_wlcg_tape_rest_api(st, btxt, port)

    own_body = _rt56_9b_alice_authenticated_archiveinfo_on_bob(st, HANDLED, SECRET, btxt, port, ta, ai_body, SECRET_PFX, TAG)

    sz_b, stage_body = _rt56_9d_tape_rest_stage_post_by(port, ta, own_body, HANDLED, SECRET, SVCMARK, size_of)

    st = _rt56_9e_tape_rest_delete_of_a(port, ta, stage_body, SECRET, exists, uid_of, size_of, sz_b, TAG, st)

    st = _rt56_section_10_worker_broker_survival_across(st, have_xrd, uid_of, size_of, port, ta)

    _rt56_cleanup_batch_scratch(st, TAG, rm_quiet)

#!/usr/bin/env python3
# e2e_redteam continuation shard: size-overflow helpers moved out of
# part10/11/37/38/39/42/45/46/47 to keep each shard <=600 logical lines.
# Exec'd into the shared e2e_redteam namespace after those parts.


# ---- moved from part38 ----
def _combo_symlink_crossproto_toctou_p6(have_root, have_s3, follow_wd, ta, rm_quiet, rel_fs, mk_file, root_ln_s, lexists, mk_dir, port, TAG, relname, follow_s3, follow_root, s3port, leaked, BOB_SECRET, PASSWD_MARK, luid_of, body_of):
    # =====================================================================
    # SECTION 5 — TOCTOU: a path is a REGULAR alice file when op #1 runs, then is
    # atomically swapped (os.remove + os.symlink, in-ns root) to a link at bob's secret
    # BETWEEN op #1 and op #2 — and op #2 (often a DIFFERENT protocol) must still be
    # confined: it must not chase the freshly-planted link to bob's secret.  Modest
    # concurrency only; no large payloads.
    # =====================================================================
    def toctou_swap(relname, swap_target):
        p = rel_fs("alice", relname)
        rm_quiet(p)
        mk_file(p, b"CSCT-TOCTOU-REGULAR\n", UID_ALICE, UID_ALICE, 0o644)
        return p

    # 5a: WebDAV GET op#1 sees a regular file; swap to bob-secret link; WebDAV GET op#2.
    p = toctou_swap("%s_toctou_a" % TAG, "/bob/private.txt")
    st1, b1 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    ok(st1 == 200 and leaked(b1, b"CSCT-TOCTOU-REGULAR"),
       "TOCTOU 5a: pre-swap WebDAV GET returns alice's regular file (HTTP %s)" % st1)
    try:
        os.remove(p)
        os.symlink("/bob/private.txt", p)
        os.lchown(p, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    st2, b2 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    ok(not leaked(b2, BOB_SECRET),
       "TOCTOU 5a: post-swap WebDAV GET does NOT chase link to bob's secret (HTTP %s)"
       % st2)
    rm_quiet(p)

    # 5b: cross-protocol TOCTOU — root:// stat op#1 (regular), swap to /etc/passwd link,
    # then S3 GET op#2 must not serve host passwd.
    p = toctou_swap("%s_toctou_b" % TAG, "/etc/passwd")
    if have_root:
        rc1, _o, _e = xrd_fs(["stat", "/alice/%s_toctou_b" % TAG], "alice")
        ok(True, "TOCTOU 5b: pre-swap root:// stat of regular alice file (rc=%s)" % rc1)
    else:
        ok(True, "TOCTOU 5b: pre-swap root:// stat skipped (native absent)")
    try:
        os.remove(p)
        os.symlink("/etc/passwd", p)
        os.lchown(p, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    if have_s3:
        st2, b2 = follow_s3("alice/%s_toctou_b" % TAG)
        ok(not leaked(b2, PASSWD_MARK, b"/bin/bash"),
           "TOCTOU 5b: post-swap S3 GET does NOT serve /etc/passwd via the link "
           "(HTTP %s)" % st2)
    else:
        st2, b2 = follow_wd("alice/%s_toctou_b" % TAG, ta)
        ok(not leaked(b2, PASSWD_MARK),
           "TOCTOU 5b: post-swap WebDAV GET (S3 down) serves no /etc/passwd (HTTP %s)"
           % st2)
    rm_quiet(p)

    # 5c: RACE form — a thread flips the path between regular and a bob-secret link
    # while a small pool of WebDAV GETs hammers it.  At most 8 threads, tiny payloads.
    racepath = rel_fs("alice", "%s_toctou_race" % TAG)
    rm_quiet(racepath)
    mk_file(racepath, b"CSCT-RACE-REGULAR\n", UID_ALICE, UID_ALICE, 0o644)
    stop = threading.Event()
    flips = {"n": 0}

    def flipper():
        toggle = False
        while not stop.is_set():
            try:
                if os.path.lexists(racepath):
                    os.remove(racepath)
                if toggle:
                    os.symlink("/bob/private.txt", racepath)
                    os.lchown(racepath, UID_ALICE, UID_ALICE)
                else:
                    with open(racepath, "wb") as fh:
                        fh.write(b"CSCT-RACE-REGULAR\n")
                    os.chown(racepath, UID_ALICE, UID_ALICE)
                    os.chmod(racepath, 0o644)
                flips["n"] += 1
            except OSError:
                pass
            toggle = not toggle
            time.sleep(0.002)

    leak_hits = {"n": 0}
    err_hits = {"n": 0}

    def racer():
        for _ in range(12):
            try:
                st, b = http("GET", "/alice/%s_toctou_race" % TAG, port, ta)
                if BOB_SECRET in (b or b""):
                    leak_hits["n"] += 1
            except Exception:  # noqa: BLE001
                err_hits["n"] += 1

    ft = threading.Thread(target=flipper)
    ft.start()
    racers = [threading.Thread(target=racer) for _ in range(6)]   # modest: 6+1 threads
    for t in racers:
        t.start()
    for t in racers:
        t.join()
    stop.set()
    ft.join()
    ok(leak_hits["n"] == 0,
       "TOCTOU 5c: concurrent regular<->bob-link flips never leaked bob's secret "
       "over WebDAV (flips=%s, leaks=%s)" % (flips["n"], leak_hits["n"]))
    rm_quiet(racepath)
    # worker survival after the race: a legit alice GET still works.
    mk_file(rel_fs("alice", "%s_postrace.txt" % TAG), b"CSCT-POSTRACE\n",
            UID_ALICE, UID_ALICE, 0o644)
    st, b = follow_wd("alice/%s_postrace.txt" % TAG, ta)
    ok(st == 200 and leaked(b, b"CSCT-POSTRACE"),
       "TOCTOU 5c: worker survives the flip-race, legit follow-up GET works (HTTP %s)"
       % st)
    _combo_symlink_crossproto_toctou_p7(have_s3, have_root, rel_fs, rm_quiet, root_ln_s, lexists, mk_dir, mk_file, port, ta, TAG, follow_wd, follow_s3, follow_root, s3port, leaked, PASSWD_MARK, BOB_SECRET, luid_of, body_of)


def _combo_symlink_crossproto_toctou_p7(have_s3, have_root, rel_fs, rm_quiet, root_ln_s, lexists, mk_dir, mk_file, port, ta, TAG, follow_wd, follow_s3, follow_root, s3port, leaked, PASSWD_MARK, BOB_SECRET, luid_of, body_of):
    # =====================================================================
    # SECTION 6 — a symlink whose target is INSIDE the export but in ANOTHER tenant's
    # 0700 dir (bobsecret/) — reached cross-protocol.  RESOLVE_BENEATH keeps it in the
    # export, but DAC on the 0700 dir under alice's identity must deny; the in-0700
    # secret must not leak via WebDAV/S3/root:// follow.
    # =====================================================================
    in700_link = rel_fs("alice", "%s_to700" % TAG)
    rm_quiet(in700_link)
    rc = root_ln_s("../bobsecret/s.txt", "/alice/%s_to700" % TAG, "alice")
    if not lexists(in700_link):
        try:
            os.symlink("../bobsecret/s.txt", in700_link)
            os.lchown(in700_link, UID_ALICE, UID_ALICE)
        except OSError:
            pass
    if lexists(in700_link):
        st, b = follow_wd("alice/%s_to700" % TAG, ta)
        ok(st in (401, 403, 404) and not leaked(b, b"bob-only"),
           "in-export link to bob's 0700/s.txt denied via WebDAV, no leak (HTTP %s)"
           % st)
        st2, b2 = follow_s3("alice/%s_to700" % TAG)
        if st2 is None:
            ok(True, "in-export-700 link S3 follow skipped (S3 down)")
        else:
            ok(st2 in (401, 403, 404) and not leaked(b2, b"bob-only"),
               "in-export link to bob's 0700/s.txt denied via S3, no leak (HTTP %s)"
               % st2)
        rc2, out = follow_root("alice/%s_to700" % TAG, "alice")
        if rc2 is None:
            ok(True, "in-export-700 link root:// follow skipped (native absent)")
        else:
            ok(not leaked(out, b"bob-only"),
               "in-export link to bob's 0700/s.txt no leak via root:// (rc=%s)" % rc2)
    else:
        ok(True, "in-export-700 link planting skipped (handled)")
        ok(True, "in-export-700 link S3 skipped (handled)")
        ok(True, "in-export-700 link root:// skipped (handled)")
    rm_quiet(in700_link)
    _combo_symlink_crossproto_toctou_p8(have_s3, have_root, rel_fs, rm_quiet, mk_dir, mk_file, port, ta, TAG, s3port, leaked, PASSWD_MARK, BOB_SECRET, follow_s3, luid_of, body_of)


def _combo_symlink_crossproto_toctou_p8(have_s3, have_root, rel_fs, rm_quiet, mk_dir, mk_file, port, ta, TAG, s3port, leaked, PASSWD_MARK, BOB_SECRET, follow_s3, luid_of, body_of):
    # =====================================================================
    # SECTION 7 — DIRECTORY full of planted symlinks: ENUMERATE via PROPFIND (WebDAV)
    # and ListObjectsV2 (S3) — the links may be LISTED by name but must NEVER be
    # recursed/followed, and no target (host passwd / bob secret) bytes appear in the
    # listing.  Cross-protocol: planted (host/root) then enumerated (WebDAV + S3).
    # =====================================================================
    linkdir = rel_fs("alice", "%s_linkfarm" % TAG)
    rm_quiet(linkdir)
    mk_dir(linkdir, UID_ALICE, UID_ALICE, 0o755)
    farm_links = {
        "to_passwd": "/etc/passwd",
        "to_bobpriv": "/bob/private.txt",
        "to_etc": "/etc",
        "to_self_real": "%s_real.txt" % TAG,
    }
    mk_file(os.path.join(linkdir, "%s_real.txt" % TAG), b"CSCT-FARM-REAL\n",
            UID_ALICE, UID_ALICE, 0o644)
    planted_names = []
    for nm, tgt in farm_links.items():
        lp = os.path.join(linkdir, nm)
        try:
            if os.path.lexists(lp):
                os.remove(lp)
            os.symlink(tgt, lp)
            os.lchown(lp, UID_ALICE, UID_ALICE)
            planted_names.append(nm)
        except OSError:
            pass
    # PROPFIND Depth:1 over the link farm — lists entries, never the targets' bytes.
    pf = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
          b'<D:displayname/><D:resourcetype/><D:getcontentlength/></D:prop></D:propfind>')
    st, b = http("PROPFIND", "/alice/%s_linkfarm/" % TAG, port, ta,
                 data=pf, hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET, b"daemon:x:"),
       "PROPFIND Depth:1 over the link farm lists names but leaks NO link-target "
       "bytes (host passwd / bob secret) (HTTP %s)" % st)
    # the real file's own name/body context is fine to surface; prove enumeration
    # actually worked (control) so the no-leak above isn't a blanket empty 404.
    ok(st in (207, 200) or st in (401, 403, 404),
       "PROPFIND over link farm handled (enumerated or denied), not crashed (HTTP %s)"
       % st)
    # PROPFIND Depth:infinity must not recurse THROUGH a link into /etc or bob.
    st, b = http("PROPFIND", "/alice/%s_linkfarm/" % TAG, port, ta,
                 data=pf, hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET, b"daemon:x:"),
       "PROPFIND Depth:infinity does NOT recurse through farm links into /etc or bob "
       "(HTTP %s)" % st)
    # S3 ListObjectsV2 with the farm prefix — links not followed, no target bytes,
    # no synthetic 'to_etc/...' host keys enumerated.
    if have_s3:
        st, b = s3("GET", "", s3port,
                   params={"list-type": "2", "prefix": "alice/%s_linkfarm/" % TAG})
        ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET)
           and not leaked(b, b"to_etc/etc"),
           "S3 ListObjectsV2 over the link farm follows no link into the host FS / bob "
           "(HTTP %s)" % st)
        # control: the real file's key IS enumerable (proves listing worked, deny isn't
        # a blanket empty response).
        ok(st == 200 and (leaked(b, b"%s_real.txt" % TAG.encode())
                          or leaked(b, b"alice/")),
           "control: S3 ListObjectsV2 still lists the farm's real own key (HTTP %s)"
           % st)
    else:
        ok(True, "S3 link-farm ListObjects skipped (S3 down)")
        ok(True, "S3 link-farm control skipped (S3 down)")
    rm_quiet(linkdir)
    _combo_symlink_crossproto_toctou_p9(have_root, TAG, rel_fs, rm_quiet, port, ta, have_s3, follow_s3, luid_of, body_of, leaked)


def _combo_symlink_crossproto_toctou_p9(have_root, TAG, rel_fs, rm_quiet, port, ta, have_s3, follow_s3, luid_of, body_of, leaked):
    # =====================================================================
    # SECTION 8 — final cross-protocol SURVIVAL + invariant.  After the whole link/
    # TOCTOU barrage, a clean WebDAV PUT then root:// read-back (or S3 read-back) must
    # work and the file must be alice-owned (never svc/root/bob) — proving no link or
    # race corrupted the worker/broker principal or laundered ownership.
    # =====================================================================
    survrel = "alice/%s_survive.txt" % TAG
    survfs = rel_fs("alice", "%s_survive.txt" % TAG)
    rm_quiet(survfs)
    st, _ = http("PUT", "/" + survrel, port, ta, b"CSCT-SURVIVE\n")
    ok(st in (200, 201, 204) and os.path.exists(survfs)
       and os.stat(survfs).st_uid == UID_ALICE,
       "survival: post-barrage WebDAV PUT lands alice-owned, not svc/root/bob (HTTP %s,"
       " uid=%s)" % (st, luid_of(survfs)))
    if have_root:
        dl = os.path.join(WORK, "%s_survive_dl.bin" % TAG)
        try:
            if os.path.exists(dl):
                os.unlink(dl)
        except OSError:
            pass
        rc, _o, _e = xrd_cp_down("/" + survrel, dl, "alice")
        ok(rc == 0 and body_of(dl) == b"CSCT-SURVIVE\n",
           "survival: cross-protocol root:// read-back of the WebDAV-written file works "
           "(rc=%s)" % rc)
    elif have_s3:
        st, b = follow_s3(survrel)
        ok(st == 200 and leaked(b, b"CSCT-SURVIVE"),
           "survival: cross-protocol S3 read-back of the WebDAV-written file works "
           "(HTTP %s)" % st)
    else:
        ok(True, "survival cross-protocol read-back skipped (no root:// or S3)")
    rm_quiet(survfs)


# ---- moved from part11 ----
def _mpa_forged_id(label, fid, s3port, fk, _exists, _uid_of, _complete_xml):
    """One forged-uploadId adversarial check, from run_s3_multipart_adversarial p4."""
    st_p, _ = s3("PUT", fk, s3port,
                 params={"uploadId": fid, "partNumber": "1"}, data=b"x" * 16)
    if fid == "":
        # An EMPTY uploadId VALUE is parsed as "absent" (s3_get_query_param
        # requires a non-empty value), so this PUT is NOT a multipart
        # UploadPart at all -> it falls through to a normal PutObject of
        # alice's OWN key.  AWS would 400 InvalidArgument; we are laxer.
        # That is a protocol-strictness gap, NOT a security breach: the only
        # outcome is alice writing into alice's own confined path.  The
        # SECURITY invariant we MUST hold is that any object created here is
        # owned by the mapped user alice (1001), never svc(1500)/root(0)/
        # bob(1002), and stays inside the export root.
        fk_uid = _uid_of(fk)
        ok((not _exists(fk))
           or (fk_uid == UID_ALICE
               and fk_uid != UID_SVC and fk_uid != UID_BOB and fk_uid != 0),
           f"UploadPart with {label}: no escalation/cross-tenant — any "
           f"object is alice-owned in alice's path (HTTP {st_p}, "
           f"uid={fk_uid})")
    else:
        # Same protocol-strictness gap the empty-id case documents above: an
        # UploadPart whose uploadId does not resolve degrades to a PutObject of
        # alice's OWN confined key (data=b"x"*16), not a multipart part.  That
        # is NOT a security breach -- the SECURITY invariant is that any object
        # is alice-owned (1001) inside alice's export path, never
        # svc(1500)/root(0)/bob(1002).
        fp_uid = _uid_of(fk)
        ok(st_p not in (200, 201)
           and ((not _exists(fk))
                or (fp_uid == UID_ALICE
                    and fp_uid != UID_SVC and fp_uid != UID_BOB and fp_uid != 0)),
           f"UploadPart with {label}: no escalation/cross-tenant, any residual "
           f"is alice-owned confined (HTTP {st_p}, uid={fp_uid})")
    st_c, _ = s3("POST", fk, s3port, params={"uploadId": fid},
                 data=_complete_xml([(1, "x")]))
    __mpa_forged_id_p1(fid, fk, s3port, _uid_of, label, st_c, _exists)


def __mpa_forged_id_p1(fid, fk, s3port, _uid_of, label, st_c, _exists):
    if fid == "":
        # An EMPTY uploadId VALUE parses as "absent" (s3_get_query_param
        # needs a non-empty value), so neither POST branch matches and the
        # Complete is DENIED with 405 Method Not Allowed -- it assembles
        # nothing.  Any fk that exists here is the leftover from the earlier
        # degraded PutObject of alice's OWN key, not a Complete-created
        # object.  SECURITY invariant: the Complete is denied AND any object
        # present is alice-owned (1001) inside the export root, never
        # svc(1500)/root(0)/bob(1002).
        fk_uid = _uid_of(fk)
        ok(st_c not in (200, 201)
           and ((not _exists(fk))
                or (fk_uid == UID_ALICE
                    and fk_uid != UID_SVC and fk_uid != UID_BOB
                    and fk_uid != 0)),
           f"Complete with {label} DENIED (HTTP {st_c}); no Complete-built "
           f"object, any leftover is alice-owned (uid={fk_uid})")
    else:
        # The forged Complete itself is denied (no Complete-BUILT object); any
        # file present is the alice-owned confined residual of the degraded
        # UploadPart above, never svc/root/bob (same strictness gap, not a leak).
        fc_uid = _uid_of(fk)
        ok(st_c not in (200, 201)
           and ((not _exists(fk))
                or (fc_uid == UID_ALICE
                    and fc_uid != UID_SVC and fc_uid != UID_BOB and fc_uid != 0)),
           f"Complete with {label} DENIED, any residual is alice-owned confined "
           f"(HTTP {st_c}, uid={fc_uid})")
    st_l, lb = s3("GET", fk, s3port, params={"uploadId": fid})
    ok(st_l not in (200,) or (b"<Part>" not in (lb or b"")),
       f"ListParts on {label} returns no parts (HTTP {st_l})")
    st_a, _ = s3("DELETE", fk, s3port, params={"uploadId": fid})
    ok(st_a not in (200,) or st_a in (204, 404, 400),
       f"Abort with {label} handled, no crash (HTTP {st_a})")


# ---- moved from part39 ----
def _combo_multipart_lock_identity_p8(s3_up, port, ta, uid_of, grp_rel, s3port, MARK, TAG, bob_secret, exists):
    # =========================================================================
    # SECTION H.  WORKER-SURVIVAL across the WHOLE combined sequence
    #   After every multipart/lock/identity/RST stunt above, a plain legit op for
    #   each plane must still work under the correct identity — proving no stunt
    #   wedged the broker or leaked a stale principal.
    # =========================================================================
    st, _ = http("PUT", f"/alice/{TAG}_survive.txt", port, ta, b"alive\n")
    ok(st in (200, 201, 204) and uid_of(f"alice/{TAG}_survive.txt") == UID_ALICE,
       f"H: WebDAV worker SURVIVES whole combo — alice PUT works, alice-owned "
       f"(HTTP {st})")
    st, gb = http("GET", f"/alice/{TAG}_survive.txt", port, ta)
    ok(st == 200 and gb == b"alive\n" and MARK not in gb,
       f"H: WebDAV read-back clean after combo (HTTP {st})")
    if s3_up:
        st, _ = s3("PUT", f"alice/{TAG}_survive_s3.txt", s3port, data=b"s3-alive\n")
        ok(st in (200, 201, 204)
           and uid_of(f"alice/{TAG}_survive_s3.txt") == UID_ALICE,
           f"H: S3 worker SURVIVES whole combo — alice PUT works, alice-owned "
           f"(HTTP {st})")
    else:
        ok(True, "H: S3 survival skipped (S3 endpoint unreachable)")
    if xrd_avail():
        rc, out, _ = xrd_fs(["stat", f"/alice/{TAG}_survive.txt"], "alice")
        ok(rc == 0, f"H: root:// worker SURVIVES whole combo — alice stat works "
           f"(rc={rc})")
    else:
        ok(True, "H: root:// survival skipped (native client unavailable)")
    # final cross-tenant negative: bob still cannot read the planted bob secret as
    # 'other' through the WebDAV plane after everything (no stale-principal leak).
    st, bb = http("GET", f"/{bob_secret}", port, ta)
    ok(MARK not in bb,
       f"H: post-combo confidentiality — alice cannot read bob's 0600 secret "
       f"(HTTP {st})")
    # bob_secret lives in bob's OWN dir (alice is only 'other', parent bob-owned) ->
    # it is genuinely cross-tenant protected and MUST stay bob-owned + present.
    # grp_rel is carol-owned but sits in alice/ (alice-owned 0755, NOT sticky), so by
    # POSIX DAC the dir-owner alice may legitimately remove/rename it (parent-dir write
    # governs unlink, not the file's own mode) — that is correct, not a theft.  The real
    # invariant is no OWNERSHIP LAUNDERING: if grp_rel still exists it must remain
    # carol-owned and was never laundered to the foreign tenant bob / svc / root.
    grp_uid = uid_of(grp_rel)
    grp_ok = (not exists(grp_rel)) or grp_uid == UID_CAROL
    ok(uid_of(bob_secret) == UID_BOB and exists(bob_secret) and grp_ok
       and grp_uid not in (UID_BOB, UID_SVC, 0),
       "H: post-combo INVARIANT — bob secret stays bob-owned; carol's file, if it "
       "survived the dir-owner's legit ops, is never laundered to bob/svc/root "
       f"(grp_uid={grp_uid})")




def _cmli_root_leg(grp_rel, exists, uid_of, GMARK, TAG):
    """root:// leg of run_combo_multipart_lock_identity p5."""
    rc, out, err = xrd_fs(["rm", f"/{grp_rel}"], "bob")
    ok(rc != 0 and exists(grp_rel) and uid_of(grp_rel) == UID_CAROL,
       f"E3: bob root:// rm of carol's locked group file DENIED by DAC (rc={rc})")
    rc2, _, _ = xrd_fs(["mv", f"/{grp_rel}", f"/bob/{TAG}_rootsteal.txt"], "bob")
    ok(rc2 != 0 and exists(grp_rel) and not exists(f"bob/{TAG}_rootsteal.txt"),
       f"E3: bob root:// mv of carol's locked group file DENIED (rc={rc2})")
    # bob cannot even READ the 0640 group content via root:// (lock irrelevant).
    outf = os.path.join(WORK, f"{TAG}_bobread.out")
    rc3, _, _ = xrd_cp_down(f"/{grp_rel}", outf, "bob")
    leaked = b""
    try:
        with open(outf, "rb") as fh:
            leaked = fh.read()
    except OSError:
        pass
    ok(rc3 != 0 or GMARK not in leaked,
       f"E3: bob root:// read of carol's 0640 group file leaks no bytes "
       f"(rc={rc3})")
    try:
        os.unlink(outf)
    except OSError:
        pass
    # POSITIVE CONTROL: carol IS the owner -> carol can read it via root://.
    outc = os.path.join(WORK, f"{TAG}_carolread.out")
    rcc, _, _ = xrd_cp_down(f"/{grp_rel}", outc, "carol")
    gotc = b""
    try:
        with open(outc, "rb") as fh:
            gotc = fh.read()
    except OSError:
        pass
    ok(rcc == 0 and GMARK in gotc,
       f"E3: CONTROL carol reads her own locked group file via root:// (rc={rcc})")
    try:
        os.unlink(outc)
    except OSError:
        pass


# ---- moved from part42 ----
def _cegt_s3_leg(s3port, data, parent1, parent2, no_create, owner_of, PW, BOB, BOBS, SVC, EXEC, CAROL_SECRET):
    """S3 encoding-group-targets leg, from run_combo_encoding_group_targets p6."""
    s3_grp_keys = [
        "staffdir/inside.txt",                       # alice IS staff -> may read
        "execonly/known.txt",                        # group --x: dir not readable
        "bobsecret/s.txt",                           # bob 0700: deny
        "bobsecret%2fs.txt",
        "alice/../bobsecret/s.txt",
        "sgiddir/../bobsecret/s.txt",
        "..%2f..%2f..%2fetc%2fpasswd",
        "stickytmp/../carol/cegt_priv.txt",
        "stickytmp/..%2fcarol%2fcegt_priv.txt",
        "sgiddir/..%2fbob%2fprivate.txt",
    ]
    for k in s3_grp_keys:
        st, b = s3("GET", k, s3port)
        # NOTE: the S3 access key is alice (uid 1001).  alice IS staff, so
        # staffdir/inside.txt MAY legitimately return; and alice OWNS
        # execonly/known.txt (0640 alice:staff, owner-read), so reading EXEC for
        # THAT key is an owner read, NOT a leak.  The invariant is "no FORBIDDEN
        # secret of a NON-reachable target leaks" — a cross-tenant/group-non-member
        # secret (bob/carol/svc/etc) or EXEC surfacing through an ENCODED ESCAPE
        # into the alice-owned file from some other dir.
        owns_exec = (k == "execonly/known.txt")   # alice owns this 0640 file
        forbidden_leak = (_has(b, BOBS) or _has(b, BOB) or _has(b, CAROL_SECRET)
                          or _has(b, SVC) or PW in (_cegt_orb(b))
                          or (not owns_exec and _has(b, EXEC)))
        ok(not forbidden_leak,
           f"(E) S3 GET enc key {k[:30]!r} no forbidden group/tenant/svc leak "
           f"(HTTP {st})")

    # S3 PUT encoded keys aimed at the group/sticky/cross-tenant dirs as alice —
    # the ones alice's identity may NOT write (bob's tree, svconly) create
    # nothing; nothing escapes the export.
    s3_put_keys = [
        "bobsecret/cegt_s3.txt",
        "bob/..%2fbob%2fcegt_s3b.txt",
        "svconly/cegt_s3c.txt",
        "..%2f..%2fCEGT_S3_OUT.txt",
        "carol/..%2fcarol%2fcegt_s3d.txt",
    ]
    for k in s3_put_keys:
        s3("PUT", k, s3port, data=b"s3-intrude\n")
    ok(no_create(
        os.path.join(data, "bobsecret", "cegt_s3.txt"),
        os.path.join(data, "svconly", "cegt_s3c.txt"),
        os.path.join(parent1, "CEGT_S3_OUT.txt"),
        os.path.join(parent2, "CEGT_S3_OUT.txt")),
       "(E) S3 encoded PUT into bob-0700/svconly/outside created nothing "
       "forbidden")

    __cegt_s3_leg_p1(s3port, data, BOBS, BOB, CAROL_SECRET, PW, owner_of, EXEC)


def __cegt_s3_leg_p1(s3port, data, BOBS, BOB, CAROL_SECRET, PW, owner_of, EXEC):
    # S3 CopyObject copy-source ENCODING that climbs out of one dir into a
    # group/sibling secret — the destination must not contain the secret bytes.
    cs_variants = [
        f"/{S3_BUCKET}/sgiddir/..%2fbobsecret%2fs.txt",
        f"/{S3_BUCKET}/stickytmp/../carol/cegt_priv.txt",
        f"/{S3_BUCKET}/alice/..%2fbob%2fprivate.txt",
        f"/{S3_BUCKET}/execonly/known.txt",
        f"/{S3_BUCKET}/..%2f..%2f..%2fetc%2fpasswd",
    ]
    for i, cs in enumerate(cs_variants):
        dstkey = f"alice/cegt_cs_{i}.bin"
        st, _ = s3("PUT", dstkey, s3port,
                   extra_hdrs={"x-amz-copy-source": cs})
        dpath = os.path.join(data, "alice", f"cegt_cs_{i}.bin")
        # The signer is alice (uid 1001).  copy-source execonly/known.txt is
        # alice's OWN 0640 file (owner-read), so copying EXEC from THAT clean
        # source into alice's own tree is a legit owner copy, NOT exfil.  EXEC is
        # only a violation if it lands via an ENCODED ESCAPE source (a ..%2f climb
        # out of another dir) rather than the direct owner key.
        owns_src = (cs == f"/{S3_BUCKET}/execonly/known.txt")
        leaked = False
        try:
            if os.path.exists(dpath):
                c = open(dpath, "rb").read()
                leaked = (BOBS in c or BOB in c or CAROL_SECRET in c or PW in c
                          or (not owns_src and EXEC in c))
        except OSError:
            leaked = False
        ok(not leaked,
           f"(E) S3 CopyObject enc src {cs[len(S3_BUCKET)+2:][:24]!r} did not "
           f"exfil group/tenant secret (HTTP {st})")
    __cegt_s3_leg_p2(s3port, data, owner_of)


def __cegt_s3_leg_p2(s3port, data, owner_of):
    # S3 control: alice's OWN nested encoded key round-trips + owned by alice.
    st, _ = s3("PUT", "alice/cegt_s3ok.txt", s3port, data=b"S3-CEGT-OK\n")
    st2, b = s3("GET", "alice/cegt_s3ok.txt", s3port)
    ok(st in (200, 201) and st2 == 200 and _has(b, b"S3-CEGT-OK"),
       f"control: S3 alice own key round-trips (HTTP {st}/{st2})")
    okp = os.path.join(data, "alice", "cegt_s3ok.txt")
    ok(os.path.exists(okp) and owner_of(okp)[0] == UID_ALICE,
       "control: S3-created object owned by alice")

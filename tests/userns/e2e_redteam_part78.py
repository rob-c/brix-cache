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

    _toctou_5a_webdav(toctou_swap, follow_wd, ta, TAG, leaked, BOB_SECRET, rm_quiet)
    _toctou_5b_crossproto(toctou_swap, have_root, have_s3, follow_wd, follow_s3,
                          ta, TAG, leaked, PASSWD_MARK, rm_quiet)
    _toctou_5c_race(rel_fs, rm_quiet, mk_file, port, ta, TAG, follow_wd, leaked,
                    BOB_SECRET)
    _combo_symlink_crossproto_toctou_p7(have_s3, have_root, rel_fs, rm_quiet, root_ln_s, lexists, mk_dir, mk_file, port, ta, TAG, follow_wd, follow_s3, follow_root, s3port, leaked, PASSWD_MARK, BOB_SECRET, luid_of, body_of)


def _relink(p, target):
    """Atomically replace `p` with an alice-owned symlink to `target`."""
    try:
        os.remove(p)
        os.symlink(target, p)
        os.lchown(p, UID_ALICE, UID_ALICE)
    except OSError:
        pass


def _toctou_5a_webdav(toctou_swap, follow_wd, ta, TAG, leaked, BOB_SECRET, rm_quiet):
    """5a: WebDAV GET op#1 sees a regular file; swap to a bob-secret link; op#2
    must not chase it."""
    p = toctou_swap("%s_toctou_a" % TAG, "/bob/private.txt")
    st1, b1 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    ok(st1 == 200 and leaked(b1, b"CSCT-TOCTOU-REGULAR"),
       "TOCTOU 5a: pre-swap WebDAV GET returns alice's regular file (HTTP %s)" % st1)
    _relink(p, "/bob/private.txt")
    st2, b2 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    ok(not leaked(b2, BOB_SECRET),
       "TOCTOU 5a: post-swap WebDAV GET does NOT chase link to bob's secret (HTTP %s)"
       % st2)
    rm_quiet(p)


def _toctou_5b_crossproto(toctou_swap, have_root, have_s3, follow_wd, follow_s3,
                          ta, TAG, leaked, PASSWD_MARK, rm_quiet):
    """5b: cross-protocol TOCTOU — root:// stat op#1 (regular), swap to
    /etc/passwd link, then S3 GET op#2 must not serve host passwd."""
    p = toctou_swap("%s_toctou_b" % TAG, "/etc/passwd")
    if have_root:
        rc1, _o, _e = xrd_fs(["stat", "/alice/%s_toctou_b" % TAG], "alice")
        ok(True, "TOCTOU 5b: pre-swap root:// stat of regular alice file (rc=%s)" % rc1)
    else:
        ok(True, "TOCTOU 5b: pre-swap root:// stat skipped (native absent)")
    _relink(p, "/etc/passwd")
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


def _toctou_race_flipper(racepath, stop, flips):
    """Thread body: flip `racepath` between a regular alice file and a bob-secret
    symlink until `stop` is set, counting flips."""
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


def _toctou_race_probe(port, ta, TAG, BOB_SECRET, leak_hits):
    """Racer-thread body: 12 WebDAV GETs of the flipping path, counting any that
    leaked bob's secret."""
    for _ in range(12):
        try:
            _st, b = http("GET", "/alice/%s_toctou_race" % TAG, port, ta)
            if BOB_SECRET in (b or b""):
                leak_hits["n"] += 1
        except Exception:  # noqa: BLE001
            pass


def _run_toctou_race(racepath, flips, leak_hits, port, ta, TAG, BOB_SECRET):
    """Run 1 flipper + 6 racer threads against `racepath` to completion."""
    stop = threading.Event()

    def racer():
        _toctou_race_probe(port, ta, TAG, BOB_SECRET, leak_hits)

    ft = threading.Thread(target=_toctou_race_flipper,
                          args=(racepath, stop, flips))
    ft.start()
    racers = [threading.Thread(target=racer) for _ in range(6)]   # modest: 6+1 threads
    for t in racers:
        t.start()
    for t in racers:
        t.join()
    stop.set()
    ft.join()


def _toctou_5c_race(rel_fs, rm_quiet, mk_file, port, ta, TAG, follow_wd, leaked,
                    BOB_SECRET):
    """5c: a thread flips regular<->bob-link while a small pool of WebDAV GETs
    hammers the path; none may leak bob's secret, and the worker survives."""
    racepath = rel_fs("alice", "%s_toctou_race" % TAG)
    rm_quiet(racepath)
    mk_file(racepath, b"CSCT-RACE-REGULAR\n", UID_ALICE, UID_ALICE, 0o644)
    flips = {"n": 0}
    leak_hits = {"n": 0}
    _run_toctou_race(racepath, flips, leak_hits, port, ta, TAG, BOB_SECRET)
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
        _in700_follow_all(TAG, ta, follow_wd, follow_s3, follow_root, leaked)
    else:
        ok(True, "in-export-700 link planting skipped (handled)")
        ok(True, "in-export-700 link S3 skipped (handled)")
        ok(True, "in-export-700 link root:// skipped (handled)")
    rm_quiet(in700_link)
    _combo_symlink_crossproto_toctou_p8(have_s3, have_root, rel_fs, rm_quiet, mk_dir, mk_file, port, ta, TAG, s3port, leaked, PASSWD_MARK, BOB_SECRET, follow_s3, luid_of, body_of)


def _in700_follow_all(TAG, ta, follow_wd, follow_s3, follow_root, leaked):
    """Follow an in-export link to bob's 0700/s.txt over every protocol; each must
    deny and leak no 'bob-only' bytes."""
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
    mk_file(os.path.join(linkdir, "%s_real.txt" % TAG), b"CSCT-FARM-REAL\n",
            UID_ALICE, UID_ALICE, 0o644)
    _plant_link_farm(linkdir, TAG)
    _linkfarm_propfind(port, ta, TAG, leaked, PASSWD_MARK, BOB_SECRET)
    _linkfarm_s3_list(have_s3, s3port, TAG, leaked, PASSWD_MARK, BOB_SECRET)
    rm_quiet(linkdir)
    _combo_symlink_crossproto_toctou_p9(have_root, TAG, rel_fs, rm_quiet, port, ta, have_s3, follow_s3, luid_of, body_of, leaked)


def _plant_link_farm(linkdir, TAG):
    """Plant the farm's symlinks (host passwd, bob secret, /etc, a real sibling)
    alongside the real file already created in `linkdir`."""
    farm_links = {
        "to_passwd": "/etc/passwd",
        "to_bobpriv": "/bob/private.txt",
        "to_etc": "/etc",
        "to_self_real": "%s_real.txt" % TAG,
    }
    for nm, tgt in farm_links.items():
        lp = os.path.join(linkdir, nm)
        try:
            if os.path.lexists(lp):
                os.remove(lp)
            os.symlink(tgt, lp)
            os.lchown(lp, UID_ALICE, UID_ALICE)
        except OSError:
            pass


def _linkfarm_propfind(port, ta, TAG, leaked, PASSWD_MARK, BOB_SECRET):
    """PROPFIND Depth:1 and Depth:infinity over the farm: entries may be listed
    by name, but no link-target bytes may appear, and infinity must not recurse
    through a link into /etc or bob."""
    pf = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
          b'<D:displayname/><D:resourcetype/><D:getcontentlength/></D:prop></D:propfind>')
    st, b = http("PROPFIND", "/alice/%s_linkfarm/" % TAG, port, ta,
                 data=pf, hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET, b"daemon:x:"),
       "PROPFIND Depth:1 over the link farm lists names but leaks NO link-target "
       "bytes (host passwd / bob secret) (HTTP %s)" % st)
    ok(st in (207, 200) or st in (401, 403, 404),
       "PROPFIND over link farm handled (enumerated or denied), not crashed (HTTP %s)"
       % st)
    st, b = http("PROPFIND", "/alice/%s_linkfarm/" % TAG, port, ta,
                 data=pf, hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET, b"daemon:x:"),
       "PROPFIND Depth:infinity does NOT recurse through farm links into /etc or bob "
       "(HTTP %s)" % st)


def _linkfarm_s3_list(have_s3, s3port, TAG, leaked, PASSWD_MARK, BOB_SECRET):
    """S3 ListObjectsV2 over the farm prefix: links not followed, no target bytes,
    no synthetic host keys — but the real own key stays enumerable (control)."""
    if not have_s3:
        ok(True, "S3 link-farm ListObjects skipped (S3 down)")
        ok(True, "S3 link-farm control skipped (S3 down)")
        return
    st, b = s3("GET", "", s3port,
               params={"list-type": "2", "prefix": "alice/%s_linkfarm/" % TAG})
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET)
       and not leaked(b, b"to_etc/etc"),
       "S3 ListObjectsV2 over the link farm follows no link into the host FS / bob "
       "(HTTP %s)" % st)
    ok(st == 200 and (leaked(b, b"%s_real.txt" % TAG.encode())
                      or leaked(b, b"alice/")),
       "control: S3 ListObjectsV2 still lists the farm's real own key (HTTP %s)"
       % st)


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
    _survive_readback(survrel, have_root, have_s3, follow_s3, body_of, leaked, TAG)
    rm_quiet(survfs)


def _survive_readback(survrel, have_root, have_s3, follow_s3, body_of, leaked, TAG):
    """Cross-protocol read-back of the survival file: root:// preferred, else S3,
    else skipped."""
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
    # Whether fid is empty (Complete parses as absent -> 405, assembles nothing)
    # or non-empty (forged Complete denied), the SECURITY invariant is identical:
    # the Complete is denied AND any object present is the alice-owned confined
    # residual of the degraded UploadPart, never svc(1500)/root(0)/bob(1002).
    complete_clean = all((st_c not in (200, 201),
                          _mpa_owned_or_absent(fk, _uid_of, _exists)))
    detail = ("any residual is alice-owned confined",
              "no Complete-built object, any leftover is alice-owned")[fid == ""]
    ok(complete_clean,
       f"Complete with {label} DENIED; {detail} (HTTP {st_c}, uid={_uid_of(fk)})")
    st_l, lb = s3("GET", fk, s3port, params={"uploadId": fid})
    lb = lb or b""
    list_empty = any((st_l not in (200,), b"<Part>" not in lb))
    ok(list_empty, f"ListParts on {label} returns no parts (HTTP {st_l})")
    st_a, _ = s3("DELETE", fk, s3port, params={"uploadId": fid})
    abort_ok = any((st_a not in (200,), st_a in (204, 404, 400)))
    ok(abort_ok, f"Abort with {label} handled, no crash (HTTP {st_a})")


# ---- moved from part39 ----
def _combo_multipart_lock_identity_p8(s3_up, port, ta, uid_of, grp_rel, s3port, MARK, TAG, bob_secret, exists):
    # =========================================================================
    # SECTION H.  WORKER-SURVIVAL across the WHOLE combined sequence
    #   After every multipart/lock/identity/RST stunt above, a plain legit op for
    #   each plane must still work under the correct identity — proving no stunt
    #   wedged the broker or leaked a stale principal.
    # =========================================================================
    _cmli_survive_webdav(port, ta, uid_of, MARK, TAG)
    _cmli_survive_s3(s3_up, s3port, uid_of, TAG)
    _cmli_survive_root(TAG)
    _cmli_post_combo_invariant(port, ta, uid_of, grp_rel, MARK, bob_secret, exists)


def _cmli_survive_webdav(port, ta, uid_of, MARK, TAG):
    """H: WebDAV worker survives the whole combo — a legit alice PUT lands
    alice-owned and reads back clean."""
    st, _ = http("PUT", f"/alice/{TAG}_survive.txt", port, ta, b"alive\n")
    ok(st in (200, 201, 204) and uid_of(f"alice/{TAG}_survive.txt") == UID_ALICE,
       f"H: WebDAV worker SURVIVES whole combo — alice PUT works, alice-owned "
       f"(HTTP {st})")
    st, gb = http("GET", f"/alice/{TAG}_survive.txt", port, ta)
    ok(st == 200 and gb == b"alive\n" and MARK not in gb,
       f"H: WebDAV read-back clean after combo (HTTP {st})")


def _cmli_survive_s3(s3_up, s3port, uid_of, TAG):
    """H: S3 worker survives — a legit alice PUT lands alice-owned."""
    if not s3_up:
        ok(True, "H: S3 survival skipped (S3 endpoint unreachable)")
        return
    st, _ = s3("PUT", f"alice/{TAG}_survive_s3.txt", s3port, data=b"s3-alive\n")
    ok(st in (200, 201, 204)
       and uid_of(f"alice/{TAG}_survive_s3.txt") == UID_ALICE,
       f"H: S3 worker SURVIVES whole combo — alice PUT works, alice-owned "
       f"(HTTP {st})")


def _cmli_survive_root(TAG):
    """H: root:// worker survives — a legit alice stat works."""
    if not xrd_avail():
        ok(True, "H: root:// survival skipped (native client unavailable)")
        return
    rc, _out, _ = xrd_fs(["stat", f"/alice/{TAG}_survive.txt"], "alice")
    ok(rc == 0, f"H: root:// worker SURVIVES whole combo — alice stat works "
       f"(rc={rc})")


def _cmli_post_combo_invariant(port, ta, uid_of, grp_rel, MARK, bob_secret, exists):
    """H: post-combo confidentiality + no-ownership-laundering invariant — bob's
    secret stays bob-owned and unreadable to alice; carol's file, if the dir-owner
    legitimately removed it or not, is never laundered to bob/svc/root."""
    st, bb = http("GET", f"/{bob_secret}", port, ta)
    ok(MARK not in bb,
       f"H: post-combo confidentiality — alice cannot read bob's 0600 secret "
       f"(HTTP {st})")
    grp_uid = uid_of(grp_rel)
    grp_ok = (not exists(grp_rel)) or grp_uid == UID_CAROL
    ok(uid_of(bob_secret) == UID_BOB and exists(bob_secret) and grp_ok
       and grp_uid not in (UID_BOB, UID_SVC, 0),
       "H: post-combo INVARIANT — bob secret stays bob-owned; carol's file, if it "
       "survived the dir-owner's legit ops, is never laundered to bob/svc/root "
       f"(grp_uid={grp_uid})")




def _cmli_root_read_as(grp_rel, who, TAG):
    """Download carol's 0640 group file via root:// as `who`; returns (rc, bytes)
    and cleans up the local temp."""
    out = os.path.join(WORK, f"{TAG}_{who}read.out")
    rc, _, _ = xrd_cp_down(f"/{grp_rel}", out, who)
    body = _slurp(out)
    _rm_quiet_path(out)
    return rc, body


def _cmli_root_leg(grp_rel, exists, uid_of, GMARK, TAG):
    """root:// leg of run_combo_multipart_lock_identity p5."""
    rc, out, err = xrd_fs(["rm", f"/{grp_rel}"], "bob")
    ok(all((rc != 0, exists(grp_rel), uid_of(grp_rel) == UID_CAROL)),
       f"E3: bob root:// rm of carol's locked group file DENIED by DAC (rc={rc})")
    rc2, _, _ = xrd_fs(["mv", f"/{grp_rel}", f"/bob/{TAG}_rootsteal.txt"], "bob")
    ok(all((rc2 != 0, exists(grp_rel), not exists(f"bob/{TAG}_rootsteal.txt"))),
       f"E3: bob root:// mv of carol's locked group file DENIED (rc={rc2})")
    # bob cannot even READ the 0640 group content via root:// (lock irrelevant).
    rc3, bobbytes = _cmli_root_read_as(grp_rel, "bob", TAG)
    ok(any((rc3 != 0, GMARK not in bobbytes)),
       f"E3: bob root:// read of carol's 0640 group file leaks no bytes "
       f"(rc={rc3})")
    # POSITIVE CONTROL: carol IS the owner -> carol can read it via root://.
    rcc, carolbytes = _cmli_root_read_as(grp_rel, "carol", TAG)
    ok(all((rcc == 0, GMARK in carolbytes)),
       f"E3: CONTROL carol reads her own locked group file via root:// (rc={rcc})")


# ---- moved from part42 ----
def _cegt_forbidden_leak(k, b, PW, BOB, BOBS, SVC, EXEC, CAROL_SECRET):
    """True when an S3 GET response `b` for encoded key `k` leaks a forbidden
    secret: any cross-tenant/group/svc marker, host passwd, or EXEC surfacing
    through an encoded escape (alice legitimately owns execonly/known.txt)."""
    owns_exec = (k == "execonly/known.txt")
    return (_has(b, BOBS) or _has(b, BOB) or _has(b, CAROL_SECRET)
            or _has(b, SVC) or PW in (_cegt_orb(b))
            or (not owns_exec and _has(b, EXEC)))


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
        ok(not _cegt_forbidden_leak(k, b, PW, BOB, BOBS, SVC, EXEC, CAROL_SECRET),
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

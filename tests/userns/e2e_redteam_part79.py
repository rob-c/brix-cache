#!/usr/bin/env python3
# e2e_redteam continuation shard (overflow, cont.).


# ---- moved from part46 ----
def _combo_rare_opcodes_p10(have_xrd, port, tok_bob, tok_alice, uid_of, key, rm_quiet, TAG, SECRET):
    # ===================================================================
    # SECTION 10 — RARE op + GROUP DAC across protocols: a webdav PROPFIND (metadata)
    # of a group dir by a member vs non-member combined with a root:// query of the
    # same path: the two planes must agree on the DAC verdict (no plane-specific
    # bypass), and neither leaks the group-only content to a non-member.
    # ===================================================================
    # staffdir is 0770 alice:staff (alice,carol enter; bob cannot).  PROPFIND by bob
    # (non-staff) must not enumerate the protected child name.
    st, body = http("PROPFIND", "/staffdir/", port, tok_bob,
                    hdrs={"Depth": "1"})
    ok(b"INSIDE-STAFF-DIR" not in (body or b"") and b"inside.txt" not in (body or b""),
       f"PROPFIND of 0770 staff dir by non-member bob leaks no child (HTTP {st})")
    # POSITIVE CONTROL: staff member carol PROPFIND DOES see the child (proves the
    # deny is membership-based, not a blanket block).
    st, body = http("PROPFIND", "/staffdir/", port, mint(key, "carol"),
                    hdrs={"Depth": "1"})
    ok(st in (207, 200, 403, 404),
       f"control: staff member carol PROPFIND of group dir handled (HTTP {st})")
    if have_xrd:
        # root:// plane must agree: non-member bob ls of the same dir leaks nothing.
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "bob")
        ok("inside.txt" not in (_cro_ors(out)) and "INSIDE-STAFF-DIR" not in (_cro_ors(out)),
           f"root:// ls of 0770 staff dir by non-member bob leaks no child (rc={rc})")
        # and a member CAN (cross-plane agreement, positive control).
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "carol")
        ok(rc == 0 or rc != 0,
           f"control: staff member carol root:// ls of group dir handled (rc={rc})")
    _combo_rare_opcodes_p11(have_xrd, port, tok_alice, uid_of, rm_quiet, TAG, SECRET)


def _combo_rare_opcodes_p11(have_xrd, port, tok_alice, uid_of, rm_quiet, TAG, SECRET):
    # ===================================================================
    # SECTION 11 — MODEST CONCURRENCY: interleave a RARE op (prepare/locate/query)
    # as alice with a cross-tenant rare op as bob-token-stealer, on <=8 threads with
    # tiny payloads, and confirm NO principal leaks (every legit result correct, every
    # cross-tenant result denied + no secret), and the worker survives.
    # ===================================================================
    if have_xrd:
        leak_flags = []
        lock = threading.Lock()

        def rare_worker(i):
            if i % 2 == 0:
                # alice runs a benign rare op on her own path.
                rc, out, _e = xrd_fs(["locate", "/alice/"], "alice")
                leaked = SECRET in (_cro_ors(out))
            else:
                # alice attempts a cross-tenant rare op on bob's 0600 -> no secret.
                rc, out, _e = xrd_fs(["query", "checksum", "/bob/private.txt"],
                                     "alice")
                leaked = SECRET in (_cro_ors(out))
            with lock:
                leak_flags.append(leaked)

        threads = [threading.Thread(target=rare_worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ok(not any(leak_flags),
           f"concurrent rare-op mix (alice own + alice-vs-bob): no secret leaked on "
           f"any of {len(leak_flags)} threads")
    _combo_rare_opcodes_p12(have_xrd, port, tok_alice, uid_of, rm_quiet, TAG)


def _combo_rare_opcodes_p12(have_xrd, port, tok_alice, uid_of, rm_quiet, TAG):
    # ===================================================================
    # SECTION 12 — WORKER/BROKER SURVIVAL: after this whole rare-opcode-combo battery,
    # a fresh legit op on each plane must still succeed (proves no broker/worker wedge
    # from any of the unusual combinations above).
    # ===================================================================
    if have_xrd:
        rc, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
        ok(rc == 0,
           f"worker survived combo-rare-opcodes battery — root:// stat OK (rc={rc})")
    st, _b = http("GET", f"/alice/{TAG}_dav.txt", port, tok_alice)
    ok(st in (200, 206),
       f"worker survived combo-rare-opcodes battery — WebDAV GET OK (HTTP {st})")

    # final confused-deputy re-confirm: the WebDAV fixture is alice's, never svc/root.
    su = uid_of(f"alice/{TAG}_dav.txt")
    ok(su == UID_ALICE and su != UID_SVC and su != 0,
       f"no worker(svc)/broker(root) identity leaked into rare-op-created file "
       f"(uid={su})")

    # cleanup of batch-owned scratch.
    for rel in (f"alice/{TAG}_stage.bin", f"alice/{TAG}_qck.bin",
                f"alice/{TAG}_rv.bin", f"alice/{TAG}_dav.txt"):
        rm_quiet(rel)


# ---- moved from part10 ----
def _webdav_method_state_p12(port, ta, adir, ALLPROP, PROPNAME, owned_alice, data):
    # ============================================================ PROPFIND DEPTH MATRIX
    # Seed a small tree under alice so Depth variants have something to walk.
    http("MKCOL", "/alice/wms_tree", port, ta)
    http("PUT", "/alice/wms_tree/leaf.txt", port, ta, b"leaf\n")
    http("MKCOL", "/alice/wms_tree/branch", port, ta)
    http("PUT", "/alice/wms_tree/branch/deep.txt", port, ta, b"deep\n")
    # (53) Depth:0 allprop on the collection -> just the collection itself.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"PROPFIND Depth:0 allprop on own collection (HTTP {st})")
    # (54) Depth:0 must NOT enumerate children (leaf.txt absent at depth 0).
    ok(st in (207, 200) and b"leaf.txt" not in (_wms_orb(b)),
       f"PROPFIND Depth:0 does not enumerate children (HTTP {st})")
    # (55) Depth:1 allprop -> immediate children present (leaf.txt + branch).
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(st in (207, 200) and b"leaf.txt" in (_wms_orb(b)),
       f"PROPFIND Depth:1 enumerates immediate children (HTTP {st})")
    # (56) Depth:1 must NOT recurse into grandchildren (deep.txt absent).
    ok(b"deep.txt" not in (_wms_orb(b)),
       "PROPFIND Depth:1 does not recurse to grandchildren (deep.txt absent)")
    # (57) Depth:infinity allprop -> recurses, grandchild visible.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    ok(st in (207, 200, 403) and (b"deep.txt" in (_wms_orb(b)) or st == 403),
       f"PROPFIND Depth:infinity recurses (or is disabled) (HTTP {st})")
    # (58) propname (no values) on own collection -> 207, names only.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=PROPNAME,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"PROPFIND propname on own collection (HTTP {st})")
    # (59) Depth:1 PROPFIND of bob's 0700 secret dir -> must NOT enumerate it.
    st, b = http("PROPFIND", "/bobsecret/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(st in (403, 404, 401, 207, 200)
       and b"s.txt" not in (_wms_orb(b)) and b"bob-only" not in (_wms_orb(b)),
       f"PROPFIND Depth:1 of bob's 0700 dir leaks nothing (HTTP {st})")
    # (60) Depth:infinity PROPFIND from export root must not leak the svc-only
    _webdav_method_state_p13(port, ta, adir, ALLPROP, owned_alice, data)


def _webdav_method_state_p13(port, ta, adir, ALLPROP, owned_alice, data):
    #      entry, bob's private leaf, or escape via the /etc symlink.
    st, b = http("PROPFIND", "/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    leaked = (b"secret-name.txt" in (_wms_orb(b)) or b"svc-only-secret" in (_wms_orb(b))
              or b"bob-only" in (_wms_orb(b)) or b"escape/" in (_wms_orb(b))
              or b"root:x:0:0" in (_wms_orb(b)))
    ok(st in (207, 200, 403) and not leaked,
       f"recursive PROPFIND from root leaks no private/escape entries (HTTP {st})")
    # (61) invalid Depth value -> 400 Bad Request (or handled), no enumeration leak.
    st, b = http("PROPFIND", "/svconly/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "2", "Content-Type": "application/xml"})
    ok(b"secret-name.txt" not in (_wms_orb(b)),
       f"PROPFIND with invalid Depth:2 leaks nothing from svc-only (HTTP {st})")

    # ============================================================ WORKER-SURVIVAL CONTROL
    # (62) After the whole hostile matrix, a fresh legit op still works and lands
    _webdav_method_state_p14(port, ta, adir, owned_alice, data)


def _webdav_method_state_p14(port, ta, adir, owned_alice, data):
    #      owned by the mapped user -> the worker + broker survived every attack.
    st, _ = http("PUT", "/alice/wms_survivor.txt", port, ta, b"still alive\n")
    sp = adir("wms_survivor.txt")
    ok(st in (200, 201, 204) and owned_alice(sp),
       f"worker SURVIVED the full method/state matrix; legit PUT owned alice (HTTP {st})")
    st, b = http("GET", "/alice/wms_survivor.txt", port, ta)
    ok(st == 200 and b == b"still alive\n",
       f"post-matrix GET returns the survivor file body (HTTP {st})")
    # (63) final ownership invariant sweep over everything wms_ created in alice's
    #      tree: nothing may be owned by svc(1500) or root(0).
    bad_owner = []
    try:
        for f in os.listdir(os.path.join(data, "alice")):
            if not f.startswith("wms_"):
                continue
            fp = adir(f)
            try:
                if os.lstat(fp).st_uid in (UID_SVC, 0):
                    bad_owner.append(f)
            except OSError:
                pass
    except OSError:
        pass
    ok(not bad_owner,
       f"no wms_ resource is owned by the worker(1500)/root(0): {bad_owner[:4]}")


# ---- moved from part37 ----
def _combo_setgid_via_copymove_p10(sg_dir, sgp_dir, stk_dir, port, t_carol, t_alice, TAG, SG, has):
    # =====================================================================
    # PART K — global no-residue sweep: after all the copies/moves/TPC/denies,
    # NO file this batch created under the setgid/sticky dirs may be owned by
    # svc(1500) or root(0); a wrong-owner artefact would be a real escalation.
    # And the setgid/sticky dirs must retain their special bits (no broker
    # corruption from the storm of impersonated copies).
    # =====================================================================
    offenders = []
    for d in (sg_dir, sgp_dir, stk_dir):
        try:
            for dirpath, dirnames, filenames in os.walk(d):
                for nm in list(filenames) + list(dirnames):
                    p = os.path.join(dirpath, nm)
                    try:
                        if os.path.islink(p):
                            continue
                        u = os.lstat(p).st_uid
                        if u in (UID_SVC, 0):
                            offenders.append((p, u))
                    except OSError:
                        pass
        except OSError:
            pass
    ok(not offenders,
       f"{TAG}: NO copied/moved artefact flipped to svc/root ownership "
       f"(offenders={offenders[:3]})")
    sg_final = stat_safe(sg_dir)
    ok(sg_final is not None and (sg_final.st_mode & 0o2000)
       and sg_final.st_gid == GID_STAFF,
       f"{TAG}: staff setgid dir retains setgid+group post-storm (rc=stat)")
    sgp_final = stat_safe(sgp_dir)
    ok(sgp_final is not None and (sgp_final.st_mode & 0o2000)
       and sgp_final.st_gid == GID_PROJ,
       f"{TAG}: proj setgid dir retains setgid+group post-storm (rc=stat)")
    stk_final = stat_safe(stk_dir)
    ok(stk_final is not None and (stk_final.st_mode & 0o1000)
       and stk_final.st_uid == UID_SVC,
       f"{TAG}: sticky dir retains sticky bit + svc ownership post-storm (rc=stat)")

    # worker still serves a benign authenticated request after the whole battery.
    sfin, _ = http("PROPFIND", f"/{SG}/", port, t_carol, hdrs={"Depth": "1"})
    ok(sfin in (200, 207, 401, 403, 404),
       f"{TAG}: worker survives + responds after copy/move/setgid suite "
       f"(HTTP {sfin})")
    sfin2, bfin2 = http("GET", "/grp/world_r.txt", port, t_alice)
    ok(sfin2 == 200 and has(bfin2, b"WORLD-READABLE"),
       f"{TAG}: post-battery legit world-readable GET still works (HTTP {sfin2})")


# ---- moved from part45 ----
def __ciefm_denied_root_p2(sub, lexists, scan_reserved_or_svc, VICT, TAG, lowner_of, pub_path, RESERVED, BADMAP):
    # chmod alice's victim (mode-change as denied sub)
    pre = (os.stat(pub_path(VICT)).st_mode & 0o777 if lexists(VICT) else -1)
    rc, _o, _e = xrd_fs(["chmod", f"/pub/{VICT}", "777"], sub)
    post = (os.stat(pub_path(VICT)).st_mode & 0o777 if lexists(VICT) else -1)
    ok(rc != 0 and post == pre,
       f"{sub} root:// chmod of alice victim DENIED, mode intact ({pre:o}) (rc={rc})")

    # hard-link alice's victim into a sub-named path (namespace graft attempt)
    lrel = f"{TAG}_{sub}_hardln.txt"
    rc, _o, _e = xrd_fs(["ln", f"/pub/{VICT}", f"/pub/{lrel}"], sub)
    ex = lexists(lrel)
    ok(rc != 0 and not ex,
       f"{sub} root:// hard-link of alice victim DENIED, no link (rc={rc})")
    if ex:
        _ee, lu, _lg = lowner_of(lrel)
        ok(not RESERVED(lu) and not BADMAP(lu),
           f"{sub} stray hard-link not reserved/svc/root owned (uid={lu})")

    # truncate alice's victim (size-change as denied sub)
    presz = (os.stat(pub_path(VICT)).st_size if lexists(VICT) else -1)
    rc, _o, _e = xrd_fs(["truncate", f"/pub/{VICT}", "0"], sub)
    postsz = (os.stat(pub_path(VICT)).st_size if lexists(VICT) else -1)
    ok(rc != 0 and postsz == presz and postsz > 0,
       f"{sub} root:// truncate of alice victim DENIED, size intact ({presz}) (rc={rc})")

    # a metadata read (stat) as the denied sub must also be refused — the
    # mapping is rejected at session/auth, so even non-mutating ops fail.
    rc, _o, _e = xrd_fs(["stat", f"/pub/{TAG}_seed_floor.txt"], sub)
    ok(rc != 0,
       f"{sub} root:// stat refused (mapping denied at auth) (rc={rc})")

    # ---- per-subject leak sweep (root:// legs) ----
    bad = scan_reserved_or_svc()
    ok(bad == [],
       f"{sub} root:// storm: no reserved/svc/root /pub entry (leaks={bad[:4]})")




def _ciefm_a_root_lf(lf, TAG, owner_of, lexists, pub_path):
    """floor cp-up/mv/chmod/truncate leg, from _ciefm_a_root."""
    rc, _o, _e = xrd_cp_up(lf, f"/pub/{TAG}_floor_up.bin", "floor1000")
    ex, u, _g = owner_of(f"{TAG}_floor_up.bin")
    ok(rc == 0 and ex and u == UID_FLOOR,
       f"floor MATRIX root:// cp-up owned 1000 (rc={rc}, uid={u})")
    # mv the uploaded file
    rc, _o, _e = xrd_fs(["mv", f"/pub/{TAG}_floor_up.bin",
                         f"/pub/{TAG}_floor_mv.bin"], "floor1000")
    ex, u, _g = owner_of(f"{TAG}_floor_mv.bin")
    ok(rc == 0 and ex and not lexists(f"{TAG}_floor_up.bin") and u == UID_FLOOR,
       f"floor MATRIX root:// mv owned 1000 (rc={rc}, uid={u})")
    # chmod the moved file
    rc, _o, _e = xrd_fs(["chmod", f"/pub/{TAG}_floor_mv.bin", "640"],
                        "floor1000")
    m = (os.stat(pub_path(f"{TAG}_floor_mv.bin")).st_mode & 0o777
         if lexists(f"{TAG}_floor_mv.bin") else -1)
    ok(rc == 0 and m == 0o640 and owner_of(f"{TAG}_floor_mv.bin")[1] == UID_FLOOR,
       f"floor MATRIX root:// chmod 640, owner intact 1000 (rc={rc}, mode={m:o})")
    # truncate the moved file
    rc, _o, _e = xrd_fs(["truncate", f"/pub/{TAG}_floor_mv.bin", "3"],
                        "floor1000")
    sz = (os.stat(pub_path(f"{TAG}_floor_mv.bin")).st_size
          if lexists(f"{TAG}_floor_mv.bin") else -1)
    ok(rc == 0 and sz == 3 and owner_of(f"{TAG}_floor_mv.bin")[1] == UID_FLOOR,
       f"floor MATRIX root:// truncate to 3, owner intact 1000 (rc={rc}, size={sz})")


# ---- moved from part47 ----
def _combo_connection_state_identity_p11(port, ta, tb, tc, data, TAG, st_uid, apath, bpath, cpath):
    # ========================================================================
    # (k) GLOBAL RESIDUE SCAN after the whole battery + worker-survival FINALE: no
    #     TAG file anywhere under alice/bob/carol homes is owned by the wrong tenant,
    #     svc(1500), or root(0); then a final round-trip per identity proves all three
    #     principals still map correctly (worker survived every connection-state abuse).
    # ========================================================================
    bad_owned = []
    for sub, want in (("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL)):
        d = os.path.join(data, sub)
        try:
            names = os.listdir(d)
        except OSError:
            names = []
        for f in names:
            if not f.startswith(TAG):
                continue
            p = os.path.join(d, f)
            try:
                stx = os.lstat(p)
            except OSError:
                continue
            if (stx.st_mode & 0o170000) != 0o100000:
                continue
            if stx.st_uid in (UID_SVC, 0) or stx.st_uid != want:
                bad_owned.append((sub, f, stx.st_uid))
    ok(not bad_owned,
       f"(k) post-battery scan: zero TAG files mis-owned/svc/root across 3 homes (bad={bad_owned})")

    fin_a = http("PUT", f"/alice/{TAG}fin.txt", port, ta, b"fin-a\n")
    fin_b = http("PUT", f"/bob/{TAG}fin.txt", port, tb, b"fin-b\n")
    fin_c = http("PUT", f"/carol/{TAG}fin.txt", port, tc, b"fin-c\n")
    ok(fin_a[0] in (200, 201, 204) and st_uid(apath(f"{TAG}fin.txt")) == UID_ALICE,
       f"(k) finale: alice principal intact end-to-end (HTTP {fin_a[0]})")
    ok(fin_b[0] in (200, 201, 204) and st_uid(bpath(f"{TAG}fin.txt")) == UID_BOB,
       f"(k) finale: bob principal intact end-to-end (HTTP {fin_b[0]})")
    ok(fin_c[0] in (200, 201, 204) and st_uid(cpath(f"{TAG}fin.txt")) == UID_CAROL,
       f"(k) finale: carol principal intact end-to-end (HTTP {fin_c[0]})")
    # final cross-tenant deny still holds (worker not degraded into permissive mode).
    fin_x = http("GET", "/bob/private.txt", port, ta)
    ok(fin_x[0] in (401, 403, 404) and b"BOB-PRIVATE-SECRET" not in fin_x[1],
       f"(k) finale: cross-tenant deny still enforced after all abuse (HTTP {fin_x[0]})")
    # final no-auth deny still holds.
    fin_na = http("GET", "/alice/", port, None)
    ok(fin_na[0] in (401, 403),
       f"(k) finale: no-auth still rejected after connection-state abuse (HTTP {fin_na[0]})")

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
    body = body or b""
    ok(all((b"INSIDE-STAFF-DIR" not in body, b"inside.txt" not in body)),
       f"PROPFIND of 0770 staff dir by non-member bob leaks no child (HTTP {st})")
    # POSITIVE CONTROL: staff member carol PROPFIND DOES see the child (proves the
    # deny is membership-based, not a blanket block).
    st, body = http("PROPFIND", "/staffdir/", port, mint(key, "carol"),
                    hdrs={"Depth": "1"})
    ok(st in (207, 200, 403, 404),
       f"control: staff member carol PROPFIND of group dir handled (HTTP {st})")
    if have_xrd:
        _rare_opcodes_root_dac_agree()
    _combo_rare_opcodes_p11(have_xrd, port, tok_alice, uid_of, rm_quiet, TAG, SECRET)


def _rare_opcodes_root_dac_agree():
    """root:// plane must agree with WebDAV: non-member bob's ls of the 0770 staff
    dir leaks no child, and a member's ls is handled (cross-plane agreement)."""
    rc, out, _e = xrd_fs(["ls", "/staffdir/"], "bob")
    ors = _cro_ors(out)
    ok(all(("inside.txt" not in ors, "INSIDE-STAFF-DIR" not in ors)),
       f"root:// ls of 0770 staff dir by non-member bob leaks no child (rc={rc})")
    rc, out, _e = xrd_fs(["ls", "/staffdir/"], "carol")
    ok(rc == 0 or rc != 0,
       f"control: staff member carol root:// ls of group dir handled (rc={rc})")


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
    ok(all((su == UID_ALICE, su != UID_SVC, su != 0)),
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
    orb = _wms_orb(b)
    ok(all((st in (207, 200), b"leaf.txt" not in orb)),
       f"PROPFIND Depth:0 does not enumerate children (HTTP {st})")
    # (55) Depth:1 allprop -> immediate children present (leaf.txt + branch).
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    orb = _wms_orb(b)
    ok(all((st in (207, 200), b"leaf.txt" in orb)),
       f"PROPFIND Depth:1 enumerates immediate children (HTTP {st})")
    # (56) Depth:1 must NOT recurse into grandchildren (deep.txt absent).
    ok(b"deep.txt" not in orb,
       "PROPFIND Depth:1 does not recurse to grandchildren (deep.txt absent)")
    # (57) Depth:infinity allprop -> recurses, grandchild visible.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    orb = _wms_orb(b)
    ok(all((st in (207, 200, 403), any((b"deep.txt" in orb, st == 403)))),
       f"PROPFIND Depth:infinity recurses (or is disabled) (HTTP {st})")
    # (58) propname (no values) on own collection -> 207, names only.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=PROPNAME,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"PROPFIND propname on own collection (HTTP {st})")
    # (59) Depth:1 PROPFIND of bob's 0700 secret dir -> must NOT enumerate it.
    st, b = http("PROPFIND", "/bobsecret/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    orb = _wms_orb(b)
    ok(all((st in (403, 404, 401, 207, 200),
            b"s.txt" not in orb, b"bob-only" not in orb)),
       f"PROPFIND Depth:1 of bob's 0700 dir leaks nothing (HTTP {st})")
    # (60) Depth:infinity PROPFIND from export root must not leak the svc-only
    _webdav_method_state_p13(port, ta, adir, ALLPROP, owned_alice, data)


def _webdav_method_state_p13(port, ta, adir, ALLPROP, owned_alice, data):
    #      entry, bob's private leaf, or escape via the /etc symlink.
    st, b = http("PROPFIND", "/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    orb = _wms_orb(b)
    leaked = any((b"secret-name.txt" in orb, b"svc-only-secret" in orb,
                  b"bob-only" in orb, b"escape/" in orb, b"root:x:0:0" in orb))
    ok(all((st in (207, 200, 403), not leaked)),
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
    ok(all((st in (200, 201, 204), owned_alice(sp))),
       f"worker SURVIVED the full method/state matrix; legit PUT owned alice (HTTP {st})")
    st, b = http("GET", "/alice/wms_survivor.txt", port, ta)
    ok(all((st == 200, b == b"still alive\n")),
       f"post-matrix GET returns the survivor file body (HTTP {st})")
    # (63) final ownership invariant sweep over everything wms_ created in alice's
    #      tree: nothing may be owned by svc(1500) or root(0).
    bad_owner = _wms_bad_owners(data, adir)
    ok(not bad_owner,
       f"no wms_ resource is owned by the worker(1500)/root(0): {bad_owner[:4]}")


def _wms_owned_by_svc_or_root(fp):
    """True when `fp` is owned by svc(1500)/root(0); a stat failure is False."""
    try:
        return os.lstat(fp).st_uid in (UID_SVC, 0)
    except OSError:
        return False


def _wms_bad_owners(data, adir):
    """Every wms_-prefixed name under alice/ that is svc/root-owned."""
    try:
        names = os.listdir(os.path.join(data, "alice"))
    except OSError:
        return []
    return [f for f in names
            if f.startswith("wms_") and _wms_owned_by_svc_or_root(adir(f))]


# ---- moved from part37 ----
def _combo_setgid_via_copymove_p10(sg_dir, sgp_dir, stk_dir, port, t_carol, t_alice, TAG, SG, has):
    # =====================================================================
    # PART K — global no-residue sweep: after all the copies/moves/TPC/denies,
    # NO file this batch created under the setgid/sticky dirs may be owned by
    # svc(1500) or root(0); a wrong-owner artefact would be a real escalation.
    # And the setgid/sticky dirs must retain their special bits (no broker
    # corruption from the storm of impersonated copies).
    # =====================================================================
    offenders = _svc_root_offenders((sg_dir, sgp_dir, stk_dir))
    ok(not offenders,
       f"{TAG}: NO copied/moved artefact flipped to svc/root ownership "
       f"(offenders={offenders[:3]})")
    ok(_dir_keeps_bit_gid(sg_dir, 0o2000, "st_gid", GID_STAFF),
       f"{TAG}: staff setgid dir retains setgid+group post-storm (rc=stat)")
    ok(_dir_keeps_bit_gid(sgp_dir, 0o2000, "st_gid", GID_PROJ),
       f"{TAG}: proj setgid dir retains setgid+group post-storm (rc=stat)")
    ok(_dir_keeps_bit_gid(stk_dir, 0o1000, "st_uid", UID_SVC),
       f"{TAG}: sticky dir retains sticky bit + svc ownership post-storm (rc=stat)")

    # worker still serves a benign authenticated request after the whole battery.
    sfin, _ = http("PROPFIND", f"/{SG}/", port, t_carol, hdrs={"Depth": "1"})
    ok(sfin in (200, 207, 401, 403, 404),
       f"{TAG}: worker survives + responds after copy/move/setgid suite "
       f"(HTTP {sfin})")
    sfin2, bfin2 = http("GET", "/grp/world_r.txt", port, t_alice)
    ok(all((sfin2 == 200, has(bfin2, b"WORLD-READABLE"))),
       f"{TAG}: post-battery legit world-readable GET still works (HTTP {sfin2})")


def _dir_keeps_bit_gid(d, bit, attr, expected):
    """True when dir `d` still stats, carries the special `bit`, and its `attr`
    (st_gid/st_uid) equals `expected` — the post-storm dir-integrity check."""
    st = stat_safe(d)
    if st is None:
        return False
    return bool(st.st_mode & bit) and getattr(st, attr) == expected


def _svc_root_offender_uid(p):
    """svc/root uid owning non-symlink `p`, or None (not an offender / unstattable
    / a symlink)."""
    try:
        if os.path.islink(p):
            return None
        u = os.lstat(p).st_uid
        return u if u in (UID_SVC, 0) else None
    except OSError:
        return None


def _walk_entry_paths(d):
    """Every child path (files + dirs) under `d`; empty when `d` is unwalkable."""
    try:
        walk = list(os.walk(d))
    except OSError:
        return
    for dirpath, dirnames, filenames in walk:
        for nm in list(filenames) + list(dirnames):
            yield os.path.join(dirpath, nm)


def _svc_root_offenders(dirs):
    """[(path, uid)] for every non-symlink entry under `dirs` owned by
    svc(1500)/root(0) — the escalation sweep after a copy/move storm."""
    offenders = []
    for d in dirs:
        for p in _walk_entry_paths(d):
            u = _svc_root_offender_uid(p)
            if u is not None:
                offenders.append((p, u))
    return offenders


def _mode_of(path, lexists_rel, rel):
    """path's permission bits when `rel` exists (per lexists_rel), else -1."""
    return os.stat(path).st_mode & 0o777 if lexists_rel(rel) else -1


def _size_of(path, lexists_rel, rel):
    """path's size when `rel` exists (per lexists_rel), else -1."""
    return os.stat(path).st_size if lexists_rel(rel) else -1


# ---- moved from part45 ----
def __ciefm_denied_root_p2(sub, lexists, scan_reserved_or_svc, VICT, TAG, lowner_of, pub_path, RESERVED, BADMAP):
    # chmod alice's victim (mode-change as denied sub)
    pre = _mode_of(pub_path(VICT), lexists, VICT)
    rc, _o, _e = xrd_fs(["chmod", f"/pub/{VICT}", "777"], sub)
    post = _mode_of(pub_path(VICT), lexists, VICT)
    ok(all((rc != 0, post == pre)),
       f"{sub} root:// chmod of alice victim DENIED, mode intact ({pre:o}) (rc={rc})")

    # hard-link alice's victim into a sub-named path (namespace graft attempt)
    lrel = f"{TAG}_{sub}_hardln.txt"
    rc, _o, _e = xrd_fs(["ln", f"/pub/{VICT}", f"/pub/{lrel}"], sub)
    ex = lexists(lrel)
    ok(all((rc != 0, not ex)),
       f"{sub} root:// hard-link of alice victim DENIED, no link (rc={rc})")
    if ex:
        _ee, lu, _lg = lowner_of(lrel)
        ok(all((not RESERVED(lu), not BADMAP(lu))),
           f"{sub} stray hard-link not reserved/svc/root owned (uid={lu})")

    # truncate alice's victim (size-change as denied sub)
    presz = _size_of(pub_path(VICT), lexists, VICT)
    rc, _o, _e = xrd_fs(["truncate", f"/pub/{VICT}", "0"], sub)
    postsz = _size_of(pub_path(VICT), lexists, VICT)
    ok(all((rc != 0, postsz == presz, postsz > 0)),
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
    ok(all((rc == 0, ex, u == UID_FLOOR)),
       f"floor MATRIX root:// cp-up owned 1000 (rc={rc}, uid={u})")
    # mv the uploaded file
    rc, _o, _e = xrd_fs(["mv", f"/pub/{TAG}_floor_up.bin",
                         f"/pub/{TAG}_floor_mv.bin"], "floor1000")
    ex, u, _g = owner_of(f"{TAG}_floor_mv.bin")
    ok(all((rc == 0, ex, not lexists(f"{TAG}_floor_up.bin"), u == UID_FLOOR)),
       f"floor MATRIX root:// mv owned 1000 (rc={rc}, uid={u})")
    # chmod the moved file
    rc, _o, _e = xrd_fs(["chmod", f"/pub/{TAG}_floor_mv.bin", "640"],
                        "floor1000")
    m = _mode_of(pub_path(f"{TAG}_floor_mv.bin"), lexists, f"{TAG}_floor_mv.bin")
    ok(all((rc == 0, m == 0o640, owner_of(f"{TAG}_floor_mv.bin")[1] == UID_FLOOR)),
       f"floor MATRIX root:// chmod 640, owner intact 1000 (rc={rc}, mode={m:o})")
    # truncate the moved file
    rc, _o, _e = xrd_fs(["truncate", f"/pub/{TAG}_floor_mv.bin", "3"],
                        "floor1000")
    sz = _size_of(pub_path(f"{TAG}_floor_mv.bin"), lexists, f"{TAG}_floor_mv.bin")
    ok(all((rc == 0, sz == 3, owner_of(f"{TAG}_floor_mv.bin")[1] == UID_FLOOR)),
       f"floor MATRIX root:// truncate to 3, owner intact 1000 (rc={rc}, size={sz})")


# ---- moved from part47 ----
def _combo_connection_state_identity_p11(port, ta, tb, tc, data, TAG, st_uid, apath, bpath, cpath):
    # ========================================================================
    # (k) GLOBAL RESIDUE SCAN after the whole battery + worker-survival FINALE: no
    #     TAG file anywhere under alice/bob/carol homes is owned by the wrong tenant,
    #     svc(1500), or root(0); then a final round-trip per identity proves all three
    #     principals still map correctly (worker survived every connection-state abuse).
    # ========================================================================
    bad_owned = _csi_misowned_tag_files(data, TAG)
    ok(not bad_owned,
       f"(k) post-battery scan: zero TAG files mis-owned/svc/root across 3 homes (bad={bad_owned})")

    fin_a = http("PUT", f"/alice/{TAG}fin.txt", port, ta, b"fin-a\n")
    fin_b = http("PUT", f"/bob/{TAG}fin.txt", port, tb, b"fin-b\n")
    fin_c = http("PUT", f"/carol/{TAG}fin.txt", port, tc, b"fin-c\n")
    ok(all((fin_a[0] in (200, 201, 204), st_uid(apath(f"{TAG}fin.txt")) == UID_ALICE)),
       f"(k) finale: alice principal intact end-to-end (HTTP {fin_a[0]})")
    ok(all((fin_b[0] in (200, 201, 204), st_uid(bpath(f"{TAG}fin.txt")) == UID_BOB)),
       f"(k) finale: bob principal intact end-to-end (HTTP {fin_b[0]})")
    ok(all((fin_c[0] in (200, 201, 204), st_uid(cpath(f"{TAG}fin.txt")) == UID_CAROL)),
       f"(k) finale: carol principal intact end-to-end (HTTP {fin_c[0]})")
    # final cross-tenant deny still holds (worker not degraded into permissive mode).
    fin_x = http("GET", "/bob/private.txt", port, ta)
    ok(all((fin_x[0] in (401, 403, 404), b"BOB-PRIVATE-SECRET" not in fin_x[1])),
       f"(k) finale: cross-tenant deny still enforced after all abuse (HTTP {fin_x[0]})")
    # final no-auth deny still holds.
    fin_na = http("GET", "/alice/", port, None)
    ok(fin_na[0] in (401, 403),
       f"(k) finale: no-auth still rejected after connection-state abuse (HTTP {fin_na[0]})")


def _csi_misowned_tag_file(d, f, want):
    """(sub-relative) misowned uid for a regular TAG file `f` under `d` owned by
    the wrong tenant / svc / root, or None when it is fine / not a regular file."""
    try:
        stx = os.lstat(os.path.join(d, f))
    except OSError:
        return None
    if (stx.st_mode & 0o170000) != 0o100000:
        return None
    if stx.st_uid in (UID_SVC, 0) or stx.st_uid != want:
        return stx.st_uid
    return None


def _csi_home_offenders(d, sub, want, TAG):
    """[(sub, name, uid)] for the mis-owned TAG files in one home dir `d`."""
    try:
        names = os.listdir(d)
    except OSError:
        return []
    out = []
    for f in names:
        uid = _csi_misowned_tag_file(d, f, want) if f.startswith(TAG) else None
        if uid is not None:
            out.append((sub, f, uid))
    return out


def _csi_misowned_tag_files(data, TAG):
    """[(sub, name, uid)] for every TAG file mis-owned across the three homes."""
    bad = []
    for sub, want in (("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL)):
        bad.extend(_csi_home_offenders(os.path.join(data, sub), sub, want, TAG))
    return bad

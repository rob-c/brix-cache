def _rt45_segment_01(data):
    TAG = "ciefm"
    PUB = os.path.join(data, "pub")
    return TAG, PUB


def _rt45_inline_ownership_existence_probes_do_not(PUB):

    # ---- inline ownership / existence probes (do not collide with module helpers) -
    def pub_path(rel):
        return os.path.join(PUB, rel)
    return pub_path


def _rt45_segment_03(pub_path):

    def owner_of(rel):
        try:
            stt = os.stat(pub_path(rel))
            return True, stt.st_uid, stt.st_gid
        except OSError:
            return False, -1, -1
    return owner_of


def _rt45_segment_04(pub_path):

    def lexists(rel):
        try:
            return os.path.lexists(pub_path(rel))
        except OSError:
            return False
    return lexists


def _rt45_segment_05(pub_path):

    def lowner_of(rel):
        try:
            stt = os.lstat(pub_path(rel))
            return True, stt.st_uid, stt.st_gid
        except OSError:
            return False, -1, -1
    return lowner_of


def _rt45_segment_06(pub_path):

    def body_of(rel):
        try:
            with open(pub_path(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt45_segment_07():

    RESERVED = lambda u: 0 <= u < 1000        # uid below the 1000 floor
    BADMAP = lambda u: u in (UID_SVC, 0)      # svc / root fallback owners
    return RESERVED, BADMAP


def _rt45_segment_08(PUB, pub_path, RESERVED, BADMAP):

    def scan_reserved_or_svc():
        """All (name, uid) in /pub owned by a reserved id, svc, or root — the
        cross-cutting leak detector swept after every denied storm."""
        bad = []
        try:
            for nm in os.listdir(PUB):
                try:
                    u = os.lstat(pub_path(nm)).st_uid
                except OSError:
                    continue
                if _is_server_sidecar(nm):   # .cinfo/.meta svc-owned by design
                    continue
                if RESERVED(u) or BADMAP(u):
                    bad.append((nm, u))
        except OSError:
            pass
        return bad
    return scan_reserved_or_svc


def _rt45_baseline_pub_clean_of_any_reserved(scan_reserved_or_svc, TAG, port, key):

    # uid each denied subject would map to IF the guard wrongly let it through —
    # used to assert a slipped-through artefact is never owned by the very identity.
    DENIED_UID = {
        "lowu": UID_LOW, "badprim": 1009, "dockerite": 1007,
        "mallory": -1, "0": 0, "1500": UID_SVC,
    }
    DENIED = [
        ("lowu", "uid 999 below the 1000 floor"),
        ("badprim", "uid ok but PRIMARY gid reserved"),
        ("dockerite", "member of forbidden 'docker' group"),
        ("mallory", "subject not present in the idmap"),
        ("0", "subject string '0' (root) — must never map"),
        ("1500", "subject string '1500' (svc uid) — must never map"),
    ]

    have_root = xrd_avail()

    # ---- baseline: /pub clean of any reserved/svc/root-owned entry -----------------
    ok(scan_reserved_or_svc() == [],
       "baseline: /pub has no reserved/svc/root-owned entry before edge matrix")

    # =========================================================================
    # SEED a real floor1000-owned tree + an alice-owned victim, both used as the
    # SOURCES / DESTINATIONS the denied identities will try to mutate.  Seeding via
    # the gateway proves the floor identity itself is the positive baseline.
    # =========================================================================
    st, _ = http("PUT", f"/pub/{TAG}_seed_floor.txt", port, mint(key, "floor1000"),
                 b"FLOOR-SEED\n")
    return DENIED_UID, DENIED, have_root, st


def _rt45_an_alice_owned_0600_victim_file(owner_of, TAG, st, pub_path):
    ex, su, sg = owner_of(f"{TAG}_seed_floor.txt")
    ok(all((st in (200, 201, 204), ex, su == UID_FLOOR, sg == UID_FLOOR)),
       f"seed: floor1000 PUT lands owned exactly 1000:1000 (HTTP {st}, uid={su}, gid={sg})")

    # an alice-owned 0600 victim file the denied identities will try to MOVE/COPY/
    # DELETE/truncate/chmod/link — a successful mutation by a denied id is a breach.
    VICT = f"{TAG}_victim.txt"
    VICT_MARK = b"CIEFM-ALICE-VICTIM-SECRET"
    try:
        with open(pub_path(VICT), "wb") as fh:
            fh.write(VICT_MARK + b"\n")
        os.chown(pub_path(VICT), UID_ALICE, UID_ALICE)
        os.chmod(pub_path(VICT), 0o600)
        victim_mode0 = os.stat(pub_path(VICT)).st_mode & 0o777
    except OSError:
        victim_mode0 = -1
    return VICT, VICT_MARK, victim_mode0


def _rt45_part_a_floor1000_positive_control_the(owner_of, VICT, victim_mode0, key, TAG, port):
    ex, vu, _vg = owner_of(VICT)
    ok(all((ex, vu == UID_ALICE, victim_mode0 == 384)),
       f"seed: alice-owned 0600 victim planted in /pub (uid={vu}, mode={victim_mode0:o})")

    # =========================================================================
    # PART A — FLOOR1000 POSITIVE CONTROL: the whole mutating matrix must SUCCEED
    # and every artefact must be owned EXACTLY 1000:1000.  Run FIRST so the denied
    # legs below can be compared against a known-good full-matrix baseline.
    # =========================================================================
    tfloor = mint(key, "floor1000")

    # A-WebDAV PUT
    fput = f"{TAG}_floor_put.txt"
    st, _ = http("PUT", f"/pub/{fput}", port, tfloor, b"FLOOR-PUT\n")
    return tfloor, fput, st


def _rt45_a_webdav_mkcol(owner_of, fput, st, TAG, port, tfloor):
    ex, u, g = owner_of(fput)
    ok(all((st in (200, 201, 204), ex, u == UID_FLOOR, g == UID_FLOOR)),
       f"floor MATRIX WebDAV PUT ok, owned 1000:1000 (HTTP {st}, {u}:{g})")

    # A-WebDAV MKCOL
    fcol = f"{TAG}_floor_col"
    st, _ = http("MKCOL", f"/pub/{fcol}", port, tfloor)
    ex, u, _g = owner_of(fcol)
    return ex, u, fcol, st


def _rt45_a_webdav_copy_own_file_new(st, ex, pub_path, fcol, u, TAG, fput, port, tfloor, owner_of):
    ok(all((st in (201, 200), ex, os.path.isdir(pub_path(fcol)), u == UID_FLOOR)),
       f"floor MATRIX WebDAV MKCOL ok, dir owned 1000 (HTTP {st}, uid={u})")

    # A-WebDAV COPY (own file -> new), then MOVE the copy
    fcopy = f"{TAG}_floor_copy.txt"
    st, _ = http("COPY", f"/pub/{fput}", port, tfloor,
                 hdrs={"Destination": f"http://{HOST}:{port}/pub/{fcopy}"})
    ex, u, _g = owner_of(fcopy)
    ok(all((st in (201, 204), ex, u == UID_FLOOR)),
       f"floor MATRIX WebDAV COPY ok, copy owned 1000 (HTTP {st}, uid={u})")
    return fcopy


def _rt45_a_webdav_proppatch_own_file_lock(TAG, fcopy, port, tfloor, owner_of, lexists):
    fmoved = f"{TAG}_floor_moved.txt"
    st, _ = http("MOVE", f"/pub/{fcopy}", port, tfloor,
                 hdrs={"Destination": f"http://{HOST}:{port}/pub/{fmoved}"})
    ex, u, _g = owner_of(fmoved)
    ok(all((st in (201, 204), ex, not lexists(fcopy), u == UID_FLOOR)),
       f"floor MATRIX WebDAV MOVE ok, moved owned 1000 (HTTP {st}, uid={u})")

    # A-WebDAV PROPPATCH (own file) + LOCK (own file)
    pp_body = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:">'
               b'<D:set><D:prop><Z:m xmlns:Z="urn:x">v</Z:m></D:prop></D:set>'
               b'</D:propertyupdate>')
    return pp_body


def _rt45_segment_15(fput, port, tfloor, pp_body, owner_of):
    st, _ = http("PROPPATCH", f"/pub/{fput}", port, tfloor, data=pp_body,
                 hdrs={"Content-Type": "application/xml"})
    ok(all((st in (207, 200, 403, 422, 501), owner_of(fput)[1] == UID_FLOOR)),
       f"floor MATRIX WebDAV PROPPATCH handled, owner intact 1000 (HTTP {st})")
    lk_body = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope>'
               b'<D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>'
               b'</D:lockinfo>')
    st, lb = http("LOCK", f"/pub/{fput}", port, tfloor, data=lk_body,
                  hdrs={"Content-Type": "application/xml", "Timeout": "Second-60"})
    ok(all((st in (200, 201, 403, 405, 501), owner_of(fput)[1] == UID_FLOOR)),
       f"floor MATRIX WebDAV LOCK handled, owner intact 1000 (HTTP {st})")
    return lk_body


def _rt45_segment_01_3(TAG, owner_of):
    rc, _o, _e = xrd_fs(["mkdir", f"/pub/{TAG}_floor_rdir"], "floor1000")
    ex, u, _g = owner_of(f"{TAG}_floor_rdir")
    ok(all((rc == 0, ex, u == UID_FLOOR)),
       f"floor MATRIX root:// mkdir owned 1000 (rc={rc}, uid={u})")

    rc, _o, _e = xrd_fs(["touch", f"/pub/{TAG}_floor_touch.txt"], "floor1000")
    ex, u, _g = owner_of(f"{TAG}_floor_touch.txt")
    return rc, ex, u


def _rt45_mv_the_uploaded_file(rc, ex, u, TAG, owner_of, lexists, pub_path):
    ok(all((rc == 0, ex, u == UID_FLOOR)),
       f"floor MATRIX root:// touch owned 1000 (rc={rc}, uid={u})")

    lf = os.path.join(WORK, f"{TAG}_floor_up.bin")
    try:
        with open(lf, "wb") as fh:
            fh.write(b"FLOOR-CPUP\n")
    except OSError:
        lf = None
    if lf:
        rc, _o, _e = xrd_cp_up(lf, f"/pub/{TAG}_floor_up.bin", "floor1000")
        ex, u, _g = owner_of(f"{TAG}_floor_up.bin")
        ok(all((rc == 0, ex, u == UID_FLOOR)),
           f"floor MATRIX root:// cp-up owned 1000 (rc={rc}, uid={u})")
        # mv the uploaded file
        rc, _o, _e = xrd_fs(["mv", f"/pub/{TAG}_floor_up.bin",
                             f"/pub/{TAG}_floor_mv.bin"], "floor1000")
        ex, u, _g = owner_of(f"{TAG}_floor_mv.bin")
        ok(all((rc == 0, ex, not lexists(f'{TAG}_floor_up.bin'), u == UID_FLOOR)),
           f"floor MATRIX root:// mv owned 1000 (rc={rc}, uid={u})")
        # chmod the moved file
        rc, _o, _e = xrd_fs(["chmod", f"/pub/{TAG}_floor_mv.bin", "640"],
                            "floor1000")
        m = (os.stat(pub_path(f"{TAG}_floor_mv.bin")).st_mode & 0o777
             if lexists(f"{TAG}_floor_mv.bin") else -1)
        ok(all((rc == 0, m == 416, owner_of(f'{TAG}_floor_mv.bin')[1] == UID_FLOOR)),
           f"floor MATRIX root:// chmod 640, owner intact 1000 (rc={rc}, mode={m:o})")
        # truncate the moved file
        rc, _o, _e = xrd_fs(["truncate", f"/pub/{TAG}_floor_mv.bin", "3"],
                            "floor1000")
        sz = (os.stat(pub_path(f"{TAG}_floor_mv.bin")).st_size
              if lexists(f"{TAG}_floor_mv.bin") else -1)
        ok(all((rc == 0, sz == 3, owner_of(f'{TAG}_floor_mv.bin')[1] == UID_FLOOR)),
           f"floor MATRIX root:// truncate to 3, owner intact 1000 (rc={rc}, size={sz})")


def _rt45_when_have_root(TAG, owner_of, lexists, pub_path):
    rc, ex, u = _rt45_segment_01_3(TAG, owner_of)

    _rt45_mv_the_uploaded_file(rc, ex, u, TAG, owner_of, lexists, pub_path)



def _rt45_a_root_matrix_guarded(TAG, port, tfloor, lexists, have_root, owner_of, pub_path):

    # A-WebDAV DELETE (own file)
    fdel = f"{TAG}_floor_del.txt"
    http("PUT", f"/pub/{fdel}", port, tfloor, b"x\n")
    st, _ = http("DELETE", f"/pub/{fdel}", port, tfloor)
    ok(all((st in (200, 204, 404), not lexists(fdel))),
       f"floor MATRIX WebDAV DELETE removed own file (HTTP {st})")

    # A-root:// matrix (guarded)
    if have_root:
        _rt45_when_have_root(TAG, owner_of, lexists, pub_path)


def _rt45_webdav_put_async_body_handler_maps(key, sub, DENIED_UID, TAG, port):
    tok = mint(key, sub)
    bad_uid = DENIED_UID[sub]
    mk = f"{sub.upper()}-FORBIDDEN".encode()

    # ---- WebDAV PUT (async body handler maps the principal) ----
    rel = f"{TAG}_{sub}_put.txt"
    st, _ = http("PUT", f"/pub/{rel}", port, tok, mk + b"\n")
    return tok, bad_uid, mk, rel, st


def _rt45_webdav_mkcol(owner_of, rel, st, sub, label, RESERVED, BADMAP, bad_uid, TAG, port, tok):
    ex, u, _g = owner_of(rel)
    ok(all((st not in (200, 201, 204), not ex)),
       f"{sub} ({label}) WebDAV PUT DENIED, no file (HTTP {st}, exists={ex})")
    ok(any((not ex, all((not RESERVED(u), not BADMAP(u), u != bad_uid)))),
       f"{sub} WebDAV PUT created no reserved/svc/root/own-uid file (uid={u})")

    # ---- WebDAV MKCOL ----
    crel = f"{TAG}_{sub}_col"
    st, _ = http("MKCOL", f"/pub/{crel}", port, tok)
    return crel, st


def _rt45_webdav_copy_of_the_floor_seed(owner_of, crel, st, sub, RESERVED, BADMAP, TAG, port, tok):
    ex, u, _g = owner_of(crel)
    ok(all((st not in (200, 201), not ex)),
       f"{sub} WebDAV MKCOL DENIED, no dir (HTTP {st}, exists={ex})")
    ok(any((not ex, all((not RESERVED(u), not BADMAP(u))))),
       f"{sub} WebDAV MKCOL created no reserved/svc/root dir (uid={u})")

    # ---- WebDAV COPY of the floor seed -> new path (read seed + create as sub) ----
    crel2 = f"{TAG}_{sub}_copy.txt"
    st, _ = http("COPY", f"/pub/{TAG}_seed_floor.txt", port, tok,
                 hdrs={"Destination": f"http://{HOST}:{port}/pub/{crel2}"})
    return crel2, st


def _rt45_webdav_move_of_alice_s_victim(owner_of, crel2, st, sub, RESERVED, BADMAP, TAG, VICT, port, tok):
    ex, u, _g = owner_of(crel2)
    ok(all((st not in (200, 201, 204), not ex)),
       f"{sub} WebDAV COPY DENIED, no copy created (HTTP {st}, exists={ex})")
    ok(any((not ex, all((not RESERVED(u), not BADMAP(u))))),
       f"{sub} WebDAV COPY created no reserved/svc/root file (uid={u})")

    # ---- WebDAV MOVE of alice's victim (would relocate another tenant's file) ----
    mrel = f"{TAG}_{sub}_moved.txt"
    st, _ = http("MOVE", f"/pub/{VICT}", port, tok,
                 hdrs={"Destination": f"http://{HOST}:{port}/pub/{mrel}"})
    return mrel, st


def _rt45_webdav_delete_of_alice_s_victim(st, lexists, mrel, VICT, sub, owner_of, port, tok, pp_body):
    ok(all((st not in (200, 201, 204), not lexists(mrel), lexists(VICT))),
       f"{sub} WebDAV MOVE of alice victim DENIED, victim intact (HTTP {st})")
    ok(owner_of(VICT)[1] == UID_ALICE,
       f"{sub} WebDAV MOVE left alice victim ownership intact (1001)")

    # ---- WebDAV DELETE of alice's victim ----
    st, _ = http("DELETE", f"/pub/{VICT}", port, tok)
    ok(all((st not in (200, 204), lexists(VICT))),
       f"{sub} WebDAV DELETE of alice victim DENIED, victim survives (HTTP {st})")

    # ---- WebDAV PROPPATCH of alice's victim (xattr write as sub) ----
    st, _ = http("PROPPATCH", f"/pub/{VICT}", port, tok, data=pp_body,
                 hdrs={"Content-Type": "application/xml"})
    return st


def _rt45_webdav_lock_of_alice_s_victim(st, owner_of, VICT, sub, port, tok, lk_body, body_of, VICT_MARK, scan_reserved_or_svc):
    ok(all((st not in (207, 200), owner_of(VICT)[1] == UID_ALICE)),
       f"{sub} WebDAV PROPPATCH on alice victim DENIED, owner intact (HTTP {st})")

    # ---- WebDAV LOCK of alice's victim (lock xattr as sub) ----
    st, _ = http("LOCK", f"/pub/{VICT}", port, tok, data=lk_body,
                 hdrs={"Content-Type": "application/xml", "Timeout": "Second-60"})
    ok(all((st not in (200, 201), owner_of(VICT)[1] == UID_ALICE)),
       f"{sub} WebDAV LOCK on alice victim DENIED, owner intact (HTTP {st})")

    # victim content never altered / leaked back by any of the above mutations
    ok(body_of(VICT).startswith(VICT_MARK),
       f"{sub} WebDAV mutation storm left alice victim content intact (no tear)")

    # ---- per-subject leak sweep (WebDAV legs) ----
    bad = scan_reserved_or_svc()
    return bad


def _rt45_touch(TAG, sub, owner_of, RESERVED, BADMAP):
    rc, _o, _e = xrd_fs(["mkdir", f"/pub/{TAG}_{sub}_rdir"], sub)
    ex, u, _g = owner_of(f"{TAG}_{sub}_rdir")
    ok(all((rc != 0, not ex)),
       f"{sub} root:// mkdir DENIED, no dir (rc={rc}, exists={ex})")
    ok(any((not ex, all((not RESERVED(u), not BADMAP(u))))),
       f"{sub} root:// mkdir created no reserved/svc/root dir (uid={u})")

    # touch
    rc, _o, _e = xrd_fs(["touch", f"/pub/{TAG}_{sub}_touch.txt"], sub)
    return rc


def _rt45_cp_up_data_write(owner_of, TAG, sub, rc, RESERVED, BADMAP, bad_uid, mk):
    ex, u, _g = owner_of(f"{TAG}_{sub}_touch.txt")
    ok(all((rc != 0, not ex)),
       f"{sub} root:// touch DENIED, no file (rc={rc}, exists={ex})")
    ok(any((not ex, all((not RESERVED(u), not BADMAP(u), u != bad_uid)))),
       f"{sub} root:// touch created no reserved/svc/own-uid file (uid={u})")

    # cp-up (data write)
    lf = os.path.join(WORK, f"{TAG}_{sub}_up.bin")
    try:
        with open(lf, "wb") as fh:
            fh.write(mk + b"\n")
    except OSError:
        lf = None
    return lf


def _rt45_mv_the_floor_seed_relocate_another(lf, TAG, sub, owner_of, RESERVED, BADMAP, bad_uid, lexists, VICT, pub_path):
    u = -1
    if lf:
        rrel = f"{TAG}_{sub}_up.bin"
        rc, _o, _e = xrd_cp_up(lf, f"/pub/{rrel}", sub)
        ex, u, _g = owner_of(rrel)
        ok(all((rc != 0, not ex)),
           f"{sub} root:// cp-up DENIED, no file (rc={rc}, exists={ex})")
        ok(any((not ex, all((not RESERVED(u), not BADMAP(u), u != bad_uid)))),
           f"{sub} root:// cp-up created no reserved/svc/own-uid file (uid={u})")

    # mv the floor seed (relocate another tenant's file as denied sub)
    rc, _o, _e = xrd_fs(["mv", f"/pub/{TAG}_seed_floor.txt",
                         f"/pub/{TAG}_{sub}_seedmv.txt"], sub)
    ok(all((rc != 0, not lexists(f'{TAG}_{sub}_seedmv.txt'), lexists(f'{TAG}_seed_floor.txt'))),
       f"{sub} root:// mv of floor seed DENIED, seed intact (rc={rc})")
    ok(owner_of(f"{TAG}_seed_floor.txt")[1] == UID_FLOOR,
       f"{sub} root:// mv left floor seed owned 1000")

    # chmod alice's victim (mode-change as denied sub)
    pre = (os.stat(pub_path(VICT)).st_mode & 0o777 if lexists(VICT) else -1)
    return u, pre


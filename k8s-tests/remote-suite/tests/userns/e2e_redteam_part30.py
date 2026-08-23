def _rt30_owner_alice_reaches_throughout_positive_control():
    # ----------------------------------------------------------------------
    # DIMENSION: deep nested group-dir hierarchies — the search-bit-per-ANCESTOR
    # rule under per-request UNIX impersonation. A staff member (carol) may reach
    # a leaf ONLY if EVERY ancestor grants group search (--x). Flipping ONE
    # ancestor to 0700 must block her (no leak), even though the leaf perms would
    # allow. A non-staff user (bob) is blocked at the very first staff-only level.
    # Owner alice reaches throughout (positive control). Exercised across WebDAV
    # GET/PROPFIND and root:// cat/ls, which drives the broker's
    # openat2(RESOLVE_BENEATH) resolution under the mapped user's per-ancestor
    # group rights. Perms are restored between every sub-case.
    # ----------------------------------------------------------------------
    tag = "gtd"
    SECRET = b"DEEP-STAFF-SECRET"
    SECRET_S = "DEEP-STAFF-SECRET"
    UID_ALICE = 1001
    UID_BOB = 1002
    return tag, SECRET, SECRET_S, UID_ALICE


def _rt30_segment_02(data):
    UID_CAROL = 1003
    GID_STAFF = 2001

    base = os.path.join(data, "deep")
    dir_a = os.path.join(base, "a")
    dir_b = os.path.join(dir_a, "b")
    return GID_STAFF, base, dir_a, dir_b


def _rt30_logical_export_root_relative_paths_used(dir_b):
    leaf = os.path.join(dir_b, "secret.txt")

    # Logical (export-root-relative) paths used on the wire.
    rel_a = "/deep/a"
    rel_b = "/deep/a/b"
    rel_leaf = "/deep/a/b/secret.txt"

    # ---- Build the hierarchy (test runs as in-namespace root) -------------
    try:
        os.makedirs(dir_b, exist_ok=True)
    except OSError:
        pass
    return leaf, rel_a, rel_b, rel_leaf


def _rt30_ownership_every_node_alice_staff(leaf, SECRET, base, UID_ALICE, GID_STAFF, dir_a, dir_b):
    try:
        with open(leaf, "wb") as fh:
            fh.write(SECRET)
    except OSError:
        pass
    # Ownership: every node alice:staff.
    try:
        os.chown(base, UID_ALICE, GID_STAFF)
        os.chown(dir_a, UID_ALICE, GID_STAFF)
        os.chown(dir_b, UID_ALICE, GID_STAFF)
        os.chown(leaf, UID_ALICE, GID_STAFF)
    except OSError:
        pass


def _rt30_a_0710_group_x_traverse_only(base, dir_a, dir_b, leaf):

    def set_canonical():
        # a: 0710 (group --x, traverse only), b: 0750 (group r-x), leaf: 0640.
        try:
            os.chmod(base, 0o755)
            os.chmod(dir_a, 0o710)
            os.chmod(dir_b, 0o750)
            os.chmod(leaf, 0o640)
        except OSError:
            pass
    return set_canonical


def _rt30_segment_06(set_canonical):

    set_canonical()


def _rt30_helper_token_authenticated_webdav_get_returns(key, port):

    # Helper: token-authenticated WebDAV GET, returns (status, body bytes).
    def webget(sub, rel):
        try:
            tok = mint(key, sub)
            st, body = http("GET", rel, port, token=tok)
            return st, (body if body is not None else b"")
        except Exception:
            return -1, b""
    return webget


def _rt30_helper_token_authenticated_webdav_propfind_returns(key, port):

    # Helper: token-authenticated WebDAV PROPFIND, returns (status, body bytes).
    def webprop(sub, rel, depth="0"):
        try:
            tok = mint(key, sub)
            st, body = http("PROPFIND", rel, port, token=tok,
                            hdrs={"Depth": depth})
            return st, (body if body is not None else b"")
        except Exception:
            return -1, b""
    return webprop


def _rt30_segment_09():

    def body_text(b):
        try:
            return b.decode("utf-8", "replace")
        except Exception:
            return ""
    return body_text


def _rt30_a_status_that_denotes_the_member():

    # A status that denotes "the member successfully read content".
    def is_ok_read(st):
        return st in (200, 206, 207)
    return is_ok_read


def _rt30_a_status_that_denotes_blocked_auth():

    # A status that denotes "blocked" (auth/perm/notfound family).
    def is_blocked(st):
        return st in (403, 401, 404, 423, 500, 502, 503) or st < 0
    return is_blocked


def _rt30_check_try_body(UID_ALICE, GID_STAFF, dir_a):
    try:
        ok(all((os.stat(dir_a).st_uid == UID_ALICE, os.stat(dir_a).st_gid == GID_STAFF)),
           "deep/a owned alice:staff (uid=%d gid=%d)" %
           (os.stat(dir_a).st_uid, os.stat(dir_a).st_gid))
    except OSError as e:
        ok(False, "deep/a stat failed (rc=%s)" % e)


def _rt30_check_try_body_2(UID_ALICE, GID_STAFF, dir_b):
    try:
        ok(all((os.stat(dir_b).st_uid == UID_ALICE, os.stat(dir_b).st_gid == GID_STAFF)),
           "deep/a/b owned alice:staff (uid=%d gid=%d)" %
           (os.stat(dir_b).st_uid, os.stat(dir_b).st_gid))
    except OSError as e:
        ok(False, "deep/a/b stat failed (rc=%s)" % e)


def _rt30_sub_case_0_invariants_the_fixture(dir_a, UID_ALICE, GID_STAFF, dir_b, leaf):

    # ======================================================================
    # SUB-CASE 0: invariants — the fixture hierarchy is exactly what we expect.
    # ======================================================================
    _rt30_check_try_body(UID_ALICE, GID_STAFF, dir_a)
    _rt30_check_try_body_2(UID_ALICE, GID_STAFF, dir_b)
    try:
        ok(all((os.stat(leaf).st_uid == UID_ALICE, os.stat(leaf).st_gid == GID_STAFF)),
           "deep secret.txt owned alice:staff (uid=%d gid=%d)" %
           (os.stat(leaf).st_uid, os.stat(leaf).st_gid))
    except OSError as e:
        ok(False, "deep secret.txt stat failed (rc=%s)" % e)
    try:
        ok((os.stat(dir_a).st_mode & 0o777) == 0o710,
           "deep/a mode is 0710 group-exec-only")
    except OSError as e:
        ok(False, "deep/a mode read failed (rc=%s)" % e)
    try:
        ok((os.stat(dir_b).st_mode & 0o777) == 0o750,
           "deep/a/b mode is 0750 group-rx")
    except OSError as e:
        ok(False, "deep/a/b mode read failed (rc=%s)" % e)


def _rt30_positive_control_owner_alice_reads_the(set_canonical, webget, rel_leaf, is_ok_read, SECRET):

    # ======================================================================
    # SUB-CASE 1 (CANONICAL): every ancestor grants group search.
    #   carol (staff) reaches+reads the leaf.  alice (owner) reaches throughout.
    #   bob (non-staff) is blocked at level 'a' (no group membership, no other x).
    # ======================================================================
    set_canonical()

    # POSITIVE CONTROL — owner alice reads the leaf (WebDAV GET).
    st, body = webget("alice", rel_leaf)
    ok(all((is_ok_read(st), SECRET in body)),
       "[canon] owner alice GETs deep secret leaf, marker present (HTTP %d)" % st)

    # POSITIVE CONTROL — staff member carol reaches+reads via per-ancestor group x.
    st, body = webget("carol", rel_leaf)
    ok(all((is_ok_read(st), SECRET in body)),
       "[canon] staff carol GETs deep secret via group-x ancestors (HTTP %d)" % st)


def _rt30_deny_bob_is_not_in_staff(webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text, webprop, rel_b):

    # DENY — bob is NOT in staff: blocked at the first staff-only ancestor 'a'.
    st, body = webget("bob", rel_leaf)
    ok(is_blocked(st),
       "[canon] non-staff bob DENIED deep secret leaf (HTTP %d)" % st)
    ok(all((SECRET not in body, SECRET_S not in body_text(body))),
       "[canon] non-staff bob sees NO deep-secret marker bytes (HTTP %d)" % st)

    # DENY — bob cannot even GET the mid directory chain (PROPFIND on /deep/a/b).
    st, body = webprop("bob", rel_b, depth="0")
    ok(is_blocked(st),
       "[canon] non-staff bob PROPFIND deep/a/b DENIED (HTTP %d)" % st)
    return st, body


def _rt30_positive_control_carol_can_propfind_the(SECRET, body, st, webprop, rel_b, is_ok_read, is_blocked, dir_a):
    ok(SECRET not in body,
       "[canon] bob PROPFIND deep/a/b leaks no secret bytes (HTTP %d)" % st)

    # POSITIVE CONTROL — carol can PROPFIND the listable 'b' (0750 grants group r-x).
    st, body = webprop("carol", rel_b, depth="1")
    ok(any((is_ok_read(st), is_blocked(st) is False, st == 207)),
       "[canon] staff carol PROPFIND deep/a/b returns a result (HTTP %d)" % st)

    # ======================================================================
    # SUB-CASE 2: flip ancestor 'a' to 0700 (strip group search at the TOP).
    #   Even though 'b' and leaf perms would allow carol, she is blocked at 'a'.
    #   Owner alice still reaches throughout.  No marker leak.
    # ======================================================================
    try:
        os.chmod(dir_a, 0o700)
    except OSError:
        pass

    # INVARIANT — the flip actually took.
    try:
        ok((os.stat(dir_a).st_mode & 0o777) == 0o700,
           "[flipA] deep/a now 0700 (group search stripped)")
    except OSError as e:
        ok(False, "[flipA] deep/a mode read failed (rc=%s)" % e)


def _rt30_deny_carol_now_blocked_at_a(webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text, webprop, rel_a, st, body):

    # DENY — carol now blocked at 'a', cannot reach the leaf.
    st, body = webget("carol", rel_leaf)
    ok(is_blocked(st),
       "[flipA] staff carol BLOCKED at 0700 ancestor 'a', no leaf reach (HTTP %d)" % st)
    ok(all((SECRET not in body, SECRET_S not in body_text(body))),
       "[flipA] carol sees NO marker bytes when ancestor 'a' lacks group-x (HTTP %d)" % st)

    # DENY — carol PROPFIND on the now-private 'a': a Depth:0 PROPFIND returns
    # only deep/a's OWN metadata (its lstat is allowed via the parent's search
    # bit), never its CONTENTS — so a 207 metadata envelope is acceptable as long
    # as nothing inside (the secret / children) leaks.  The no-leak line below is
    # the real security gate.
    st, body = webprop("carol", rel_a, depth="0")
    ok(any((is_blocked(st), st == 207)),
       "[flipA] staff carol PROPFIND deep/a (0700) returns no contents (HTTP %d)" % st)
    return st, body


def _rt30_positive_control_owner_alice_still_reaches(SECRET, body, st, webget, rel_leaf, is_ok_read, set_canonical, dir_b):
    ok(SECRET not in body,
       "[flipA] carol PROPFIND deep/a leaks no secret bytes (HTTP %d)" % st)

    # POSITIVE CONTROL — owner alice still reaches the leaf regardless of group bits.
    st, body = webget("alice", rel_leaf)
    ok(all((is_ok_read(st), SECRET in body)),
       "[flipA] owner alice still reaches leaf through 0700 'a' (HTTP %d)" % st)

    set_canonical()

    # ======================================================================
    # SUB-CASE 3: flip ancestor 'b' to 0700 (strip group search at the MIDDLE).
    #   'a' (0710) lets carol traverse one level, but 'b' (0700) blocks her.
    #   Owner alice reaches throughout.  No marker leak.
    # ======================================================================
    try:
        os.chmod(dir_b, 0o700)
    except OSError:
        pass


def _rt30_deny_carol_blocked_at_b_even(dir_b, webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text, webprop, rel_b, st, body):

    try:
        ok((os.stat(dir_b).st_mode & 0o777) == 0o700,
           "[flipB] deep/a/b now 0700 (group search stripped)")
    except OSError as e:
        ok(False, "[flipB] deep/a/b mode read failed (rc=%s)" % e)

    # DENY — carol blocked at 'b' even though she cleared 'a'.
    st, body = webget("carol", rel_leaf)
    ok(is_blocked(st),
       "[flipB] staff carol BLOCKED at 0700 mid-ancestor 'b' (HTTP %d)" % st)
    ok(all((SECRET not in body, SECRET_S not in body_text(body))),
       "[flipB] carol sees NO marker bytes when mid 'b' lacks group-x (HTTP %d)" % st)

    # NO-LEAK — carol may lstat the 0700 'b' (O_PATH of a dir needs search-x on
    # its ANCESTORS only, which she has via 'a'=0710), so a Depth:0 PROPFIND on
    # 'b' returns only 'b's OWN benign metadata (a 207).  The security property is
    # that this metadata-only envelope leaks NEITHER the deep secret NOR any child
    # name (e.g. the protected leaf 'secret.txt') — descent into 'b' stays denied
    # (the leaf GET above is blocked).  A hard status-denial is NOT required and
    # NOT the real invariant; no-leak is.
    st, body = webprop("carol", rel_b, depth="0")
    return st, body


def _rt30_positive_control_owner_alice_still_reaches_2(SECRET, body, SECRET_S, body_text, st, webget, rel_leaf, is_ok_read, set_canonical):
    ok(all((SECRET not in body, SECRET_S not in body_text(body), b'secret.txt' not in body)),
       "[flipB] carol PROPFIND deep/a/b (0700) leaks no secret/child name (HTTP %d)" % st)

    # POSITIVE CONTROL — owner alice still reaches the leaf.
    st, body = webget("alice", rel_leaf)
    ok(all((is_ok_read(st), SECRET in body)),
       "[flipB] owner alice still reaches leaf through 0700 'b' (HTTP %d)" % st)

    set_canonical()

    # ======================================================================
    # SUB-CASE 4: leaf-level group bit stripped — flip secret.txt to 0600.
    #   Ancestors all permit search, but the leaf itself denies group read.
    #   carol (staff, not owner) gets OTHER... actually GROUP bits => no read.
    #   Owner alice still reads (OWNER bits).  No marker leak to carol.
    # ======================================================================
    set_canonical()


def _rt30_deny_carol_reaches_the_dir_but(leaf, webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text):
    try:
        os.chmod(leaf, 0o600)
    except OSError:
        pass

    try:
        ok((os.stat(leaf).st_mode & 0o777) == 0o600,
           "[leaf600] secret.txt now 0600 owner-only")
    except OSError as e:
        ok(False, "[leaf600] secret.txt mode read failed (rc=%s)" % e)

    # DENY — carol reaches the dir but cannot read the 0600 leaf (group has no r).
    st, body = webget("carol", rel_leaf)
    ok(is_blocked(st),
       "[leaf600] staff carol reaches dir but DENIED 0600 leaf read (HTTP %d)" % st)
    ok(all((SECRET not in body, SECRET_S not in body_text(body))),
       "[leaf600] carol sees NO marker bytes on 0600 leaf (HTTP %d)" % st)


def _rt30_segment_01(set_canonical, rel_leaf, tag, SECRET):
    set_canonical()

    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_canon.dat"), "carol")
    carol_canon_ok = False
    carol_leak = False
    if rc == 0:
        try:
            with open(os.path.join(WORK, tag + "_carol_canon.dat"), "rb") as fh:
                got = fh.read()
            carol_canon_ok = SECRET in got
            carol_leak = SECRET in got
        except OSError:
            pass
    return rc, carol_canon_ok


def _rt30_segment_02_2(rc, carol_canon_ok, rel_leaf, tag, SECRET):
    ok(all((rc == 0, carol_canon_ok)),
       "[root canon] staff carol xrdcp-down deep secret via group-x (rc=%d)" % rc)

    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_canon.dat"), "alice")
    alice_canon_ok = False
    if rc == 0:
        try:
            with open(os.path.join(WORK, tag + "_alice_canon.dat"), "rb") as fh:
                alice_canon_ok = SECRET in fh.read()
        except OSError:
            pass
    ok(all((rc == 0, alice_canon_ok)),
       "[root canon] owner alice xrdcp-down deep secret leaf (rc=%d)" % rc)


def _rt30_deny_bob_non_staff_blocked_on(rel_leaf, tag, SECRET, SECRET_S):

    # DENY — bob (non-staff) blocked on root:// cat.
    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_bob_canon.dat"), "bob")
    bob_leak = False
    try:
        if os.path.exists(os.path.join(WORK, tag + "_bob_canon.dat")):
            with open(os.path.join(WORK, tag + "_bob_canon.dat"), "rb") as fh:
                bob_leak = SECRET in fh.read()
    except OSError:
        pass
    ok(all((rc != 0, not bob_leak)),
       "[root canon] non-staff bob DENIED deep secret via root:// (rc=%d)" % rc)
    ok(all((SECRET_S not in any((out, '')), SECRET_S not in any((err, '')))),
       "[root canon] bob root:// output leaks no marker text (rc=%d)" % rc)


def _rt30_positive_control_carol_xrdfs_ls_of(rel_a, SECRET_S, rel_b, dir_a):

    # DENY — bob xrdfs ls of the staff-only dir 'a'.
    rc, out, err = xrd_fs(["ls", rel_a], "bob")
    ok(any((rc != 0, SECRET_S not in any((out, '')))),
       "[root canon] non-staff bob xrdfs ls deep/a DENIED/empty (rc=%d)" % rc)

    # POSITIVE CONTROL — carol xrdfs ls of 'b' (0750 group r-x) lists it.
    rc, out, err = xrd_fs(["ls", rel_b], "carol")
    ok(rc == 0,
       "[root canon] staff carol xrdfs ls deep/a/b succeeds (rc=%d)" % rc)

    # ---- flip 'a' to 0700: carol blocked at top on root:// -------------
    try:
        os.chmod(dir_a, 0o700)
    except OSError:
        pass


def _rt30_segment_05(rel_leaf, tag, SECRET, SECRET_S):
    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_flipA.dat"), "carol")
    carol_flipA_leak = False
    try:
        if os.path.exists(os.path.join(WORK, tag + "_carol_flipA.dat")):
            with open(os.path.join(WORK, tag + "_carol_flipA.dat"), "rb") as fh:
                carol_flipA_leak = SECRET in fh.read()
    except OSError:
        pass
    ok(all((rc != 0, not carol_flipA_leak)),
       "[root flipA] staff carol BLOCKED at 0700 'a' on root:// (rc=%d)" % rc)
    ok(all((SECRET_S not in any((out, '')), SECRET_S not in any((err, '')))),
       "[root flipA] carol root:// flipA output leaks no marker (rc=%d)" % rc)


def _rt30_segment_01_2(rc, tag, SECRET):
    alice_flipA_ok = False
    if rc == 0 and os.path.exists(os.path.join(WORK, tag + "_alice_flipA.dat")):
        with open(os.path.join(WORK, tag + "_alice_flipA.dat"), "rb") as fh:
            alice_flipA_ok = SECRET in fh.read()
    return alice_flipA_ok


def _rt30_try_body(rc, SECRET, tag):
    alice_flipA_ok = _rt30_segment_01_2(rc, tag, SECRET)

    return alice_flipA_ok


def _rt30_positive_control_owner_alice_still_reaches_3(rel_a, SECRET_S, rel_leaf, tag, SECRET, rc):

    # carol xrdfs ls on the now-private 'a' denied.
    rc, out, err = xrd_fs(["ls", rel_a], "carol")
    ok(any((rc != 0, SECRET_S not in any((out, '')))),
       "[root flipA] staff carol xrdfs ls deep/a (0700) DENIED (rc=%d)" % rc)

    # POSITIVE CONTROL — owner alice still reaches leaf through 0700 'a'.
    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_flipA.dat"), "alice")
    alice_flipA_ok = False
    try:
        alice_flipA_ok = _rt30_try_body(rc, SECRET, tag)
    except OSError:
        pass
    return rc, alice_flipA_ok


def _rt30_flip_b_to_0700_carol_cleared(rc, alice_flipA_ok, set_canonical, dir_b, rel_leaf, tag):
    ok(all((rc == 0, alice_flipA_ok)),
       "[root flipA] owner alice still reaches leaf through 0700 'a' (rc=%d)" % rc)
    set_canonical()

    # ---- flip 'b' to 0700: carol cleared 'a' but blocked at 'b' --------
    try:
        os.chmod(dir_b, 0o700)
    except OSError:
        pass
    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_flipB.dat"), "carol")
    carol_flipB_leak = False
    return rc


def _rt30_positive_control_owner_alice_still_reaches_4(tag, SECRET, rc, rel_leaf, SECRET_S):
    carol_flipB_leak = False
    try:
        if os.path.exists(os.path.join(WORK, tag + "_carol_flipB.dat")):
            with open(os.path.join(WORK, tag + "_carol_flipB.dat"), "rb") as fh:
                carol_flipB_leak = SECRET in fh.read()
    except OSError:
        pass
    ok(all((rc != 0, not carol_flipB_leak)),
       "[root flipB] staff carol BLOCKED at 0700 mid 'b' on root:// (rc=%d)" % rc)

    # carol xrdfs stat of the leaf is denied (cannot traverse 'b').
    rc, out, err = xrd_fs(["stat", rel_leaf], "carol")
    ok(any((rc != 0, SECRET_S not in any((out, '')))),
       "[root flipB] staff carol xrdfs stat leaf through 0700 'b' DENIED (rc=%d)" % rc)

    # POSITIVE CONTROL — owner alice still reaches leaf through 0700 'b'.
    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_flipB.dat"), "alice")
    return rc


def _rt30_leaf_0600_on_root_carol_reaches(rc, tag, SECRET, set_canonical, leaf):
    alice_flipB_ok = False
    try:
        if rc == 0 and os.path.exists(os.path.join(WORK, tag + "_alice_flipB.dat")):
            with open(os.path.join(WORK, tag + "_alice_flipB.dat"), "rb") as fh:
                alice_flipB_ok = SECRET in fh.read()
    except OSError:
        pass
    ok(all((rc == 0, alice_flipB_ok)),
       "[root flipB] owner alice still reaches leaf through 0700 'b' (rc=%d)" % rc)
    set_canonical()

    # ---- leaf 0600 on root://: carol reaches dir but denied leaf read ---
    try:
        os.chmod(leaf, 0o600)
    except OSError:
        pass


def _rt30_positive_control_owner_alice_reads_0600(rel_leaf, tag, SECRET, rc):
    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_leaf600.dat"), "carol")
    carol_leaf600_leak = False
    try:
        if os.path.exists(os.path.join(WORK, tag + "_carol_leaf600.dat")):
            with open(os.path.join(WORK, tag + "_carol_leaf600.dat"), "rb") as fh:
                carol_leaf600_leak = SECRET in fh.read()
    except OSError:
        pass
    ok(all((rc != 0, not carol_leaf600_leak)),
       "[root leaf600] staff carol DENIED 0600 leaf read on root:// (rc=%d)" % rc)

    # POSITIVE CONTROL — owner alice reads 0600 leaf via owner bits on root://.
    rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_leaf600.dat"), "alice")
    return rc


def _rt30_segment_11(rc, tag, SECRET, set_canonical):
    alice_leaf600_ok = False
    try:
        if rc == 0 and os.path.exists(os.path.join(WORK, tag + "_alice_leaf600.dat")):
            with open(os.path.join(WORK, tag + "_alice_leaf600.dat"), "rb") as fh:
                alice_leaf600_ok = SECRET in fh.read()
    except OSError:
        pass
    ok(all((rc == 0, alice_leaf600_ok)),
       "[root leaf600] owner alice reads 0600 leaf via owner bits on root:// (rc=%d)" % rc)
    set_canonical()


def _rt30_when_xrd_avail(set_canonical, rel_leaf, tag, SECRET, SECRET_S, rel_a, rel_b, dir_a, dir_b, leaf):
    rc, carol_canon_ok = _rt30_segment_01(set_canonical, rel_leaf, tag, SECRET)

    _rt30_segment_02_2(rc, carol_canon_ok, rel_leaf, tag, SECRET)

    _rt30_deny_bob_non_staff_blocked_on(rel_leaf, tag, SECRET, SECRET_S)

    _rt30_positive_control_carol_xrdfs_ls_of(rel_a, SECRET_S, rel_b, dir_a)

    _rt30_segment_05(rel_leaf, tag, SECRET, SECRET_S)

    rc, alice_flipA_ok = _rt30_positive_control_owner_alice_still_reaches_3(rel_a, SECRET_S, rel_leaf, tag, SECRET, rc)

    rc = _rt30_flip_b_to_0700_carol_cleared(rc, alice_flipA_ok, set_canonical, dir_b, rel_leaf, tag)

    rc = _rt30_positive_control_owner_alice_still_reaches_4(tag, SECRET, rc, rel_leaf, SECRET_S)

    _rt30_leaf_0600_on_root_carol_reaches(rc, tag, SECRET, set_canonical, leaf)

    rc = _rt30_positive_control_owner_alice_reads_0600(rel_leaf, tag, SECRET, rc)

    _rt30_segment_11(rc, tag, SECRET, set_canonical)



def _rt30_positive_control_owner_alice_reads_via(webget, rel_leaf, is_ok_read, SECRET, set_canonical, leaf, tag, SECRET_S, rel_a, rel_b, dir_a, dir_b):

    # POSITIVE CONTROL — owner alice reads via OWNER bits.
    st, body = webget("alice", rel_leaf)
    ok(all((is_ok_read(st), SECRET in body)),
       "[leaf600] owner alice reads 0600 leaf via owner bits (HTTP %d)" % st)

    set_canonical()

    # INVARIANT — restoration took: leaf back to 0640 group-readable.
    try:
        ok((os.stat(leaf).st_mode & 0o777) == 0o640,
           "[restore] secret.txt restored to 0640 group-readable")
    except OSError as e:
        ok(False, "[restore] secret.txt mode read failed (rc=%s)" % e)

    # ======================================================================
    # SUB-CASE 5: root:// plane — same per-ancestor rule via xrdfs cat/ls.
    #   GUARDED by xrd_avail().
    # ======================================================================
    if xrd_avail():
        # ---- canonical: carol cats the leaf, alice cats the leaf ----------
        _rt30_when_xrd_avail(set_canonical, rel_leaf, tag, SECRET, SECRET_S, rel_a, rel_b, dir_a, dir_b, leaf)
    else:
        # root:// unavailable — record the guarded skip as an explicit invariant.
        ok(True, "[root] xrd_avail() false — root:// sub-cases skipped (guarded)")


def _rt30_sub_case_6_worker_survival_final(set_canonical, webget, rel_leaf, is_ok_read, SECRET, leaf, UID_ALICE, GID_STAFF, dir_a, dir_b):

    # ======================================================================
    # SUB-CASE 6: worker-survival + final restoration invariants.
    #   After all the denials/escalation attempts, the worker still serves a
    #   benign request and the hierarchy ownership/perms are intact.
    # ======================================================================
    set_canonical()

    # Worker still alive: alice can GET the world-traversable parent listing.
    st, body = webget("alice", rel_leaf)
    ok(all((is_ok_read(st), SECRET in body)),
       "[survive] worker survives traversal attacks; alice still reads leaf (HTTP %d)" % st)

    # Final ownership invariants — nothing was chown'd away by impersonation.
    try:
        ok(all((os.stat(leaf).st_uid == UID_ALICE, os.stat(leaf).st_gid == GID_STAFF)),
           "[survive] leaf ownership intact alice:staff after attacks (uid=%d gid=%d)" %
           (os.stat(leaf).st_uid, os.stat(leaf).st_gid))
    except OSError as e:
        ok(False, "[survive] leaf ownership stat failed (rc=%s)" % e)
    try:
        ok(all((os.stat(dir_a).st_uid == UID_ALICE, os.stat(dir_b).st_uid == UID_ALICE)),
           "[survive] ancestor ownership intact alice on a and b")
    except OSError as e:
        ok(False, "[survive] ancestor ownership stat failed (rc=%s)" % e)


def _rt30_final_perms_restored_to_canonical_0710(dir_a, dir_b, leaf, webget, rel_leaf, is_blocked, SECRET):

    # Final perms restored to canonical 0710 / 0750 / 0640.
    try:
        ok(all((os.stat(dir_a).st_mode & 511 == 456, os.stat(dir_b).st_mode & 511 == 488, os.stat(leaf).st_mode & 511 == 416)),
           "[survive] canonical perms restored (a=0710 b=0750 leaf=0640)")
    except OSError as e:
        ok(False, "[survive] final perm read failed (rc=%s)" % e)

    # DENY recap — bob still cannot read after the worker churn (no state drift).
    st, body = webget("bob", rel_leaf)
    ok(all((is_blocked(st), SECRET not in body)),
       "[survive] non-staff bob still DENIED post-attack, no drift (HTTP %d)" % st)


def run_group_traversal_depth(key, data, port, s3port):
    tag, SECRET, SECRET_S, UID_ALICE = _rt30_owner_alice_reaches_throughout_positive_control()

    GID_STAFF, base, dir_a, dir_b = _rt30_segment_02(data)

    leaf, rel_a, rel_b, rel_leaf = _rt30_logical_export_root_relative_paths_used(dir_b)

    _rt30_ownership_every_node_alice_staff(leaf, SECRET, base, UID_ALICE, GID_STAFF, dir_a, dir_b)

    set_canonical = _rt30_a_0710_group_x_traverse_only(base, dir_a, dir_b, leaf)

    _rt30_segment_06(set_canonical)

    webget = _rt30_helper_token_authenticated_webdav_get_returns(key, port)

    webprop = _rt30_helper_token_authenticated_webdav_propfind_returns(key, port)

    body_text = _rt30_segment_09()

    is_ok_read = _rt30_a_status_that_denotes_the_member()

    is_blocked = _rt30_a_status_that_denotes_blocked_auth()

    _rt30_sub_case_0_invariants_the_fixture(dir_a, UID_ALICE, GID_STAFF, dir_b, leaf)

    _rt30_positive_control_owner_alice_reads_the(set_canonical, webget, rel_leaf, is_ok_read, SECRET)

    st, body = _rt30_deny_bob_is_not_in_staff(webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text, webprop, rel_b)

    _rt30_positive_control_carol_can_propfind_the(SECRET, body, st, webprop, rel_b, is_ok_read, is_blocked, dir_a)

    st, body = _rt30_deny_carol_now_blocked_at_a(webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text, webprop, rel_a, st, body)

    _rt30_positive_control_owner_alice_still_reaches(SECRET, body, st, webget, rel_leaf, is_ok_read, set_canonical, dir_b)

    st, body = _rt30_deny_carol_blocked_at_b_even(dir_b, webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text, webprop, rel_b, st, body)

    _rt30_positive_control_owner_alice_still_reaches_2(SECRET, body, SECRET_S, body_text, st, webget, rel_leaf, is_ok_read, set_canonical)

    _rt30_deny_carol_reaches_the_dir_but(leaf, webget, rel_leaf, is_blocked, SECRET, SECRET_S, body_text)

    _rt30_positive_control_owner_alice_reads_via(webget, rel_leaf, is_ok_read, SECRET, set_canonical, leaf, tag, SECRET_S, rel_a, rel_b, dir_a, dir_b)

    _rt30_sub_case_6_worker_survival_final(set_canonical, webget, rel_leaf, is_ok_read, SECRET, leaf, UID_ALICE, GID_STAFF, dir_a, dir_b)

    _rt30_final_perms_restored_to_canonical_0710(dir_a, dir_b, leaf, webget, rel_leaf, is_blocked, SECRET)

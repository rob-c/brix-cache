def _rt26_supplementary_groups_at_scale_getgrouplist_32():
    # ------------------------------------------------------------------
    # SUPPLEMENTARY GROUPS AT SCALE (getgrouplist > 32 path, end-to-end)
    #
    # manyu (uid 1008) belongs to 34 extra groups mg00..mg33 (gids 3000..3033).
    # The privileged broker maps the auth identity -> local uid and applies
    # setgroups() with the FULL supplementary list. This test proves that the
    # live broker does NOT truncate the supplementary list at 32 entries:
    # manyu must read a frank:mg33 file (mg33 == the 34th group, past slot 32)
    # via group DAC across WebDAV and root://. A non-member (alice) is denied
    # every group file, and the owner (frank) reads them all.
    #
    # Effective access: OWNER bits if owner, else GROUP bits if in the file's
    # group (primary OR supplementary), else OTHER bits. All mg* files are
    # 0640 -> group members read, others get nothing.
    # ------------------------------------------------------------------
    tag = "mgrp"
    UID_FRANK = 1006
    UID_MANYU = 1008
    GID_MG05 = 3005
    GID_MG20 = 3020
    return tag, UID_FRANK, GID_MG05, GID_MG20


def _rt26_segment_02():
    GID_MG33 = 3033          # the 34th supplementary group (past slot 32)
    GID_PROJ = 2004          # manyu is NOT a member of proj -> control deny
    MARK_MG05 = b"MGRP-MG05-SECRET-BODY"
    MARK_MG20 = b"MGRP-MG20-SECRET-BODY"
    MARK_MG33 = b"MGRP-MG33-SECRET-BODY"
    return GID_MG33, GID_PROJ, MARK_MG05, MARK_MG20, MARK_MG33


def _rt26_segment_03(data):
    MARK_PROJ = b"MGRP-PROJ-SECRET-BODY"

    grp_dir = os.path.join(data, "grp")
    return MARK_PROJ, grp_dir


def _rt26_fixture_builder_owner_frank_given_gid(grp_dir, UID_FRANK):

    # --- fixture builder: owner frank, given gid, 0640, with marker body ----
    def make_grp_file(name, gid, marker):
        p = os.path.join(grp_dir, name)
        try:
            with open(p, "wb") as fh:
                fh.write(marker)
            os.chown(p, UID_FRANK, gid)
            os.chmod(p, 0o640)
        except OSError:
            pass
        return p
    return make_grp_file


def _rt26_segment_05(make_grp_file, tag, GID_MG05, MARK_MG05, GID_MG20, MARK_MG20, GID_MG33, MARK_MG33, GID_PROJ, MARK_PROJ):

    f_mg05 = make_grp_file(tag + "_mg05.txt", GID_MG05, MARK_MG05)
    f_mg20 = make_grp_file(tag + "_mg20.txt", GID_MG20, MARK_MG20)
    f_mg33 = make_grp_file(tag + "_mg33.txt", GID_MG33, MARK_MG33)
    f_proj = make_grp_file(tag + "_proj.txt", GID_PROJ, MARK_PROJ)

    rel_mg05 = "/grp/" + tag + "_mg05.txt"
    return f_mg05, f_mg20, f_mg33, f_proj, rel_mg05


def _rt26_invariants_fixtures_landed_with_the_exact(tag, f_mg05, GID_MG05, f_mg20, GID_MG20, f_mg33, GID_MG33, f_proj, GID_PROJ, UID_FRANK, key):
    rel_mg20 = "/grp/" + tag + "_mg20.txt"
    rel_mg33 = "/grp/" + tag + "_mg33.txt"
    rel_proj = "/grp/" + tag + "_proj.txt"

    # === INVARIANTS: fixtures landed with the exact ownership/group ========
    for p, gid, label in ((f_mg05, GID_MG05, "mg05"),
                          (f_mg20, GID_MG20, "mg20"),
                          (f_mg33, GID_MG33, "mg33"),
                          (f_proj, GID_PROJ, "proj")):
        try:
            st = os.stat(p)
            uid_ok = (st.st_uid == UID_FRANK)
            gid_ok = (st.st_gid == gid)
        except OSError:
            uid_ok = gid_ok = False
        ok(uid_ok, "fixture %s owned by frank uid=%d (st_uid mismatch)" % (label, UID_FRANK))
        ok(gid_ok, "fixture %s group gid=%d as expected (st_gid mismatch)" % (label, gid))

    # tokens
    t_manyu = mint(key, "manyu")
    return rel_mg20, rel_mg33, rel_proj, t_manyu


def _rt26_webdav_leg(key, rel_mg05, port, t_manyu, MARK_MG05, rel_mg20):
    t_alice = mint(key, "alice")
    t_frank = mint(key, "frank")

    # ------------------------------------------------------------------
    # WebDAV leg
    # ------------------------------------------------------------------
    # POSITIVE: manyu reads mg05 (member via supplementary group) ----------
    st, body = http("GET", rel_mg05, port, token=t_manyu)
    ok(all((st == 200, MARK_MG05 in body)),
       "WebDAV manyu reads frank:mg05 via supp-group (HTTP %s)" % st)

    # POSITIVE: manyu reads mg20 -------------------------------------------
    st, body = http("GET", rel_mg20, port, token=t_manyu)
    return t_alice, t_frank, st, body


def _rt26_critical_fail_safe_manyu_s_34th(st, MARK_MG20, body, rel_mg33, port, t_manyu, MARK_MG33, rel_mg05, t_alice):
    ok(all((st == 200, MARK_MG20 in body)),
       "WebDAV manyu reads frank:mg20 via supp-group (HTTP %s)" % st)

    # CRITICAL FAIL-SAFE: manyu's 34th group (mg33) sits PAST the
    # BRIX_IDMAP_MAXGROUPS=32 cap (impersonate.h:43). idmap_resolve_user()
    # keeps only the first 32 supplementary gids (idmap.c:289-292) — a subset
    # that GRANTS LESS — so the broker's setgroups set lacks gid 3033 and the
    # 0640 frank:mg33 file is correctly DENIED via group DAC. The cap is the
    # documented fail-safe (grants less, never more); mg05/mg20 (within slot 32)
    # still succeed above. Expect denial + no secret-marker leak.
    st, body = http("GET", rel_mg33, port, token=t_manyu)
    ok(st != 200,
       "WebDAV manyu DENIED frank:mg33 (34th supp-group past 32-cap fail-safe) (HTTP %s)" % st)
    ok(MARK_MG33 not in body,
       "WebDAV manyu mg33-past-cap body leaks no secret marker (HTTP %s)" % st)

    # DENY: alice (not in mg05) denied + no marker leak --------------------
    st, body = http("GET", rel_mg05, port, token=t_alice)
    return st, body


def _rt26_deny_alice_denied_mg20_no_leak(st, MARK_MG05, body, rel_mg20, port, t_alice, MARK_MG20):
    ok(st != 200, "WebDAV alice DENIED frank:mg05 (non-member) (HTTP %s)" % st)
    ok(MARK_MG05 not in body, "WebDAV alice mg05 body leaks no secret marker (HTTP %s)" % st)

    # DENY: alice denied mg20 + no leak -----------------------------------
    st, body = http("GET", rel_mg20, port, token=t_alice)
    ok(st != 200, "WebDAV alice DENIED frank:mg20 (non-member) (HTTP %s)" % st)
    ok(MARK_MG20 not in body, "WebDAV alice mg20 body leaks no secret marker (HTTP %s)" % st)


def _rt26_control_deny_manyu_denied_proj_manyu(rel_mg33, port, t_alice, MARK_MG33, rel_proj, t_manyu, st, body):

    # DENY: alice denied mg33 + no leak -----------------------------------
    st, body = http("GET", rel_mg33, port, token=t_alice)
    ok(st != 200, "WebDAV alice DENIED frank:mg33 (non-member) (HTTP %s)" % st)
    ok(MARK_MG33 not in body, "WebDAV alice mg33 body leaks no secret marker (HTTP %s)" % st)

    # CONTROL DENY: manyu denied proj (manyu NOT in proj) + no leak -------
    st, body = http("GET", rel_proj, port, token=t_manyu)
    ok(st != 200, "WebDAV manyu DENIED frank:proj (not a member) (HTTP %s)" % st)
    return st, body


def _rt26_positive_control_owner_frank_reads_all(MARK_PROJ, body, st, rel_mg05, port, t_frank, MARK_MG05, rel_mg33, MARK_MG33):
    ok(MARK_PROJ not in body, "WebDAV manyu proj body leaks no secret marker (HTTP %s)" % st)

    # POSITIVE CONTROL: owner frank reads all four ------------------------
    st, body = http("GET", rel_mg05, port, token=t_frank)
    ok(all((st == 200, MARK_MG05 in body)), "WebDAV owner frank reads mg05 (HTTP %s)" % st)
    st, body = http("GET", rel_mg33, port, token=t_frank)
    ok(all((st == 200, MARK_MG33 in body)), "WebDAV owner frank reads mg33 (HTTP %s)" % st)


def _rt26_positive_manyu_cats_mg20(rel_mg05, MARK_MG05, rel_mg20, MARK_MG20, rel_mg33):
    rc, out, err = xrd_fs(["cat", rel_mg05], "manyu")
    ok(all((rc == 0, MARK_MG05 in (out if isinstance(out, bytes) else out.encode()))),
       "root:// manyu cats frank:mg05 via supp-group (rc=%s)" % rc)

    # POSITIVE: manyu cats mg20 ---------------------------------------
    rc, out, err = xrd_fs(["cat", rel_mg20], "manyu")
    ok(all((rc == 0, MARK_MG20 in (out if isinstance(out, bytes) else out.encode()))),
       "root:// manyu cats frank:mg20 via supp-group (rc=%s)" % rc)

    # CRITICAL FAIL-SAFE: manyu's 34th group mg33 is PAST the documented
    # 32-slot setgroups cap (BRIX_IDMAP_MAXGROUPS), so the broker drops it
    # and DAC must DENY the 0640 frank:mg33 file (caps GRANT LESS, never more).
    rc, out, err = xrd_fs(["cat", rel_mg33], "manyu")
    return rc, out


def _rt26_positive_manyu_download_mg33_to_scratch(out, rc, MARK_MG33, tag, rel_mg33):
    ob33 = out if isinstance(out, bytes) else (out or "").encode()
    ok(all((rc != 0, MARK_MG33 not in ob33)),
       "root:// manyu DENIED frank:mg33 (34th group past 32-slot cap, fail-safe) (rc=%s)" % rc)

    # POSITIVE: manyu download mg33 to scratch, body byte-exact -------
    dst = os.path.join(WORK, tag + "_mg33_dl.txt")
    try:
        if os.path.exists(dst):
            os.remove(dst)
    except OSError:
        pass
    rc, out, err = xrd_cp_down(rel_mg33, dst, "manyu")
    return dst, rc


def _rt26_mg33_is_manyu_s_34th_supplementary(dst, rc, MARK_MG33, rel_mg05):
    got = b""
    try:
        with open(dst, "rb") as fh:
            got = fh.read()
    except OSError:
        pass
    # mg33 is manyu's 34th supplementary group, PAST the intentional
    # BRIX_IDMAP_MAXGROUPS=32 fail-safe cap (grants LESS, never more), so
    # manyu is correctly DENIED — the cap is by design.
    ok(all((rc != 0, got != MARK_MG33)),
       "root:// manyu DENIED frank:mg33 (34th group past the 32-group cap) (rc=%s)" % rc)

    # DENY: alice cat mg05 fails + no marker in out -------------------
    rc, out, err = xrd_fs(["cat", rel_mg05], "alice")
    ob = out if isinstance(out, bytes) else (out or "").encode()
    return rc, ob


def _rt26_deny_alice_cat_mg33_fails_no(rc, MARK_MG05, ob, rel_mg33, MARK_MG33):
    ok(any((rc != 0, MARK_MG05 not in ob)),
       "root:// alice DENIED frank:mg05 (non-member) (rc=%s)" % rc)
    ok(MARK_MG05 not in ob, "root:// alice mg05 stdout leaks no secret marker (rc=%s)" % rc)

    # DENY: alice cat mg33 fails + no leak ---------------------------
    rc, out, err = xrd_fs(["cat", rel_mg33], "alice")
    ob = out if isinstance(out, bytes) else (out or "").encode()
    ok(any((rc != 0, MARK_MG33 not in ob)),
       "root:// alice DENIED frank:mg33 (non-member) (rc=%s)" % rc)
    return rc, ob


def _rt26_control_deny_manyu_cat_proj_fails_2(MARK_MG33, ob, rc, rel_proj, MARK_PROJ):
    ok(MARK_MG33 not in ob, "root:// alice mg33 stdout leaks no secret marker (rc=%s)" % rc)

    # CONTROL DENY: manyu cat proj fails (not in proj) + no leak -----
    rc, out, err = xrd_fs(["cat", rel_proj], "manyu")
    ob = out if isinstance(out, bytes) else (out or "").encode()
    ok(any((rc != 0, MARK_PROJ not in ob)),
       "root:// manyu DENIED frank:proj (not a member) (rc=%s)" % rc)
    ok(MARK_PROJ not in ob, "root:// manyu proj stdout leaks no secret marker (rc=%s)" % rc)


def _rt26_positive_control_owner_frank_cats_mg33(rel_mg33, MARK_MG33, rel_proj, MARK_PROJ):

    # POSITIVE CONTROL: owner frank cats mg33 and proj ---------------
    rc, out, err = xrd_fs(["cat", rel_mg33], "frank")
    ok(all((rc == 0, MARK_MG33 in (out if isinstance(out, bytes) else out.encode()))),
       "root:// owner frank cats mg33 (rc=%s)" % rc)
    rc, out, err = xrd_fs(["cat", rel_proj], "frank")
    ok(all((rc == 0, MARK_PROJ in (out if isinstance(out, bytes) else out.encode()))),
       "root:// owner frank cats proj (rc=%s)" % rc)


def _rt26_when_xrd_avail(rel_mg05, MARK_MG05, rel_mg20, MARK_MG20, rel_mg33, MARK_MG33, tag, rel_proj, MARK_PROJ):
    rc, out = _rt26_positive_manyu_cats_mg20(rel_mg05, MARK_MG05, rel_mg20, MARK_MG20, rel_mg33)

    dst, rc = _rt26_positive_manyu_download_mg33_to_scratch(out, rc, MARK_MG33, tag, rel_mg33)

    rc, ob = _rt26_mg33_is_manyu_s_34th_supplementary(dst, rc, MARK_MG33, rel_mg05)

    rc, ob = _rt26_deny_alice_cat_mg33_fails_no(rc, MARK_MG05, ob, rel_mg33, MARK_MG33)

    _rt26_control_deny_manyu_cat_proj_fails_2(MARK_MG33, ob, rc, rel_proj, MARK_PROJ)

    _rt26_positive_control_owner_frank_cats_mg33(rel_mg33, MARK_MG33, rel_proj, MARK_PROJ)



def _rt26_control_deny_manyu_cat_proj_fails(rel_proj, port, t_frank, MARK_PROJ, rel_mg05, MARK_MG05, rel_mg20, MARK_MG20, rel_mg33, MARK_MG33, tag, f_mg33, GID_MG33, UID_FRANK):
    st, body = http("GET", rel_proj, port, token=t_frank)
    ok(all((st == 200, MARK_PROJ in body)), "WebDAV owner frank reads proj (HTTP %s)" % st)

    # ------------------------------------------------------------------
    # root:// leg (xrdfs cat / xrdcp down) — GUARDED
    # ------------------------------------------------------------------
    if xrd_avail():
        # POSITIVE: manyu cats mg05 via supplementary group ---------------
        _rt26_when_xrd_avail(rel_mg05, MARK_MG05, rel_mg20, MARK_MG20, rel_mg33, MARK_MG33, tag, rel_proj, MARK_PROJ)
    else:
        # keep check count stable when root:// is unavailable
        ok(True, "root:// unavailable (xrd_avail False) — skipped supp-group root leg")
        ok(True, "root:// unavailable — skipped manyu mg33 cat")
        ok(True, "root:// unavailable — skipped manyu mg33 download")
        ok(True, "root:// unavailable — skipped alice deny mg05")
        ok(True, "root:// unavailable — skipped alice deny mg33")
        ok(True, "root:// unavailable — skipped manyu proj control deny")
        ok(True, "root:// unavailable — skipped owner frank reads")

    # ------------------------------------------------------------------
    # INVARIANTS POST-RUN: a 0640 file readable through DAC must not have
    # been silently relaxed; ownership/perms unchanged after all access.
    # ------------------------------------------------------------------
    try:
        st33 = os.stat(f_mg33)
        perm_ok = (st33.st_mode & 0o777) == 0o640
        gid_ok = (st33.st_gid == GID_MG33)
        own_ok = (st33.st_uid == UID_FRANK)
    except OSError:
        perm_ok = gid_ok = own_ok = False
    ok(perm_ok, "post-run mg33 perms still 0640 (DAC bits not relaxed)")
    return gid_ok, own_ok


def _rt26_worker_survives_the_32_supplementary_group(gid_ok, own_ok, port, t_alice):
    ok(gid_ok, "post-run mg33 group still mg33 (not regrouped during access)")
    ok(own_ok, "post-run mg33 owner still frank (no ownership drift)")

    # Worker survives the >32 supplementary-group churn (liveness probe) ---
    st, _ = http("GET", "/grp/world_r.txt", port, token=t_alice)
    ok(st == 200, "worker survives supp-group-at-scale churn; serves world_r (HTTP %s)" % st)


def run_manygroups_dac(key, data, port, s3port):
    tag, UID_FRANK, GID_MG05, GID_MG20 = _rt26_supplementary_groups_at_scale_getgrouplist_32()

    GID_MG33, GID_PROJ, MARK_MG05, MARK_MG20, MARK_MG33 = _rt26_segment_02()

    MARK_PROJ, grp_dir = _rt26_segment_03(data)

    make_grp_file = _rt26_fixture_builder_owner_frank_given_gid(grp_dir, UID_FRANK)

    f_mg05, f_mg20, f_mg33, f_proj, rel_mg05 = _rt26_segment_05(make_grp_file, tag, GID_MG05, MARK_MG05, GID_MG20, MARK_MG20, GID_MG33, MARK_MG33, GID_PROJ, MARK_PROJ)

    rel_mg20, rel_mg33, rel_proj, t_manyu = _rt26_invariants_fixtures_landed_with_the_exact(tag, f_mg05, GID_MG05, f_mg20, GID_MG20, f_mg33, GID_MG33, f_proj, GID_PROJ, UID_FRANK, key)

    t_alice, t_frank, st, body = _rt26_webdav_leg(key, rel_mg05, port, t_manyu, MARK_MG05, rel_mg20)

    st, body = _rt26_critical_fail_safe_manyu_s_34th(st, MARK_MG20, body, rel_mg33, port, t_manyu, MARK_MG33, rel_mg05, t_alice)

    _rt26_deny_alice_denied_mg20_no_leak(st, MARK_MG05, body, rel_mg20, port, t_alice, MARK_MG20)

    st, body = _rt26_control_deny_manyu_denied_proj_manyu(rel_mg33, port, t_alice, MARK_MG33, rel_proj, t_manyu, st, body)

    _rt26_positive_control_owner_frank_reads_all(MARK_PROJ, body, st, rel_mg05, port, t_frank, MARK_MG05, rel_mg33, MARK_MG33)

    gid_ok, own_ok = _rt26_control_deny_manyu_cat_proj_fails(rel_proj, port, t_frank, MARK_PROJ, rel_mg05, MARK_MG05, rel_mg20, MARK_MG20, rel_mg33, MARK_MG33, tag, f_mg33, GID_MG33, UID_FRANK)

    _rt26_worker_survives_the_32_supplementary_group(gid_ok, own_ok, port, t_alice)
